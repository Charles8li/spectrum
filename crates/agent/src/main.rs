use std::{
    collections::HashMap,
    io::SeekFrom,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::Parser;
use enigo::{Enigo, Key, MouseButton};
use futures::StreamExt;
use lanrdp_common::{
    agent_store_path, derive_psk, generate_session_token, hmac_sha256,
    proto::{self, control_envelope::Msg, AuthMethod, ControlEnvelope},
    recv_message, send_message, SessionStore, StoredClient,
};
use quinn::Endpoint;
use rand::{rngs::OsRng, RngCore};
use rcgen::{Certificate, CertificateParams};
use rustls::{Certificate as RustlsCertificate, PrivateKey};
use screenshots::Screen;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    sync::Mutex,
    time::{sleep, Duration},
};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "LAN remote desktop agent", long_about = None)]
struct AgentArgs {
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: String,

    #[arg(long)]
    pin: String,

    #[arg(long, default_value_t = false)]
    mdns: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = AgentArgs::parse();
    let listen: SocketAddr = args.listen.parse().context("invalid listen address")?;

    let store_path = agent_store_path()?;
    let session_store = Arc::new(Mutex::new(SessionStore::load(store_path).await?));

    let cert_path = lanrdp_common::config_dir()?.join("agent_cert.der");
    let key_path = lanrdp_common::config_dir()?.join("agent_key.der");
    let (cert_chain, priv_key) = load_or_create_cert(&cert_path, &key_path)?;

    let endpoint = Endpoint::server(build_server_config(cert_chain.clone(), priv_key)?, listen)?;
    info!(?listen, "lanrdp agent listening");

    run(endpoint, session_store, args.pin).await
}

fn load_or_create_cert(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<RustlsCertificate>, PrivateKey)> {
    if cert_path.exists() && key_path.exists() {
        let cert = std::fs::read(cert_path)?;
        let key = std::fs::read(key_path)?;
        return Ok((vec![RustlsCertificate(cert)], PrivateKey(key)));
    }

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut params = CertificateParams::new(vec!["lanrdp.local".into()]);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "lanrdp-agent");
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let cert = Certificate::from_params(params)?;
    let der = cert.serialize_der()?;
    let key = cert.serialize_private_key_der();
    std::fs::write(cert_path, &der)?;
    std::fs::write(key_path, &key)?;
    Ok((vec![RustlsCertificate(der)], PrivateKey(key)))
}

fn build_server_config(
    cert: Vec<RustlsCertificate>,
    key: PrivateKey,
) -> Result<quinn::ServerConfig> {
    let mut server_config = quinn::ServerConfig::with_single_cert(cert, key)?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.max_idle_timeout(Some(quinn::IdleTimeout::try_from(
        std::time::Duration::from_secs(30),
    )?));
    server_config.transport = Arc::new(transport);
    Ok(server_config)
}

async fn run(
    endpoint: Endpoint,
    store: Arc<Mutex<lanrdp_common::SessionStore>>,
    pin: String,
) -> Result<()> {
    let mut incoming = endpoint.incoming();
    while let Some(conn) = incoming.next().await {
        let store = store.clone();
        let pin = pin.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(conn, store, &pin).await {
                error!(?err, "connection ended with error");
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    connecting: quinn::Connecting,
    store: Arc<Mutex<lanrdp_common::SessionStore>>,
    pin: &str,
) -> Result<()> {
    let connection = connecting.await?;
    info!(remote = ?connection.remote_address(), "accepted connection");

    let (mut control_send, mut control_recv) = connection.accept_bi().await?;
    let descriptor = lanrdp_common::StreamDescriptor::read_header(&mut control_recv).await?;
    if descriptor.ty != lanrdp_common::STREAM_TYPE_CONTROL {
        return Err(anyhow!("expected control stream"));
    }
    lanrdp_common::StreamDescriptor::control()
        .write_header(&mut control_send)
        .await?;

    let hello: ControlEnvelope = recv_message(&mut control_recv).await?;
    let device = match hello.msg {
        Some(Msg::Hello(hello)) => hello,
        _ => return Err(anyhow!("expected hello")),
    };

    let mut store_lock = store.lock().await;
    let challenge = random_bytes();
    let mut response = ControlEnvelope { msg: None };
    let auth_method;
    if let Some(entry) = store_lock.get(&device.device_id) {
        auth_method = AuthMethod::AuthMethodResume as i32;
        response.msg = Some(Msg::Auth(proto::Auth {
            method: AuthMethod::AuthMethodResume as i32,
            challenge: challenge.clone(),
            proof: bytes::Bytes::new(),
        }));
        send_message(&mut control_send, &response).await?;
        drop(store_lock);

        let auth_reply: ControlEnvelope = recv_message(&mut control_recv).await?;
        let proof = match auth_reply.msg {
            Some(Msg::Auth(auth)) => auth.proof,
            _ => return Err(anyhow!("expected auth reply")),
        };
        let expected = hmac_sha256(&entry.psk, &challenge);
        if proof.as_ref() != &expected[..] {
            return Err(anyhow!("invalid resume proof"));
        }
        let token = entry.session_token.clone();
        let ok = ControlEnvelope {
            msg: Some(Msg::AuthOk(proto::AuthOk {
                session_token: token.into(),
            })),
        };
        send_message(&mut control_send, &ok).await?;
    } else {
        auth_method = AuthMethod::AuthMethodPin as i32;
        response.msg = Some(Msg::Auth(proto::Auth {
            method: AuthMethod::AuthMethodPin as i32,
            challenge: challenge.clone(),
            proof: bytes::Bytes::new(),
        }));
        send_message(&mut control_send, &response).await?;

        let auth_reply: ControlEnvelope = recv_message(&mut control_recv).await?;
        let proof = match auth_reply.msg {
            Some(Msg::Auth(auth)) => auth.proof,
            _ => return Err(anyhow!("expected auth proof")),
        };
        let psk = derive_psk(pin, &device.device_id);
        let expected = hmac_sha256(&psk, &challenge);
        if proof.as_ref() != &expected[..] {
            return Err(anyhow!("invalid pin proof"));
        }
        let token = generate_session_token();
        let stored = lanrdp_common::StoredClient {
            device_id: device.device_id.clone(),
            session_token: token.clone(),
            psk: psk.to_vec(),
            peer_label: Some(device.name.clone()),
        };
        store_lock.upsert(stored);
        store_lock.save().await?;
        drop(store_lock);
        let ok = ControlEnvelope {
            msg: Some(Msg::AuthOk(proto::AuthOk {
                session_token: token.clone().into(),
            })),
        };
        send_message(&mut control_send, &ok).await?;
    }

    info!(device_id = %device.device_id, method = auth_method, "authenticated");

    // Wait for session configuration
    let cfg_msg: ControlEnvelope = recv_message(&mut control_recv).await?;
    let session_cfg = match cfg_msg.msg {
        Some(Msg::SessionConfig(cfg)) => cfg,
        _ => return Err(anyhow!("expected session config")),
    };
    info!(?session_cfg, "received session config");

    // Confirm configuration
    send_message(&mut control_send, &ControlEnvelope { msg: None }).await?;

    let control_send = Arc::new(Mutex::new(control_send));
    let pending_shells: Arc<Mutex<HashMap<u32, ShellResources>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let file_transfers: Arc<Mutex<HashMap<u64, FileTransferState>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let session_cfg = Arc::new(session_cfg);

    let dispatcher = tokio::spawn(dispatch_streams(
        connection.clone(),
        pending_shells.clone(),
        file_transfers.clone(),
        control_send.clone(),
        session_cfg.clone(),
    ));

    let mut next_sid: u32 = 1;

    loop {
        match recv_message::<_, ControlEnvelope>(&mut control_recv).await {
            Ok(env) => match env.msg {
                Some(Msg::ShellOpen(open)) => {
                    let sid = next_sid;
                    next_sid = next_sid.wrapping_add(1).max(1);
                    info!(sid, cwd = %open.cwd, cols = open.cols, rows = open.rows, "opening shell session");

                    match spawn_shell_process(&open) {
                        Ok(resources) => {
                            pending_shells.lock().await.insert(sid, resources);
                            let mut guard = control_send.lock().await;
                            send_message(
                                &mut *guard,
                                &ControlEnvelope {
                                    msg: Some(Msg::ShellOpened(proto::ShellOpened { sid })),
                                },
                            )
                            .await?;
                        }
                        Err(err) => {
                            warn!(?err, "failed to spawn shell");
                            let mut guard = control_send.lock().await;
                            let exit = ControlEnvelope {
                                msg: Some(Msg::ShellExit(proto::ShellExit { sid, code: -1 })),
                            };
                            send_message(&mut *guard, &exit).await?;
                        }
                    }
                }
                Some(Msg::ShellResize(resize)) => {
                    info!(
                        sid = resize.sid,
                        cols = resize.cols,
                        rows = resize.rows,
                        "shell resize requested (not yet implemented)"
                    );
                }
                Some(Msg::InputEvent(event)) => log_input_event(None, event),
                Some(Msg::FileOffer(offer)) => {
                    info!(id = offer.id, name = %offer.name, size = offer.size, "file offer received");
                    file_transfers.lock().await.insert(
                        offer.id,
                        FileTransferState {
                            offer,
                            target_path: None,
                            resume_offset: 0,
                        },
                    );
                }
                Some(Msg::FileAccept(accept)) => {
                    let mut transfers = file_transfers.lock().await;
                    if let Some(state) = transfers.get_mut(&accept.id) {
                        let path = PathBuf::from(&accept.target_dir).join(&state.offer.name);
                        if let Some(parent) = path.parent() {
                            fs::create_dir_all(parent).await?;
                        }
                        state.target_path = Some(path.clone());
                        state.resume_offset = accept.resume_offset;
                        let ack = ControlEnvelope {
                            msg: Some(Msg::FileAccept(accept.clone())),
                        };
                        let mut guard = control_send.lock().await;
                        send_message(&mut *guard, &ack).await?;
                        info!(id = accept.id, target = ?path, "prepared to receive file");
                    } else {
                        warn!(id = accept.id, "got file accept without offer");
                    }
                }
                Some(_) => {
                    warn!("unhandled control message");
                }
                None => {
                    info!("control stream closed by peer");
                    break;
                }
            },
            Err(err) => {
                warn!(?err, "control stream ended");
                break;
            }
        }
    }

    let _ = dispatcher.await;

    Ok(())
}

fn random_bytes() -> Bytes {
    let mut buf = vec![0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.into()
}

async fn dispatch_streams(
    connection: quinn::Connection,
    pending_shells: Arc<Mutex<HashMap<u32, ShellResources>>>,
    file_transfers: Arc<Mutex<HashMap<u64, FileTransferState>>>,
    control_send: Arc<Mutex<quinn::SendStream>>,
    session_cfg: Arc<proto::SessionConfig>,
) -> Result<()> {
    loop {
        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
            break;
        };
        let pending_shells = pending_shells.clone();
        let file_transfers = file_transfers.clone();
        let control_send = control_send.clone();
        let session_cfg = session_cfg.clone();

        tokio::spawn(async move {
            match lanrdp_common::StreamDescriptor::read_header(&mut recv).await {
                Ok(descriptor) => match descriptor.ty {
                    lanrdp_common::STREAM_TYPE_PTY => {
                        if let Some(sid) = descriptor.extra {
                            if let Some(resources) = pending_shells.lock().await.remove(&sid) {
                                if let Err(err) = run_shell_session_stream(
                                    sid,
                                    resources,
                                    send,
                                    recv,
                                    control_send,
                                )
                                .await
                                {
                                    warn!(sid, ?err, "shell session errored");
                                }
                            } else {
                                warn!(sid, "received PTY stream without pending shell");
                            }
                        } else {
                            warn!("PTY stream missing sid");
                        }
                    }
                    lanrdp_common::STREAM_TYPE_VIDEO => {
                        if let Err(err) = handle_video_stream(send, recv, session_cfg).await {
                            warn!(?err, "video stream errored");
                        }
                    }
                    lanrdp_common::STREAM_TYPE_INPUT => {
                        if let Err(err) = handle_input_stream(send, recv).await {
                            warn!(?err, "input stream errored");
                        }
                    }
                    lanrdp_common::STREAM_TYPE_FILE => {
                        let fid = descriptor.extra.unwrap_or_default() as u64;
                        if let Err(err) =
                            handle_file_stream(fid, send, recv, file_transfers, control_send).await
                        {
                            warn!(id = fid, ?err, "file stream errored");
                        }
                    }
                    _ => warn!(ty = descriptor.ty, "unsupported stream type"),
                },
                Err(err) => warn!(?err, "failed to read stream descriptor"),
            }
        });
    }

    Ok(())
}

struct ShellResources {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

struct FileTransferState {
    offer: proto::FileOffer,
    target_path: Option<PathBuf>,
    resume_offset: u64,
}

fn spawn_shell_process(open: &proto::ShellOpen) -> Result<ShellResources> {
    let mut command = if cfg!(target_os = "windows") {
        let mut cmd = Command::new("cmd");
        cmd.arg("/K");
        cmd
    } else {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-i");
        cmd
    };

    if !open.cwd.is_empty() {
        command.current_dir(&open.cwd);
    }

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().context("spawn shell")?;
    let stdin = child.stdin.take().context("child stdin unavailable")?;
    let stdout = child.stdout.take().context("child stdout unavailable")?;
    let stderr = child.stderr.take().context("child stderr unavailable")?;

    Ok(ShellResources {
        child,
        stdin,
        stdout,
        stderr,
    })
}

async fn handle_video_stream(
    mut send: quinn::SendStream,
    _recv: quinn::RecvStream,
    session_cfg: Arc<proto::SessionConfig>,
) -> Result<()> {
    lanrdp_common::StreamDescriptor::video()
        .write_header(&mut send)
        .await?;

    let (target_width, target_height) = normalize_dimensions(session_cfg.width, session_cfg.height);
    let color = proto::ColorFormat::ColorFormatRgb565 as i32;

    let frame_delay = if session_cfg.max_fps == 0 {
        Duration::from_millis(1000)
    } else {
        Duration::from_millis(1000 / session_cfg.max_fps as u64)
    };

    let mut seq: u64 = 0;
    let screens = Screen::all().context("list displays")?;
    let Some(primary) = screens.first() else {
        return Err(anyhow!("no displays available for capture"));
    };

    loop {
        match primary.capture() {
            Ok(image) => {
                let rgb565 = convert_capture_to_rgb565(
                    image.buffer(),
                    image.width() as u32,
                    image.height() as u32,
                    target_width,
                    target_height,
                );

                let frame = proto::VideoFrameHeader {
                    seq,
                    ts_ms: lanrdp_common::now_millis(),
                    width: target_width,
                    height: target_height,
                    key: seq == 0,
                    codec: session_cfg.video,
                    color,
                    stride: target_width.saturating_mul(2),
                    payload: rgb565.into(),
                    tiles: Vec::new(),
                };
                if let Err(err) = send_message(&mut send, &frame).await {
                    warn!(?err, "failed to send video frame");
                    break;
                }
            }
            Err(err) => {
                warn!(?err, "screen capture failed, stopping video stream");
                break;
            }
        }

        seq = seq.wrapping_add(1);
        sleep(frame_delay).await;
    }

    Ok(())
}

fn normalize_dimensions(requested_width: u32, requested_height: u32) -> (u32, u32) {
    let width = requested_width.max(1);
    let height = requested_height.max(1);
    (width, height)
}

fn convert_capture_to_rgb565(
    bgra: &[u8],
    src_width: u32,
    src_height: u32,
    target_width: u32,
    target_height: u32,
) -> Vec<u8> {
    let mut output = vec![0u8; (target_width * target_height * 2) as usize];

    for ty in 0..target_height {
        let sy = ty.saturating_mul(src_height).saturating_div(target_height);
        for tx in 0..target_width {
            let sx = tx.saturating_mul(src_width).saturating_div(target_width);
            let src_index = ((sy * src_width + sx) * 4) as usize;
            let b = bgra.get(src_index).copied().unwrap_or_default();
            let g = bgra.get(src_index + 1).copied().unwrap_or_default();
            let r = bgra.get(src_index + 2).copied().unwrap_or_default();

            let rgb565 = ((r as u16 & 0xF8) << 8) | ((g as u16 & 0xFC) << 3) | ((b as u16) >> 3);
            let dst_index = ((ty * target_width + tx) * 2) as usize;
            output[dst_index] = (rgb565 >> 8) as u8;
            output[dst_index + 1] = rgb565 as u8;
        }
    }

    output
}

async fn handle_input_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    lanrdp_common::StreamDescriptor::input()
        .write_header(&mut send)
        .await?;

    let mut enigo = Enigo::new();

    loop {
        match recv_message::<_, proto::InputEvent>(&mut recv).await {
            Ok(event) => log_input_event(Some(&mut enigo), event),
            Err(err) => {
                warn!(?err, "input stream closed");
                break;
            }
        }
    }

    Ok(())
}

fn map_button(button: u32) -> Option<MouseButton> {
    match button {
        0 => Some(MouseButton::Left),
        1 => Some(MouseButton::Right),
        2 => Some(MouseButton::Middle),
        _ => None,
    }
}

fn log_input_event(enigo: Option<&mut Enigo>, event: proto::InputEvent) {
    match event.event {
        Some(proto::input_event::Event::Key(key)) => {
            if let Some(injector) = enigo {
                let code = key.scancode as u16;
                if key.down {
                    injector.key_down(Key::Raw(code));
                } else {
                    injector.key_up(Key::Raw(code));
                }
            }
            info!(
                scancode = key.scancode,
                down = key.down,
                "key event injected"
            );
        }
        Some(proto::input_event::Event::Mouse(mouse)) => {
            if let Some(injector) = enigo.as_ref() {
                match proto::MouseEventType::from_i32(mouse.r#type) {
                    Some(proto::MouseEventType::MouseEventTypeMove) => {
                        if mouse.delta_x != 0 || mouse.delta_y != 0 {
                            injector.mouse_move_relative(mouse.delta_x, mouse.delta_y);
                        } else {
                            injector.mouse_move_to(mouse.x, mouse.y);
                        }
                    }
                    Some(proto::MouseEventType::MouseEventTypeButton) => {
                        if let Some(button) = map_button(mouse.button) {
                            if mouse.down {
                                injector.mouse_down(button);
                            } else {
                                injector.mouse_up(button);
                            }
                        }
                    }
                    Some(proto::MouseEventType::MouseEventTypeScroll) => {
                        if mouse.delta_y != 0 {
                            injector.mouse_scroll_y(mouse.delta_y);
                        }
                        if mouse.delta_x != 0 {
                            injector.mouse_scroll_x(mouse.delta_x);
                        }
                    }
                    None => warn!(kind = mouse.r#type, "unknown mouse event"),
                }
            }

            info!(
                x = mouse.x,
                y = mouse.y,
                delta_x = mouse.delta_x,
                delta_y = mouse.delta_y,
                button = mouse.button,
                down = mouse.down,
                kind = ?mouse.r#type,
                "mouse event injected"
            );
        }
        None => warn!("empty input event received"),
    }
}

async fn handle_file_stream(
    fid: u64,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    transfers: Arc<Mutex<HashMap<u64, FileTransferState>>>,
    control_send: Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    lanrdp_common::StreamDescriptor::file(fid as u32)
        .write_header(&mut send)
        .await?;

    let mut state_guard = transfers.lock().await;
    let state = state_guard
        .get(&fid)
        .cloned()
        .ok_or_else(|| anyhow!("unknown file transfer {fid}"))?;
    drop(state_guard);

    let target = state
        .target_path
        .ok_or_else(|| anyhow!("file transfer {fid} missing target path"))?;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&target)
        .await?;

    if state.resume_offset > 0 {
        file.seek(SeekFrom::Start(state.resume_offset)).await?;
    } else {
        file.set_len(0).await?;
    }

    let mut hasher = Sha256::new();
    loop {
        match recv_message::<_, proto::FileChunk>(&mut recv).await {
            Ok(chunk) => {
                file.seek(SeekFrom::Start(chunk.offset + state.resume_offset))
                    .await?;
                file.write_all(&chunk.data).await?;
                hasher.update(&chunk.data);
            }
            Err(err) => {
                warn!(id = fid, ?err, "file stream closed");
                break;
            }
        }
    }

    let digest = hasher.finalize().to_vec();
    if digest != state.offer.sha256 {
        warn!(id = fid, "received file digest does not match offer");
    }

    let mut transfers = transfers.lock().await;
    transfers.remove(&fid);
    drop(transfers);

    let mut guard = control_send.lock().await;
    send_message(
        &mut *guard,
        &ControlEnvelope {
            msg: Some(Msg::FileComplete(proto::FileComplete {
                id: fid,
                sha256: digest.into(),
            })),
        },
    )
    .await?;
    let _ = send.finish().await;
    info!(id = fid, path = ?target, "file transfer completed");

    Ok(())
}

async fn run_shell_session_stream(
    sid: u32,
    mut resources: ShellResources,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    control_send: Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    lanrdp_common::StreamDescriptor::pty(sid)
        .write_header(&mut send)
        .await?;

    let send = Arc::new(Mutex::new(send));

    let mut stdin = resources.stdin;
    let mut stdout = resources.stdout;
    let mut stderr = resources.stderr;

    let send_stdout = send.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let read = match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) => {
                    warn!(?err, "shell stdout read error");
                    break;
                }
            };
            let mut guard = send_stdout.lock().await;
            if let Err(err) =
                lanrdp_common::send_bytes(&mut *guard, Bytes::copy_from_slice(&buf[..read])).await
            {
                warn!(?err, "failed to forward stdout");
                break;
            }
        }
    });

    let send_stderr = send.clone();
    let stderr_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let read = match stderr.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) => {
                    warn!(?err, "shell stderr read error");
                    break;
                }
            };
            let mut guard = send_stderr.lock().await;
            if let Err(err) =
                lanrdp_common::send_bytes(&mut *guard, Bytes::copy_from_slice(&buf[..read])).await
            {
                warn!(?err, "failed to forward stderr");
                break;
            }
        }
    });

    let stdin_task = tokio::spawn(async move {
        loop {
            match lanrdp_common::recv_bytes(&mut recv).await {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        break;
                    }
                    if let Err(err) = stdin.write_all(&bytes).await {
                        warn!(?err, "failed to write to shell stdin");
                        break;
                    }
                }
                Err(err) => {
                    warn!(?err, "client input stream ended");
                    break;
                }
            }
        }
        let _ = stdin.shutdown().await;
    });

    let status = resources.child.wait().await?;

    stdin_task.await.ok();
    stdout_task.await.ok();
    stderr_task.await.ok();

    {
        let mut guard = send.lock().await;
        let _ = guard.finish().await;
    }

    let code = status.code().unwrap_or_default();
    info!(sid, code, "shell session completed");
    let mut guard = control_send.lock().await;
    send_message(
        &mut *guard,
        &ControlEnvelope {
            msg: Some(Msg::ShellExit(proto::ShellExit { sid, code })),
        },
    )
    .await?;

    Ok(())
}
