use std::{
    io::SeekFrom,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::Parser;
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
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    sync::Mutex,
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
                            {
                                let mut guard = control_send.lock().await;
                                send_message(
                                    &mut *guard,
                                    &ControlEnvelope {
                                        msg: Some(Msg::ShellOpened(proto::ShellOpened { sid })),
                                    },
                                )
                                .await?;
                            }

                            let connection = connection.clone();
                            let control_send = control_send.clone();
                            tokio::spawn(async move {
                                if let Err(err) =
                                    run_shell_session(connection, sid, resources, control_send)
                                        .await
                                {
                                    warn!(sid, ?err, "shell session errored");
                                }
                            });
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
                Some(Msg::FileOffer(offer)) => {
                    let control_send = control_send.clone();
                    let connection = connection.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_file_offer(connection, control_send, offer).await {
                            warn!(?err, "file transfer failed");
                        }
                    });
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

    Ok(())
}

fn random_bytes() -> Bytes {
    let mut buf = vec![0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.into()
}

async fn handle_file_offer(
    connection: quinn::Connection,
    control_send: Arc<Mutex<quinn::SendStream>>,
    offer: proto::FileOffer,
) -> Result<()> {
    if offer.is_dir {
        anyhow::bail!("directory transfer is not supported in this build");
    }
    if offer.id > u32::MAX as u64 {
        anyhow::bail!("file identifier exceeds supported range");
    }

    let dest_path = resolve_target_path(&offer.target_dir, &offer.name)?;
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let resume_offset = match fs::metadata(&dest_path).await {
        Ok(meta) => meta.len().min(offer.size),
        Err(_) => 0,
    };

    info!(
        id = offer.id,
        path = %dest_path.display(),
        resume_offset,
        "accepting file offer"
    );

    {
        let mut guard = control_send.lock().await;
        let accept = ControlEnvelope {
            msg: Some(Msg::FileAccept(proto::FileAccept {
                id: offer.id,
                target_dir: offer.target_dir.clone(),
                overwrite: resume_offset == 0,
                resume_offset,
            })),
        };
        send_message(&mut *guard, &accept).await?;
    }

    receive_file_stream(connection, control_send, offer, dest_path, resume_offset).await
}

fn resolve_target_path(base: &str, name: &str) -> Result<PathBuf> {
    let name_path = Path::new(name);
    if name_path.is_absolute() {
        anyhow::bail!("file name must be relative");
    }
    for component in name_path.components() {
        if matches!(component, Component::ParentDir) {
            anyhow::bail!("file name may not traverse directories");
        }
    }

    let mut dest = if base.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(base)
    };
    dest.push(name_path);
    Ok(dest)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct ShellResources {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
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

async fn run_shell_session(
    connection: quinn::Connection,
    sid: u32,
    mut resources: ShellResources,
    control_send: Arc<Mutex<quinn::SendStream>>,
) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let descriptor = lanrdp_common::StreamDescriptor::read_header(&mut recv).await?;
    if descriptor.ty != lanrdp_common::STREAM_TYPE_PTY || descriptor.extra != Some(sid) {
        anyhow::bail!("unexpected stream type for shell {sid}");
    }

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

async fn receive_file_stream(
    connection: quinn::Connection,
    control_send: Arc<Mutex<quinn::SendStream>>,
    offer: proto::FileOffer,
    dest_path: PathBuf,
    resume_offset: u64,
) -> Result<()> {
    let file_id = offer.id as u32;
    let (mut send, mut recv) = connection.accept_bi().await?;
    let descriptor = lanrdp_common::StreamDescriptor::read_header(&mut recv).await?;
    if descriptor.ty != lanrdp_common::STREAM_TYPE_FILE || descriptor.extra != Some(file_id) {
        anyhow::bail!("unexpected stream type for file transfer {}", offer.id);
    }

    lanrdp_common::StreamDescriptor::file(file_id)
        .write_header(&mut send)
        .await?;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(&dest_path)
        .await?;
    if resume_offset == 0 {
        file.set_len(0).await?;
    }
    file.seek(SeekFrom::Start(resume_offset)).await?;

    let mut received = resume_offset;
    loop {
        match lanrdp_common::recv_bytes(&mut recv).await {
            Ok(bytes) => {
                if bytes.is_empty() {
                    break;
                }
                file.write_all(&bytes).await?;
                received += bytes.len() as u64;
            }
            Err(err) => {
                warn!(id = offer.id, ?err, "file stream ended unexpectedly");
                break;
            }
        }
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);

    let mut hasher = Sha256::new();
    let mut reader = fs::File::open(&dest_path).await?;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let digest = hasher.finalize();
    let digest_bytes = Bytes::copy_from_slice(&digest[..]);

    {
        let mut guard = control_send.lock().await;
        let complete = ControlEnvelope {
            msg: Some(Msg::FileComplete(proto::FileComplete {
                id: offer.id,
                sha256: digest_bytes.clone(),
            })),
        };
        send_message(&mut *guard, &complete).await?;
    }

    let expected = offer.sha256.as_ref();
    if expected != digest_bytes.as_ref() {
        warn!(
            id = offer.id,
            expected = %to_hex(expected),
            actual = %to_hex(digest_bytes.as_ref()),
            "file checksum mismatch"
        );
    } else {
        info!(
            id = offer.id,
            path = %dest_path.display(),
            size = received,
            "stored file"
        );
    }

    let _ = send.finish().await;

    Ok(())
}
