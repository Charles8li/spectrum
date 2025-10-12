use std::{
    io::{self as stdio, SeekFrom, Write},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use hostname::get as hostname_get;
use lanrdp_common::{
    client_store_path, config_dir, derive_psk, hmac_sha256,
    proto::{
        self, control_envelope::Msg, AuthMethod, ColorFormat, ControlEnvelope, Hello,
        SessionConfig, VideoCodec,
    },
    recv_bytes, recv_message, send_bytes, send_message, SessionStore, StoredClient,
};
use quinn::{ClientConfig, Endpoint};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rustls::{
    client::ServerCertVerifier, Certificate, ClientConnection, RootCertStore, ServerName,
};
use sha2::{Digest, Sha256};
use tokio::{
    fs::File,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, Stdin},
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "LAN remote desktop client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Connect(ConnectArgs),
    Shell(ShellArgs),
    Send(SendArgs),
    /// Launch the guided text interface
    Interactive,
}

#[derive(clap::Args, Debug, Clone)]
struct SessionOptions {
    #[arg(long = "video", default_value = "tile")]
    video_codec: String,

    #[arg(long = "res", default_value = "1280x720")]
    resolution: String,

    #[arg(long = "fps", default_value_t = 30)]
    max_fps: u32,

    #[arg(long = "color", default_value = "yuv420")]
    color_format: String,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            video_codec: "tile".to_string(),
            resolution: "1280x720".to_string(),
            max_fps: 30,
            color_format: "yuv420".to_string(),
        }
    }
}

#[derive(clap::Args, Debug, Clone)]
struct ConnectArgs {
    #[arg()] // host:port
    address: String,

    #[arg(long, help = "Pairing PIN when connecting for the first time")]
    pin: Option<String>,

    #[command(flatten)]
    session: SessionOptions,
}

#[derive(clap::Args, Debug, Clone)]
struct ShellArgs {
    address: String,
    #[arg(long)]
    pin: Option<String>,

    #[command(flatten)]
    session: SessionOptions,

    #[arg(
        long,
        default_value = ".",
        help = "Remote working directory for the shell session"
    )]
    cwd: String,

    #[arg(long, default_value_t = 80, help = "Initial terminal columns")]
    cols: u32,

    #[arg(long, default_value_t = 24, help = "Initial terminal rows")]
    rows: u32,
}

#[derive(clap::Args, Debug, Clone)]
struct SendArgs {
    address: String,
    source: String,
    target_dir: String,
    #[arg(long)]
    pin: Option<String>,
    #[command(flatten)]
    session: SessionOptions,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Connect(args) => connect(args).await?,
        Commands::Shell(args) => shell(args).await?,
        Commands::Send(args) => send(args).await?,
        Commands::Interactive => interactive().await?,
    }
    Ok(())
}

async fn interactive() -> Result<()> {
    println!("LANRDP interactive console");
    println!("Enter '-' for optional fields to clear stored values. Press Ctrl+D to exit.\n");

    let mut reader = BufReader::new(tokio::io::stdin());
    let mut session_defaults = SessionOptions::default();
    let mut last_address = String::from("127.0.0.1:8443");
    let mut last_pin: Option<String> = None;
    let mut last_shell_cwd = String::from(".");
    let mut last_shell_cols = 80u32;
    let mut last_shell_rows = 24u32;
    let mut last_source = String::from("./file.bin");
    let mut last_target_dir = String::from("/tmp");

    loop {
        println!("==============================");
        println!("[1] Connect test");
        println!("[2] Interactive shell");
        println!("[3] Send file");
        println!("[q] Quit");

        let choice = prompt_line(&mut reader, "Choice: ").await?;
        match choice.as_str() {
            "1" => {
                let (address, pin, session) = prompt_connect_inputs(
                    &mut reader,
                    &last_address,
                    last_pin.as_deref(),
                    &session_defaults,
                )
                .await?;
                if let Err(err) = connect(ConnectArgs {
                    address: address.clone(),
                    pin: pin.clone(),
                    session: session.clone(),
                })
                .await
                {
                    eprintln!("Connection failed: {err:?}");
                } else {
                    println!("Connection succeeded.");
                }
                last_address = address;
                last_pin = pin;
                session_defaults = session;
            }
            "2" => {
                let (address, pin, session) = prompt_connect_inputs(
                    &mut reader,
                    &last_address,
                    last_pin.as_deref(),
                    &session_defaults,
                )
                .await?;
                let cwd =
                    prompt_with_default(&mut reader, "Working directory", &last_shell_cwd).await?;
                let cols = prompt_u32(&mut reader, "Columns", last_shell_cols).await?;
                let rows = prompt_u32(&mut reader, "Rows", last_shell_rows).await?;

                let mut args = ShellArgs {
                    address: address.clone(),
                    pin: pin.clone(),
                    session: session.clone(),
                    cwd: cwd.clone(),
                    cols,
                    rows,
                };

                if let Err(err) = shell(args.clone()).await {
                    eprintln!("Shell session failed: {err:?}");
                } else {
                    println!("Shell session ended.");
                }

                last_address = address;
                last_pin = pin;
                session_defaults = session;
                last_shell_cwd = cwd;
                last_shell_cols = args.cols;
                last_shell_rows = args.rows;
            }
            "3" => {
                let (address, pin, session) = prompt_connect_inputs(
                    &mut reader,
                    &last_address,
                    last_pin.as_deref(),
                    &session_defaults,
                )
                .await?;
                let source = prompt_with_default(&mut reader, "Source file", &last_source).await?;
                let target_dir =
                    prompt_with_default(&mut reader, "Target directory", &last_target_dir).await?;

                if let Err(err) = send(SendArgs {
                    address: address.clone(),
                    source: source.clone(),
                    target_dir: target_dir.clone(),
                    pin: pin.clone(),
                    session: session.clone(),
                })
                .await
                {
                    eprintln!("File transfer failed: {err:?}");
                } else {
                    println!("File transfer completed.");
                }

                last_address = address;
                last_pin = pin;
                session_defaults = session;
                last_source = source;
                last_target_dir = target_dir;
            }
            "q" | "Q" => {
                println!("Goodbye");
                break;
            }
            other => {
                println!("Unrecognised choice '{other}'. Please select 1, 2, 3, or q.");
            }
        }
    }

    Ok(())
}

async fn prompt_connect_inputs(
    reader: &mut BufReader<Stdin>,
    last_address: &str,
    last_pin: Option<&str>,
    defaults: &SessionOptions,
) -> Result<(String, Option<String>, SessionOptions)> {
    let address = prompt_with_default(reader, "Server address", last_address).await?;
    let pin = prompt_optional(reader, "PIN", last_pin).await?;
    let session = prompt_session_options(reader, defaults).await?;
    Ok((address, pin, session))
}

async fn prompt_session_options(
    reader: &mut BufReader<Stdin>,
    current: &SessionOptions,
) -> Result<SessionOptions> {
    let video_codec = prompt_with_default(reader, "Video codec", &current.video_codec).await?;
    let resolution =
        prompt_with_default(reader, "Resolution (e.g. 1280x720)", &current.resolution).await?;
    let max_fps = prompt_u32(reader, "Maximum FPS", current.max_fps).await?;
    let color_format = prompt_with_default(reader, "Color format", &current.color_format).await?;
    Ok(SessionOptions {
        video_codec,
        resolution,
        max_fps,
        color_format,
    })
}

async fn prompt_line(reader: &mut BufReader<Stdin>, prompt: &str) -> Result<String> {
    print!("{prompt}");
    stdio::stdout().flush()?;
    let mut buf = String::new();
    let bytes = reader.read_line(&mut buf).await?;
    if bytes == 0 {
        return Err(anyhow!("standard input closed"));
    }
    Ok(buf.trim().to_string())
}

async fn prompt_with_default(
    reader: &mut BufReader<Stdin>,
    label: &str,
    default: &str,
) -> Result<String> {
    let prompt = format!("{label} [{}]: ", default);
    let input = prompt_line(reader, &prompt).await?;
    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

async fn prompt_optional(
    reader: &mut BufReader<Stdin>,
    label: &str,
    current: Option<&str>,
) -> Result<Option<String>> {
    let prompt = match current {
        Some(existing) => format!("{label} [{}] (Enter keeps, '-' clears): ", existing),
        None => format!("{label} (press Enter to skip): "),
    };
    let input = prompt_line(reader, &prompt).await?;
    if input.is_empty() {
        Ok(current.map(|s| s.to_string()))
    } else if input == "-" {
        Ok(None)
    } else {
        Ok(Some(input))
    }
}

async fn prompt_u32(reader: &mut BufReader<Stdin>, label: &str, default: u32) -> Result<u32> {
    loop {
        let prompt = format!("{label} [{}]: ", default);
        let input = prompt_line(reader, &prompt).await?;
        if input.is_empty() {
            return Ok(default);
        }
        match input.parse::<u32>() {
            Ok(value) => return Ok(value),
            Err(_) => {
                println!("Please enter a valid integer.");
            }
        }
    }
}

async fn connect(args: ConnectArgs) -> Result<()> {
    let (session, prefs) =
        establish_session(&args.address, args.pin.as_deref(), &args.session).await?;

    info!(
        width = prefs.width,
        height = prefs.height,
        fps = prefs.max_fps,
        color = ?prefs.color,
        video = ?prefs.video,
        "session configured",
    );

    let EstablishedSession {
        endpoint,
        connection,
        ..
    } = session;

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await?;

    Ok(())
}

async fn shell(args: ShellArgs) -> Result<()> {
    let (session, _prefs) =
        establish_session(&args.address, args.pin.as_deref(), &args.session).await?;

    let ShellArgs {
        cols, rows, cwd, ..
    } = args.clone();

    let EstablishedSession {
        endpoint,
        connection,
        mut control_send,
        mut control_recv,
    } = session;

    let open = ControlEnvelope {
        msg: Some(Msg::ShellOpen(proto::ShellOpen {
            cwd: cwd.clone(),
            cols,
            rows,
        })),
    };
    send_message(&mut control_send, &open).await?;

    let sid = loop {
        let env: ControlEnvelope = recv_message(&mut control_recv).await?;
        match env.msg {
            Some(Msg::ShellOpened(opened)) => break opened.sid,
            Some(Msg::ShellExit(exit)) => {
                anyhow::bail!("remote shell refused to start (code {})", exit.code);
            }
            Some(_) | None => continue,
        }
    };

    let (mut pty_send, mut pty_recv) = connection.open_bi().await?;
    lanrdp_common::StreamDescriptor::pty(sid)
        .write_header(&mut pty_send)
        .await?;
    let descriptor = lanrdp_common::StreamDescriptor::read_header(&mut pty_recv).await?;
    if descriptor.ty != lanrdp_common::STREAM_TYPE_PTY || descriptor.extra != Some(sid) {
        return Err(anyhow!("server rejected PTY stream"));
    }

    let control_task = tokio::spawn(wait_for_shell_exit(control_recv, sid));
    let input_task = tokio::spawn(forward_stdin(pty_send));
    let output_task = tokio::spawn(forward_stdout(pty_recv));

    let exit_code = control_task.await??;
    info!(sid, exit_code, "shell session finished");

    input_task.abort();
    let _ = input_task.await;
    let _ = output_task.await;

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await?;

    Ok(())
}

async fn send(args: SendArgs) -> Result<()> {
    let (session, _) = establish_session(&args.address, args.pin.as_deref(), &args.session).await?;

    let EstablishedSession {
        endpoint,
        connection,
        mut control_send,
        mut control_recv,
    } = session;

    let source_path = Path::new(&args.source);
    let file_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("source must reference a file name"))?
        .to_string();

    let metadata = tokio::fs::metadata(source_path)
        .await
        .with_context(|| format!("missing source file: {}", source_path.display()))?;
    if metadata.is_dir() {
        anyhow::bail!("directory transfer is not supported in this MVP");
    }

    let mut file = File::open(source_path).await?;
    let mut hasher = Sha256::new();
    let mut hash_buf = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut hash_buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&hash_buf[..read]);
    }
    let digest = hasher.finalize();
    let sha_bytes = Bytes::copy_from_slice(&digest[..]);

    let file_size = metadata.len();
    file.seek(SeekFrom::Start(0)).await?;

    let mut rng = thread_rng();
    let file_id: u64 = rng.gen();

    let offer = ControlEnvelope {
        msg: Some(Msg::FileOffer(proto::FileOffer {
            id: file_id,
            name: file_name.clone(),
            size: file_size,
            sha256: sha_bytes.clone(),
            is_dir: false,
            target_dir: args.target_dir.clone(),
        })),
    };
    send_message(&mut control_send, &offer).await?;
    info!(id = file_id, size = file_size, "sent file offer");

    let accept = loop {
        let env: ControlEnvelope = recv_message(&mut control_recv).await?;
        match env.msg {
            Some(Msg::FileAccept(accept)) if accept.id == file_id => break accept,
            Some(Msg::FileComplete(done)) if done.id == file_id => {
                warn!("received premature completion for file {file_id}");
            }
            Some(_) | None => continue,
        }
    };

    if accept.resume_offset > file_size {
        anyhow::bail!("remote requested resume past end of file");
    }

    let (mut file_send, mut file_recv) = connection.open_bi().await?;
    lanrdp_common::StreamDescriptor::file(file_id as u32)
        .write_header(&mut file_send)
        .await?;
    let descriptor = lanrdp_common::StreamDescriptor::read_header(&mut file_recv).await?;
    if descriptor.ty != lanrdp_common::STREAM_TYPE_FILE || descriptor.extra != Some(file_id as u32)
    {
        anyhow::bail!("agent rejected file stream");
    }

    drop(file_recv);

    if accept.resume_offset > 0 {
        file.seek(SeekFrom::Start(accept.resume_offset)).await?;
    }

    let mut sent = accept.resume_offset;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            lanrdp_common::send_bytes(&mut file_send, Bytes::new()).await?;
            break;
        }
        lanrdp_common::send_bytes(&mut file_send, Bytes::copy_from_slice(&buf[..read])).await?;
        sent += read as u64;
    }
    file_send.finish().await?;
    info!(id = file_id, sent, "completed upload stream");

    let complete = loop {
        let env: ControlEnvelope = recv_message(&mut control_recv).await?;
        match env.msg {
            Some(Msg::FileComplete(done)) if done.id == file_id => break done,
            Some(_) | None => continue,
        }
    };

    if complete.sha256 != sha_bytes {
        warn!("remote reported mismatched checksum for file {file_id}");
    } else {
        info!(id = file_id, "remote verified checksum");
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await?;

    Ok(())
}

#[derive(Debug, Clone)]
struct SessionPreferences {
    width: u32,
    height: u32,
    max_fps: u32,
    color: ColorFormat,
    video: VideoCodec,
}

struct EstablishedSession {
    endpoint: Endpoint,
    connection: quinn::Connection,
    control_send: quinn::SendStream,
    control_recv: quinn::RecvStream,
}

async fn establish_session(
    address: &str,
    pin: Option<&str>,
    opts: &SessionOptions,
) -> Result<(EstablishedSession, SessionPreferences)> {
    let address: SocketAddr = address
        .parse()
        .with_context(|| format!("invalid server address: {address}"))?;

    let (width, height) = parse_resolution(&opts.resolution)?;
    let color = parse_color(&opts.color_format)?;
    let video = parse_video(&opts.video_codec)?;
    let prefs = SessionPreferences {
        width,
        height,
        max_fps: opts.max_fps,
        color,
        video,
    };

    let client_id = load_or_create_client_id().await?;
    let client_name = hostname_get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "lanrdp-client".to_string());

    let mut store = SessionStore::load(client_store_path()?).await?;
    let server_key = format!("{}", address);

    let endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().unwrap())?;
    endpoint.set_default_client_config(build_client_config());

    let connection = endpoint
        .connect(address, "lanrdp")
        .map_err(|_| anyhow!("unable to start connect"))?
        .await?;
    info!(remote = ?connection.remote_address(), "connected to server");

    let (mut control_send, mut control_recv) = connection.open_bi().await?;
    lanrdp_common::StreamDescriptor::control()
        .write_header(&mut control_send)
        .await?;
    let descriptor = lanrdp_common::StreamDescriptor::read_header(&mut control_recv).await?;
    if descriptor.ty != lanrdp_common::STREAM_TYPE_CONTROL {
        return Err(anyhow!("server did not acknowledge control stream"));
    }

    let hello = ControlEnvelope {
        msg: Some(Msg::Hello(Hello {
            device_id: client_id.clone(),
            name: client_name.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            caps: vec![
                format!("video:{}", opts.video_codec),
                format!("color:{}", opts.color_format),
            ],
        })),
    };
    send_message(&mut control_send, &hello).await?;

    let challenge_msg: ControlEnvelope = recv_message(&mut control_recv).await?;
    let auth = match challenge_msg.msg {
        Some(Msg::Auth(auth)) => auth,
        _ => return Err(anyhow!("expected auth challenge")),
    };

    let method = AuthMethod::from_i32(auth.method).unwrap_or(AuthMethod::AuthMethodPin);
    let proof_bytes = match method {
        AuthMethod::AuthMethodPin => {
            let pin = pin.ok_or_else(|| anyhow!("PIN required for first pairing"))?;
            let psk = derive_psk(pin, &client_id);
            store.upsert_with_key(
                server_key.clone(),
                StoredClient {
                    device_id: client_id.clone(),
                    session_token: Vec::new(),
                    psk: psk.to_vec(),
                    peer_label: Some(server_key.clone()),
                },
            );
            Bytes::copy_from_slice(&hmac_sha256(&psk, &auth.challenge)[..])
        }
        AuthMethod::AuthMethodResume => {
            let entry = store
                .get(&server_key)
                .ok_or_else(|| anyhow!("server requested resume but no session stored"))?;
            Bytes::copy_from_slice(&hmac_sha256(&entry.psk, &auth.challenge)[..])
        }
    };

    let auth_reply = ControlEnvelope {
        msg: Some(Msg::Auth(proto::Auth {
            method: auth.method,
            challenge: Bytes::new(),
            proof: proof_bytes,
        })),
    };
    send_message(&mut control_send, &auth_reply).await?;

    let ok_msg: ControlEnvelope = recv_message(&mut control_recv).await?;
    let auth_ok = match ok_msg.msg {
        Some(Msg::AuthOk(ok)) => ok,
        _ => return Err(anyhow!("missing auth acknowledgement")),
    };
    if let Some(entry) = store.get_mut(&server_key) {
        entry.session_token = auth_ok.session_token.to_vec();
        entry.device_id = client_id.clone();
    }
    store.save().await?;

    let session_cfg = ControlEnvelope {
        msg: Some(Msg::SessionConfig(SessionConfig {
            width: prefs.width,
            height: prefs.height,
            max_fps: prefs.max_fps,
            color: prefs.color as i32,
            video: prefs.video as i32,
        })),
    };
    send_message(&mut control_send, &session_cfg).await?;

    // consume configuration acknowledgement (empty message)
    let _ = recv_message::<_, ControlEnvelope>(&mut control_recv).await?;

    Ok((
        EstablishedSession {
            endpoint,
            connection,
            control_send,
            control_recv,
        },
        prefs,
    ))
}

async fn forward_stdin(mut send: quinn::SendStream) -> Result<()> {
    let mut stdin = io::stdin();
    let mut buf = [0u8; 4096];
    loop {
        let read = stdin.read(&mut buf).await?;
        if read == 0 {
            let _ = send.finish().await;
            break;
        }
        if let Err(err) = send_bytes(&mut send, Bytes::copy_from_slice(&buf[..read])).await {
            warn!(?err, "failed to send input to remote");
            break;
        }
    }
    Ok(())
}

async fn forward_stdout(mut recv: quinn::RecvStream) -> Result<()> {
    let mut stdout = io::stdout();
    loop {
        match recv_bytes(&mut recv).await {
            Ok(bytes) => {
                if bytes.is_empty() {
                    break;
                }
                stdout.write_all(&bytes).await?;
                stdout.flush().await?;
            }
            Err(err) => {
                warn!(?err, "remote output stream closed");
                break;
            }
        }
    }
    Ok(())
}

async fn wait_for_shell_exit(mut control_recv: quinn::RecvStream, sid: u32) -> Result<i32> {
    loop {
        let env: ControlEnvelope = recv_message(&mut control_recv).await?;
        match env.msg {
            Some(Msg::ShellExit(exit)) if exit.sid == sid => return Ok(exit.code),
            Some(_) | None => continue,
        }
    }
}

fn build_client_config() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    // Allow self-signed certificates; rely on PSK for authentication in MVP
    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(AcceptAnyServerCert));
    ClientConfig::new(Arc::new(config))
}

struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

async fn load_or_create_client_id() -> Result<String> {
    let path = config_dir()?.join("client_id.txt");
    if let Ok(contents) = tokio::fs::read_to_string(&path).await {
        return Ok(contents.trim().to_string());
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();
    tokio::fs::write(&path, &id).await?;
    Ok(id)
}

fn parse_resolution(res: &str) -> Result<(u32, u32)> {
    let parts: Vec<_> = res.split('x').collect();
    if parts.len() != 2 {
        return Err(anyhow!("resolution must be WIDTHxHEIGHT"));
    }
    let width = parts[0].parse::<u32>()?;
    let height = parts[1].parse::<u32>()?;
    Ok((width, height))
}

fn parse_color(color: &str) -> Result<ColorFormat> {
    match color.to_ascii_lowercase().as_str() {
        "rgb565" => Ok(ColorFormat::ColorFormatRgb565),
        "yuv420" => Ok(ColorFormat::ColorFormatYuv420),
        other => Err(anyhow!("unsupported color format: {other}")),
    }
}

fn parse_video(video: &str) -> Result<VideoCodec> {
    match video.to_ascii_lowercase().as_str() {
        "h264" => Ok(VideoCodec::VideoCodecH264),
        "tile" => Ok(VideoCodec::VideoCodecTile),
        other => Err(anyhow!("unsupported video codec: {other}")),
    }
}
