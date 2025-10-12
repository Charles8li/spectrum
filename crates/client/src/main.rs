use std::{net::SocketAddr, sync::Arc};

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
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Connect(args) => connect(args).await?,
        Commands::Shell(args) => shell(args).await?,
        Commands::Send(_) => {
            warn!("send command not yet implemented in this MVP");
        }
    }
    Ok(())
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
