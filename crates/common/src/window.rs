use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    authorization::{Command, CommandRequest, Grant, PeerId, TargetRef, PROTOCOL_VERSION},
    transport::verified_peer_certificate,
};

pub const MAX_WIDTH: u32 = 1920;
pub const MAX_HEIGHT: u32 = 1080;
pub const MAX_PIXELS_BYTES: usize = MAX_WIDTH as usize * MAX_HEIGHT as usize * 4;
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
pub const FRAME_INTERVAL: Duration = Duration::from_millis(500);
const MAX_JSON: usize = 4096;

#[derive(Clone)]
pub struct Frame {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

pub fn pixel_bytes(width: u32, height: u32) -> Result<usize> {
    ensure!(
        width > 0 && width <= MAX_WIDTH && height > 0 && height <= MAX_HEIGHT,
        "window dimensions exceed the supported range"
    );
    Ok(width as usize * height as usize * 4)
}

impl Frame {
    pub fn new(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self> {
        ensure!(
            pixels.len() == pixel_bytes(width, height)?,
            "invalid window frame length"
        );
        Ok(Self {
            width,
            height,
            pixels,
        })
    }
    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowHello {
    pub version: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowInfo {
    pub version: u16,
    pub target: TargetRef,
    pub width: u32,
    pub height: u32,
}

impl WindowInfo {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == PROTOCOL_VERSION,
            "unsupported window protocol version"
        );
        pixel_bytes(self.width, self.height)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameHeader {
    request_id: std::num::NonZeroU64,
    info: WindowInfo,
}

pub async fn send_json<W: AsyncWrite + Unpin, T: Serialize>(
    mut writer: W,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_JSON, "control message too large");
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_u32(bytes.len() as u32).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("control send timed out")?
}

pub async fn recv_json<R: AsyncRead + Unpin, T: DeserializeOwned>(mut reader: R) -> Result<T> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let length = reader.read_u32().await? as usize;
        ensure!(
            length > 0 && length <= MAX_JSON,
            "invalid control message size"
        );
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("control receive timed out")?
}

pub async fn send_frame<W: AsyncWrite + Unpin>(
    mut writer: W,
    request_id: std::num::NonZeroU64,
    target: TargetRef,
    frame: &Frame,
) -> Result<()> {
    let info = WindowInfo {
        version: PROTOCOL_VERSION,
        target,
        width: frame.width,
        height: frame.height,
    };
    send_json(&mut writer, &FrameHeader { request_id, info }).await?;
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_all(&frame.pixels).await?;
        writer.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("window frame send timed out")?
}

pub async fn recv_frame<R: AsyncRead + Unpin>(
    mut reader: R,
    request_id: std::num::NonZeroU64,
    expected: WindowInfo,
) -> Result<Frame> {
    let header: FrameHeader = recv_json(&mut reader).await?;
    header.info.validate()?;
    ensure!(
        header.request_id == request_id && header.info.target == expected.target,
        "unexpected window frame identity"
    );
    ensure!(
        header.info.width == expected.width && header.info.height == expected.height,
        "shared window changed size"
    );
    let mut pixels = vec![0; pixel_bytes(header.info.width, header.info.height)?];
    tokio::time::timeout(IO_TIMEOUT, reader.read_exact(&mut pixels))
        .await
        .context("window frame receive timed out")??;
    Frame::new(header.info.width, header.info.height, pixels)
}

pub fn require_lan_address(address: SocketAddr) -> Result<()> {
    let allowed = match address.ip() {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    };
    ensure!(
        allowed && address.port() != 0,
        "use a loopback or private LAN address with a nonzero port"
    );
    Ok(())
}

pub trait FrameSource: Send + 'static {
    fn info(&self) -> WindowInfo;
    fn is_current(&self) -> bool;
    fn capture(&mut self) -> Result<Frame>;
}

fn current_target<S: FrameSource>(
    source: &Mutex<S>,
    expected: WindowInfo,
) -> Result<Option<TargetRef>> {
    let capture = source
        .lock()
        .map_err(|_| anyhow::anyhow!("capture state is unavailable"))?;
    let current_info = capture.info();
    ensure!(current_info == expected, "shared window metadata changed");
    Ok(capture.is_current().then_some(current_info.target))
}

pub async fn serve_window<S: FrameSource>(
    connection: &quinn::Connection,
    source: Arc<Mutex<S>>,
    mut grant: Grant,
    trust_current: impl Fn() -> bool + Send + Sync,
) -> Result<()> {
    let peer = PeerId::from_certificate(&verified_peer_certificate(connection)?)?;
    let expires_at = tokio::time::Instant::from_std(grant.expires_at());
    let run = async {
        ensure!(trust_current(), "pairing was revoked");
        let (info, current) = {
            let capture = source
                .lock()
                .map_err(|_| anyhow::anyhow!("capture state is unavailable"))?;
            (capture.info(), capture.is_current())
        };
        info.validate()?;
        grant.validate_scope(peer, current.then_some(info.target), Instant::now())?;
        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, connection.accept_bi())
            .await
            .context("control stream timed out")??;
        let hello: WindowHello = recv_json(&mut recv).await?;
        ensure!(
            hello.version == PROTOCOL_VERSION,
            "unsupported window protocol version"
        );
        ensure!(trust_current(), "pairing was revoked");
        grant.validate_scope(peer, current_target(&source, info)?, Instant::now())?;
        send_json(&mut send, &info).await?;
        for _ in 0..3600 {
            let request: CommandRequest = recv_json(&mut recv).await?;
            tokio::time::sleep(FRAME_INTERVAL).await;
            ensure!(trust_current(), "pairing was revoked");
            let command = grant.authorize(
                peer,
                &request,
                current_target(&source, info)?,
                Instant::now(),
            )?;
            match command {
                Command::DescribeTarget { .. } => send_json(&mut send, &info).await?,
                Command::ReadFrame { .. } => {
                    let capture_source = source.clone();
                    let frame = tokio::task::spawn_blocking(move || {
                        capture_source
                            .lock()
                            .map_err(|_| anyhow::anyhow!("capture state is unavailable"))?
                            .capture()
                    })
                    .await??;
                    ensure!(trust_current(), "pairing was revoked");
                    grant.validate_scope(peer, current_target(&source, info)?, Instant::now())?;
                    ensure!(
                        frame.width == info.width && frame.height == info.height,
                        "shared window changed size"
                    );
                    send_frame(&mut send, request.request_id, info.target, &frame).await?;
                }
            }
        }
        anyhow::bail!("session request limit reached")
    };
    let revoked = async {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if !trust_current() {
                break Err(anyhow::anyhow!("pairing was revoked"));
            }
            match source.try_lock() {
                Ok(source) if !source.is_current() => {
                    break Err(anyhow::anyhow!("shared window is unavailable"))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    break Err(anyhow::anyhow!("capture state is unavailable"))
                }
                _ => {}
            }
        }
    };
    let mut result = tokio::select! {
        result = run => result,
        result = revoked => result,
        _ = tokio::time::sleep_until(expires_at) => Err(anyhow::anyhow!("window authorization expired")),
        reason = connection.closed() => match reason {
            quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 0u32.into() => Ok(()),
            _ => Err(anyhow::anyhow!("window connection closed")),
        },
    };
    if matches!(connection.close_reason(), Some(quinn::ConnectionError::ApplicationClosed(close)) if close.error_code == 0u32.into())
    {
        result = Ok(());
    }
    connection.close(0u32.into(), b"window session ended");
    result
}
