use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
};

pub mod authorization;
pub mod pairing;
pub mod pairing_transport;
pub mod transport;
pub mod window;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/lanrdp.rs"));
}

pub const STREAM_TYPE_CONTROL: u8 = 0;
pub const STREAM_TYPE_PTY: u8 = 1;
pub const STREAM_TYPE_VIDEO: u8 = 2;
pub const STREAM_TYPE_INPUT: u8 = 3;
pub const STREAM_TYPE_FILE: u8 = 4;

pub const DEFAULT_MAX_FRAME_SIZE: usize = 1 << 20; // 1 MiB
pub const DEFAULT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct StoredClient {
    pub device_id: String,
    pub session_token: Vec<u8>,
    pub psk: Vec<u8>,
    pub peer_label: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SessionDb {
    clients: HashMap<String, StoredClient>,
}

#[derive(Clone)]
pub struct SessionStore {
    path: PathBuf,
    data: SessionDb,
}

impl SessionStore {
    pub async fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self {
                path,
                data: SessionDb::default(),
            });
        }
        let file = fs::File::open(&path).await?;
        ensure!(
            file.metadata().await?.len() <= 64 * 1024,
            "session store too large"
        );
        let mut buf = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut buf).await?;
        ensure!(buf.len() <= 64 * 1024, "session store too large");
        let data: SessionDb = if buf.is_empty() {
            SessionDb::default()
        } else {
            serde_json::from_slice(&buf).context("invalid session store")?
        };
        Ok(Self { path, data })
    }

    pub fn get(&self, device_id: &str) -> Option<&StoredClient> {
        self.data.clients.get(device_id)
    }

    pub fn get_mut(&mut self, device_id: &str) -> Option<&mut StoredClient> {
        self.data.clients.get_mut(device_id)
    }

    pub fn upsert(&mut self, client: StoredClient) {
        self.upsert_with_key(client.device_id.clone(), client);
    }

    pub fn upsert_with_key(&mut self, key: String, client: StoredClient) {
        self.data.clients.insert(key, client);
    }

    pub async fn save(&self) -> Result<()> {
        let serialized = serde_json::to_vec_pretty(&self.data)?;
        let mut file = fs::File::create(&self.path).await?;
        file.write_all(&serialized).await?;
        Ok(())
    }
}

pub fn derive_psk(pin: &str, device_id: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(format!("lanrdp-pin:{}", pin).as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(device_id.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn generate_session_token() -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn hmac_sha256(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(payload);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

pub fn verify_hmac_sha256(key: &[u8], payload: &[u8], proof: &[u8]) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(payload);
    mac.verify_slice(proof)
        .context("invalid authentication proof")
}

pub fn require_live_transport() -> Result<()> {
    anyhow::bail!(
        "legacy desktop sessions are disabled: desktop permissions and secure storage are not integrated"
    )
}

pub fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct StreamDescriptor {
    pub ty: u8,
    pub extra: Option<u32>,
}

impl StreamDescriptor {
    pub fn control() -> Self {
        Self {
            ty: STREAM_TYPE_CONTROL,
            extra: None,
        }
    }

    pub fn video() -> Self {
        Self {
            ty: STREAM_TYPE_VIDEO,
            extra: None,
        }
    }

    pub fn input() -> Self {
        Self {
            ty: STREAM_TYPE_INPUT,
            extra: None,
        }
    }

    pub fn pty(sid: u32) -> Self {
        Self {
            ty: STREAM_TYPE_PTY,
            extra: Some(sid),
        }
    }

    pub fn file(fid: u32) -> Self {
        Self {
            ty: STREAM_TYPE_FILE,
            extra: Some(fid),
        }
    }

    pub async fn write_header<W>(&self, mut writer: W) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        self.validate()?;
        writer.write_all(&[self.ty]).await?;
        if let Some(extra) = self.extra {
            writer.write_all(&extra.to_be_bytes()).await?;
        }
        writer.flush().await?;
        Ok(())
    }

    pub async fn read_header<R>(mut reader: R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut ty = [0u8; 1];
        reader.read_exact(&mut ty).await?;
        let ty = ty[0];
        let extra = match ty {
            STREAM_TYPE_CONTROL | STREAM_TYPE_VIDEO | STREAM_TYPE_INPUT => None,
            STREAM_TYPE_PTY | STREAM_TYPE_FILE => {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf).await?;
                Some(u32::from_be_bytes(buf))
            }
            _ => anyhow::bail!("unsupported stream type"),
        };
        let descriptor = Self { ty, extra };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn validate(&self) -> Result<()> {
        match self.ty {
            STREAM_TYPE_CONTROL | STREAM_TYPE_VIDEO | STREAM_TYPE_INPUT => {
                ensure!(self.extra.is_none(), "unexpected stream identifier");
            }
            STREAM_TYPE_PTY | STREAM_TYPE_FILE => {
                ensure!(
                    self.extra.is_some_and(|id| id != 0),
                    "invalid stream identifier"
                );
            }
            _ => anyhow::bail!("unsupported stream type"),
        }
        Ok(())
    }
}

fn frame_len(len: usize) -> Result<u32> {
    ensure!(len <= DEFAULT_MAX_FRAME_SIZE, "frame too large");
    u32::try_from(len).context("frame length overflow")
}

pub async fn send_message<W, M>(writer: W, message: &M) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
    M: prost::Message,
{
    let len = frame_len(message.encoded_len())?;
    let mut buf = Vec::with_capacity(len as usize);
    message.encode(&mut buf)?;
    send_bytes(writer, Bytes::from(buf)).await
}

pub async fn recv_message<R, M>(reader: R) -> Result<M>
where
    R: tokio::io::AsyncRead + Unpin,
    M: prost::Message + Default,
{
    Ok(M::decode(recv_bytes(reader).await?)?)
}

pub async fn send_bytes<W>(mut writer: W, data: Bytes) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let len = frame_len(data.len())?;
    tokio::time::timeout(DEFAULT_IO_TIMEOUT, async {
        writer.write_all(&len.to_be_bytes()).await?;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    })
    .await
    .context("frame send timed out")?
}

pub async fn recv_bytes<R>(mut reader: R) -> Result<Bytes>
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(DEFAULT_IO_TIMEOUT, async {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        frame_len(len)?;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        Ok(Bytes::from(buf))
    })
    .await
    .context("frame receive timed out")?
}

pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("config directory not available")?;
    Ok(base.join("lanrdp"))
}

pub fn agent_store_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("agent_sessions.json"))
}

pub fn client_store_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("client_sessions.json"))
}
