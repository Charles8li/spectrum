use anyhow::{ensure, Context, Result};
use lanrdp_common::{
    authorization::{
        Capability, Command, CommandRequest, Grant, PeerId, TargetRef, PROTOCOL_VERSION,
    },
    transport::{quic_client_config, quic_server_config},
    window::{
        recv_frame, recv_json, send_json, serve_window, Frame, FrameSource, WindowHello, WindowInfo,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    num::NonZeroU64,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, Notify};

fn identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["synthetic.invalid".into()]).unwrap();
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    (
        params.self_signed(&key).unwrap().der().clone(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}
fn target() -> TargetRef {
    TargetRef {
        id: NonZeroU64::new(11).unwrap(),
        generation: NonZeroU64::new(7).unwrap(),
    }
}
struct Source {
    alive: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
    checked: Option<Arc<Notify>>,
    generation: Arc<AtomicU64>,
    gate: Option<CaptureGate>,
}
struct CaptureGate {
    entered: Option<oneshot::Sender<()>>,
    resume: mpsc::Receiver<()>,
}
impl FrameSource for Source {
    fn info(&self) -> WindowInfo {
        let mut target = target();
        target.generation = NonZeroU64::new(self.generation.load(Ordering::Acquire)).unwrap();
        WindowInfo {
            version: PROTOCOL_VERSION,
            target,
            width: 8,
            height: 6,
        }
    }
    fn is_current(&self) -> bool {
        let current = self.alive.load(Ordering::Acquire);
        if let Some(checked) = &self.checked {
            checked.notify_one();
        }
        current
    }
    fn capture(&mut self) -> Result<Frame> {
        ensure!(self.is_current(), "synthetic target closed");
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = &mut self.gate {
            let _ = gate
                .entered
                .take()
                .context("capture already started")?
                .send(());
            gate.resume
                .recv_timeout(Duration::from_secs(2))
                .context("synthetic capture was not resumed")?;
        }
        Frame::new(8, 6, vec![64; 192])
    }
}

async fn connections() -> Result<(
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
    CertificateDer<'static>,
    CertificateDer<'static>,
)> {
    let (client_cert, client_key) = identity();
    let (server_cert, server_key) = identity();
    let server = quinn::Endpoint::server(
        quic_server_config(client_cert.clone(), server_cert.clone(), server_key)?,
        "127.0.0.1:0".parse()?,
    )?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quic_client_config(
        server_cert.clone(),
        client_cert.clone(),
        client_key,
    )?);
    let connect = async {
        Ok::<_, anyhow::Error>(
            client
                .connect(server.local_addr()?, "synthetic.invalid")?
                .await?,
        )
    };
    let accept = async {
        Ok::<_, anyhow::Error>(
            server
                .accept()
                .await
                .context("missing synthetic peer")?
                .await?,
        )
    };
    let (client_connection, server_connection) = tokio::try_join!(connect, accept)?;
    Ok((
        server,
        client,
        server_connection,
        client_connection,
        client_cert,
        server_cert,
    ))
}

async fn scenario(wrong_target: bool, revoke: bool, wrong_peer: bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client, server_connection, client_connection, client_cert, server_cert) =
            connections().await?;
        let alive = Arc::new(AtomicBool::new(true));
        let paired = Arc::new(AtomicBool::new(true));
        let reads = Arc::new(AtomicUsize::new(0));
        let source = Arc::new(Mutex::new(Source {
            alive: alive.clone(),
            reads: reads.clone(),
            checked: None,
            generation: Arc::new(AtomicU64::new(7)),
            gate: None,
        }));
        let grant = Grant::new(
            PeerId::from_certificate(if wrong_peer {
                &server_cert
            } else {
                &client_cert
            })?,
            target(),
            &[Capability::ReadFrame],
            Instant::now(),
            Duration::from_secs(3),
        )?;
        let paired_check = paired.clone();
        let handler = tokio::spawn(async move {
            serve_window(&server_connection, source, grant, move || {
                paired_check.load(Ordering::Acquire)
            })
            .await
        });
        let (mut send, mut recv) = client_connection.open_bi().await?;
        let hello = send_json(
            &mut send,
            &WindowHello {
                version: PROTOCOL_VERSION,
            },
        )
        .await;
        if wrong_peer {
            let info = if hello.is_ok() {
                recv_json::<_, WindowInfo>(&mut recv).await
            } else {
                Err(anyhow::anyhow!("peer closed before hello"))
            };
            ensure!(info.is_err());
            ensure!(reads.load(Ordering::SeqCst) == 0);
            ensure!(handler.await?.is_err());
        } else {
            hello?;
            let info: WindowInfo = recv_json(&mut recv).await?;
            let requested = if wrong_target {
                TargetRef {
                    id: target().id,
                    generation: NonZeroU64::new(8).unwrap(),
                }
            } else {
                target()
            };
            let request_id = NonZeroU64::new(1).unwrap();
            send_json(
                &mut send,
                &CommandRequest {
                    version: PROTOCOL_VERSION,
                    request_id,
                    command: Command::ReadFrame { target: requested },
                },
            )
            .await?;
            let frame = recv_frame(&mut recv, request_id, info).await;
            if wrong_target {
                ensure!(frame.is_err());
                ensure!(reads.load(Ordering::SeqCst) == 0);
            } else {
                ensure!(frame?.pixels() == [64; 192]);
                ensure!(reads.load(Ordering::SeqCst) == 1);
                if revoke {
                    paired.store(false, Ordering::Release);
                } else {
                    alive.store(false, Ordering::Release);
                }
                tokio::time::timeout(Duration::from_secs(1), client_connection.closed()).await?;
            }
            ensure!(handler.await?.is_err());
        }
        client.close(0u32.into(), b"test ended");
        server.close(0u32.into(), b"test ended");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("synthetic session timed out")?
}

#[derive(Clone, Copy)]
enum Interruption {
    CloseTarget,
    RevokePairing,
    ReplaceTarget,
}

async fn interrupted_handshake(interruption: Interruption) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client, server_connection, client_connection, client_cert, _) =
            connections().await?;
        let alive = Arc::new(AtomicBool::new(true));
        let paired = Arc::new(AtomicBool::new(true));
        let reads = Arc::new(AtomicUsize::new(0));
        let checked = Arc::new(Notify::new());
        let generation = Arc::new(AtomicU64::new(7));
        let source = Arc::new(Mutex::new(Source {
            alive: alive.clone(),
            reads: reads.clone(),
            checked: Some(checked.clone()),
            generation: generation.clone(),
            gate: None,
        }));
        let grant = Grant::new(
            PeerId::from_certificate(&client_cert)?,
            target(),
            &[Capability::ReadFrame],
            Instant::now(),
            Duration::from_secs(3),
        )?;
        let paired_check = paired.clone();
        let handler = tokio::spawn(async move {
            serve_window(&server_connection, source, grant, move || {
                paired_check.load(Ordering::Acquire)
            })
            .await
        });
        checked.notified().await;
        match interruption {
            Interruption::CloseTarget => alive.store(false, Ordering::Release),
            Interruption::RevokePairing => paired.store(false, Ordering::Release),
            Interruption::ReplaceTarget => generation.store(8, Ordering::Release),
        }
        let (mut send, mut recv) = client_connection.open_bi().await?;
        if send_json(
            &mut send,
            &WindowHello {
                version: PROTOCOL_VERSION,
            },
        )
        .await
        .is_ok()
        {
            ensure!(
                recv_json::<_, WindowInfo>(&mut recv).await.is_err(),
                "window metadata was sent after authorization ended"
            );
        }
        ensure!(handler.await?.is_err());
        ensure!(reads.load(Ordering::SeqCst) == 0);
        client.close(0u32.into(), b"test ended");
        server.close(0u32.into(), b"test ended");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("interrupted synthetic handshake timed out")?
}

#[tokio::test]
async fn target_closed_during_handshake_receives_no_window_metadata() {
    interrupted_handshake(Interruption::CloseTarget)
        .await
        .unwrap();
}

#[tokio::test]
async fn pairing_revoked_during_handshake_receives_no_window_metadata() {
    interrupted_handshake(Interruption::RevokePairing)
        .await
        .unwrap();
}

#[tokio::test]
async fn target_replaced_during_handshake_receives_no_window_metadata() {
    interrupted_handshake(Interruption::ReplaceTarget)
        .await
        .unwrap();
}

async fn interrupted_capture(interruption: Interruption) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client, server_connection, client_connection, client_cert, _) =
            connections().await?;
        let alive = Arc::new(AtomicBool::new(true));
        let paired = Arc::new(AtomicBool::new(true));
        let reads = Arc::new(AtomicUsize::new(0));
        let generation = Arc::new(AtomicU64::new(7));
        let (entered, capture_entered) = oneshot::channel();
        let (resume, continue_capture) = mpsc::channel();
        let source = Arc::new(Mutex::new(Source {
            alive: alive.clone(),
            reads: reads.clone(),
            checked: None,
            generation: generation.clone(),
            gate: Some(CaptureGate {
                entered: Some(entered),
                resume: continue_capture,
            }),
        }));
        let grant = Grant::new(
            PeerId::from_certificate(&client_cert)?,
            target(),
            &[Capability::ReadFrame],
            Instant::now(),
            Duration::from_secs(3),
        )?;
        let paired_check = paired.clone();
        let handler = tokio::spawn(async move {
            serve_window(&server_connection, source, grant, move || {
                paired_check.load(Ordering::Acquire)
            })
            .await
        });
        let (mut send, mut recv) = client_connection.open_bi().await?;
        send_json(
            &mut send,
            &WindowHello {
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        let info: WindowInfo = recv_json(&mut recv).await?;
        let request_id = NonZeroU64::new(1).unwrap();
        send_json(
            &mut send,
            &CommandRequest {
                version: PROTOCOL_VERSION,
                request_id,
                command: Command::ReadFrame {
                    target: info.target,
                },
            },
        )
        .await?;
        capture_entered.await?;
        match interruption {
            Interruption::CloseTarget => alive.store(false, Ordering::Release),
            Interruption::RevokePairing => paired.store(false, Ordering::Release),
            Interruption::ReplaceTarget => generation.store(8, Ordering::Release),
        }
        resume.send(())?;
        ensure!(recv_frame(&mut recv, request_id, info).await.is_err());
        ensure!(handler.await?.is_err());
        ensure!(reads.load(Ordering::SeqCst) == 1);
        client.close(0u32.into(), b"test ended");
        server.close(0u32.into(), b"test ended");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("interrupted synthetic capture timed out")?
}

#[tokio::test]
async fn target_closed_during_capture_receives_no_frame() {
    interrupted_capture(Interruption::CloseTarget)
        .await
        .unwrap();
}

#[tokio::test]
async fn pairing_revoked_during_capture_receives_no_frame() {
    interrupted_capture(Interruption::RevokePairing)
        .await
        .unwrap();
}

#[tokio::test]
async fn target_replaced_during_capture_receives_no_frame() {
    interrupted_capture(Interruption::ReplaceTarget)
        .await
        .unwrap();
}

#[tokio::test]
async fn closed_target_stops_the_active_window_session() {
    scenario(false, false, false).await.unwrap();
}
#[tokio::test]
async fn revoked_pairing_stops_the_active_window_session() {
    scenario(false, true, false).await.unwrap();
}
#[tokio::test]
async fn reused_target_generation_is_rejected_before_capture() {
    scenario(true, false, false).await.unwrap();
}
#[tokio::test]
async fn unauthorized_peer_receives_no_window_metadata() {
    scenario(false, false, true).await.unwrap();
}
