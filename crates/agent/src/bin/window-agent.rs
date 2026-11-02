use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use lanrdp_common::{
    authorization::{Capability, Grant, PeerId, TargetRef},
    transport::quic_server_config,
    window::{require_lan_address, serve_window, FrameSource, IO_TIMEOUT},
};
use spectrum_window::{
    cli::{identity_command, IdentityCommand},
    identity::IdentityStore,
};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureStage {
    NetworkInterfaces,
    PairingSetup,
    PairingExchange,
    PairingWindow,
    Identity,
    TestWindow,
    WindowSelection,
    WindowSize,
    CaptureSetup,
    SharingWindow,
    SharingListener,
    WindowSession,
}

#[cfg(windows)]
impl FailureStage {
    fn message(self) -> &'static str {
        match self {
            Self::NetworkInterfaces => "P1: Spectrum could not inspect the local network interfaces.",
            Self::PairingSetup => "P2: Spectrum could not prepare pairing. Check local identity storage and network availability.",
            Self::PairingExchange => "P3: Pairing did not finish. Open Spectrum on both devices and try again.",
            Self::PairingWindow => "P4: Spectrum could not open the pairing window.",
            Self::Identity => "W1: Spectrum could not load the paired device identities.",
            Self::TestWindow => "W2: Spectrum could not create the built-in test window.",
            Self::WindowSelection => "W3: The selected window is unavailable. Choose it again.",
            Self::WindowSize => "W4: The selected window exceeds the supported capture size of 1920 by 1080 pixels.",
            Self::CaptureSetup => "W5: Spectrum could not prepare capture for the selected window.",
            Self::SharingWindow => "W6: Spectrum could not open the sharing status window.",
            Self::SharingListener => "W7: Spectrum could not start the window connection listener. Its port may already be in use.",
            Self::WindowSession => "W8: The shared window session could not continue.",
        }
    }
}

#[cfg(windows)]
impl std::fmt::Display for FailureStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

#[cfg(windows)]
impl std::error::Error for FailureStage {}

#[cfg(windows)]
fn already_paired(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string() == "another device is already paired; unpair first")
}

#[cfg(windows)]
fn capture_failure(error: anyhow::Error) -> anyhow::Error {
    let too_large = error
        .chain()
        .any(|cause| cause.to_string() == "window dimensions exceed the supported range");
    error.context(if too_large {
        FailureStage::WindowSize
    } else {
        FailureStage::CaptureSetup
    })
}

#[cfg(windows)]
fn public_failure_message(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<FailureStage>()
        .map_or("Spectrum could not continue.", |stage| stage.message())
}

#[derive(Parser)]
#[command(
    version,
    about = "Share one authorized application window over a trusted LAN connection"
)]
struct Args {
    #[arg(long, global = true, default_value = ".spectrum/agent")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Choose one local window and share it until stopped or expired.
    Share {
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: SocketAddr,
        #[arg(long, default_value_t=300, value_parser=clap::value_parser!(u64).range(1..=900))]
        seconds: u64,
        /// Share a self-owned synthetic application instead of opening the chooser.
        #[arg(long)]
        demo: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let state_dir =
        if args.command.is_none() && args.state_dir == std::path::Path::new(".spectrum/agent") {
            std::env::current_exe()?
                .parent()
                .context("application directory is unavailable")?
                .join(".spectrum/agent")
        } else {
            args.state_dir
        };
    let store = IdentityStore::new(state_dir);
    match args.command {
        Some(Command::Identity { command }) => identity_command(command, &store),
        Some(Command::Share {
            listen,
            seconds,
            demo,
        }) => share(store, listen, seconds, demo).await,
        None => interactive(store).await,
    }
}

#[cfg(windows)]
async fn interactive(store: IdentityStore) -> Result<()> {
    use spectrum_window::{
        discovery::{local_interfaces, WINDOW_PORT},
        native::{choose_share_kind, confirm_unpair, show_message, WindowView},
        pair_service::PairingOffer,
    };
    use zeroize::Zeroizing;

    let result = async {
        let interfaces = local_interfaces().context(FailureStage::NetworkInterfaces)?;
        let offer = PairingOffer::new(store.clone(), &interfaces).context(FailureStage::PairingSetup)?;
        let notice = Zeroizing::new(format!("Enter this code on the viewing device:\n\n{}\n\nClose this window to cancel. The code expires after two minutes.", offer.code().as_str()));
        let status = WindowView::open_status("Spectrum - Pair device", &notice).context(FailureStage::PairingWindow)?;
        let sink = status.sink();
        let paired = offer.wait(|| sink.closed()).await;
        let cancelled = sink.closed();
        sink.close();
        status.wait();
        if cancelled { return Ok(()); }
        let paired = paired.context(FailureStage::PairingExchange)?;
        let Some(demo) = choose_share_kind() else { return Ok(()); };
        let address = SocketAddr::new(paired.interface.address.into(), WINDOW_PORT);
        share(store.clone(), address, 300, demo).await
    }.await;
    if let Err(error) = &result {
        if already_paired(error) {
            if confirm_unpair() {
                if store.unpair().is_ok() {
                    show_message("Previous pairing removed. Open Spectrum again to pair a device.");
                    return Ok(());
                }
                show_message("The previous pairing could not be removed.");
            }
        } else {
            show_message(public_failure_message(error));
        }
    }
    result.map_err(|error| anyhow::anyhow!(public_failure_message(&error)))
}

#[cfg(not(windows))]
async fn interactive(_: IdentityStore) -> Result<()> {
    anyhow::bail!("window sharing requires Windows")
}

#[cfg(windows)]
async fn until_sharing_stops<S, F>(
    source: &Mutex<S>,
    trusted: impl Fn() -> bool,
    stopped: impl Fn() -> bool,
    deadline: tokio::time::Instant,
    activity: F,
) -> Result<()>
where
    S: FrameSource,
    F: std::future::Future<Output = Result<()>>,
{
    let monitor = async {
        loop {
            if stopped() {
                return Ok(());
            }
            ensure!(trusted(), "pairing was revoked");
            match source.try_lock() {
                Ok(source) => ensure!(source.is_current(), "shared window is unavailable"),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    anyhow::bail!("capture state is unavailable")
                }
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    tokio::select! {
        biased;
        result = monitor => result,
        _ = tokio::time::sleep_until(deadline) => Err(anyhow::anyhow!("window authorization expired")),
        result = activity => result,
    }
}

#[cfg(windows)]
async fn share(store: IdentityStore, listen: SocketAddr, seconds: u64, demo: bool) -> Result<()> {
    use rand::Rng;
    use spectrum_window::native::{choose_window, WindowCapture, WindowView};
    use std::num::NonZeroU64;
    require_lan_address(listen)?;
    let identity = store.load().context(FailureStage::Identity)?;
    let peer = store.peer().context(FailureStage::Identity)?;
    let config = quic_server_config(peer.clone(), identity.certificate, identity.key)
        .context(FailureStage::Identity)?;
    let fixture = if demo {
        let view = WindowView::open("Spectrum - Synthetic application")
            .context(FailureStage::TestWindow)?;
        view.sink()
            .set_frame(spectrum_window::demo_frame().context(FailureStage::TestWindow)?)
            .context(FailureStage::TestWindow)?;
        Some(view)
    } else {
        None
    };
    let choice = if let Some(fixture) = &fixture {
        fixture.choice().context(FailureStage::WindowSelection)?
    } else {
        let selected = tokio::task::spawn_blocking(choose_window)
            .await
            .context(FailureStage::WindowSelection)?;
        match selected {
            Ok(choice) => choice,
            Err(error) if error.to_string() == "window selection was cancelled" => return Ok(()),
            Err(error) => return Err(error.context(FailureStage::WindowSelection)),
        }
    };
    let target = TargetRef {
        id: NonZeroU64::new(rand::thread_rng().gen_range(1..u64::MAX)).unwrap(),
        generation: NonZeroU64::new(rand::thread_rng().gen_range(1..u64::MAX)).unwrap(),
    };
    let capture = WindowCapture::open(choice, target).map_err(capture_failure)?;
    ensure!(capture.is_current(), FailureStage::WindowSelection);
    let source = Arc::new(Mutex::new(capture));
    let stop = WindowView::open_status(
        "Spectrum - Sharing one window - close to stop",
        "Sharing one authorized application window.\nClose this window to stop sharing.",
    )
    .context(FailureStage::SharingWindow)?;
    let stop_signal = stop.sink();
    let endpoint =
        quinn::Endpoint::server(config, listen).context(FailureStage::SharingListener)?;
    println!("Ready to share the selected window with the paired peer. Close the sharing window to stop.");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let activity = async {
        for _ in 0..3 {
            if stop_signal.closed() {
                return Ok(());
            }
            ensure!(store.peer_is(&peer), "pairing was revoked");
            let incoming = endpoint.accept().await.context("window listener closed")?;
            match tokio::time::timeout(IO_TIMEOUT, incoming).await {
                Ok(Ok(connection)) => {
                    if stop_signal.closed() {
                        return Ok(());
                    }
                    ensure!(store.peer_is(&peer), "pairing was revoked");
                    let now = Instant::now();
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let grant = Grant::new(
                        PeerId::from_certificate(&peer)?,
                        target,
                        &[Capability::DescribeTarget, Capability::ReadFrame],
                        now,
                        remaining,
                    )?;
                    let session = serve_window(&connection, source.clone(), grant, || {
                        store.peer_is(&peer) && !stop_signal.closed()
                    })
                    .await;
                    if stop_signal.closed() {
                        return Ok(());
                    }
                    return session;
                }
                _ => eprintln!("Connection rejected."),
            }
        }
        anyhow::bail!("connection attempt limit reached")
    };
    let result = until_sharing_stops(
        &source,
        || store.peer_is(&peer),
        || stop_signal.closed(),
        deadline,
        activity,
    )
    .await;
    endpoint.close(0u32.into(), b"window sharing ended");
    drop(stop);
    drop(fixture);
    result.context(FailureStage::WindowSession)
}

#[cfg(not(windows))]
async fn share(_: IdentityStore, _: SocketAddr, _: u64, _: bool) -> Result<()> {
    anyhow::bail!("window sharing requires Windows")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use lanrdp_common::{
        authorization::PROTOCOL_VERSION,
        window::{Frame, WindowInfo},
    };
    use std::{
        num::NonZeroU64,
        sync::atomic::{AtomicBool, Ordering},
    };

    struct WaitingSource(Arc<AtomicBool>);

    impl FrameSource for WaitingSource {
        fn info(&self) -> WindowInfo {
            WindowInfo {
                version: PROTOCOL_VERSION,
                target: TargetRef {
                    id: NonZeroU64::new(1).unwrap(),
                    generation: NonZeroU64::new(1).unwrap(),
                },
                width: 1,
                height: 1,
            }
        }

        fn is_current(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }

        fn capture(&mut self) -> Result<Frame> {
            anyhow::bail!("unexpected synthetic capture")
        }
    }

    #[derive(Clone, Copy)]
    enum WaitingInterruption {
        Cancel,
        Revoke,
        CloseTarget,
        Expire,
    }

    async fn interrupted_wait(interruption: WaitingInterruption) -> Result<()> {
        let current = Arc::new(AtomicBool::new(true));
        let trusted = Arc::new(AtomicBool::new(true));
        let stopped = Arc::new(AtomicBool::new(false));
        let source = Mutex::new(WaitingSource(current.clone()));
        let deadline = tokio::time::Instant::now()
            + if matches!(interruption, WaitingInterruption::Expire) {
                Duration::from_millis(80)
            } else {
                Duration::from_secs(3)
            };
        let transition = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            match interruption {
                WaitingInterruption::Cancel => stopped.store(true, Ordering::Release),
                WaitingInterruption::Revoke => trusted.store(false, Ordering::Release),
                WaitingInterruption::CloseTarget => current.store(false, Ordering::Release),
                WaitingInterruption::Expire => {}
            }
        };
        let pending = until_sharing_stops(
            &source,
            || trusted.load(Ordering::Acquire),
            || stopped.load(Ordering::Acquire),
            deadline,
            std::future::pending(),
        );
        let (result, _) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(pending, transition)
        })
        .await?;
        match interruption {
            WaitingInterruption::Cancel => ensure!(result.is_ok()),
            _ => ensure!(result.is_err()),
        }
        Ok(())
    }

    #[tokio::test]
    async fn pending_connection_stops_after_user_cancels() -> Result<()> {
        interrupted_wait(WaitingInterruption::Cancel).await
    }

    #[tokio::test]
    async fn pending_connection_stops_after_pairing_is_revoked() -> Result<()> {
        interrupted_wait(WaitingInterruption::Revoke).await
    }

    #[tokio::test]
    async fn pending_connection_stops_after_the_target_closes() -> Result<()> {
        interrupted_wait(WaitingInterruption::CloseTarget).await
    }

    #[tokio::test]
    async fn pending_connection_stops_at_authorization_deadline() -> Result<()> {
        interrupted_wait(WaitingInterruption::Expire).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_does_not_wait_for_a_busy_capture() -> Result<()> {
        let source = Arc::new(Mutex::new(WaitingSource(Arc::new(AtomicBool::new(true)))));
        let stopped = Arc::new(AtomicBool::new(false));
        let (locked, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let held_source = source.clone();
        let worker = std::thread::spawn(move || {
            let _guard = held_source.lock().unwrap();
            let _ = locked.send(());
            let _ = released.recv_timeout(Duration::from_secs(2));
        });
        ready.await?;
        let transition = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            stopped.store(true, Ordering::Release);
        };
        let pending = until_sharing_stops(
            &source,
            || true,
            || stopped.load(Ordering::Acquire),
            tokio::time::Instant::now() + Duration::from_secs(3),
            std::future::pending(),
        );
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(pending, transition)
        })
        .await;
        release.send(())?;
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("synthetic capture worker failed"))?;
        result?.0
    }

    #[test]
    fn capture_size_failures_are_distinguished_from_other_capture_errors() {
        let size = capture_failure(anyhow::anyhow!(
            "window dimensions exceed the supported range"
        ));
        assert_eq!(
            public_failure_message(&size),
            FailureStage::WindowSize.message()
        );
        let other = capture_failure(anyhow::anyhow!("synthetic private detail"));
        assert_eq!(
            public_failure_message(&other),
            FailureStage::CaptureSetup.message()
        );
        assert!(!public_failure_message(&other).contains("synthetic private detail"));
    }

    #[test]
    fn existing_pairing_is_detected_through_stage_context() {
        let conflict = anyhow::anyhow!("another device is already paired; unpair first")
            .context(FailureStage::PairingExchange);
        assert!(already_paired(&conflict));
        assert_eq!(
            public_failure_message(&conflict),
            FailureStage::PairingExchange.message()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an interactive Windows desktop and captures only an owned synthetic window"]
    async fn short_code_pairing_can_share_a_synthetic_window() -> Result<()> {
        use lanrdp_common::{
            authorization::{Command, CommandRequest, PROTOCOL_VERSION},
            pairing::PairCode,
            transport::quic_client_config,
            window::{recv_frame, recv_json, send_json, WindowHello, WindowInfo},
        };
        use spectrum_window::{
            discovery::{Candidate, Interface, PAIRING_PORT},
            identity::SERVER_NAME,
            pair_service::{pair_with_candidate, PairingOffer},
        };
        use std::{
            net::{Ipv4Addr, SocketAddrV4},
            num::NonZeroU64,
            sync::atomic::{AtomicU64, Ordering},
        };

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                for role in ["agent", "client"] {
                    let directory = self.0.join(role);
                    for file in ["identity.bin", "peer.der"] {
                        let _ = std::fs::remove_file(directory.join(file));
                    }
                    let _ = std::fs::remove_dir(directory);
                }
                let _ = std::fs::remove_dir(&self.0);
            }
        }

        tokio::time::timeout(Duration::from_secs(20), async {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "spectrum-share-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path)?;
            let fixture = Fixture(path);
            let agent = IdentityStore::new(fixture.0.join("agent"));
            let client = IdentityStore::new(fixture.0.join("client"));
            let interface = Interface::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0))?;
            let offer = PairingOffer::new(agent.clone(), &[interface])?;
            let code = PairCode::parse(offer.code().as_str())?;
            let candidate = Candidate {
                interface,
                address: SocketAddrV4::new(Ipv4Addr::LOCALHOST, PAIRING_PORT).into(),
            };
            let (offered, paired) = tokio::join!(
                offer.wait(|| false),
                pair_with_candidate(&client, candidate, &code)
            );
            offered?;
            paired?;

            let blocker = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let blocked_error = share(agent.clone(), blocker.local_addr()?, 2, true)
                .await
                .expect_err("occupied window listener must be rejected");
            assert_eq!(
                public_failure_message(&blocked_error),
                FailureStage::SharingListener.message()
            );
            drop(blocker);

            let reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let address = reservation.local_addr()?;
            drop(reservation);
            let source = tokio::spawn(share(agent, address, 12, true));
            tokio::time::sleep(Duration::from_millis(500)).await;
            let identity = client.load()?;
            let peer = client.peer()?;
            let mut viewer = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
            viewer.set_default_client_config(quic_client_config(
                peer,
                identity.certificate,
                identity.key,
            )?);
            let connection = viewer.connect(address, SERVER_NAME)?.await?;
            let (mut send, mut recv) = connection.open_bi().await?;
            send_json(
                &mut send,
                &WindowHello {
                    version: PROTOCOL_VERSION,
                },
            )
            .await?;
            let info: WindowInfo = recv_json(&mut recv).await?;
            info.validate()?;
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
            let frame = recv_frame(&mut recv, request_id, info).await?;
            assert!(
                frame
                    .pixels()
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .filter(|pixel| pixel[0].abs_diff(210) < 12
                        && pixel[1].abs_diff(110) < 12
                        && pixel[2].abs_diff(35) < 12)
                    .count()
                    > 100
            );
            connection.close(0u32.into(), b"test complete");
            tokio::time::timeout(Duration::from_secs(3), source).await???;
            viewer.close(0u32.into(), b"test complete");
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }
}
