use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use lanrdp_common::{
    authorization::{Command as WindowCommand, CommandRequest, PROTOCOL_VERSION},
    transport::{quic_client_config, verified_peer_certificate},
    window::{
        recv_frame, recv_json, require_lan_address, send_json, WindowHello, WindowInfo, IO_TIMEOUT,
    },
};
use spectrum_window::{
    cli::{identity_command, IdentityCommand},
    identity::{IdentityStore, SERVER_NAME},
};
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU64,
    path::PathBuf,
    time::Duration,
};

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureStage {
    NetworkInterfaces,
    DiscoveryWindow,
    Discovery,
    InputWindow,
    PairingWindow,
    PairingExchange,
    WindowSession,
}

#[cfg(windows)]
impl FailureStage {
    fn message(self) -> &'static str {
        match self {
            Self::NetworkInterfaces => {
                "P1: Spectrum could not inspect the local network interfaces."
            }
            Self::DiscoveryWindow => "P2: Spectrum could not open the discovery window.",
            Self::Discovery => "P3: Spectrum could not search the local network for devices.",
            Self::InputWindow => "P4: Spectrum could not open the pairing input window.",
            Self::PairingWindow => "P5: Spectrum could not open the pairing status window.",
            Self::PairingExchange => {
                "P6: Pairing did not finish. Check the code and try again on both devices."
            }
            Self::WindowSession => "W1: The paired window session could not continue.",
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
fn public_failure_message(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<FailureStage>()
        .map_or("Spectrum could not continue.", |stage| stage.message())
}

#[derive(Parser)]
#[command(
    version,
    about = "View one authorized application window from a paired Windows device"
)]
struct Args {
    #[arg(long, global = true, default_value = ".spectrum/client")]
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
    /// View the selected remote window. Closing the viewer ends the connection.
    View {
        address: SocketAddr,
        /// End after a bounded number of frames for a read-only diagnostic run.
        #[arg(long, value_parser=clap::value_parser!(u16).range(1..=3600))]
        frames: Option<u16>,
    },
    /// Check pairing and window metadata without requesting a frame.
    Probe { address: SocketAddr },
    /// Check local identity protection with synthetic data, without networking.
    SelfCheck,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let state_dir =
        if args.command.is_none() && args.state_dir == std::path::Path::new(".spectrum/client") {
            std::env::current_exe()?
                .parent()
                .context("application directory is unavailable")?
                .join(".spectrum/client")
        } else {
            args.state_dir
        };
    let store = IdentityStore::new(state_dir);
    match args.command {
        Some(Command::Identity { command }) => identity_command(command, &store),
        Some(Command::SelfCheck) => {
            spectrum_window::identity::self_check()?;
            println!("Local identity protection: OK. No connection opened.");
            Ok(())
        }
        Some(Command::View { address, frames }) => {
            view(store, address, false, frames, false, None).await
        }
        Some(Command::Probe { address }) => view(store, address, true, None, false, None).await,
        None => interactive(store).await,
    }
}

#[cfg(windows)]
async fn interactive(store: IdentityStore) -> Result<()> {
    use spectrum_window::{
        discovery::{discover, local_interfaces, WINDOW_PORT},
        native::{confirm_unpair, prompt_device_code, show_message, WindowView},
        pair_service::pair_with_candidate,
    };

    let result = async {
        let interfaces = local_interfaces().context(FailureStage::NetworkInterfaces)?;
        let status = WindowView::open_status("Spectrum - Find a device", "Searching the local network for a sharing device.\nClose this window to cancel.").context(FailureStage::DiscoveryWindow)?;
        let sink = status.sink();
        let found = tokio::select! {
            result = discover(&interfaces) => result,
            _ = async { while !sink.closed() { tokio::time::sleep(Duration::from_millis(100)).await; } } => Ok(Vec::new()),
        };
        let cancelled = sink.closed();
        sink.close();
        status.wait();
        if cancelled { return Ok(()); }
        let peers = found.context(FailureStage::Discovery)?;
        if peers.is_empty() {
            show_message("No sharing device was found. Open Spectrum on the other device and try again.");
            return Ok(());
        }
        let count = peers.len();
        let choice = tokio::task::spawn_blocking(move || prompt_device_code(count)).await.context(FailureStage::InputWindow)?;
        let (selected, code) = match choice {
            Ok(value) => value,
            Err(error) if error.to_string() == "pairing was cancelled" => return Ok(()),
            Err(error) => return Err(error.context(FailureStage::InputWindow)),
        };
        let candidate = peers[selected];
        let status = WindowView::open_status("Spectrum - Pair device", "Connecting to the selected device.\nClose this window to cancel.").context(FailureStage::PairingWindow)?;
        let sink = status.sink();
        let paired = tokio::select! {
            result = pair_with_candidate(&store, candidate, &code) => result,
            _ = async { while !sink.closed() { tokio::time::sleep(Duration::from_millis(100)).await; } } => Ok(()),
        };
        let cancelled = sink.closed();
        sink.close();
        status.wait();
        if cancelled { return Ok(()); }
        paired.context(FailureStage::PairingExchange)?;
        let window_address = SocketAddr::new(candidate.address.ip(), WINDOW_PORT);
        view(store.clone(), window_address, false, None, true, Some(candidate.interface.address.into())).await.context(FailureStage::WindowSession)
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
    anyhow::bail!("window viewing requires Windows")
}

#[cfg(windows)]
async fn view(
    store: IdentityStore,
    address: SocketAddr,
    probe: bool,
    frames: Option<u16>,
    wait_for_source: bool,
    local_address: Option<IpAddr>,
) -> Result<()> {
    use spectrum_window::native::WindowView;
    require_lan_address(address)?;
    let identity = store.load()?;
    let peer = store.peer()?;
    let bind = if let Some(local) = local_address {
        require_lan_address(SocketAddr::new(local, 1))?;
        SocketAddr::new(local, 0)
    } else if address.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quic_client_config(
        peer.clone(),
        identity.certificate,
        identity.key,
    )?);
    let waiting = if wait_for_source {
        Some(WindowView::open_status(
            "Spectrum - Waiting for sharing",
            "Waiting for the sharing device to select a window.\nClose this window to cancel.",
        )?)
    } else {
        None
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let connection = loop {
        ensure!(store.peer_is(&peer), "pairing was revoked");
        let connecting = endpoint.connect(address, SERVER_NAME)?;
        let attempt = tokio::select! {
            result = tokio::time::timeout(if wait_for_source { Duration::from_secs(3) } else { IO_TIMEOUT }, connecting) => result,
            _ = async {
                if let Some(waiting) = &waiting {
                    while !waiting.sink().closed() { tokio::time::sleep(Duration::from_millis(100)).await; }
                } else { std::future::pending::<()>().await; }
            } => { endpoint.close(0u32.into(), b"viewer cancelled"); return Ok(()); }
        };
        match attempt {
            Ok(Ok(connection)) => break connection,
            Err(_) | Ok(Err(quinn::ConnectionError::TimedOut))
                if wait_for_source && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(_) => anyhow::bail!("connection timed out"),
            Ok(Err(error)) => return Err(error.into()),
        }
    };
    if let Some(waiting) = waiting {
        waiting.sink().close();
        waiting.wait();
    }
    ensure!(
        verified_peer_certificate(&connection)? == peer,
        "peer identity does not match pairing"
    );
    let result = async {
        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, connection.open_bi())
            .await
            .context("control stream timed out")??;
        send_json(
            &mut send,
            &WindowHello {
                version: PROTOCOL_VERSION,
            },
        )
        .await?;
        let info: WindowInfo = recv_json(&mut recv).await?;
        info.validate()?;
        if probe {
            println!("Paired connection: OK. Window metadata: OK. No frame requested.");
            return Ok(());
        }
        let viewer = WindowView::open("Spectrum - Remote application window")?;
        let sink = viewer.sink();
        let transfer = async {
            for id in 1..=u64::from(frames.unwrap_or(3600)) {
                ensure!(store.peer_is(&peer), "pairing was revoked");
                let request_id = NonZeroU64::new(id).unwrap();
                send_json(
                    &mut send,
                    &CommandRequest {
                        version: PROTOCOL_VERSION,
                        request_id,
                        command: WindowCommand::ReadFrame {
                            target: info.target,
                        },
                    },
                )
                .await?;
                sink.set_frame(recv_frame(&mut recv, request_id, info).await?)?;
            }
            if frames.is_some() {
                Ok(())
            } else {
                anyhow::bail!("session request limit reached")
            }
        };
        let stopped = async {
            while !sink.closed() && store.peer_is(&peer) {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let result = tokio::select! {result=transfer=>result,_=stopped=>Ok(())};
        sink.end();
        if frames.is_some() {
            sink.close();
        }
        connection.close(0u32.into(), b"viewer ended");
        if result.is_err() {
            eprintln!("Window session ended.");
        }
        while !sink.closed() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        viewer.wait();
        result
    }
    .await;
    connection.close(0u32.into(), b"viewer ended");
    endpoint.close(0u32.into(), b"viewer ended");
    result
}

#[cfg(not(windows))]
async fn view(
    _: IdentityStore,
    _: SocketAddr,
    _: bool,
    _: Option<u16>,
    _: bool,
    _: Option<IpAddr>,
) -> Result<()> {
    anyhow::bail!("window viewing requires Windows")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use lanrdp_common::{
        authorization::{Capability, Grant, PeerId, TargetRef},
        transport::quic_server_config,
        window::{serve_window, Frame, FrameSource},
    };
    use std::{
        net::Ipv4Addr,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
        time::Instant,
    };

    #[test]
    fn pairing_conflicts_and_public_messages_survive_stage_context() {
        let conflict = anyhow::anyhow!("another device is already paired; unpair first")
            .context(FailureStage::PairingExchange);
        assert!(already_paired(&conflict));
        let other =
            anyhow::anyhow!("synthetic private detail").context(FailureStage::WindowSession);
        assert_eq!(
            public_failure_message(&other),
            FailureStage::WindowSession.message()
        );
        assert!(!public_failure_message(&other).contains("synthetic private detail"));
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "spectrum-view-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn store(&self, name: &str) -> IdentityStore {
            IdentityStore::new(self.0.join(name))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for name in ["agent", "client"] {
                let path = self.0.join(name);
                for file in ["identity.bin", "peer.der"] {
                    let _ = std::fs::remove_file(path.join(file));
                }
                let _ = std::fs::remove_dir(path);
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    struct Source {
        target: TargetRef,
    }
    impl FrameSource for Source {
        fn info(&self) -> WindowInfo {
            WindowInfo {
                version: PROTOCOL_VERSION,
                target: self.target,
                width: 2,
                height: 2,
            }
        }
        fn is_current(&self) -> bool {
            true
        }
        fn capture(&mut self) -> Result<Frame> {
            Frame::new(2, 2, vec![44u8; 16])
        }
    }

    #[tokio::test]
    #[ignore = "requires an interactive Windows desktop and uses only an owned synthetic window"]
    async fn viewer_waits_for_the_paired_source_and_displays_a_synthetic_frame() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let fixture = Fixture::new();
            let agent = fixture.store("agent");
            let client = fixture.store("client");
            let agent_identity = agent.load_or_initialize()?;
            let client_identity = client.load_or_initialize()?;
            agent.remember_authenticated(client_identity.certificate.clone())?;
            client.remember_authenticated(agent_identity.certificate.clone())?;
            let reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let address = reservation.local_addr()?;
            drop(reservation);
            let target = TargetRef {
                id: NonZeroU64::new(9).unwrap(),
                generation: NonZeroU64::new(10).unwrap(),
            };
            let server = async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                let config = quic_server_config(
                    client_identity.certificate.clone(),
                    agent_identity.certificate,
                    agent_identity.key,
                )?;
                let endpoint = quinn::Endpoint::server(config, address)?;
                let connection = endpoint
                    .accept()
                    .await
                    .context("synthetic connection was not received")?
                    .await?;
                let grant = Grant::new(
                    PeerId::from_certificate(&client_identity.certificate)?,
                    target,
                    &[Capability::DescribeTarget, Capability::ReadFrame],
                    Instant::now(),
                    Duration::from_secs(10),
                )?;
                let source = Arc::new(Mutex::new(Source { target }));
                let result = serve_window(&connection, source, grant, || true).await;
                endpoint.close(0u32.into(), b"test complete");
                result
            };
            let (viewer_result, server_result) = tokio::join!(
                view(
                    client,
                    address,
                    false,
                    Some(1),
                    true,
                    Some(Ipv4Addr::LOCALHOST.into())
                ),
                server
            );
            viewer_result?;
            server_result?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
}
