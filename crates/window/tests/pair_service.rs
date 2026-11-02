#![cfg(windows)]

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU64,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use lanrdp_common::{
    authorization::{
        Capability, Command, CommandRequest, Grant, PeerId, TargetRef, PROTOCOL_VERSION,
    },
    pairing::PairCode,
    transport::{quic_client_config, quic_server_config},
    window::{
        recv_frame, recv_json, send_json, serve_window, Frame, FrameSource, WindowHello, WindowInfo,
    },
};
use spectrum_window::{
    discovery::{Candidate, Interface, PAIRING_PORT},
    identity::IdentityStore,
    pair_service::{pair_with_candidate, PairingOffer},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "spectrum-pair-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn store(&self, name: &str) -> IdentityStore {
        IdentityStore::new(self.0.join(name))
    }
}

struct SyntheticSource {
    target: TargetRef,
}
impl FrameSource for SyntheticSource {
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
        Frame::new(2, 2, vec![42u8; 16])
    }
}
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

#[tokio::test]
async fn pairing_service_persists_both_authenticated_identities_on_loopback() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let fixture = Fixture::new();
        let agent = fixture.store("agent");
        let client = fixture.store("client");
        let interface = Interface::new(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0))?;
        let offer = PairingOffer::new(agent.clone(), &[interface])?;
        let viewer_code = PairCode::parse(offer.code().as_str())?;
        let candidate = Candidate {
            interface,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, PAIRING_PORT)),
        };
        let (server_result, viewer_result) = tokio::join!(
            offer.wait(|| false),
            pair_with_candidate(&client, candidate, &viewer_code)
        );
        server_result?;
        viewer_result?;
        let agent_identity = agent.load()?;
        let client_identity = client.load()?;
        assert!(agent.peer_is(&client_identity.certificate));
        assert!(client.peer_is(&agent_identity.certificate));

        let server = quinn::Endpoint::server(
            quic_server_config(
                client_identity.certificate.clone(),
                agent_identity.certificate.clone(),
                agent_identity.key,
            )?,
            "127.0.0.1:0".parse()?,
        )?;
        let mut viewer = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        viewer.set_default_client_config(quic_client_config(
            agent_identity.certificate,
            client_identity.certificate.clone(),
            client_identity.key,
        )?);
        let connect = async {
            Ok::<_, anyhow::Error>(
                viewer
                    .connect(server.local_addr()?, "spectrum.invalid")?
                    .await?,
            )
        };
        let accept = async { Ok::<_, anyhow::Error>(server.accept().await.unwrap().await?) };
        let (viewer_connection, server_connection) = tokio::try_join!(connect, accept)?;
        let target = TargetRef {
            id: NonZeroU64::new(7).unwrap(),
            generation: NonZeroU64::new(8).unwrap(),
        };
        let grant = Grant::new(
            PeerId::from_certificate(&client_identity.certificate)?,
            target,
            &[Capability::DescribeTarget, Capability::ReadFrame],
            Instant::now(),
            Duration::from_secs(5),
        )?;
        let source = Arc::new(Mutex::new(SyntheticSource { target }));
        let receive = async {
            let (mut send, mut recv) = viewer_connection.open_bi().await?;
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
                    command: Command::ReadFrame { target },
                },
            )
            .await?;
            assert_eq!(
                recv_frame(&mut recv, request_id, info).await?.pixels(),
                &[42u8; 16]
            );
            viewer_connection.close(0u32.into(), b"test complete");
            Ok::<_, anyhow::Error>(())
        };
        let (server_result, viewer_result) = tokio::join!(
            serve_window(&server_connection, source, grant, || true),
            receive
        );
        server_result?;
        viewer_result?;
        viewer.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
