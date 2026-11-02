use std::{
    io::Write,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use lanrdp_common::{
    authorization::{
        Capability, Command, CommandRequest, Grant, PeerId, TargetRef, PROTOCOL_VERSION,
    },
    recv_bytes, send_bytes,
    transport::{
        hybrid_provider, quic_client_config, quic_server_config, tls_client_config,
        tls_server_config, verified_peer_certificate, verify_tls_session, APPLICATION_PROTOCOL,
        MAX_CERTIFICATE_SIZE,
    },
};
use rustls::{
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::WebPkiClientVerifier,
    ClientConfig, ClientConnection, HandshakeKind, NamedGroup, RootCertStore, ServerConfig,
    ServerConnection,
};

const SERVER_NAME: &str = "synthetic.invalid";
const WIRE_LIMIT: usize = 64 * 1024;

struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate: certificate.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }

    fn client_config(&self, trusted_server: &Self) -> ClientConfig {
        tls_client_config(
            trusted_server.certificate.clone(),
            self.certificate.clone(),
            self.key.clone_key(),
        )
        .unwrap()
    }

    fn server_config(&self, trusted_client: &Self) -> ServerConfig {
        tls_server_config(
            trusted_client.certificate.clone(),
            self.certificate.clone(),
            self.key.clone_key(),
        )
        .unwrap()
    }
}

fn handshake(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
) -> Result<(ClientConnection, ServerConnection)> {
    let mut client = ClientConnection::new(client, ServerName::try_from(name.to_owned())?)?;
    let mut server = ServerConnection::new(server)?;
    client.set_buffer_limit(Some(WIRE_LIMIT));
    server.set_buffer_limit(Some(WIRE_LIMIT));
    for _ in 0..16 {
        let mut wire = Vec::new();
        client.write_tls(&mut wire)?;
        ensure!(wire.len() <= WIRE_LIMIT, "synthetic TLS buffer limit");
        if !wire.is_empty() {
            server.read_tls(&mut wire.as_slice())?;
            server.process_new_packets()?;
        }
        wire.clear();
        server.write_tls(&mut wire)?;
        ensure!(wire.len() <= WIRE_LIMIT, "synthetic TLS buffer limit");
        if !wire.is_empty() {
            client.read_tls(&mut wire.as_slice())?;
            client.process_new_packets()?;
        }
        if !client.is_handshaking()
            && !server.is_handshaking()
            && !client.wants_write()
            && !server.wants_write()
        {
            return Ok((client, server));
        }
    }
    anyhow::bail!("synthetic TLS handshake limit")
}

fn classical_server(server: &Identity, client: &Identity) -> ServerConfig {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519];
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    roots.add(client.certificate.clone()).unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server.certificate.clone()], server.key.clone_key())
        .unwrap();
    config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    config
}

#[test]
fn mutually_trusted_peers_negotiate_the_required_hybrid_group() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let (mut client, mut server) = handshake(
        Arc::new(client.client_config(&server)),
        Arc::new(server.server_config(&client)),
        SERVER_NAME,
    )
    .unwrap();
    verify_tls_session(&client).unwrap();
    verify_tls_session(&server).unwrap();
    for state in [&**client, &**server] {
        assert_eq!(
            state.negotiated_key_exchange_group().unwrap().name(),
            NamedGroup::X25519MLKEM768
        );
    }
    client.writer().write_all(b"synthetic payload").unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    server.read_tls(&mut wire.as_slice()).unwrap();
    server.process_new_packets().unwrap();
    let mut received = [0u8; 17];
    std::io::Read::read_exact(&mut server.reader(), &mut received).unwrap();
    assert_eq!(&received, b"synthetic payload");
}

#[test]
fn wrong_server_identity_and_name_are_rejected() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let other = Identity::new(SERVER_NAME);
    assert!(handshake(
        Arc::new(client.client_config(&other)),
        Arc::new(server.server_config(&client)),
        SERVER_NAME,
    )
    .is_err());
    assert!(handshake(
        Arc::new(client.client_config(&server)),
        Arc::new(server.server_config(&client)),
        "other.invalid",
    )
    .is_err());
}

#[test]
fn untrusted_client_identity_is_rejected() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let other = Identity::new("client.invalid");
    assert!(handshake(
        Arc::new(client.client_config(&server)),
        Arc::new(server.server_config(&other)),
        SERVER_NAME,
    )
    .is_err());
}

#[test]
fn missing_client_identity_is_rejected() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let mut roots = RootCertStore::empty();
    roots.add(server.certificate.clone()).unwrap();
    let mut anonymous = ClientConfig::builder_with_provider(hybrid_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    anonymous.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    assert!(handshake(
        Arc::new(anonymous),
        Arc::new(server.server_config(&client)),
        SERVER_NAME,
    )
    .is_err());
}

#[test]
fn classical_only_peer_cannot_poison_a_later_hybrid_handshake() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let config = Arc::new(client.client_config(&server));
    assert!(handshake(
        config.clone(),
        Arc::new(classical_server(&server, &client)),
        SERVER_NAME,
    )
    .is_err());
    let (client, server) =
        handshake(config, Arc::new(server.server_config(&client)), SERVER_NAME).unwrap();
    verify_tls_session(&client).unwrap();
    verify_tls_session(&server).unwrap();
}

#[test]
fn repeated_connections_require_fresh_handshakes() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let client_config = Arc::new(client.client_config(&server));
    let server_config = Arc::new(server.server_config(&client));
    for _ in 0..2 {
        let (client, server) =
            handshake(client_config.clone(), server_config.clone(), SERVER_NAME).unwrap();
        verify_tls_session(&client).unwrap();
        verify_tls_session(&server).unwrap();
        assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
    }
}

#[test]
fn unexpected_application_protocol_is_rejected() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let mut config = client.client_config(&server);
    config.alpn_protocols = vec![b"other/1".to_vec()];
    assert!(handshake(
        Arc::new(config),
        Arc::new(server.server_config(&client)),
        SERVER_NAME,
    )
    .is_err());
}

#[test]
fn incomplete_handshake_is_not_a_verified_session() {
    let client = Identity::new("client.invalid");
    let server = Identity::new(SERVER_NAME);
    let connection = ClientConnection::new(
        Arc::new(client.client_config(&server)),
        ServerName::try_from(SERVER_NAME).unwrap(),
    )
    .unwrap();
    assert!(verify_tls_session(&connection).is_err());
}

#[test]
fn malformed_or_oversized_trust_material_is_rejected() {
    let client = Identity::new("client.invalid");
    for bytes in [vec![0; 16], vec![0; MAX_CERTIFICATE_SIZE + 1]] {
        assert!(tls_client_config(
            bytes.into(),
            client.certificate.clone(),
            client.key.clone_key()
        )
        .is_err());
    }
}

async fn loopback_pair(
    client_config: quinn::ClientConfig,
    server_config: quinn::ServerConfig,
) -> Result<(
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
)> {
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(client_config);
    let client_connect =
        async { Ok::<_, anyhow::Error>(client.connect(server.local_addr()?, SERVER_NAME)?.await?) };
    let server_connect = async {
        Ok::<_, anyhow::Error>(
            server
                .accept()
                .await
                .context("missing loopback peer")?
                .await?,
        )
    };
    let (client_connection, server_connection) = tokio::try_join!(client_connect, server_connect)?;
    Ok((client, server, client_connection, server_connection))
}

#[tokio::test]
async fn loopback_quic_authenticates_both_peers_and_exchanges_synthetic_data() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let client = Identity::new("client.invalid");
        let server = Identity::new(SERVER_NAME);
        let (client_endpoint, server_endpoint, client_connection, server_connection) =
            loopback_pair(
                quic_client_config(
                    server.certificate.clone(),
                    client.certificate.clone(),
                    client.key.clone_key(),
                )?,
                quic_server_config(
                    client.certificate.clone(),
                    server.certificate.clone(),
                    server.key.clone_key(),
                )?,
            )
            .await?;
        ensure!(verified_peer_certificate(&client_connection)? == server.certificate);
        let authenticated_client = verified_peer_certificate(&server_connection)?;
        ensure!(authenticated_client == client.certificate);
        let peer = PeerId::from_certificate(&authenticated_client)?;
        let target = TargetRef {
            id: NonZeroU64::new(11).unwrap(),
            generation: NonZeroU64::new(7).unwrap(),
        };
        let mut grant = Grant::new(
            peer,
            target,
            &[Capability::ReadFrame],
            Instant::now(),
            Duration::from_secs(30),
        )?;
        let sender = async {
            let (mut send, mut recv) = client_connection.open_bi().await?;
            let request = CommandRequest {
                version: PROTOCOL_VERSION,
                request_id: NonZeroU64::new(1).unwrap(),
                command: Command::ReadFrame { target },
            };
            send_bytes(&mut send, Bytes::from(serde_json::to_vec(&request)?)).await?;
            send.finish()?;
            ensure!(recv_bytes(&mut recv).await?.as_ref() == b"synthetic frame");
            Ok::<_, anyhow::Error>(())
        };
        let receiver = async {
            let (mut send, mut recv) = server_connection.accept_bi().await?;
            let request = serde_json::from_slice::<CommandRequest>(&recv_bytes(&mut recv).await?)?;
            let command = grant.authorize(peer, &request, Some(target), Instant::now())?;
            ensure!(command == Command::ReadFrame { target });
            send_bytes(&mut send, Bytes::from_static(b"synthetic frame")).await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(sender, receiver)?;
        client_connection.close(0u32.into(), b"done");
        client_endpoint.close(0u32.into(), b"done");
        server_endpoint.close(0u32.into(), b"done");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn loopback_quic_rejects_a_classical_only_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let client = Identity::new("client.invalid");
        let server = Identity::new(SERVER_NAME);
        let classical = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(classical_server(&server, &client))?,
        ));
        let result = loopback_pair(
            quic_client_config(
                server.certificate.clone(),
                client.certificate.clone(),
                client.key.clone_key(),
            )?,
            classical,
        )
        .await;
        ensure!(
            result.is_err(),
            "classical-only QUIC handshake was accepted"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .unwrap()
    .unwrap();
}
