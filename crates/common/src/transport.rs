use std::{sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rustls::{
    crypto::{aws_lc_rs, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
    ClientConfig, CommonState, HandshakeKind, NamedGroup, ProtocolVersion, RootCertStore,
    ServerConfig,
};

pub const APPLICATION_PROTOCOL: &[u8] = b"spectrum/1";
pub const MAX_CERTIFICATE_SIZE: usize = 64 * 1024;
const MAX_PRIVATE_KEY_SIZE: usize = 16 * 1024;

pub fn hybrid_provider() -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    Arc::new(provider)
}

fn trust_store(certificate: CertificateDer<'static>) -> Result<RootCertStore> {
    ensure!(
        !certificate.is_empty() && certificate.len() <= MAX_CERTIFICATE_SIZE,
        "invalid trust certificate size"
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate)
        .context("invalid trust certificate")?;
    Ok(roots)
}

fn check_identity(certificate: &CertificateDer<'_>, key: &PrivateKeyDer<'_>) -> Result<()> {
    ensure!(
        !certificate.is_empty() && certificate.len() <= MAX_CERTIFICATE_SIZE,
        "invalid identity certificate size"
    );
    ensure!(
        !key.secret_der().is_empty() && key.secret_der().len() <= MAX_PRIVATE_KEY_SIZE,
        "invalid identity key size"
    );
    Ok(())
}

pub fn tls_client_config(
    trusted_server: CertificateDer<'static>,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    check_identity(&certificate, &key)?;
    let mut config = ClientConfig::builder_with_provider(hybrid_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(trust_store(trusted_server)?)
        .with_client_auth_cert(vec![certificate], key)?;
    config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    // Every connection rechecks identity and performs a fresh hybrid exchange.
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

pub fn tls_server_config(
    trusted_client: CertificateDer<'static>,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    check_identity(&certificate, &key)?;
    let provider = hybrid_provider();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(trust_store(trusted_client)?),
        provider.clone(),
    )
    .build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![certificate], key)?;
    config.alpn_protocols = vec![APPLICATION_PROTOCOL.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(config)
}

pub fn verify_tls_session(state: &CommonState) -> Result<()> {
    ensure!(!state.is_handshaking(), "TLS handshake is incomplete");
    ensure!(
        state.protocol_version() == Some(ProtocolVersion::TLSv1_3),
        "TLS 1.3 is required"
    );
    ensure!(
        state
            .negotiated_key_exchange_group()
            .map(|group| group.name())
            == Some(NamedGroup::X25519MLKEM768),
        "hybrid key exchange is required"
    );
    ensure!(
        state
            .handshake_kind()
            .is_some_and(|kind| kind != HandshakeKind::Resumed),
        "a fresh handshake is required"
    );
    ensure!(
        state.alpn_protocol() == Some(APPLICATION_PROTOCOL),
        "unexpected application protocol"
    );
    ensure!(
        state
            .peer_certificates()
            .is_some_and(|chain| !chain.is_empty()),
        "peer identity is missing"
    );
    Ok(())
}

fn transport_limits() -> Result<Arc<quinn::TransportConfig>> {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_bidi_streams(2u32.into());
    config.max_concurrent_uni_streams(0u32.into());
    config.stream_receive_window((64 * 1024u32).into());
    config.receive_window((256 * 1024u32).into());
    config.send_window(256 * 1024);
    config.crypto_buffer_size(64 * 1024);
    config.datagram_receive_buffer_size(None);
    config.max_idle_timeout(Some(Duration::from_secs(5).try_into()?));
    Ok(Arc::new(config))
}

pub fn quic_client_config(
    trusted_server: CertificateDer<'static>,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ClientConfig> {
    let tls = tls_client_config(trusted_server, certificate, key)?;
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(transport_limits()?);
    Ok(config)
}

pub fn quic_server_config(
    trusted_client: CertificateDer<'static>,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    let tls = tls_server_config(trusted_client, certificate, key)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(transport_limits()?);
    config.max_incoming(4);
    config.incoming_buffer_size(16 * 1024);
    config.incoming_buffer_size_total(64 * 1024);
    Ok(config)
}

pub fn verified_peer_certificate(
    connection: &quinn::Connection,
) -> Result<CertificateDer<'static>> {
    let result = (|| {
        let handshake = connection
            .handshake_data()
            .context("TLS metadata is missing")?;
        let handshake = handshake
            .downcast::<HandshakeData>()
            .map_err(|_| anyhow::anyhow!("unexpected TLS implementation"))?;
        ensure!(
            handshake.protocol.as_deref() == Some(APPLICATION_PROTOCOL),
            "unexpected application protocol"
        );
        let identity = connection
            .peer_identity()
            .context("peer identity is missing")?;
        let certificates = identity
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| anyhow::anyhow!("unexpected peer identity"))?;
        ensure!(certificates.len() == 1, "unexpected peer certificate chain");
        let certificate = certificates[0].clone();
        ensure!(
            certificate.len() <= MAX_CERTIFICATE_SIZE,
            "peer certificate too large"
        );
        Ok(certificate)
    })();
    if result.is_err() {
        connection.close(1u32.into(), b"unverified peer");
    }
    result
}
