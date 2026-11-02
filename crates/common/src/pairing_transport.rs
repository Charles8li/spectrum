use std::{sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    pairing::{PairCode, PairRole, PairingStart},
    transport::hybrid_provider,
};

pub const PAIRING_PROTOCOL: &[u8] = b"spectrum-pair/1";
pub const PAIRING_SERVER_NAME: &str = "spectrum.invalid";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Spectrum-Pairing-v1";
const MAX_CERTIFICATE: usize = 2048;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const VERSION: u8 = 1;

// The provisional certificate proves possession only. The short-code exchange
// authenticates this specific TLS channel before either peer is saved.
#[derive(Debug)]
struct ProvisionalVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for ProvisionalVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity.is_empty() || end_entity.len() > MAX_CERTIFICATE || !intermediates.is_empty()
        {
            return Err(rustls::Error::General("invalid pairing certificate".into()));
        }
        let mut roots = RootCertStore::empty();
        roots.add(end_entity.clone().into_owned())?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|_| rustls::Error::General("invalid pairing certificate".into()))?;
        verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not enabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn limits() -> Result<Arc<quinn::TransportConfig>> {
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_bidi_streams(1u32.into());
    config.max_concurrent_uni_streams(0u32.into());
    config.stream_receive_window((16 * 1024u32).into());
    config.receive_window((32 * 1024u32).into());
    config.send_window(32 * 1024);
    config.crypto_buffer_size(64 * 1024);
    config.datagram_receive_buffer_size(None);
    config.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    Ok(Arc::new(config))
}

pub fn pairing_server_config(
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig> {
    ensure!(
        !certificate.is_empty() && certificate.len() <= MAX_CERTIFICATE,
        "invalid pairing certificate"
    );
    let mut tls = ServerConfig::builder_with_provider(hybrid_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)?;
    tls.alpn_protocols = vec![PAIRING_PROTOCOL.to_vec()];
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    config.transport_config(limits()?);
    config.max_incoming(1);
    config.incoming_buffer_size(16 * 1024);
    config.incoming_buffer_size_total(16 * 1024);
    Ok(config)
}

pub fn pairing_client_config() -> Result<quinn::ClientConfig> {
    let provider = hybrid_provider();
    let mut tls = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProvisionalVerifier { provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![PAIRING_PROTOCOL.to_vec()];
    tls.resumption = rustls::client::Resumption::disabled();
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    config.transport_config(limits()?);
    Ok(config)
}

fn channel_binding(connection: &quinn::Connection) -> Result<[u8; 32]> {
    let handshake = connection
        .handshake_data()
        .context("pairing TLS metadata is missing")?;
    let handshake = handshake
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow::anyhow!("unexpected pairing TLS implementation"))?;
    ensure!(
        handshake.protocol.as_deref() == Some(PAIRING_PROTOCOL),
        "unexpected pairing protocol"
    );
    let mut binding = [0u8; 32];
    connection
        .export_keying_material(&mut binding, EXPORTER_LABEL, b"")
        .map_err(|_| anyhow::anyhow!("pairing channel binding failed"))?;
    Ok(binding)
}

async fn send_packet<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CERTIFICATE,
        "invalid pairing packet"
    );
    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_u16(bytes.len() as u16).await?;
        writer.write_all(bytes).await?;
        writer.flush().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("pairing send timed out")?
}

async fn receive_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let length = reader.read_u16().await? as usize;
        ensure!(
            length > 0 && length <= MAX_CERTIFICATE,
            "invalid pairing packet"
        );
        let mut bytes = vec![0u8; length];
        reader.read_exact(&mut bytes).await?;
        Ok::<_, anyhow::Error>(bytes)
    })
    .await
    .context("pairing receive timed out")?
}

fn certificate(bytes: Vec<u8>, own: &CertificateDer<'_>) -> Result<CertificateDer<'static>> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_CERTIFICATE,
        "invalid peer certificate"
    );
    let peer = CertificateDer::from(bytes);
    ensure!(
        peer.as_ref() != own.as_ref(),
        "cannot pair an identity with itself"
    );
    let mut roots = RootCertStore::empty();
    roots
        .add(peer.clone())
        .context("invalid peer certificate")?;
    Ok(peer)
}

pub async fn pair_viewer<F>(
    connection: &quinn::Connection,
    code: &PairCode,
    own_certificate: &CertificateDer<'_>,
    remember: F,
) -> Result<()>
where
    F: FnOnce(CertificateDer<'static>) -> Result<()>,
{
    let result = async {
        let binding = channel_binding(connection)?;
        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, connection.open_bi())
            .await
            .context("pairing stream timed out")??;
        let (start, message) = PairingStart::start(PairRole::Viewer, code)?;
        let mut hello = [0u8; 33];
        hello[0] = VERSION;
        hello[1..].copy_from_slice(&message);
        send_packet(&mut send, &hello).await?;
        let reply = receive_packet(&mut recv).await?;
        ensure!(
            reply.len() == 33 && reply[0] == VERSION,
            "invalid pairing response"
        );
        let key = start.finish(&reply[1..])?;
        let proof = key.confirmation(&binding);
        send_packet(&mut send, &proof).await?;
        let peer_proof = receive_packet(&mut recv).await?;
        let _confirmed = key.verify_peer(&binding, &peer_proof)?;
        send_packet(&mut send, own_certificate.as_ref()).await?;
        let peer = certificate(receive_packet(&mut recv).await?, own_certificate)?;
        send_packet(&mut send, &[VERSION]).await?;
        ensure!(
            receive_packet(&mut recv).await? == [VERSION],
            "pairing was not committed"
        );
        remember(peer)?;
        send_packet(&mut send, &[VERSION]).await?;
        send.finish()?;
        ensure!(
            receive_packet(&mut recv).await? == [VERSION],
            "pairing did not finish"
        );
        ensure!(
            tokio::time::timeout(IO_TIMEOUT, send.stopped())
                .await??
                .is_none(),
            "pairing stream stopped"
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        connection.close(1u32.into(), b"pairing failed");
    }
    result
}

pub async fn pair_sharer<F>(
    connection: &quinn::Connection,
    code: &PairCode,
    own_certificate: &CertificateDer<'_>,
    remember: F,
) -> Result<()>
where
    F: FnOnce(CertificateDer<'static>) -> Result<()>,
{
    let result = async {
        let binding = channel_binding(connection)?;
        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, connection.accept_bi())
            .await
            .context("pairing stream timed out")??;
        let hello = receive_packet(&mut recv).await?;
        ensure!(
            hello.len() == 33 && hello[0] == VERSION,
            "invalid pairing request"
        );
        let (start, message) = PairingStart::start(PairRole::Sharer, code)?;
        let key = start.finish(&hello[1..])?;
        let mut reply = [0u8; 33];
        reply[0] = VERSION;
        reply[1..].copy_from_slice(&message);
        send_packet(&mut send, &reply).await?;
        let peer_proof = receive_packet(&mut recv).await?;
        let own_proof = key.confirmation(&binding);
        let _confirmed = key.verify_peer(&binding, &peer_proof)?;
        send_packet(&mut send, &own_proof).await?;
        let peer = certificate(receive_packet(&mut recv).await?, own_certificate)?;
        send_packet(&mut send, own_certificate.as_ref()).await?;
        ensure!(
            receive_packet(&mut recv).await? == [VERSION],
            "pairing was cancelled"
        );
        remember(peer)?;
        send_packet(&mut send, &[VERSION]).await?;
        ensure!(
            receive_packet(&mut recv).await? == [VERSION],
            "peer did not finish pairing"
        );
        send_packet(&mut send, &[VERSION]).await?;
        send.finish()?;
        ensure!(
            tokio::time::timeout(IO_TIMEOUT, send.stopped())
                .await??
                .is_none(),
            "pairing stream stopped"
        );
        Ok(())
    }
    .await;
    if result.is_err() {
        connection.close(1u32.into(), b"pairing failed");
    }
    result
}
