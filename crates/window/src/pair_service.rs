use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use lanrdp_common::{
    pairing::PairCode,
    pairing_transport::{
        pair_sharer, pair_viewer, pairing_client_config, pairing_server_config, PAIRING_SERVER_NAME,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::UdpSocket, task::JoinSet, time::Instant};
use zeroize::Zeroizing;

use crate::{
    discovery::{self, Candidate, Interface, PAIRING_PORT},
    identity::IdentityStore,
};

const PAIRING_LIFETIME: Duration = Duration::from_secs(120);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

fn temporary_identity() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let mut params = rcgen::CertificateParams::new(vec![PAIRING_SERVER_NAME.into()])?;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate()?;
    let certificate = params.self_signed(&key)?.der().clone();
    let encoded = Zeroizing::new(key.serialize_der());
    Ok((
        certificate,
        PrivatePkcs8KeyDer::from(encoded.to_vec()).into(),
    ))
}

struct OfferNetwork {
    interface: Interface,
    endpoint: quinn::Endpoint,
    discovery: UdpSocket,
}

pub struct PairingOffer {
    code: PairCode,
    certificate: CertificateDer<'static>,
    store: IdentityStore,
    networks: Vec<OfferNetwork>,
}

impl PairingOffer {
    pub fn new(store: IdentityStore, interfaces: &[Interface]) -> Result<Self> {
        ensure!(
            !interfaces.is_empty() && interfaces.len() <= 16,
            "no supported local network interface"
        );
        let identity = store.load_or_initialize()?;
        let certificate = identity.certificate;
        let (temporary_certificate, temporary_key) = temporary_identity()?;
        let config = pairing_server_config(temporary_certificate, temporary_key)?;
        let code = PairCode::generate()?;
        let mut networks = Vec::new();
        for interface in interfaces.iter().copied() {
            let address = SocketAddrV4::new(interface.address, PAIRING_PORT);
            let Ok(endpoint) = quinn::Endpoint::server(config.clone(), address.into()) else {
                continue;
            };
            match discovery::listener(interface) {
                Ok(discovery) => networks.push(OfferNetwork {
                    interface,
                    endpoint,
                    discovery,
                }),
                Err(_) => endpoint.close(0u32.into(), b"pairing unavailable"),
            }
        }
        ensure!(
            !networks.is_empty(),
            "could not open device discovery on a private network"
        );
        Ok(Self {
            code,
            certificate,
            store,
            networks,
        })
    }

    pub fn code(&self) -> &PairCode {
        &self.code
    }

    pub async fn wait<F>(self, cancelled: F) -> Result<Candidate>
    where
        F: Fn() -> bool,
    {
        let deadline = Instant::now() + PAIRING_LIFETIME;
        let mut responses = JoinSet::new();
        let mut accepts = JoinSet::new();
        let mut endpoints = Vec::new();
        for network in self.networks {
            let index = endpoints.len();
            let endpoint = network.endpoint.clone();
            let interface = network.interface;
            accepts.spawn(async move {
                endpoint
                    .accept()
                    .await
                    .map(|incoming| (index, interface, incoming))
            });
            responses.spawn(discovery::respond(network.discovery, interface, deadline));
            endpoints.push(network.endpoint);
        }
        let cancellation = async {
            while !cancelled() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let result = async {
            let (index, interface, incoming) = tokio::select! {
                value = accepts.join_next() => value.context("pairing listener closed")??.context("pairing listener closed")?,
                _ = tokio::time::sleep_until(deadline) => anyhow::bail!("pairing code expired"),
                _ = cancellation => anyhow::bail!("pairing was cancelled"),
            };
            accepts.abort_all();
            responses.abort_all();
            for (other, endpoint) in endpoints.iter().enumerate() {
                if other != index { endpoint.close(0u32.into(), b"pairing continued elsewhere"); }
            }
            let remote = incoming.remote_address();
            ensure!(discovery::peer_is_local(interface, remote), "pairing peer is outside the local network");
            let connection = tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming).await.context("pairing connection timed out")??;
            tokio::select! {
                result = pair_sharer(&connection, &self.code, &self.certificate, |peer| self.store.remember_authenticated(peer)) => result?,
                _ = tokio::time::sleep_until(deadline) => anyhow::bail!("pairing code expired"),
                _ = async { while !cancelled() { tokio::time::sleep(Duration::from_millis(100)).await; } } => anyhow::bail!("pairing was cancelled"),
            }
            connection.close(0u32.into(), b"pairing complete");
            Ok(Candidate { interface, address: remote })
        }.await;
        accepts.abort_all();
        responses.abort_all();
        for endpoint in endpoints {
            endpoint.close(0u32.into(), b"pairing ended");
        }
        result
    }
}

pub async fn pair_with_candidate(
    store: &IdentityStore,
    candidate: Candidate,
    code: &PairCode,
) -> Result<()> {
    ensure!(
        candidate.address.port() == PAIRING_PORT
            && discovery::peer_is_local(candidate.interface, candidate.address),
        "invalid local pairing device"
    );
    let identity = store.load_or_initialize()?;
    let local = SocketAddr::new(IpAddr::V4(candidate.interface.address), 0);
    let mut endpoint = quinn::Endpoint::client(local)?;
    endpoint.set_default_client_config(pairing_client_config()?);
    let connection = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        endpoint.connect(candidate.address, PAIRING_SERVER_NAME)?,
    )
    .await
    .context("pairing connection timed out")??;
    let result = pair_viewer(&connection, code, &identity.certificate, |peer| {
        store.remember_authenticated(peer)
    })
    .await;
    connection.close(0u32.into(), b"pairing ended");
    endpoint.close(0u32.into(), b"pairing ended");
    result
}
