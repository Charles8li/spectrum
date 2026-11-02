use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use lanrdp_common::{
    pairing::PairCode,
    pairing_transport::{
        pair_sharer, pair_viewer, pairing_client_config, pairing_server_config, PAIRING_PROTOCOL,
        PAIRING_SERVER_NAME,
    },
    transport::hybrid_provider,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ClientConfig, RootCertStore,
};

fn identity(name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    (
        params.self_signed(&key).unwrap().der().clone(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

async fn run_pairing(viewer_code: &str, sharer_code: &str) -> Result<(bool, bool, bool, bool)> {
    let (temporary_certificate, temporary_key) = identity(PAIRING_SERVER_NAME);
    let (viewer_certificate, _) = identity(PAIRING_SERVER_NAME);
    let (sharer_certificate, _) = identity(PAIRING_SERVER_NAME);
    let server = quinn::Endpoint::server(
        pairing_server_config(temporary_certificate, temporary_key)?,
        "127.0.0.1:0".parse()?,
    )?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(pairing_client_config()?);
    let connect = async {
        Ok::<_, anyhow::Error>(
            client
                .connect(server.local_addr()?, PAIRING_SERVER_NAME)?
                .await?,
        )
    };
    let accept = async { Ok::<_, anyhow::Error>(server.accept().await.unwrap().await?) };
    let (viewer_connection, sharer_connection) = tokio::try_join!(connect, accept)?;
    let viewer_saved = Arc::new(Mutex::new(None));
    let sharer_saved = Arc::new(Mutex::new(None));
    let viewer_slot = viewer_saved.clone();
    let sharer_slot = sharer_saved.clone();
    let viewer_code = PairCode::parse(viewer_code)?;
    let sharer_code = PairCode::parse(sharer_code)?;
    let (viewer_result, sharer_result) = tokio::join!(
        pair_viewer(
            &viewer_connection,
            &viewer_code,
            &viewer_certificate,
            |peer| {
                *viewer_slot.lock().unwrap() = Some(peer);
                Ok(())
            }
        ),
        pair_sharer(
            &sharer_connection,
            &sharer_code,
            &sharer_certificate,
            |peer| {
                *sharer_slot.lock().unwrap() = Some(peer);
                Ok(())
            }
        )
    );
    let viewer_matches = viewer_saved.lock().unwrap().as_ref() == Some(&sharer_certificate);
    let sharer_matches = sharer_saved.lock().unwrap().as_ref() == Some(&viewer_certificate);
    client.close(0u32.into(), b"test complete");
    server.close(0u32.into(), b"test complete");
    Ok((
        viewer_result.is_ok(),
        sharer_result.is_ok(),
        viewer_matches,
        sharer_matches,
    ))
}

#[tokio::test]
async fn matching_code_exchanges_only_authenticated_certificates_over_hybrid_quic() {
    let result = tokio::time::timeout(Duration::from_secs(10), run_pairing("007351", "007351"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, (true, true, true, true));
}

#[tokio::test]
async fn wrong_code_never_commits_a_peer_certificate() {
    let result = tokio::time::timeout(Duration::from_secs(10), run_pairing("007351", "007352"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, (false, false, false, false));
}

#[tokio::test]
async fn relaying_pairing_messages_across_different_tls_channels_is_rejected() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (agent_temporary, agent_temporary_key) = identity(PAIRING_SERVER_NAME);
        let (relay_temporary, relay_temporary_key) = identity(PAIRING_SERVER_NAME);
        let (agent_certificate, _) = identity(PAIRING_SERVER_NAME);
        let (viewer_certificate, _) = identity(PAIRING_SERVER_NAME);
        let agent = quinn::Endpoint::server(
            pairing_server_config(agent_temporary, agent_temporary_key)?,
            "127.0.0.1:0".parse()?,
        )?;
        let relay = quinn::Endpoint::server(
            pairing_server_config(relay_temporary, relay_temporary_key)?,
            "127.0.0.1:0".parse()?,
        )?;
        let mut viewer = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let mut relay_client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        viewer.set_default_client_config(pairing_client_config()?);
        relay_client.set_default_client_config(pairing_client_config()?);
        let viewer_connect = async {
            Ok::<_, anyhow::Error>(
                viewer
                    .connect(relay.local_addr()?, PAIRING_SERVER_NAME)?
                    .await?,
            )
        };
        let agent_connect = async {
            Ok::<_, anyhow::Error>(
                relay_client
                    .connect(agent.local_addr()?, PAIRING_SERVER_NAME)?
                    .await?,
            )
        };
        let relay_accept = async { Ok::<_, anyhow::Error>(relay.accept().await.unwrap().await?) };
        let agent_accept = async { Ok::<_, anyhow::Error>(agent.accept().await.unwrap().await?) };
        let (viewer_connection, relay_viewer, relay_agent, agent_connection) =
            tokio::try_join!(viewer_connect, relay_accept, agent_connect, agent_accept)?;
        let saved = Arc::new(Mutex::new(0usize));
        let viewer_saved = saved.clone();
        let agent_saved = saved.clone();
        let viewer_code = PairCode::parse("007351")?;
        let agent_code = PairCode::parse("007351")?;
        let relaying = async {
            let (mut viewer_send, mut viewer_recv) = relay_viewer.accept_bi().await?;
            let (mut agent_send, mut agent_recv) = relay_agent.open_bi().await?;
            tokio::select! {
                _ = tokio::io::copy(&mut viewer_recv, &mut agent_send) => {},
                _ = tokio::io::copy(&mut agent_recv, &mut viewer_send) => {},
            }
            relay_viewer.close(1u32.into(), b"test relay ended");
            relay_agent.close(1u32.into(), b"test relay ended");
            Ok::<_, anyhow::Error>(())
        };
        let (viewer_result, agent_result, relay_result) = tokio::join!(
            pair_viewer(
                &viewer_connection,
                &viewer_code,
                &viewer_certificate,
                |_| {
                    *viewer_saved.lock().unwrap() += 1;
                    Ok(())
                }
            ),
            pair_sharer(&agent_connection, &agent_code, &agent_certificate, |_| {
                *agent_saved.lock().unwrap() += 1;
                Ok(())
            }),
            relaying,
        );
        relay_result?;
        assert!(viewer_result.is_err() && agent_result.is_err());
        assert_eq!(*saved.lock().unwrap(), 0);
        for endpoint in [viewer, relay_client, relay, agent] {
            endpoint.close(0u32.into(), b"test complete");
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn provisional_certificate_must_match_the_expected_server_name() -> Result<()> {
    let (certificate, key) = identity("different.invalid");
    let server = quinn::Endpoint::server(
        pairing_server_config(certificate, key)?,
        "127.0.0.1:0".parse()?,
    )?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(pairing_client_config()?);
    let (client_result, server_result) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(5),
            client.connect(server.local_addr()?, PAIRING_SERVER_NAME)?
        ),
        tokio::time::timeout(Duration::from_secs(5), async {
            server.accept().await.unwrap().await
        })
    );
    assert!(!matches!(client_result, Ok(Ok(_))));
    assert!(!matches!(server_result, Ok(Ok(_))));
    client.close(0u32.into(), b"test complete");
    server.close(0u32.into(), b"test complete");
    Ok(())
}

#[tokio::test]
async fn classical_only_pairing_handshake_is_rejected() -> Result<()> {
    let (certificate, key) = identity(PAIRING_SERVER_NAME);
    let server = quinn::Endpoint::server(
        pairing_server_config(certificate.clone(), key)?,
        "127.0.0.1:0".parse()?,
    )?;
    let mut provider = (*hybrid_provider()).clone();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let mut tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![PAIRING_PROTOCOL.to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(config);
    let (client_result, server_result) = tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(5),
            client.connect(server.local_addr()?, PAIRING_SERVER_NAME)?
        ),
        tokio::time::timeout(Duration::from_secs(5), async {
            server.accept().await.unwrap().await
        })
    );
    assert!(!matches!(client_result, Ok(Ok(_))));
    assert!(!matches!(server_result, Ok(Ok(_))));
    client.close(0u32.into(), b"test complete");
    server.close(0u32.into(), b"test complete");
    Ok(())
}
