#![cfg(windows)]

use anyhow::{ensure, Context, Result};
use lanrdp_common::{
    authorization::{
        Capability, Command, CommandRequest, Grant, PeerId, TargetRef, PROTOCOL_VERSION,
    },
    transport::{quic_client_config, quic_server_config, verified_peer_certificate},
    window::{
        recv_frame, recv_json, send_json, serve_window, Frame, FrameSource, WindowHello, WindowInfo,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spectrum_window::{
    demo_frame,
    identity::SERVER_NAME,
    native::{WindowCapture, WindowView},
};
use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn identity() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.into()]).unwrap();
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    (
        params.self_signed(&key).unwrap().der().clone(),
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

fn has_demo_colors(frame: &Frame) -> bool {
    let mut blue = 0;
    let mut green = 0;
    for pixel in frame.pixels().as_chunks::<4>().0 {
        if pixel[0].abs_diff(210) < 12 && pixel[1].abs_diff(110) < 12 && pixel[2].abs_diff(35) < 12
        {
            blue += 1;
        }
        if pixel[0].abs_diff(65) < 12 && pixel[1].abs_diff(180) < 12 && pixel[2].abs_diff(115) < 12
        {
            green += 1;
        }
    }
    blue > 100 && green > 100
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an interactive Windows desktop and captures only self-owned synthetic windows"]
async fn owned_window_is_captured_encrypted_and_rendered_then_stops_on_close() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        spectrum_window::identity::self_check()?;
        let fixture = WindowView::open("Spectrum - Synthetic source")?;
        fixture.sink().set_frame(demo_frame()?)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let target = TargetRef {
            id: NonZeroU64::new(11).unwrap(),
            generation: NonZeroU64::new(7).unwrap(),
        };
        let capture = WindowCapture::open(fixture.choice()?, target)?;
        let source = Arc::new(Mutex::new(capture));
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
            Ok::<_, anyhow::Error>(client.connect(server.local_addr()?, SERVER_NAME)?.await?)
        };
        let accept = async {
            Ok::<_, anyhow::Error>(
                server
                    .accept()
                    .await
                    .context("missing owned test peer")?
                    .await?,
            )
        };
        let (client_connection, server_connection) = tokio::try_join!(connect, accept)?;
        ensure!(verified_peer_certificate(&client_connection)? == server_cert);
        let grant = Grant::new(
            PeerId::from_certificate(&client_cert)?,
            target,
            &[Capability::DescribeTarget, Capability::ReadFrame],
            Instant::now(),
            Duration::from_secs(10),
        )?;
        let server_source = source.clone();
        let handler = tokio::spawn(async move {
            serve_window(&server_connection, server_source, grant, || true).await
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
        info.validate()?;
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
        let frame = recv_frame(&mut recv, request_id, info).await?;
        ensure!(
            has_demo_colors(&frame),
            "owned source pixels did not arrive"
        );
        let viewer = WindowView::open("Spectrum - Synthetic receiving client")?;
        viewer.sink().set_frame(frame)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut viewer_capture = WindowCapture::open(
            viewer.choice()?,
            TargetRef {
                id: NonZeroU64::new(12).unwrap(),
                generation: NonZeroU64::new(8).unwrap(),
            },
        )?;
        ensure!(
            has_demo_colors(&viewer_capture.capture()?),
            "received pixels were not rendered in the owned viewer"
        );
        let changed_pixels: Vec<u8> = (0..640 * 360).flat_map(|_| [120u8, 40, 180, 255]).collect();
        fixture
            .sink()
            .set_frame(Frame::new(640, 360, changed_pixels)?)?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let request_id = NonZeroU64::new(2).unwrap();
        send_json(
            &mut send,
            &CommandRequest {
                version: PROTOCOL_VERSION,
                request_id,
                command: Command::ReadFrame { target },
            },
        )
        .await?;
        let updated = recv_frame(&mut recv, request_id, info).await?;
        ensure!(
            updated
                .pixels()
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|pixel| pixel[0].abs_diff(120) < 12
                    && pixel[1].abs_diff(40) < 12
                    && pixel[2].abs_diff(180) < 12)
                .count()
                > 1000,
            "updated source content did not arrive"
        );
        fixture.sink().close();
        fixture.wait();
        ensure!(
            tokio::time::timeout(Duration::from_secs(2), client_connection.closed())
                .await
                .is_ok(),
            "closing the source did not stop the connection"
        );
        ensure!(handler.await?.is_err(), "closed source remained authorized");
        ensure!(!source
            .lock()
            .map_err(|_| anyhow::anyhow!("owned test state poisoned"))?
            .is_current());
        viewer.sink().end();
        viewer.sink().close();
        viewer.wait();
        drop(viewer_capture);
        client.close(0u32.into(), b"test ended");
        server.close(0u32.into(), b"test ended");
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("owned window experiment timed out")?
}
