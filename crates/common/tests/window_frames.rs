use lanrdp_common::{
    authorization::{TargetRef, PROTOCOL_VERSION},
    window::{
        pixel_bytes, recv_frame, recv_json, require_lan_address, send_frame, send_json, Frame,
        WindowInfo, MAX_HEIGHT, MAX_WIDTH,
    },
};
use std::num::NonZeroU64;
use tokio::io::AsyncWriteExt;

fn target() -> TargetRef {
    TargetRef {
        id: NonZeroU64::new(11).unwrap(),
        generation: NonZeroU64::new(7).unwrap(),
    }
}
fn info() -> WindowInfo {
    WindowInfo {
        version: PROTOCOL_VERSION,
        target: target(),
        width: 8,
        height: 6,
    }
}

#[test]
fn invalid_dimensions_and_incomplete_pixels_are_rejected() {
    for (w, h) in [
        (0, 1),
        (1, 0),
        (MAX_WIDTH + 1, 1),
        (1, MAX_HEIGHT + 1),
        (u32::MAX, u32::MAX),
    ] {
        assert!(pixel_bytes(w, h).is_err());
    }
    assert!(Frame::new(8, 6, vec![0; 191]).is_err());
    assert!(Frame::new(8, 6, vec![0; 193]).is_err());
}

#[test]
fn only_explicit_lan_endpoints_are_accepted() {
    for address in [
        "127.0.0.1:8443",
        "192.168.50.2:8443",
        "[::1]:8443",
        "[fd00::2]:8443",
    ] {
        assert!(require_lan_address(address.parse().unwrap()).is_ok());
    }
    for address in [
        "0.0.0.0:8443",
        "127.0.0.1:0",
        "203.0.113.5:8443",
        "224.0.0.1:8443",
        "[2001:db8::2]:8443",
    ] {
        assert!(require_lan_address(address.parse().unwrap()).is_err());
    }
}

#[tokio::test]
async fn exact_bgra_frame_and_control_metadata_round_trip() {
    let (mut sender, mut receiver) = tokio::io::duplex(1024);
    let frame = Frame::new(8, 6, (0..192).map(|i| i as u8).collect()).unwrap();
    let send = async {
        send_json(&mut sender, &info()).await.unwrap();
        send_frame(&mut sender, NonZeroU64::new(1).unwrap(), target(), &frame)
            .await
            .unwrap();
    };
    let recv = async {
        let received: WindowInfo = recv_json(&mut receiver).await.unwrap();
        received.validate().unwrap();
        let frame = recv_frame(&mut receiver, NonZeroU64::new(1).unwrap(), received)
            .await
            .unwrap();
        assert_eq!(
            frame.pixels(),
            (0..192).map(|i| i as u8).collect::<Vec<_>>()
        );
    };
    tokio::join!(send, recv);
}

#[tokio::test]
async fn oversized_control_prefix_is_rejected_before_payload_allocation() {
    let (mut sender, mut receiver) = tokio::io::duplex(8);
    sender.write_u32(u32::MAX).await.unwrap();
    assert!(recv_json::<_, WindowInfo>(&mut receiver).await.is_err());
}

#[tokio::test]
async fn wrong_request_identity_and_resize_are_rejected() {
    for wrong_request in [true, false] {
        let (mut sender, mut receiver) = tokio::io::duplex(1024);
        let frame = if wrong_request {
            Frame::new(8, 6, vec![0; 192]).unwrap()
        } else {
            Frame::new(9, 6, vec![0; 216]).unwrap()
        };
        send_frame(&mut sender, NonZeroU64::new(2).unwrap(), target(), &frame)
            .await
            .unwrap();
        assert!(recv_frame(
            &mut receiver,
            NonZeroU64::new(if wrong_request { 1 } else { 2 }).unwrap(),
            info()
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn truncated_frame_never_becomes_a_displayable_frame() {
    let (mut sender, mut receiver) = tokio::io::duplex(1024);
    send_json(
        &mut sender,
        &serde_json::json!({"request_id":1,"info":info()}),
    )
    .await
    .unwrap();
    sender.write_all(&[0; 8]).await.unwrap();
    drop(sender);
    assert!(
        recv_frame(&mut receiver, NonZeroU64::new(1).unwrap(), info())
            .await
            .is_err()
    );
}
