use bytes::Bytes;
use lanrdp_common::{
    derive_psk, hmac_sha256,
    proto::{control_envelope::Msg, ControlEnvelope, Hello},
    recv_bytes, recv_message, require_live_transport, send_bytes, send_message, verify_hmac_sha256,
    StreamDescriptor, DEFAULT_MAX_FRAME_SIZE,
};

#[tokio::test]
async fn protobuf_frames_preserve_message_boundaries() {
    let hello = ControlEnvelope {
        msg: Some(Msg::Hello(Hello {
            device_id: "synthetic-peer".into(),
            name: "synthetic-client".into(),
            version: "test".into(),
            caps: Vec::new(),
        })),
    };
    let empty = ControlEnvelope { msg: None };
    let mut wire = Vec::new();
    send_message(&mut wire, &hello).await.unwrap();
    send_message(&mut wire, &empty).await.unwrap();
    let mut reader = wire.as_slice();
    assert_eq!(
        recv_message::<_, ControlEnvelope>(&mut reader)
            .await
            .unwrap(),
        hello
    );
    assert_eq!(
        recv_message::<_, ControlEnvelope>(&mut reader)
            .await
            .unwrap(),
        empty
    );
    assert!(reader.is_empty());
}

#[tokio::test]
async fn byte_frames_accept_empty_and_exact_limit() {
    for data in [
        Bytes::new(),
        Bytes::from(vec![0x55; DEFAULT_MAX_FRAME_SIZE]),
    ] {
        let mut wire = Vec::new();
        send_bytes(&mut wire, data.clone()).await.unwrap();
        assert_eq!(recv_bytes(wire.as_slice()).await.unwrap(), data);
    }
}

#[tokio::test]
async fn oversized_sends_do_not_write_a_partial_frame() {
    let mut wire = Vec::new();
    assert!(
        send_bytes(&mut wire, Bytes::from(vec![0; DEFAULT_MAX_FRAME_SIZE + 1]))
            .await
            .is_err()
    );
    assert!(wire.is_empty());
    let message = ControlEnvelope {
        msg: Some(Msg::Hello(Hello {
            name: "x".repeat(DEFAULT_MAX_FRAME_SIZE),
            ..Default::default()
        })),
    };
    assert!(send_message(&mut wire, &message).await.is_err());
    assert!(wire.is_empty());
}

#[tokio::test]
async fn oversized_receives_are_rejected_without_a_payload() {
    for length in [(DEFAULT_MAX_FRAME_SIZE + 1) as u32, u32::MAX] {
        let header = length.to_be_bytes();
        let error = recv_bytes(header.as_slice()).await.unwrap_err();
        assert_eq!(error.to_string(), "frame too large");
    }
}

#[tokio::test]
async fn truncated_and_malformed_frames_fail() {
    for wire in [&[0, 0][..], &[0, 0, 0, 2, 1][..]] {
        assert!(recv_bytes(wire).await.is_err());
    }
    assert!(recv_message::<_, ControlEnvelope>(&[0, 0, 0, 1, 0xff][..])
        .await
        .is_err());
}

#[tokio::test]
async fn stalled_peer_has_a_receive_deadline() {
    let (_writer, reader) = tokio::io::duplex(1);
    let error = recv_bytes(reader).await.unwrap_err();
    assert_eq!(error.to_string(), "frame receive timed out");
}

#[tokio::test]
async fn stream_headers_round_trip() {
    for descriptor in [
        StreamDescriptor::control(),
        StreamDescriptor::video(),
        StreamDescriptor::input(),
        StreamDescriptor::pty(7),
        StreamDescriptor::file(9),
    ] {
        let mut wire = Vec::new();
        descriptor.write_header(&mut wire).await.unwrap();
        let decoded = StreamDescriptor::read_header(wire.as_slice())
            .await
            .unwrap();
        assert_eq!(
            (decoded.ty, decoded.extra),
            (descriptor.ty, descriptor.extra)
        );
    }
}

#[tokio::test]
async fn unknown_streams_and_invalid_identifiers_fail() {
    for wire in [&[255][..], &[1, 0, 0, 0, 0][..], &[4, 0, 0][..]] {
        assert!(StreamDescriptor::read_header(wire).await.is_err());
    }
    for descriptor in [
        StreamDescriptor::pty(0),
        StreamDescriptor::file(0),
        StreamDescriptor {
            ty: 0,
            extra: Some(1),
        },
        StreamDescriptor {
            ty: 255,
            extra: None,
        },
    ] {
        let mut wire = Vec::new();
        assert!(descriptor.write_header(&mut wire).await.is_err());
        assert!(wire.is_empty());
    }
}

#[test]
fn proofs_reject_wrong_identity_changed_challenge_and_wrong_length() {
    let key = derive_psk("synthetic-pairing-code", "synthetic-peer-a");
    let other = derive_psk("synthetic-pairing-code", "synthetic-peer-b");
    let challenge = [0x55; 32];
    let proof = hmac_sha256(&key, &challenge);
    assert!(verify_hmac_sha256(&key, &challenge, &proof).is_ok());
    assert!(verify_hmac_sha256(&other, &challenge, &proof).is_err());
    assert!(verify_hmac_sha256(&key, &[0x56; 32], &proof).is_err());
    assert!(verify_hmac_sha256(&key, &challenge, &proof[..31]).is_err());
}

#[test]
fn unverified_live_transport_is_refused() {
    assert!(require_live_transport().is_err());
}
