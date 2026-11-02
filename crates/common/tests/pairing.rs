use lanrdp_common::pairing::{PairCode, PairRole, PairingStart};

fn exchange(
    viewer_code: &str,
    sharer_code: &str,
) -> (
    lanrdp_common::pairing::PairingKey,
    lanrdp_common::pairing::PairingKey,
) {
    let viewer_code = PairCode::parse(viewer_code).unwrap();
    let sharer_code = PairCode::parse(sharer_code).unwrap();
    let (viewer, viewer_message) = PairingStart::start(PairRole::Viewer, &viewer_code).unwrap();
    let (sharer, sharer_message) = PairingStart::start(PairRole::Sharer, &sharer_code).unwrap();
    (
        viewer.finish(&sharer_message).unwrap(),
        sharer.finish(&viewer_message).unwrap(),
    )
}

#[test]
fn matching_codes_authenticate_both_directions_on_the_same_channel() {
    let (viewer, sharer) = exchange("007351", "007351");
    let binding = [4u8; 32];
    let viewer_proof = viewer.confirmation(&binding);
    let sharer_proof = sharer.confirmation(&binding);
    assert!(viewer.verify_peer(&binding, &sharer_proof).is_ok());
    assert!(sharer.verify_peer(&binding, &viewer_proof).is_ok());
}

#[test]
fn mismatched_codes_never_authenticate() {
    let (viewer, sharer) = exchange("007351", "007352");
    let binding = [4u8; 32];
    let viewer_proof = viewer.confirmation(&binding);
    let sharer_proof = sharer.confirmation(&binding);
    assert!(viewer.verify_peer(&binding, &sharer_proof).is_err());
    assert!(sharer.verify_peer(&binding, &viewer_proof).is_err());
}

#[test]
fn mismatched_channels_and_reflected_proofs_are_rejected() {
    let (viewer, sharer) = exchange("007351", "007351");
    let binding = [4u8; 32];
    let viewer_proof = viewer.confirmation(&binding);
    let sharer_proof = sharer.confirmation(&binding);
    assert!(viewer.verify_peer(&[5u8; 32], &sharer_proof).is_err());
    assert!(sharer.verify_peer(&binding, &sharer_proof).is_err());
    let (viewer, _) = exchange("007351", "007351");
    assert!(viewer.verify_peer(&binding, &viewer_proof).is_err());
}

#[test]
fn proofs_from_another_exchange_cannot_be_replayed() {
    let (viewer, sharer) = exchange("007351", "007351");
    let binding = [4u8; 32];
    let stale_proof = sharer.confirmation(&binding);
    let (new_viewer, _) = exchange("007351", "007351");
    assert!(new_viewer.verify_peer(&binding, &stale_proof).is_err());
    drop(viewer);
}

#[test]
fn malformed_codes_and_messages_are_rejected() {
    for input in [
        "",
        "12345",
        "1234567",
        "12 456",
        "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}",
    ] {
        assert!(PairCode::parse(input).is_err());
    }
    let code = PairCode::parse("007351").unwrap();
    let (viewer, _) = PairingStart::start(PairRole::Viewer, &code).unwrap();
    assert!(viewer.finish(&[0u8; 31]).is_err());
}

#[test]
fn generated_codes_have_six_ascii_digits() {
    for _ in 0..32 {
        let code = PairCode::generate().unwrap();
        assert_eq!(code.as_str().len(), 6);
        assert!(code.as_str().bytes().all(|byte| byte.is_ascii_digit()));
    }
}
