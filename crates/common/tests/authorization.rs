use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

use lanrdp_common::authorization::{
    Capability, Command, CommandRequest, Grant, PeerId, TargetRef, MAX_GRANT_LIFETIME,
    PROTOCOL_VERSION,
};
use rustls::pki_types::CertificateDer;

fn peer(value: u8) -> PeerId {
    PeerId::from_certificate(&CertificateDer::from(vec![value; 32])).unwrap()
}

fn target(id: u64, generation: u64) -> TargetRef {
    TargetRef {
        id: NonZeroU64::new(id).unwrap(),
        generation: NonZeroU64::new(generation).unwrap(),
    }
}

fn request(request_id: u64, command: Command) -> CommandRequest {
    CommandRequest {
        version: PROTOCOL_VERSION,
        request_id: NonZeroU64::new(request_id).unwrap(),
        command,
    }
}

fn grant(now: Instant) -> Grant {
    Grant::new(
        peer(1),
        target(11, 7),
        &[Capability::ReadFrame],
        now,
        Duration::from_secs(30),
    )
    .unwrap()
}

#[test]
fn valid_command_is_bound_to_peer_target_and_capability() {
    let now = Instant::now();
    let command = Command::ReadFrame {
        target: target(11, 7),
    };
    assert!(
        grant(now)
            .authorize(peer(1), &request(1, command), Some(target(11, 7)), now)
            .unwrap()
            == command
    );
}

#[test]
fn wrong_peer_is_rejected_without_consuming_the_request() {
    let now = Instant::now();
    let mut grant = grant(now);
    let request = request(
        1,
        Command::ReadFrame {
            target: target(11, 7),
        },
    );
    assert!(grant
        .authorize(peer(2), &request, Some(target(11, 7)), now)
        .is_err());
    assert!(grant
        .authorize(peer(1), &request, Some(target(11, 7)), now)
        .is_ok());
}

#[test]
fn missing_changed_and_reused_targets_are_rejected() {
    let now = Instant::now();
    let mut grant = grant(now);
    let valid_request = request(
        1,
        Command::ReadFrame {
            target: target(11, 7),
        },
    );
    for current in [None, Some(target(12, 7)), Some(target(11, 8))] {
        assert!(grant
            .authorize(peer(1), &valid_request, current, now)
            .is_err());
    }
    let wrong_target = request(
        1,
        Command::ReadFrame {
            target: target(12, 7),
        },
    );
    assert!(grant
        .authorize(peer(1), &wrong_target, Some(target(11, 7)), now)
        .is_err());
}

#[test]
fn expiry_boundary_and_time_before_issue_are_rejected() {
    let now = Instant::now();
    let mut grant = grant(now);
    let request = request(
        1,
        Command::ReadFrame {
            target: target(11, 7),
        },
    );
    for time in [now - Duration::from_secs(1), now + Duration::from_secs(30)] {
        assert!(grant
            .authorize(peer(1), &request, Some(target(11, 7)), time)
            .is_err());
    }
}

#[test]
fn revocation_is_permanent_for_the_grant() {
    let now = Instant::now();
    let mut grant = grant(now);
    grant.revoke();
    let request = request(
        1,
        Command::ReadFrame {
            target: target(11, 7),
        },
    );
    assert!(grant
        .authorize(peer(1), &request, Some(target(11, 7)), now)
        .is_err());
}

#[test]
fn missing_capability_and_unsupported_version_are_rejected() {
    let now = Instant::now();
    let mut grant = grant(now);
    let describe = request(
        1,
        Command::DescribeTarget {
            target: target(11, 7),
        },
    );
    assert!(grant
        .authorize(peer(1), &describe, Some(target(11, 7)), now)
        .is_err());
    let mut wrong_version = request(
        1,
        Command::ReadFrame {
            target: target(11, 7),
        },
    );
    wrong_version.version = PROTOCOL_VERSION + 1;
    assert!(grant
        .authorize(peer(1), &wrong_version, Some(target(11, 7)), now)
        .is_err());
}

#[test]
fn duplicate_or_older_request_ids_are_rejected() {
    let now = Instant::now();
    let mut grant = grant(now);
    let command = Command::ReadFrame {
        target: target(11, 7),
    };
    assert!(grant
        .authorize(peer(1), &request(2, command), Some(target(11, 7)), now)
        .is_ok());
    for id in [1, 2] {
        assert!(grant
            .authorize(peer(1), &request(id, command), Some(target(11, 7)), now)
            .is_err());
    }
}

#[test]
fn invalid_lifetime_or_capabilities_are_rejected() {
    let now = Instant::now();
    for lifetime in [Duration::ZERO, MAX_GRANT_LIFETIME + Duration::from_secs(1)] {
        assert!(Grant::new(
            peer(1),
            target(11, 7),
            &[Capability::ReadFrame],
            now,
            lifetime
        )
        .is_err());
    }
    assert!(Grant::new(peer(1), target(11, 7), &[], now, Duration::from_secs(1)).is_err());
}

#[test]
fn unknown_fields_commands_and_zero_identifiers_are_rejected() {
    let valid = serde_json::to_string(&request(
        1,
        Command::ReadFrame {
            target: target(11, 7),
        },
    ))
    .unwrap();
    for invalid in [
        valid.replacen("{", "{\"extra\":true,", 1),
        valid.replace("read_frame", "shell"),
        valid.replace("\"request_id\":1", "\"request_id\":0"),
        valid.replace("\"generation\":7", "\"generation\":0"),
        valid.replace("\"id\":11", "\"id\":0"),
    ] {
        assert!(serde_json::from_str::<CommandRequest>(&invalid).is_err());
    }
}
