#![cfg(windows)]

use spectrum_window::identity::{fingerprint, IdentityStore};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "spectrum-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn store(&self, name: &str) -> IdentityStore {
        IdentityStore::new(self.root.join(name))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for role in ["agent", "client"] {
            let directory = self.root.join(role);
            for file in ["identity.bin", "peer.der"] {
                let _ = std::fs::remove_file(directory.join(file));
            }
            let _ = std::fs::remove_dir(directory);
        }
        for file in ["agent.der", "client.der", "invalid.der"] {
            let _ = std::fs::remove_file(self.root.join(file));
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}

#[test]
fn account_protected_identity_round_trips_without_plaintext_key_storage() {
    let fixture = Fixture::new();
    let store = fixture.store("agent");
    let certificate = store.initialize().unwrap();
    let identity = store.load().unwrap();
    assert!(identity.certificate == certificate);
    let encoded = std::fs::read(fixture.root.join("agent/identity.bin")).unwrap();
    let key = identity.key.secret_der();
    assert!(!encoded.windows(key.len()).any(|part| part == key));
    assert!(store.initialize().is_err());
    let exported = store
        .export_certificate(&fixture.root.join("agent.der"))
        .unwrap();
    assert!(exported == certificate);
    assert!(store
        .export_certificate(&fixture.root.join("agent.der"))
        .is_err());
}

#[test]
fn explicit_fingerprint_pairing_and_revocation_are_checked() {
    let fixture = Fixture::new();
    let agent = fixture.store("agent");
    let client = fixture.store("client");
    let agent_cert = agent.initialize().unwrap();
    let client_cert = client.initialize().unwrap();
    agent
        .export_certificate(&fixture.root.join("agent.der"))
        .unwrap();
    client
        .export_certificate(&fixture.root.join("client.der"))
        .unwrap();
    assert!(agent
        .pair(&fixture.root.join("client.der"), &fingerprint(&agent_cert))
        .is_err());
    assert!(agent
        .pair(&fixture.root.join("agent.der"), &fingerprint(&agent_cert))
        .is_err());
    agent
        .pair(&fixture.root.join("client.der"), &fingerprint(&client_cert))
        .unwrap();
    client
        .pair(&fixture.root.join("agent.der"), &fingerprint(&agent_cert))
        .unwrap();
    assert!(agent.peer_is(&client_cert) && client.peer_is(&agent_cert));
    assert!(agent
        .pair(&fixture.root.join("client.der"), &fingerprint(&client_cert))
        .is_err());
    agent.unpair().unwrap();
    agent.unpair().unwrap();
    assert!(!agent.peer_is(&client_cert));
}

#[test]
fn corrupted_and_truncated_identity_files_fail_closed() {
    let fixture = Fixture::new();
    let agent = fixture.store("agent");
    agent.initialize().unwrap();
    let path = fixture.root.join("agent/identity.bin");
    let original = std::fs::read(&path).unwrap();
    for encoded in [vec![0; 16], original[..15].to_vec(), {
        let mut corrupt = original.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        corrupt
    }] {
        std::fs::write(&path, encoded).unwrap();
        assert!(agent.load().is_err());
        assert!(agent.initialize().is_err());
    }
}

#[test]
fn automatic_identity_reuses_existing_keys_and_never_replaces_a_peer() {
    let fixture = Fixture::new();
    let agent = fixture.store("agent");
    let client = fixture.store("client");
    let first = agent.load_or_initialize().unwrap();
    let second = agent.load_or_initialize().unwrap();
    assert!(first.certificate == second.certificate);
    let client_certificate = client.load_or_initialize().unwrap().certificate;
    agent
        .remember_authenticated(client_certificate.clone())
        .unwrap();
    agent
        .remember_authenticated(client_certificate.clone())
        .unwrap();
    assert!(agent.remember_authenticated(first.certificate).is_err());
    let third_key = rcgen::KeyPair::generate().unwrap();
    let third_certificate = rcgen::CertificateParams::new(vec!["spectrum.invalid".into()])
        .unwrap()
        .self_signed(&third_key)
        .unwrap()
        .der()
        .clone();
    assert!(agent.remember_authenticated(third_certificate).is_err());
    assert!(agent.peer_is(&client_certificate));
}
