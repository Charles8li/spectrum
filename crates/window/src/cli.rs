use crate::identity::{fingerprint, IdentityStore};
use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum IdentityCommand {
    /// Create an identity protected by this Windows account.
    Init,
    /// Export only the public certificate for out-of-band pairing.
    ExportCertificate {
        #[arg(long)]
        output: PathBuf,
    },
    /// Trust a peer after independently checking its certificate fingerprint.
    Pair {
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
    /// Revoke the paired peer. Active window sessions stop.
    Unpair,
}

pub fn identity_command(command: IdentityCommand, store: &IdentityStore) -> Result<()> {
    match command {
        IdentityCommand::Init => {
            let certificate = store.initialize()?;
            println!(
                "Identity created. Certificate SHA-256: {}",
                fingerprint(&certificate)
            );
        }
        IdentityCommand::ExportCertificate { output } => {
            let certificate = store.export_certificate(&output)?;
            println!(
                "Public certificate exported. SHA-256: {}",
                fingerprint(&certificate)
            );
        }
        IdentityCommand::Pair {
            certificate,
            fingerprint,
        } => {
            store.pair(&certificate, &fingerprint)?;
            println!("Peer paired.");
        }
        IdentityCommand::Unpair => {
            store.unpair()?;
            println!("Pairing revoked.");
        }
    }
    Ok(())
}
