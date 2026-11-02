use std::{
    num::NonZeroU64,
    time::{Duration, Instant},
};

use anyhow::{ensure, Context, Result};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_GRANT_LIFETIME: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Identifies certificate bytes; callers must authenticate the peer before use.
    pub fn from_certificate(certificate: &CertificateDer<'_>) -> Result<Self> {
        ensure!(
            !certificate.is_empty() && certificate.len() <= crate::transport::MAX_CERTIFICATE_SIZE,
            "invalid peer certificate size"
        );
        Ok(Self(Sha256::digest(certificate.as_ref()).into()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRef {
    pub id: NonZeroU64,
    pub generation: NonZeroU64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    DescribeTarget,
    ReadFrame,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    DescribeTarget { target: TargetRef },
    ReadFrame { target: TargetRef },
}

impl Command {
    fn target(self) -> TargetRef {
        match self {
            Self::DescribeTarget { target } | Self::ReadFrame { target } => target,
        }
    }

    fn capability(self) -> Capability {
        match self {
            Self::DescribeTarget { .. } => Capability::DescribeTarget,
            Self::ReadFrame { .. } => Capability::ReadFrame,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub version: u16,
    pub request_id: NonZeroU64,
    pub command: Command,
}

pub struct Grant {
    peer: PeerId,
    target: TargetRef,
    describe_target: bool,
    read_frame: bool,
    issued_at: Instant,
    expires_at: Instant,
    last_request_id: u64,
    revoked: bool,
}

impl Grant {
    pub fn new(
        peer: PeerId,
        target: TargetRef,
        capabilities: &[Capability],
        now: Instant,
        lifetime: Duration,
    ) -> Result<Self> {
        ensure!(
            !lifetime.is_zero() && lifetime <= MAX_GRANT_LIFETIME,
            "invalid authorization lifetime"
        );
        ensure!(
            !capabilities.is_empty() && capabilities.len() <= 2,
            "invalid authorization capabilities"
        );
        Ok(Self {
            peer,
            target,
            describe_target: capabilities.contains(&Capability::DescribeTarget),
            read_frame: capabilities.contains(&Capability::ReadFrame),
            issued_at: now,
            expires_at: now
                .checked_add(lifetime)
                .context("authorization time overflow")?,
            last_request_id: 0,
            revoked: false,
        })
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn validate_scope(
        &self,
        authenticated_peer: PeerId,
        current_target: Option<TargetRef>,
        now: Instant,
    ) -> Result<()> {
        ensure!(!self.revoked, "authorization was revoked");
        ensure!(
            now >= self.issued_at && now < self.expires_at,
            "authorization is not current"
        );
        ensure!(authenticated_peer == self.peer, "unauthorized peer");
        ensure!(
            current_target == Some(self.target),
            "authorized target is unavailable"
        );
        Ok(())
    }

    /// Check immediately before dispatch against the authenticated peer and current target.
    pub fn authorize(
        &mut self,
        authenticated_peer: PeerId,
        request: &CommandRequest,
        current_target: Option<TargetRef>,
        now: Instant,
    ) -> Result<Command> {
        self.validate_scope(authenticated_peer, current_target, now)?;
        ensure!(
            request.version == PROTOCOL_VERSION,
            "unsupported command version"
        );
        ensure!(
            request.request_id.get() > self.last_request_id,
            "stale command request"
        );
        ensure!(
            current_target == Some(self.target) && request.command.target() == self.target,
            "authorized target is unavailable"
        );
        let allowed = match request.command.capability() {
            Capability::DescribeTarget => self.describe_target,
            Capability::ReadFrame => self.read_frame,
        };
        ensure!(allowed, "command capability was not granted");
        self.last_request_id = request.request_id.get();
        Ok(request.command)
    }
}
