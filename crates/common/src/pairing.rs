use std::ptr::NonNull;

use anyhow::{ensure, Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

const CODE_DIGITS: usize = 6;
const MESSAGE_LEN: usize = 32;
const KEY_LEN: usize = 64;
const PROOF_LEN: usize = 32;
const VIEWER_NAME: &[u8] = b"spectrum pairing viewer v1";
const SHARER_NAME: &[u8] = b"spectrum pairing sharer v1";
const PROOF_LABEL: &[u8] = b"spectrum pairing confirmation v1\0";

type ConfirmationMac = Hmac<Sha256>;

pub struct PairCode(Zeroizing<[u8; CODE_DIGITS]>);

impl PairCode {
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        let limit = (u32::MAX as u64 + 1) / 1_000_000 * 1_000_000;
        for _ in 0..128 {
            let mut bytes = Zeroizing::new([0u8; 4]);
            rng.try_fill_bytes(bytes.as_mut())
                .context("secure random source is unavailable")?;
            let number = Zeroizing::new(u32::from_be_bytes(*bytes) as u64);
            if *number < limit {
                let mut value = Zeroizing::new(*number % 1_000_000);
                let mut digits = Zeroizing::new([b'0'; CODE_DIGITS]);
                for digit in digits.iter_mut().rev() {
                    *digit += (*value % 10) as u8;
                    *value /= 10;
                }
                return Ok(Self(digits));
            }
        }
        anyhow::bail!("secure random source could not generate a code")
    }

    pub fn parse(input: &str) -> Result<Self> {
        let bytes = input.as_bytes();
        ensure!(
            bytes.len() == CODE_DIGITS && bytes.iter().all(u8::is_ascii_digit),
            "enter the six-digit pairing code"
        );
        let mut digits = Zeroizing::new([0u8; CODE_DIGITS]);
        digits.copy_from_slice(bytes);
        Ok(Self(digits))
    }

    pub fn as_str(&self) -> &str {
        // Codes are constructed only from ASCII digits.
        std::str::from_utf8(self.0.as_ref()).expect("valid pairing code")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PairRole {
    Viewer,
    Sharer,
}

impl PairRole {
    fn peer(self) -> Self {
        match self {
            Self::Viewer => Self::Sharer,
            Self::Sharer => Self::Viewer,
        }
    }

    fn label(self) -> u8 {
        match self {
            Self::Viewer => 1,
            Self::Sharer => 2,
        }
    }
}

struct SpakeContext(NonNull<aws_lc_sys::SPAKE2_CTX>);

impl Drop for SpakeContext {
    fn drop(&mut self) {
        // The context was allocated by AWS-LC and is freed exactly once.
        unsafe { aws_lc_sys::SPAKE2_CTX_free(self.0.as_ptr()) }
    }
}

pub struct PairingStart {
    context: SpakeContext,
    role: PairRole,
}

impl PairingStart {
    pub fn start(role: PairRole, code: &PairCode) -> Result<(Self, [u8; MESSAGE_LEN])> {
        let (native_role, own_name, peer_name) = match role {
            PairRole::Viewer => (
                aws_lc_sys::spake2_role_t_spake2_role_alice,
                VIEWER_NAME,
                SHARER_NAME,
            ),
            PairRole::Sharer => (
                aws_lc_sys::spake2_role_t_spake2_role_bob,
                SHARER_NAME,
                VIEWER_NAME,
            ),
        };
        // AWS-LC copies both static role names into the new context.
        let pointer = unsafe {
            aws_lc_sys::SPAKE2_CTX_new(
                native_role,
                own_name.as_ptr(),
                own_name.len(),
                peer_name.as_ptr(),
                peer_name.len(),
            )
        };
        let context = SpakeContext(NonNull::new(pointer).context("pairing initialization failed")?);
        let mut message = [0u8; MESSAGE_LEN];
        let mut written = 0usize;
        // Output and code buffers remain valid for this single-use operation.
        let result = unsafe {
            aws_lc_sys::SPAKE2_generate_msg(
                context.0.as_ptr(),
                message.as_mut_ptr(),
                &mut written,
                message.len(),
                code.0.as_ptr(),
                code.0.len(),
            )
        };
        ensure!(
            result == 1 && written == MESSAGE_LEN,
            "pairing initialization failed"
        );
        Ok((Self { context, role }, message))
    }

    pub fn finish(self, peer_message: &[u8]) -> Result<PairingKey> {
        ensure!(peer_message.len() == MESSAGE_LEN, "invalid pairing message");
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        let mut written = 0usize;
        // The context is consumed after one peer message; AWS-LC validates it.
        let result = unsafe {
            aws_lc_sys::SPAKE2_process_msg(
                self.context.0.as_ptr(),
                key.as_mut_ptr(),
                &mut written,
                key.len(),
                peer_message.as_ptr(),
                peer_message.len(),
            )
        };
        ensure!(result == 1 && written == KEY_LEN, "invalid pairing message");
        Ok(PairingKey {
            role: self.role,
            key,
        })
    }
}

pub struct PairingKey {
    role: PairRole,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl PairingKey {
    fn mac(&self, role: PairRole, channel_binding: &[u8; 32]) -> ConfirmationMac {
        let mut mac = ConfirmationMac::new_from_slice(self.key.as_ref()).expect("valid HMAC key");
        mac.update(PROOF_LABEL);
        mac.update(&[role.label()]);
        mac.update(channel_binding);
        mac
    }

    pub fn confirmation(&self, channel_binding: &[u8; 32]) -> [u8; PROOF_LEN] {
        self.mac(self.role, channel_binding)
            .finalize()
            .into_bytes()
            .into()
    }

    pub fn verify_peer(self, channel_binding: &[u8; 32], proof: &[u8]) -> Result<ConfirmedPair> {
        ensure!(proof.len() == PROOF_LEN, "pairing confirmation failed");
        self.mac(self.role.peer(), channel_binding)
            .verify_slice(proof)
            .map_err(|_| anyhow::anyhow!("pairing confirmation failed"))?;
        Ok(ConfirmedPair { _private: () })
    }
}

pub struct ConfirmedPair {
    _private: (),
}
