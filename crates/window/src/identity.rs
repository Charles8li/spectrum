use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SERVER_NAME: &str = "spectrum.invalid";
const MAGIC: &[u8; 8] = b"SPID0001";
const MAX_IDENTITY: usize = 96 * 1024;
const MAX_CERTIFICATE: usize = 64 * 1024;

pub struct Identity {
    pub certificate: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

#[derive(Clone)]
pub struct IdentityStore {
    directory: PathBuf,
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path).context("cannot open identity or pairing file")?;
    ensure!(
        file.metadata()?.len() <= maximum as u64,
        "identity or pairing file is too large"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "identity or pairing file is too large"
    );
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("output already exists or cannot be created")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn create_identity_directory(directory: &Path) -> Result<()> {
    use std::os::windows::{ffi::OsStrExt, fs::MetadataExt};
    use windows::{
        core::{w, PCWSTR},
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::{
                Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
            },
            Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT},
        },
    };

    if directory.is_dir() {
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
            "identity directory cannot be a link"
        );
        return Ok(());
    }
    let parent = directory
        .parent()
        .context("identity directory has no parent")?;
    fs::create_dir_all(parent)?;
    let mut name: Vec<u16> = directory.as_os_str().encode_wide().collect();
    ensure!(!name.contains(&0), "invalid identity directory");
    name.push(0);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            1,
            &mut descriptor,
            None,
        )?;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    // The descriptor is passed only for creation of this new state directory.
    let result = unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attributes)) };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    result.context("cannot create private identity directory")?;
    Ok(())
}

#[cfg(not(windows))]
fn create_identity_directory(_: &Path) -> Result<()> {
    anyhow::bail!("identity storage requires Windows")
}

pub fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    Sha256::digest(certificate.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn self_check() -> Result<()> {
    let protected = protect(b"synthetic identity protection check")?;
    let plaintext = Zeroizing::new(unprotect(&protected)?);
    ensure!(
        plaintext.as_slice() == b"synthetic identity protection check",
        "identity protection self-check failed"
    );
    Ok(())
}

impl IdentityStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn load_or_initialize(&self) -> Result<Identity> {
        if !self.directory.join("identity.bin").exists() {
            self.initialize()?;
        }
        self.load()
    }

    pub fn initialize(&self) -> Result<CertificateDer<'static>> {
        ensure!(
            !self.directory.join("identity.bin").exists(),
            "identity already exists"
        );
        let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.into()])?;
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let key = rcgen::KeyPair::generate()?;
        let certificate = params.self_signed(&key)?.der().clone();
        let key_bytes = Zeroizing::new(key.serialize_der());
        let protected = protect(&key_bytes)?;
        ensure!(
            protected.len() <= 32 * 1024,
            "protected identity is too large"
        );
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&(protected.len() as u32).to_be_bytes());
        encoded.extend_from_slice(certificate.as_ref());
        encoded.extend_from_slice(&protected);
        create_identity_directory(&self.directory)?;
        write_new(&self.directory.join("identity.bin"), &encoded)?;
        Ok(certificate)
    }

    fn encoded_identity(&self) -> Result<(CertificateDer<'static>, Vec<u8>)> {
        let encoded = read_bounded(&self.directory.join("identity.bin"), MAX_IDENTITY)?;
        ensure!(
            encoded.len() >= 16 && &encoded[..8] == MAGIC,
            "invalid identity file"
        );
        let cert_len = u32::from_be_bytes(encoded[8..12].try_into()?) as usize;
        let key_len = u32::from_be_bytes(encoded[12..16].try_into()?) as usize;
        ensure!(
            cert_len > 0 && cert_len <= MAX_CERTIFICATE && key_len > 0 && key_len <= 32 * 1024,
            "invalid identity lengths"
        );
        ensure!(
            encoded.len() == 16 + cert_len + key_len,
            "truncated or oversized identity file"
        );
        Ok((
            CertificateDer::from(encoded[16..16 + cert_len].to_vec()),
            encoded[16 + cert_len..].to_vec(),
        ))
    }

    pub fn load(&self) -> Result<Identity> {
        let (certificate, protected) = self.encoded_identity()?;
        let plaintext = Zeroizing::new(unprotect(&protected)?);
        ensure!(plaintext.len() <= 16 * 1024, "invalid private key size");
        Ok(Identity {
            certificate,
            key: PrivatePkcs8KeyDer::from(plaintext.to_vec()).into(),
        })
    }

    pub fn export_certificate(&self, output: &Path) -> Result<CertificateDer<'static>> {
        let (certificate, _) = self.encoded_identity()?;
        write_new(output, certificate.as_ref())?;
        Ok(certificate)
    }

    pub fn pair(&self, certificate_path: &Path, expected_fingerprint: &str) -> Result<()> {
        ensure!(
            expected_fingerprint.len() == 64
                && expected_fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
            "expected a 64-digit certificate fingerprint"
        );
        let certificate = CertificateDer::from(read_bounded(certificate_path, MAX_CERTIFICATE)?);
        ensure!(
            fingerprint(&certificate).eq_ignore_ascii_case(expected_fingerprint),
            "peer certificate fingerprint does not match"
        );
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.clone())
            .context("invalid peer certificate")?;
        let (local, _) = self.encoded_identity()?;
        ensure!(certificate != local, "cannot pair an identity with itself");
        write_new(&self.directory.join("peer.der"), certificate.as_ref())
    }

    pub fn remember_authenticated(&self, certificate: CertificateDer<'static>) -> Result<()> {
        ensure!(
            !certificate.is_empty() && certificate.len() <= MAX_CERTIFICATE,
            "invalid peer certificate size"
        );
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.clone())
            .context("invalid peer certificate")?;
        let (local, _) = self.encoded_identity()?;
        ensure!(certificate != local, "cannot pair an identity with itself");
        let path = self.directory.join("peer.der");
        if path.exists() {
            ensure!(
                self.peer()? == certificate,
                "another device is already paired; unpair first"
            );
            return Ok(());
        }
        write_new(&path, certificate.as_ref())
    }

    pub fn peer(&self) -> Result<CertificateDer<'static>> {
        Ok(CertificateDer::from(read_bounded(
            &self.directory.join("peer.der"),
            MAX_CERTIFICATE,
        )?))
    }

    pub fn peer_is(&self, expected: &CertificateDer<'_>) -> bool {
        self.peer()
            .is_ok_and(|certificate| certificate == *expected)
    }

    pub fn unpair(&self) -> Result<()> {
        match fs::remove_file(self.directory.join("peer.der")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("cannot revoke pairing"),
        }
    }
}

#[cfg(windows)]
fn crypt(bytes: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows::{
        core::PCWSTR,
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::Cryptography::{
                CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
            },
        },
    };
    use zeroize::Zeroize;
    ensure!(bytes.len() <= MAX_IDENTITY, "protected data is too large");
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    }
    .context("Windows identity protection failed")?;
    let result = if output.cbData as usize <= MAX_IDENTITY && !output.pbData.is_null() {
        // DPAPI owns this allocation until LocalFree; copy only its reported bytes.
        let data = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
        let bytes = data.to_vec();
        data.zeroize();
        Ok(bytes)
    } else {
        Err(anyhow::anyhow!(
            "invalid Windows identity protection result"
        ))
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
    }
    result
}

#[cfg(windows)]
fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    crypt(bytes, true)
}
#[cfg(windows)]
fn unprotect(bytes: &[u8]) -> Result<Vec<u8>> {
    crypt(bytes, false)
}
#[cfg(not(windows))]
fn protect(_: &[u8]) -> Result<Vec<u8>> {
    anyhow::bail!("identity storage requires Windows")
}
#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> Result<Vec<u8>> {
    anyhow::bail!("identity storage requires Windows")
}
