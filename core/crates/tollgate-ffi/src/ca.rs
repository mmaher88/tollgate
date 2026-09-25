//! The certificate authority files in the data directory.
//!
//! `ca.pem` holds the root certificate and `ca.key` its private key, both PEM and both
//! readable only by the owner (mode 0600). The Swift side additionally applies the file
//! protection class `completeUntilFirstUserAuthentication` to the App Group directory.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use tollgate_mitm::CertAuthority;

use crate::error::{TollgateError, catch_panic};
use crate::sha256_hex;

/// Root certificate, PEM.
pub const CA_CERT_FILE: &str = "ca.pem";
/// Root private key, PEM (PKCS#8).
pub const CA_KEY_FILE: &str = "ca.key";
/// Subject common name of a generated root.
pub const CA_COMMON_NAME: &str = "Tollgate Root CA";
/// Name iOS shows for the configuration profile and the certificate.
pub const PROFILE_DISPLAY_NAME: &str = "Tollgate Root CA";
/// Reverse-DNS identifier of the configuration profile.
pub const PROFILE_IDENTIFIER: &str = "dev.tollgate.ca";

/// The root certificate the app asks the user to trust.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CaInfo {
    pub cert_pem: String,
    /// SHA-256 of the DER certificate, lowercase hex without separators.
    pub sha256_fingerprint: String,
    /// True when this call generated the CA, false when it was already stored.
    pub created: bool,
}

fn ca_error(e: impl std::fmt::Display) -> TollgateError {
    TollgateError::Ca {
        message: e.to_string(),
    }
}

fn info(ca: &CertAuthority, created: bool) -> CaInfo {
    CaInfo {
        cert_pem: ca.cert_pem(),
        sha256_fingerprint: sha256_hex(ca.cert_der()),
        created,
    }
}

fn read_optional(path: &Path) -> Result<Option<String>, TollgateError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::io(format!("{}: {e}", path.display()))),
    }
}

/// Loads the CA from `dir`. `Ok(None)` unless both files exist; an error when both exist
/// but do not form a valid CA.
pub fn load_ca(dir: &Path) -> Result<Option<CertAuthority>, TollgateError> {
    let cert = read_optional(&dir.join(CA_CERT_FILE))?;
    let key = read_optional(&dir.join(CA_KEY_FILE))?;
    match (cert, key) {
        (Some(cert), Some(key)) => CertAuthority::from_pem(&cert, &key)
            .map(Some)
            .map_err(ca_error),
        _ => Ok(None),
    }
}

/// Writes `text` to `path` through a temporary file created with mode 0600, then renames
/// it into place, so the file is never readable by others and never half written.
pub(crate) fn write_private(path: &Path, text: &str) -> Result<(), TollgateError> {
    let name = path
        .file_name()
        .map_or_else(|| "file".into(), |name| name.to_string_lossy().into_owned());
    let tmp: PathBuf = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = options
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        TollgateError::io(format!("{}: {e}", path.display()))
    })
}

fn generate_in(dir: &Path) -> Result<CaInfo, TollgateError> {
    if let Some(ca) = load_ca(dir)? {
        return Ok(info(&ca, false));
    }
    fs::create_dir_all(dir).map_err(|e| TollgateError::io(format!("{}: {e}", dir.display())))?;
    let ca = CertAuthority::generate(CA_COMMON_NAME).map_err(ca_error)?;
    // The key first: a certificate on disk always has its key next to it.
    write_private(&dir.join(CA_KEY_FILE), &ca.key_pem())?;
    write_private(&dir.join(CA_CERT_FILE), &ca.cert_pem())?;
    log::info!("generated a new root CA in {}", dir.display());
    Ok(info(&ca, true))
}

/// Returns the CA stored in `data_dir`, generating and storing one first when `ca.pem` or
/// `ca.key` is missing. A stored pair that is not a valid CA is an error and is left
/// untouched, so the user's installed root is never replaced silently.
#[uniffi::export]
pub fn generate_ca(data_dir: String) -> Result<CaInfo, TollgateError> {
    catch_panic(|| generate_in(Path::new(&data_dir)))
}

/// The iOS configuration profile (`.mobileconfig`) that installs the stored root. Fails
/// when no CA is stored.
#[uniffi::export]
pub fn ca_mobileconfig(data_dir: String) -> Result<Vec<u8>, TollgateError> {
    catch_panic(|| {
        let ca = load_ca(Path::new(&data_dir))?
            .ok_or_else(|| ca_error("no CA in the data directory; call generate_ca first"))?;
        Ok(ca.mobileconfig(PROFILE_DISPLAY_NAME, PROFILE_IDENTIFIER))
    })
}
