//! The root certificate authority and the leaf certificates the proxy presents.
//!
//! The CA is generated once by the app and stored as PEM. Leaves are always issued from the
//! stored certificate (rcgen's `x509-parser` feature reads its name and key identifier), so
//! a later release that changes how CAs are generated cannot break leaves for a CA that is
//! already installed on the phone.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use lru::LruCache;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

use crate::MitmError;

/// The CA certificate is valid for this many days, starting one day before it was made.
pub const CA_VALIDITY_DAYS: i64 = 3650;
/// Leaves are valid for this many days, starting one day before they were issued.
pub const LEAF_VALIDITY_DAYS: i64 = 30;
/// Leaves kept in memory, least recently used first out.
pub const LEAF_CACHE_SIZE: usize = 128;
/// A cached leaf older than this is issued again, so a long-running tunnel never serves a
/// leaf close to its end date.
pub const LEAF_REISSUE_SECS: u64 = 7 * 24 * 60 * 60;
/// A cached leaf issued up to this far in the future is still served. Leaves start one day
/// before they were issued, so a small clock correction backwards keeps them valid, while a
/// leaf issued when the clock was ahead by more than this is issued again: its start date
/// could be in the future, and every client would reject it.
const LEAF_CLOCK_TOLERANCE_SECS: u64 = 60 * 60;

struct CachedLeaf {
    key: Arc<CertifiedKey>,
    issued_at: u64,
}

/// An ECDSA P-256 root CA plus a cache of the leaves it issued. `Send + Sync`.
pub struct CertAuthority {
    cert_pem: String,
    key_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    provider: Arc<CryptoProvider>,
    leaves: Mutex<LruCache<String, CachedLeaf>>,
}

impl CertAuthority {
    /// A new root: ECDSA P-256, subject `CN=<common_name>, O=Tollgate`, path length 0,
    /// valid from one day ago for [`CA_VALIDITY_DAYS`].
    pub fn generate(common_name: &str) -> Result<CertAuthority, MitmError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        name.push(DnType::OrganizationName, "Tollgate");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = params.not_before + Duration::days(CA_VALIDITY_DAYS);
        let cert = params.self_signed(&key)?;
        CertAuthority::from_pem(&cert.pem(), &key.serialize_pem())
    }

    /// Loads a stored CA. Fails if either PEM does not parse, if the certificate is not a
    /// CA, or if the key does not belong to the certificate.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<CertAuthority, MitmError> {
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| MitmError::InvalidCertificate(e.to_string()))?;
        let key = KeyPair::from_pem(key_pem).map_err(|e| MitmError::InvalidKey(e.to_string()))?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der)
            .map_err(|e| MitmError::InvalidCertificate(e.to_string()))?;
        if !parsed.is_ca() {
            return Err(MitmError::NotCa);
        }
        if parsed.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
            return Err(MitmError::KeyMismatch);
        }
        let issuer = Issuer::from_ca_cert_der(&cert_der, key)?;
        let cache_size = NonZeroUsize::new(LEAF_CACHE_SIZE).expect("cache size is not zero");
        Ok(CertAuthority {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            cert_der,
            issuer,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            leaves: Mutex::new(LruCache::new(cache_size)),
        })
    }

    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    pub fn key_pem(&self) -> String {
        self.key_pem.clone()
    }

    pub fn cert_der(&self) -> Vec<u8> {
        self.cert_der.to_vec()
    }

    /// The leaf for `host`, from the cache or newly issued.
    ///
    /// `host` is a DNS name or an IP address (IPv6 with or without brackets); it is
    /// lowercased and a trailing dot is removed. The leaf is ECDSA P-256 with an empty
    /// subject, the host as its only subject alternative name, the `serverAuth` extended
    /// key usage and an authority key identifier matching the CA.
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, MitmError> {
        self.leaf_at(host, tollgate_common::clock::unix_secs())
    }

    /// [`CertAuthority::leaf`] with `now` (wall-clock unix seconds) passed in.
    pub(crate) fn leaf_at(&self, host: &str, now: u64) -> Result<Arc<CertifiedKey>, MitmError> {
        let name = normalize_host(host);
        if name.is_empty() {
            return Err(MitmError::InvalidHost(host.to_string()));
        }
        if let Some(cached) = self.cache().get(&name)
            && reusable(cached.issued_at, now)
        {
            return Ok(cached.key.clone());
        }
        let key = Arc::new(self.issue(&name, now)?);
        self.cache().put(
            name,
            CachedLeaf {
                key: key.clone(),
                issued_at: now,
            },
        );
        Ok(key)
    }

    /// Number of leaves in the cache.
    pub fn cached_leaves(&self) -> usize {
        self.cache().len()
    }

    fn issue(&self, name: &str, now: u64) -> Result<CertifiedKey, MitmError> {
        let issued = i64::try_from(now)
            .ok()
            .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
            .unwrap_or_else(OffsetDateTime::now_utc);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        // new() stores the name as a DNS name, or as an IP address when it parses as one.
        let mut params = CertificateParams::new(vec![name.to_string()])?;
        // An empty subject: the name lives only in the SAN, which rcgen then marks critical.
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = issued - Duration::days(1);
        params.not_after = params.not_before + Duration::days(LEAF_VALIDITY_DAYS);
        let cert = params.signed_by(&key, &self.issuer)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        CertifiedKey::from_der(vec![cert.der().clone()], key_der, &self.provider)
            .map_err(|e| MitmError::Tls(e.to_string()))
    }

    fn cache(&self) -> MutexGuard<'_, LruCache<String, CachedLeaf>> {
        self.leaves.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether a leaf issued at `issued_at` can still be served at `now`: it is younger than
/// [`LEAF_REISSUE_SECS`] and was not issued while the wall clock was ahead.
fn reusable(issued_at: u64, now: u64) -> bool {
    issued_at <= now.saturating_add(LEAF_CLOCK_TOLERANCE_SECS)
        && now.saturating_sub(issued_at) < LEAF_REISSUE_SECS
}

/// Shows the CA's name, never its key.
impl std::fmt::Debug for CertAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertAuthority")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

/// Lowercase, without a trailing dot or IPv6 brackets.
fn normalize_host(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    fn not_before(key: &CertifiedKey) -> i64 {
        let (_, cert) = x509_parser::parse_x509_certificate(&key.cert[0]).expect("leaf parses");
        cert.validity().not_before.timestamp()
    }

    #[test]
    fn a_leaf_issued_while_the_clock_was_ahead_is_issued_again() {
        let ca = CertAuthority::generate("Test CA").expect("ca");
        let now = tollgate_common::clock::unix_secs();
        let ahead = ca.leaf_at("example.com", now + 2 * DAY).expect("leaf");
        assert!(not_before(&ahead) > now as i64);
        let back = ca.leaf_at("example.com", now).expect("leaf");
        assert!(!Arc::ptr_eq(&ahead, &back));
        assert!(not_before(&back) <= now as i64);
        // The new leaf replaced the cached one.
        let again = ca.leaf_at("example.com", now).expect("leaf");
        assert!(Arc::ptr_eq(&back, &again));
    }

    #[test]
    fn a_leaf_is_reused_within_the_reissue_window_and_small_corrections() {
        let ca = CertAuthority::generate("Test CA").expect("ca");
        let now = tollgate_common::clock::unix_secs();
        let first = ca.leaf_at("example.com", now).expect("leaf");
        assert_eq!(not_before(&first), (now - DAY) as i64);
        let later = ca.leaf_at("example.com", now + DAY).expect("leaf");
        assert!(Arc::ptr_eq(&first, &later));
        let corrected = ca
            .leaf_at("example.com", now - LEAF_CLOCK_TOLERANCE_SECS)
            .expect("leaf");
        assert!(Arc::ptr_eq(&first, &corrected));
        let old = ca
            .leaf_at("example.com", now + LEAF_REISSUE_SECS)
            .expect("leaf");
        assert!(!Arc::ptr_eq(&first, &old));
    }
}
