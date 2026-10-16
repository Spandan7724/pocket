//! The per-install pocket CA (SECURITY.md §Network): created on first use under the data
//! dir (dir 0700, key 0600), installed only into guest trust stores, and used to issue leaf
//! certificates for the few domains the proxy terminates.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, date_time_ymd,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct Ca {
    dir: PathBuf,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// `(year, month, day)` of a Unix day number (proleptic Gregorian).
fn civil(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = (yoe + era * 400 + i64::from(m <= 2)) as i32;
    (y, m, d)
}

fn date(days_from_now: i64) -> (i32, u8, u8) {
    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 / 86_400)
        .unwrap_or(0);
    civil(today + days_from_now)
}

macro_rules! validity {
    ($p:expr, $from:expr, $to:expr) => {{
        let (y, m, d) = date($from);
        $p.not_before = date_time_ymd(y, m, d);
        let (y, m, d) = date($to);
        $p.not_after = date_time_ymd(y, m, d);
    }};
}

fn ca_params(id: &str) -> CertificateParams {
    let mut p = CertificateParams::default();
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("pocket CA {id}"));
    dn.push(DnType::OrganizationName, "pocket (local install)");
    p.distinguished_name = dn;
    p
}

fn write_private(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

impl Ca {
    /// Loads the CA from `dir`, creating it on first use. Refuses a key that others can read.
    pub fn load_or_create(dir: &Path) -> io::Result<Ca> {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let (key_p, cert_p, id_p) = (dir.join("ca.key"), dir.join("ca.crt"), dir.join("ca.id"));
        if !key_p.exists() || !cert_p.exists() || !id_p.exists() {
            let id: String = {
                let mut b = [0u8; 4];
                io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut b)?;
                b.iter().map(|x| format!("{x:02x}")).collect()
            };
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(other)?;
            let mut params = ca_params(&id);
            validity!(params, -1, 3650);
            let cert = params.self_signed(&key).map_err(other)?;
            write_private(&key_p, key.serialize_pem().as_bytes(), 0o600)?;
            write_private(&cert_p, cert.pem().as_bytes(), 0o644)?;
            write_private(&id_p, id.as_bytes(), 0o644)?;
        }
        let meta = fs::metadata(&key_p)?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is readable by other users; fix with `chmod 600 {}`",
                    key_p.display(),
                    key_p.display()
                ),
            ));
        }
        let key = KeyPair::from_pem(&fs::read_to_string(&key_p)?).map_err(other)?;
        let id = fs::read_to_string(&id_p)?.trim().to_string();
        let cert_pem = fs::read_to_string(&cert_p)?;
        let cert_der = pem_certs(cert_pem.as_bytes())
            .into_iter()
            .next()
            .ok_or_else(|| other("ca.crt holds no certificate"))?;
        Ok(Ca {
            dir: dir.to_path_buf(),
            cert_pem,
            cert_der,
            issuer: Issuer::new(ca_params(&id), key),
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// TLS server config presenting a leaf for `host` (cached per host; HTTP/1.1 only, so
    /// every intercepted request goes through one parser).
    pub fn server_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        if let Some(c) = self.leaves.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        let mut params = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let mut p = CertificateParams::new(Vec::<String>::new()).map_err(other)?;
                p.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
                p
            }
            Err(_) => CertificateParams::new(vec![host.to_string()]).map_err(other)?,
        };
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        validity!(params, -1, 365);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(other)?;
        let cert = params.signed_by(&key, &self.issuer).map_err(other)?;
        let chain = vec![cert.der().clone(), self.cert_der.clone()];
        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(crate::tls::provider())
            .with_safe_default_protocol_versions()
            .map_err(other)?
            .with_no_client_auth()
            .with_single_cert(chain, pk)
            .map_err(other)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves
            .lock()
            .unwrap()
            .insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

/// Every certificate in a PEM bundle; malformed entries are skipped.
pub fn pem_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem)
        .filter_map(Result::ok)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_377), (2025, 10, 16));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }

    #[test]
    fn created_once_with_private_key_and_reloaded() {
        let d = std::env::temp_dir().join(format!("pocket-ca-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let a = Ca::load_or_create(&d).unwrap();
        let mode = |p: &str| fs::metadata(d.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode("ca.key"), 0o600);
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let b = Ca::load_or_create(&d).unwrap();
        assert_eq!(a.cert_pem(), b.cert_pem());
        b.server_config("api.example.com").unwrap();
        fs::set_permissions(d.join("ca.key"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Ca::load_or_create(&d).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
