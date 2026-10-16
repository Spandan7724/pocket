//! TLS plumbing for intercepted connections: one crypto provider, the host's trust store for
//! verifying real upstreams, and the client config used to re-encrypt.

use std::sync::{Arc, OnceLock};

use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::{RootCertStore, ServerConfig};

pub fn provider() -> Arc<CryptoProvider> {
    static P: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
];

/// Roots for upstream verification: `SSL_CERT_FILE` if set (as OpenSSL does), else the
/// distribution bundle, else the Mozilla roots compiled in.
pub fn upstream_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let files: Vec<String> = match std::env::var("SSL_CERT_FILE") {
        Ok(f) if !f.is_empty() => vec![f],
        _ => SYSTEM_BUNDLES.iter().map(|s| s.to_string()).collect(),
    };
    for f in files {
        if let Ok(pem) = std::fs::read(&f) {
            let (added, _) = roots.add_parsable_certificates(crate::ca::pem_certs(&pem));
            if added > 0 {
                return roots;
            }
        }
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

pub fn client_config(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut c = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(c)
}

/// A server config for tests and fakes: `chain` + PKCS#8 `key`.
pub fn server_config(
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let mut c = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}
