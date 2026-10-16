//! Local fake HTTPS services for tests that would otherwise need real ones: one listener on
//! loopback, a test CA of its own, a certificate for every name it plays, and a record of
//! every request it received (heads and bodies, never echoed back). pocketd reaches it
//! through `POCKETD_TEST_UPSTREAM` (debug builds) and trusts it through `SSL_CERT_FILE`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[derive(Debug, Clone)]
pub struct Req {
    pub sni: String,
    pub method: String,
    pub path: String,
    pub head: String,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    }
}

pub struct Resp {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn text(status: u16, body: &str) -> Resp {
        Resp {
            status,
            content_type: "text/plain".into(),
            headers: vec![],
            body: body.as_bytes().to_vec(),
        }
    }
}

pub type Handler = Arc<dyn Fn(&Req) -> Resp + Send + Sync>;

pub struct Fake {
    pub addr: SocketAddr,
    pub ca_pem: String,
    pub ca_file: PathBuf,
    pub names: Vec<String>,
    pub seen: Arc<Mutex<Vec<Req>>>,
}

impl Fake {
    /// `POCKETD_TEST_UPSTREAM` value routing `names` here.
    pub fn upstream_env(&self) -> String {
        format!("{}={}", self.names.join(","), self.addr)
    }

    pub fn requests(&self) -> Vec<Req> {
        self.seen.lock().unwrap().clone()
    }
}

fn read_req(r: &mut BufReader<impl Read>, sni: &str) -> Option<Req> {
    let mut head = String::new();
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).ok()? == 0 {
            return None;
        }
        if l == "\r\n" {
            break;
        }
        head.push_str(&l);
    }
    let mut first = head.lines().next()?.split(' ');
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let mut req = Req {
        sni: sni.to_string(),
        method,
        path,
        head,
        body: vec![],
    };
    if let Some(n) = req.header("content-length") {
        let mut b = vec![0u8; n.parse().ok()?];
        r.read_exact(&mut b).ok()?;
        req.body = b;
    } else if req
        .header("transfer-encoding")
        .is_some_and(|t| t.contains("chunked"))
    {
        loop {
            let mut l = String::new();
            r.read_line(&mut l).ok()?;
            let n = usize::from_str_radix(l.trim().split(';').next()?, 16).ok()?;
            let mut b = vec![0u8; n + 2];
            r.read_exact(&mut b).ok()?;
            if n == 0 {
                break;
            }
            req.body.extend_from_slice(&b[..n]);
        }
    }
    Some(req)
}

/// Starts the fake on `127.0.0.1:0`; `dir` receives the CA bundle file.
pub fn start(names: &[&str], dir: &Path, handler: Handler) -> Fake {
    let mut cap = CertificateParams::new(Vec::<String>::new()).unwrap();
    cap.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cap.distinguished_name
        .push(DnType::CommonName, "pocket test fake upstream CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = cap.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(cap, ca_key);
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone(), ca_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap(),
    );
    std::fs::create_dir_all(dir).unwrap();
    let ca_file = dir.join("fake-ca.pem");
    std::fs::write(&ca_file, ca_cert.pem()).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Req>>> = Default::default();
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for tcp in l.incoming().flatten() {
            let (cfg, seen, handler) = (cfg.clone(), s2.clone(), handler.clone());
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                while tls.conn.is_handshaking() {
                    if tls.conn.complete_io(&mut tls.sock).is_err() {
                        return;
                    }
                }
                let sni = tls.conn.server_name().unwrap_or("").to_string();
                let mut r = BufReader::new(tls);
                while let Some(req) = read_req(&mut r, &sni) {
                    let resp = handler(&req);
                    seen.lock().unwrap().push(req);
                    let mut out = format!(
                        "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
                        resp.status,
                        resp.content_type,
                        resp.body.len()
                    );
                    for (k, v) in &resp.headers {
                        out.push_str(&format!("{k}: {v}\r\n"));
                    }
                    out.push_str("\r\n");
                    let w = r.get_mut();
                    if w.write_all(out.as_bytes()).is_err()
                        || w.write_all(&resp.body).is_err()
                        || w.flush().is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Fake {
        addr,
        ca_pem: ca_cert.pem(),
        ca_file,
        names: names.iter().map(|s| s.to_string()).collect(),
        seen,
    }
}
