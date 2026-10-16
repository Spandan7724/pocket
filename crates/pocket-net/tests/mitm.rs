//! Selective TLS interception against a local fake HTTPS upstream with its own CA: bound
//! destinations are terminated (pocket-CA leaf, credentials injected, upstream verified);
//! un-bound destinations pass through and the client sees the upstream's real certificate.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use pocket_net::ca::Ca;
use pocket_net::mitm::{Action, HookFut, LocalResponse, Mitm, MitmHooks, ReqHead};
use pocket_net::policy::{Policy, Rule};
use pocket_net::proxy::{ConnectFut, Connector, ProxyCtx, ResolveFut, Resolver, Upstream, serve};
use pocket_proto::rpc::{NetEntry, Verdict};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct Dns;
impl Resolver for Dns {
    fn resolve<'a>(&'a self, _host: &'a str) -> ResolveFut<'a> {
        Box::pin(async { Ok(vec!["93.184.215.14".parse().unwrap()]) })
    }
}

struct Redirect(SocketAddr);
impl Connector for Redirect {
    fn connect(&self, _addr: SocketAddr) -> ConnectFut<'_> {
        let to = self.0;
        Box::pin(async move {
            Ok(Box::new(tokio::net::TcpStream::connect(to).await?) as Box<dyn Upstream>)
        })
    }
}

struct TestCa {
    cert: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

fn test_ca() -> TestCa {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "fake upstream CA");
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    TestCa {
        cert: cert.der().clone(),
        issuer: Issuer::new(p, key),
    }
}

/// Fake HTTPS upstream for every name in `names`: records request heads, never echoes them.
async fn fake_upstream(ca: &TestCa, names: &[&str]) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap()
        .signed_by(&key, &ca.issuer)
        .unwrap();
    let cfg = pocket_net::tls::server_config(
        vec![cert.der().clone(), ca.cert.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Default::default();
    let s2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = l.accept().await.unwrap();
            let acc = TlsAcceptor::from(cfg.clone());
            let seen = s2.clone();
            tokio::spawn(async move {
                let Ok(mut t) = acc.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let Ok(n) = t.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        while buf.len() < i + 4 + len {
                            let n = t.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        buf.drain(..i + 4 + len);
                        seen.lock().unwrap().push(head);
                        let _ = t
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nupstream")
                            .await;
                    }
                }
            });
        }
    });
    (addr, seen)
}

struct Hooks;
impl MitmHooks for Hooks {
    fn intercepts(&self, host: &str, _port: u16) -> bool {
        host == "bound.test"
    }
    fn body_needed(&self, _host: &str, req: &ReqHead) -> usize {
        if req.method == "POST" { 64 } else { 0 }
    }
    fn request<'a>(
        &'a self,
        _host: &'a str,
        req: &'a mut ReqHead,
        body: &'a [u8],
        _complete: bool,
    ) -> HookFut<'a> {
        Box::pin(async move {
            if body.windows(4).any(|w| w == b"main") {
                return Action::Respond(LocalResponse {
                    status: 403,
                    content_type: "text/plain".into(),
                    extra_headers: vec![],
                    body: b"guardrail".to_vec(),
                    reason: "push to main".into(),
                    denied: true,
                });
            }
            let mut injected = false;
            for (_, v) in req.headers.iter_mut() {
                if v.contains("PLACEHOLDER") {
                    *v = v.replace("PLACEHOLDER", "REALSECRET");
                    injected = true;
                }
            }
            Action::Forward { injected }
        })
    }
}

struct H {
    ctx: Arc<ProxyCtx>,
    log: Arc<Mutex<Vec<NetEntry>>>,
    seen: Arc<Mutex<Vec<String>>>,
    pocket_ca: CertificateDer<'static>,
    upstream_ca: CertificateDer<'static>,
}

async fn harness() -> H {
    let up_ca = test_ca();
    let (addr, seen) = fake_upstream(&up_ca, &["bound.test", "free.test"]).await;
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "pocket-mitm-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let ca = Arc::new(Ca::load_or_create(&dir).unwrap());
    let mut roots = RootCertStore::empty();
    roots.add(up_ca.cert.clone()).unwrap();
    let log: Arc<Mutex<Vec<NetEntry>>> = Default::default();
    let l2 = log.clone();
    let mut policy = Policy::profile("offline").unwrap();
    policy.allow.push(Rule::parse("*.test").unwrap());
    let ctx = Arc::new(ProxyCtx {
        pocket: "p".into(),
        policy: RwLock::new(policy),
        resolver: Arc::new(Dns),
        connector: Arc::new(Redirect(addr)),
        log: Box::new(move |e| l2.lock().unwrap().push(e)),
        mitm: Some(Arc::new(Mitm {
            ca: ca.clone(),
            client: pocket_net::tls::client_config(roots),
            hooks: Arc::new(Hooks),
        })),
    });
    H {
        ctx,
        log,
        seen,
        pocket_ca: ca.cert_der().clone(),
        upstream_ca: up_ca.cert,
    }
}

/// CONNECT through the proxy, then TLS trusting only `root`; returns the TLS stream and the
/// certificate chain the client was shown.
async fn tunnel(
    h: &H,
    host: &str,
    root: &CertificateDer<'static>,
) -> Result<
    (
        impl AsyncRead + AsyncWrite + Unpin,
        Vec<CertificateDer<'static>>,
    ),
    String,
> {
    let (mut c, s) = duplex(1 << 16);
    tokio::spawn(serve(s, h.ctx.clone()));
    c.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut resp = Vec::new();
    while !resp.ends_with(b"\r\n\r\n") {
        let mut b = [0u8; 1];
        if c.read(&mut b).await.unwrap() == 0 {
            return Err(String::from_utf8_lossy(&resp).into());
        }
        resp.push(b[0]);
    }
    assert!(
        resp.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&resp)
    );
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let cfg = ClientConfig::builder_with_provider(pocket_net::tls::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let t = TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from(host.to_string()).unwrap(), c)
        .await
        .map_err(|e| e.to_string())?;
    let chain = t
        .get_ref()
        .1
        .peer_certificates()
        .unwrap_or_default()
        .to_vec();
    Ok((t, chain))
}

async fn get(t: &mut (impl AsyncRead + AsyncWrite + Unpin), req: &str) -> String {
    t.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    while !out.ends_with(b"upstream") && !out.ends_with(b"guardrail") {
        let n = t.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed after {}", String::from_utf8_lossy(&out));
        out.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn bound_domain_is_intercepted_and_injected() {
    let h = harness().await;
    let (mut t, chain) = tunnel(&h, "bound.test", &h.pocket_ca).await.unwrap();
    assert_eq!(
        chain.last(),
        Some(&h.pocket_ca),
        "leaf chains to the pocket CA"
    );
    let r = get(&mut t, "GET /v1/messages HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer PLACEHOLDER\r\n\r\n").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    // Keep-alive: a second request on the same tunnel.
    let r = get(&mut t, "GET /two HTTP/1.1\r\nHost: bound.test\r\n\r\n").await;
    assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let r = get(&mut t, "POST /git-receive-pack HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 22\r\n\r\nupdate refs/heads/main").await;
    assert!(r.contains("guardrail") && r.contains("403"), "{r}");
    let seen = h.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[0].contains("Authorization: Bearer REALSECRET"),
        "{}",
        seen[0]
    );
    assert!(!seen.iter().any(|s| s.contains("PLACEHOLDER")));
    drop(t);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let log = h.log.lock().unwrap().clone();
    let first = log
        .iter()
        .find(|e| e.path.as_deref() == Some("/v1/messages"))
        .unwrap();
    assert!(first.injected && first.kind == "https" && first.status == Some(200));
    let blocked = log.iter().find(|e| e.verdict == Verdict::Denied).unwrap();
    assert_eq!(blocked.reason, "push to main");
}

#[tokio::test]
async fn bound_domain_rejects_wrong_host_header() {
    let h = harness().await;
    let (mut t, _) = tunnel(&h, "bound.test", &h.pocket_ca).await.unwrap();
    t.write_all(b"GET / HTTP/1.1\r\nHost: free.test\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    let _ = t.read_to_string(&mut out).await;
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(h.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unbound_domain_sees_the_real_certificate() {
    let h = harness().await;
    let (mut t, chain) = tunnel(&h, "free.test", &h.upstream_ca).await.unwrap();
    assert!(chain.iter().all(|c| c != &h.pocket_ca));
    let r = get(
        &mut t,
        "GET / HTTP/1.1\r\nHost: free.test\r\nAuthorization: Bearer PLACEHOLDER\r\n\r\n",
    )
    .await;
    assert!(r.starts_with("HTTP/1.1 200"));
    assert!(
        h.seen.lock().unwrap()[0].contains("PLACEHOLDER"),
        "pass-through is untouched"
    );
    // A client trusting only the pocket CA cannot talk to an un-bound domain.
    assert!(tunnel(&h, "free.test", &h.pocket_ca).await.is_err());
}
