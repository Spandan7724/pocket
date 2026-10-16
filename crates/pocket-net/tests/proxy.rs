use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use pocket_net::policy::{Policy, Rule};
use pocket_net::proxy::{ConnectFut, Connector, ProxyCtx, ResolveFut, Resolver, Upstream, serve};
use pocket_proto::rpc::{NetEntry, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;

const PUBLIC: &str = "93.184.215.14";

#[derive(Default)]
struct FakeDns {
    rebind_calls: AtomicUsize,
    calls: AtomicUsize,
}

impl Resolver for FakeDns {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFut<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ips: Vec<&str> = match host {
            "allowed.test" | "evil.test" => vec![PUBLIC],
            "private.test" => vec!["10.0.0.5"],
            "metadata.test" => vec!["169.254.169.254"],
            "loop.test" => vec!["127.0.0.1"],
            "mixed.test" => vec![PUBLIC, "127.0.0.1"],
            "v6loop.test" => vec!["::1"],
            "rebind.test" => {
                if self.rebind_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    vec![PUBLIC]
                } else {
                    vec!["127.0.0.1"]
                }
            }
            _ => vec![],
        };
        let ips = ips.into_iter().map(|s| s.parse().unwrap()).collect();
        Box::pin(async move { Ok(ips) })
    }
}

/// Sends every connection to a local fake upstream and records the requested address.
struct Redirect {
    to: SocketAddr,
    seen: Mutex<Vec<SocketAddr>>,
}

impl Connector for Redirect {
    fn connect(&self, addr: SocketAddr) -> ConnectFut<'_> {
        self.seen.lock().unwrap().push(addr);
        let to = self.to;
        Box::pin(async move {
            Ok(Box::new(tokio::net::TcpStream::connect(to).await?) as Box<dyn Upstream>)
        })
    }
}

struct Harness {
    ctx: Arc<ProxyCtx>,
    log: Arc<Mutex<Vec<NetEntry>>>,
    dns: Arc<FakeDns>,
    conn: Arc<Redirect>,
    upstream_got: Arc<Mutex<Vec<Vec<u8>>>>,
}

async fn harness(policy: Policy) -> Harness {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let to = l.local_addr().unwrap();
    let upstream_got: Arc<Mutex<Vec<Vec<u8>>>> = Default::default();
    let got = upstream_got.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let got = got.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    got.lock().unwrap().push(buf[..n].to_vec());
                    if n == 0 {
                        break;
                    }
                    if buf.starts_with(b"GET /chunked") {
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
                            .await;
                    } else if buf.starts_with(b"GET ") {
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                            .await;
                    } else {
                        let _ = s.write_all(b"tls-reply").await;
                        break;
                    }
                }
            });
        }
    });
    let log: Arc<Mutex<Vec<NetEntry>>> = Default::default();
    let l2 = log.clone();
    let dns = Arc::new(FakeDns::default());
    let conn = Arc::new(Redirect {
        to,
        seen: Mutex::new(vec![]),
    });
    let ctx = Arc::new(ProxyCtx {
        pocket: "p".into(),
        policy: RwLock::new(policy),
        resolver: dns.clone(),
        connector: conn.clone(),
        log: Box::new(move |e| l2.lock().unwrap().push(e)),
        mitm: None,
        on_block: None,
    });
    Harness {
        ctx,
        log,
        dns,
        conn,
        upstream_got,
    }
}

/// Runs one proxy conversation: sends `req`, then `after` once the head is answered.
async fn talk(h: &Harness, req: &[u8], after: &[u8]) -> String {
    let (mut client, server) = duplex(1 << 20);
    let task = tokio::spawn(serve(server, h.ctx.clone()));
    client.write_all(req).await.unwrap();
    let mut out = vec![];
    let mut buf = vec![0u8; 65536];
    let n = client.read(&mut buf).await.unwrap();
    out.extend_from_slice(&buf[..n]);
    if !after.is_empty() && out.starts_with(b"HTTP/1.1 200") {
        client.write_all(after).await.unwrap();
    }
    client.shutdown().await.unwrap();
    while let Ok(n) = client.read(&mut buf).await {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    task.await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn wildcard() -> Policy {
    Policy {
        profile: "wild".into(),
        allow: vec![
            Rule::parse("*").unwrap(),
            Rule::parse("0.0.0.0/0").unwrap(),
            Rule::parse("[::/0]").unwrap(),
        ],
        deny: vec![],
        default_ports: vec![80, 443],
    }
}

fn hello(name: &str) -> Vec<u8> {
    // Minimal TLS 1.2-framed ClientHello with one SNI entry.
    let mut sni = vec![0u8];
    sni.extend((name.len() as u16).to_be_bytes());
    sni.extend(name.as_bytes());
    let mut list = (sni.len() as u16).to_be_bytes().to_vec();
    list.extend(sni);
    let mut ext = vec![0, 0];
    ext.extend((list.len() as u16).to_be_bytes());
    ext.extend(list);
    let mut body = vec![3, 3];
    body.extend([7u8; 32]);
    body.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut hs = vec![1, 0];
    hs.extend((body.len() as u16).to_be_bytes());
    hs.extend(body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[tokio::test]
async fn allowed_connect_tunnels_to_the_checked_address() {
    let h = harness(wildcard()).await;
    let out = talk(
        &h,
        b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n",
        &hello("allowed.test"),
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.ends_with("tls-reply"), "{out}");
    assert_eq!(h.upstream_got.lock().unwrap()[0], hello("allowed.test"));
    let e = &h.log.lock().unwrap()[0];
    assert_eq!(
        (e.verdict, e.host.as_str(), e.ip.as_deref(), e.port),
        (Verdict::Allowed, "allowed.test", Some(PUBLIC), 443)
    );
    assert!(e.bytes_up > 0 && e.bytes_down == 9);
    assert_eq!(
        *h.conn.seen.lock().unwrap(),
        [SocketAddr::new(PUBLIC.parse().unwrap(), 443)]
    );
}

#[tokio::test]
async fn private_loopback_link_local_and_metadata_denied_even_via_wildcard() {
    let h = harness(wildcard()).await;
    for target in [
        "private.test:443",
        "metadata.test:80",
        "loop.test:443",
        "v6loop.test:443",
        "mixed.test:443",
        "127.0.0.1:443",
        "10.1.2.3:443",
        "192.168.0.1:443",
        "172.20.0.1:443",
        "169.254.169.254:80",
        "100.100.100.200:80",
        "[::1]:443",
        "[fe80::1]:443",
        "[fd00:ec2::254]:80",
        "[::ffff:127.0.0.1]:443",
        "localhost:443",
    ] {
        let out = talk(
            &h,
            format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes(),
            b"",
        )
        .await;
        assert!(
            out.starts_with("HTTP/1.1 403") || out.starts_with("HTTP/1.1 502"),
            "{target}: {out}"
        );
        let e = h.log.lock().unwrap().last().unwrap().clone();
        assert_eq!(e.verdict, Verdict::Denied, "{target}");
        if target != "localhost:443" {
            assert!(e.reason.contains("always denied"), "{target}: {}", e.reason);
        }
    }
    let plain = talk(
        &h,
        b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
        b"",
    )
    .await;
    assert!(plain.starts_with("HTTP/1.1 403"), "{plain}");
    assert!(
        h.conn.seen.lock().unwrap().is_empty(),
        "nothing private was ever dialled"
    );
    assert!(h.upstream_got.lock().unwrap().is_empty());
}

#[tokio::test]
async fn dns_rebinding_cannot_reach_a_private_address() {
    let h = harness(wildcard()).await;
    let out = talk(
        &h,
        b"CONNECT rebind.test:443 HTTP/1.1\r\n\r\n",
        &hello("rebind.test"),
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert_eq!(
        h.dns.calls.load(Ordering::SeqCst),
        1,
        "resolved exactly once per request"
    );
    let out = talk(
        &h,
        b"CONNECT rebind.test:443 HTTP/1.1\r\n\r\n",
        &hello("rebind.test"),
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert_eq!(
        *h.conn.seen.lock().unwrap(),
        [SocketAddr::new(PUBLIC.parse::<IpAddr>().unwrap(), 443)]
    );
}

#[tokio::test]
async fn sni_must_match_the_connect_target() {
    let h = harness(wildcard()).await;
    let _ = talk(
        &h,
        b"CONNECT allowed.test:443 HTTP/1.1\r\n\r\n",
        &hello("evil.test"),
    )
    .await;
    assert!(
        h.upstream_got.lock().unwrap().iter().all(|d| d.is_empty()),
        "no bytes forwarded"
    );
    let e = h.log.lock().unwrap()[0].clone();
    assert_eq!(e.verdict, Verdict::Denied);
    assert!(e.reason.contains("SNI"), "{}", e.reason);
}

#[tokio::test]
async fn plain_http_is_rewritten_and_logged() {
    let mut pol = Policy::profile("strict").unwrap();
    pol.allow.push(Rule::parse("allowed.test").unwrap());
    let h = harness(pol).await;
    let out = talk(&h, b"GET http://allowed.test/a/b?c=1 HTTP/1.1\r\nHost: allowed.test\r\nProxy-Connection: keep-alive\r\nUser-Agent: t\r\n\r\n", b"").await;
    assert!(out.ends_with("hello"), "{out}");
    let sent = String::from_utf8(h.upstream_got.lock().unwrap()[0].clone()).unwrap();
    assert!(sent.starts_with("GET /a/b?c=1 HTTP/1.1\r\n"), "{sent}");
    assert!(!sent.to_lowercase().contains("proxy-connection"), "{sent}");
    let e = h.log.lock().unwrap()[0].clone();
    assert_eq!(
        (e.verdict, e.status, e.method.as_deref(), e.path.as_deref()),
        (Verdict::Allowed, Some(200), Some("GET"), Some("/a/b?c=1"))
    );

    let out = talk(
        &h,
        b"GET http://allowed.test/ HTTP/1.1\r\nHost: evil.test\r\n\r\n",
        b"",
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 403"), "Host mismatch: {out}");
    let out = talk(&h, b"CONNECT example.org:443 HTTP/1.1\r\n\r\n", b"").await;
    assert!(
        out.starts_with("HTTP/1.1 403") && out.contains("not allowed by profile strict"),
        "{out}"
    );
    let out = talk(&h, b"CONNECT allowed.test:22 HTTP/1.1\r\n\r\n", b"").await;
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    for junk in [
        &b"\x16\x03\x01garbage\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\n\r\n",
        b"get http://a/ HTTP/1.1\r\n\r\n",
        b"GET https://allowed.test/ HTTP/1.1\r\n\r\n",
    ] {
        let out = talk(&h, junk, b"").await;
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    }
    let log = h.log.lock().unwrap();
    assert_eq!(
        log.iter().filter(|e| e.verdict == Verdict::Denied).count(),
        3
    );
}

#[tokio::test]
async fn plain_http_keep_alive_reuses_the_upstream_and_logs_each_request() {
    let mut pol = Policy::profile("strict").unwrap();
    pol.allow.push(Rule::parse("allowed.test").unwrap());
    let h = harness(pol).await;
    let (mut client, server) = duplex(1 << 20);
    let task = tokio::spawn(serve(server, h.ctx.clone()));
    let mut buf = vec![0u8; 4096];
    let mut read_until = async |client: &mut tokio::io::DuplexStream, needle: &str| {
        let mut out = String::new();
        while !out.contains(needle) {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed early: {out}");
            out.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        out
    };
    client
        .write_all(b"GET http://allowed.test/one HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut client, "hello").await;
    client
        .write_all(b"GET http://allowed.test/chunked HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        .await
        .unwrap();
    let out = read_until(&mut client, "0\r\n\r\n").await;
    assert!(out.contains("3\r\nabc\r\n2\r\nde\r\n"), "{out}");
    // A request to a host outside the policy on the same connection is still blocked.
    client
        .write_all(b"GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n")
        .await
        .unwrap();
    let out = read_until(&mut client, "blocked by pocket").await;
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    client.shutdown().await.unwrap();
    task.await.unwrap();
    assert_eq!(
        h.conn.seen.lock().unwrap().len(),
        1,
        "one upstream connection for both requests"
    );
    let log = h.log.lock().unwrap();
    let paths: Vec<_> = log
        .iter()
        .map(|e| (e.path.clone().unwrap_or_default(), e.verdict))
        .collect();
    assert_eq!(
        paths,
        [
            ("/one".into(), Verdict::Allowed),
            ("/chunked".into(), Verdict::Allowed),
            ("/".into(), Verdict::Denied)
        ]
    );
    assert_eq!(log[1].status, Some(200));
}
