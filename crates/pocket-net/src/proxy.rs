//! Host side of env-proxy mode: one guest connection = one HTTP proxy conversation
//! (`CONNECT host:port` or an absolute-form `http://` request). Everything from the guest
//! is hostile: the head is size- and time-limited, the target is policy-checked by name,
//! every resolved address is checked against the always-denied ranges, and we connect to
//! exactly the address we checked (no second resolution → no DNS rebinding window).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pocket_proto::rpc::{NetEntry, Verdict};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::policy::{Policy, forbidden_ip, normalize_host};
use crate::sni;

const MAX_HEAD: usize = 64 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub type ResolveFut<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

pub trait Resolver: Send + Sync {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFut<'a>;
}

pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> ResolveFut<'a> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, 0)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

pub trait Upstream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Upstream for T {}

pub type ConnectFut<'a> = Pin<Box<dyn Future<Output = io::Result<Box<dyn Upstream>>> + Send + 'a>>;

/// Opens upstream connections to an already-checked address.
pub trait Connector: Send + Sync {
    fn connect(&self, addr: SocketAddr) -> ConnectFut<'_>;
}

pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect(&self, addr: SocketAddr) -> ConnectFut<'_> {
        Box::pin(async move {
            let s = TcpStream::connect(addr).await?;
            let _ = s.set_nodelay(true);
            Ok(Box::new(s) as Box<dyn Upstream>)
        })
    }
}

pub struct ProxyCtx {
    pub pocket: String,
    pub policy: RwLock<Policy>,
    pub resolver: Arc<dyn Resolver>,
    pub connector: Arc<dyn Connector>,
    pub log: Box<dyn Fn(NetEntry) + Send + Sync>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Head {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    /// Bytes after the head (start of a body or of the tunnelled stream).
    rest: Vec<u8>,
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Option<Head>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    parse_head(&buf, end).map(Some)
}

fn parse_head(buf: &[u8], end: usize) -> io::Result<Head> {
    let text = std::str::from_utf8(&buf[..end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 request head"))?;
    let mut lines = text.split("\r\n");
    let line = lines.next().unwrap_or_default();
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    };
    if !version.starts_with("HTTP/1.")
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }
    let mut headers = vec![];
    for l in lines {
        let (k, v) = l
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed header"))?;
        if k.is_empty()
            || k.bytes().any(|b| b <= b' ' || b == 0x7f)
            || v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed header",
            ));
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Ok(Head {
        method: method.into(),
        target: target.into(),
        version: version.into(),
        headers,
        rest: buf[end + 4..].to_vec(),
    })
}

/// Every parser the proxy runs on guest bytes before any policy check; the fuzz target
/// drives this.
pub fn fuzz_parsers(data: &[u8]) {
    let _ = sni::client_hello_sni(data);
    let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
        return;
    };
    if let Ok(h) = parse_head(data, end) {
        let _ = split_authority(&h.target, None);
        let _ = split_authority(&h.target, Some(80));
        for (_, v) in &h.headers {
            let _ = split_authority(v, Some(80));
        }
        if let Some(rest) = h.target.strip_prefix("http://") {
            let _ = split_authority(rest.split('/').next().unwrap_or(""), Some(80));
        }
    }
}

/// `host:port` with optional `[v6]`; `default` when the port is absent.
fn split_authority(a: &str, default: Option<u16>) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default?,
            None => return None,
        };
        (h.to_string(), port)
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().ok()?),
            None => (a.to_string(), default?),
            _ => return None,
        }
    };
    if host.is_empty() || port == 0 || host.bytes().any(|b| b <= b' ' || b"/?#@\\".contains(&b)) {
        return None;
    }
    Some((normalize_host(&host), port))
}

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, code: u16, reason: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nX-Pocket-Blocked: 1\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(msg.as_bytes()).await;
    let _ = s.shutdown().await;
}

struct Outcome {
    entry: NetEntry,
}

impl Outcome {
    fn new(pocket: &str, kind: &str, host: &str, port: u16) -> Outcome {
        Outcome {
            entry: NetEntry {
                pocket: pocket.into(),
                ts_ms: now_ms(),
                kind: kind.into(),
                host: host.into(),
                ip: None,
                port,
                method: None,
                path: None,
                status: None,
                bytes_up: 0,
                bytes_down: 0,
                verdict: Verdict::Denied,
                reason: String::new(),
            },
        }
    }
}

/// Resolves and checks every address; returns the connected upstream.
async fn connect_checked(
    ctx: &ProxyCtx,
    host: &str,
    port: u16,
    o: &mut Outcome,
) -> Result<Box<dyn Upstream>, String> {
    let addrs = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => ctx
            .resolver
            .resolve(host)
            .await
            .map_err(|e| format!("cannot resolve {host}: {e}"))?,
    };
    if addrs.is_empty() {
        return Err(format!("{host} has no addresses"));
    }
    if let Some((ip, why)) = addrs
        .iter()
        .find_map(|ip| forbidden_ip(*ip).map(|w| (ip, w)))
    {
        o.entry.ip = Some(ip.to_string());
        return Err(format!(
            "{host} resolves to {ip}, which is {why} (always denied)"
        ));
    }
    let mut last = String::new();
    for ip in addrs {
        o.entry.ip = Some(ip.to_string());
        match tokio::time::timeout(
            CONNECT_TIMEOUT,
            ctx.connector.connect(SocketAddr::new(ip, port)),
        )
        .await
        {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "timed out".into(),
        }
    }
    Err(format!("connect {host}:{port}: {last}"))
}

/// Serves one guest proxy connection to completion and logs it.
pub async fn serve<S>(mut guest: S, ctx: Arc<ProxyCtx>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut guest)).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            respond(
                &mut guest,
                400,
                "Bad Request",
                &format!("pocket proxy: {e}\n"),
            )
            .await;
            return;
        }
        Err(_) => {
            respond(
                &mut guest,
                408,
                "Request Timeout",
                "pocket proxy: request head timed out\n",
            )
            .await;
            return;
        }
    };
    let o = if head.method == "CONNECT" {
        connect(&mut guest, head, &ctx).await
    } else {
        plain(&mut guest, head, &ctx).await
    };
    if let Some(o) = o {
        (ctx.log)(o.entry);
    }
}

async fn connect<S>(guest: &mut S, head: Head, ctx: &ProxyCtx) -> Option<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((host, port)) = split_authority(&head.target, None) else {
        respond(
            guest,
            400,
            "Bad Request",
            "pocket proxy: CONNECT needs host:port\n",
        )
        .await;
        return None;
    };
    let mut o = Outcome::new(&ctx.pocket, "connect", &host, port);
    o.entry.method = Some("CONNECT".into());
    let decision = ctx.policy.read().unwrap().decide(&host, port);
    if let Err(why) = decision {
        o.entry.reason = why.clone();
        respond(
            guest,
            403,
            "Forbidden",
            &format!("blocked by pocket: {why}\n"),
        )
        .await;
        return Some(o);
    }
    let mut up = match connect_checked(ctx, &host, port, &mut o).await {
        Ok(s) => s,
        Err(why) => {
            o.entry.reason = why.clone();
            let code = if why.contains("always denied") {
                403
            } else {
                502
            };
            respond(
                guest,
                code,
                "Blocked",
                &format!("blocked by pocket: {why}\n"),
            )
            .await;
            return Some(o);
        }
    };
    if guest
        .write_all(format!("{} 200 Connection established\r\n\r\n", head.version).as_bytes())
        .await
        .is_err()
    {
        return None;
    }
    // First flight from the client: if it is a TLS ClientHello its SNI must name the
    // CONNECT host (no domain fronting through an allowed name).
    let mut first = head.rest;
    if first.is_empty() {
        let mut buf = vec![0u8; 16 * 1024 + 5];
        match tokio::time::timeout(Duration::from_secs(30), guest.read(&mut buf)).await {
            Ok(Ok(n)) => {
                buf.truncate(n);
                first = buf;
            }
            _ => return None,
        }
    }
    if let Some(name) = sni::client_hello_sni(&first) {
        let name = normalize_host(&name);
        if name != host {
            o.entry.reason = format!("TLS SNI {name} does not match CONNECT target {host}");
            return Some(o);
        }
    }
    if up.write_all(&first).await.is_err() {
        return None;
    }
    o.entry.verdict = Verdict::Allowed;
    o.entry.reason = "allowed".into();
    let (a, b) = tokio::io::copy_bidirectional(guest, &mut up)
        .await
        .unwrap_or((0, 0));
    o.entry.bytes_up = a + first.len() as u64;
    o.entry.bytes_down = b;
    Some(o)
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "upgrade",
];

async fn plain<S>(guest: &mut S, head: Head, ctx: &ProxyCtx) -> Option<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(rest) = head.target.strip_prefix("http://") else {
        respond(
            guest,
            400,
            "Bad Request",
            "pocket proxy: only CONNECT and absolute http:// requests are proxied (this client sent an https:// URL without CONNECT; use curl or GNU wget)\n",
        )
        .await;
        return None;
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if authority.contains('@') {
        respond(
            guest,
            400,
            "Bad Request",
            "pocket proxy: credentials in URLs are not proxied\n",
        )
        .await;
        return None;
    }
    let Some((host, port)) = split_authority(authority, Some(80)) else {
        respond(
            guest,
            400,
            "Bad Request",
            "pocket proxy: bad request target\n",
        )
        .await;
        return None;
    };
    let mut o = Outcome::new(&ctx.pocket, "http", &host, port);
    o.entry.method = Some(head.method.clone());
    o.entry.path = Some(path.chars().take(512).collect());
    // A Host header naming something else would let an allowed target route elsewhere.
    if let Some((_, h)) = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
    {
        let matches = split_authority(h, Some(80)).is_some_and(|(hh, hp)| hh == host && hp == port);
        if !matches {
            o.entry.reason =
                format!("Host header {h:?} does not match request target {host}:{port}");
            respond(
                guest,
                403,
                "Forbidden",
                &format!("blocked by pocket: {}\n", o.entry.reason),
            )
            .await;
            return Some(o);
        }
    }
    let decision = ctx.policy.read().unwrap().decide(&host, port);
    if let Err(why) = decision {
        o.entry.reason = why.clone();
        respond(
            guest,
            403,
            "Forbidden",
            &format!("blocked by pocket: {why}\n"),
        )
        .await;
        return Some(o);
    }
    let mut up = match connect_checked(ctx, &host, port, &mut o).await {
        Ok(s) => s,
        Err(why) => {
            o.entry.reason = why.clone();
            let code = if why.contains("always denied") {
                403
            } else {
                502
            };
            respond(
                guest,
                code,
                "Blocked",
                &format!("blocked by pocket: {why}\n"),
            )
            .await;
            return Some(o);
        }
    };
    let mut req = format!("{} {path} {}\r\n", head.method, head.version);
    let mut has_host = false;
    for (k, v) in &head.headers {
        let lk = k.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lk.as_str()) {
            continue;
        }
        has_host |= lk == "host";
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        req.push_str(&format!("Host: {authority}\r\n"));
    }
    // One request per connection keeps the proxy from having to parse message bodies.
    req.push_str("Connection: close\r\n\r\n");
    if up.write_all(req.as_bytes()).await.is_err() || up.write_all(&head.rest).await.is_err() {
        return None;
    }
    let mut first = vec![0u8; 16 * 1024];
    let n = match tokio::time::timeout(Duration::from_secs(60), up.read(&mut first)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            o.entry.reason = "upstream closed without a response".into();
            respond(guest, 502, "Bad Gateway", "pocket proxy: upstream closed\n").await;
            return Some(o);
        }
    };
    first.truncate(n);
    o.entry.status = std::str::from_utf8(&first[..n.min(32)])
        .ok()
        .and_then(|s| s.split(' ').nth(1))
        .and_then(|c| c.parse().ok());
    if guest.write_all(&first).await.is_err() {
        return None;
    }
    o.entry.verdict = Verdict::Allowed;
    o.entry.reason = "allowed".into();
    let (a, b) = tokio::io::copy_bidirectional(guest, &mut up)
        .await
        .unwrap_or((0, 0));
    o.entry.bytes_up = (req.len() + head.rest.len()) as u64 + a;
    o.entry.bytes_down = n as u64 + b;
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorities() {
        assert_eq!(
            split_authority("Example.com:443", None),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            split_authority("[::1]:8080", None),
            Some(("::1".into(), 8080))
        );
        assert_eq!(
            split_authority("a.com", Some(80)),
            Some(("a.com".into(), 80))
        );
        assert_eq!(split_authority("a.com", None), None);
        for bad in [
            "a.com:0",
            "a.com:x",
            "u@a.com:1",
            ":443",
            "[::1]x",
            "a b:1",
            "::1:443",
        ] {
            assert_eq!(split_authority(bad, None), None, "{bad}");
        }
    }
}
