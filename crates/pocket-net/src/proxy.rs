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

/// `(host, port, reason)` of a destination the policy blocked.
pub type BlockHook = Box<dyn Fn(&str, u16, &str) + Send + Sync>;

pub struct ProxyCtx {
    pub pocket: String,
    pub policy: RwLock<Policy>,
    pub resolver: Arc<dyn Resolver>,
    pub connector: Arc<dyn Connector>,
    pub log: Box<dyn Fn(NetEntry) + Send + Sync>,
    /// TLS interception for the destinations its hooks claim; `None` = pass-through only.
    pub mitm: Option<Arc<crate::mitm::Mitm>>,
    /// Called when the policy (not an always-denied range) blocks `host:port`.
    pub on_block: Option<BlockHook>,
}

impl ProxyCtx {
    fn blocked(&self, host: &str, port: u16, why: &str) {
        if let Some(f) = &self.on_block {
            f(host, port, why);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) struct Head {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) version: String,
    pub(crate) headers: Vec<(String, String)>,
    /// Bytes after the head (start of a body or of the tunnelled stream).
    pub(crate) rest: Vec<u8>,
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Option<Head>> {
    read_head_with(s, Vec::with_capacity(4096)).await
}

pub(crate) async fn read_head_with<S: AsyncRead + Unpin>(
    s: &mut S,
    mut buf: Vec<u8>,
) -> io::Result<Option<Head>> {
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
pub(crate) fn split_authority(a: &str, default: Option<u16>) -> Option<(String, u16)> {
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

pub(crate) async fn respond<S: AsyncWrite + Unpin>(s: &mut S, code: u16, reason: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\nX-Pocket-Blocked: 1\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(msg.as_bytes()).await;
    let _ = s.shutdown().await;
}

pub(crate) struct Outcome {
    pub(crate) entry: NetEntry,
}

impl Outcome {
    pub(crate) fn new(pocket: &str, kind: &str, host: &str, port: u16) -> Outcome {
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
                injected: false,
            },
        }
    }
}

/// Resolves and checks every address; returns the connected upstream.
pub(crate) async fn connect_checked(
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
        connect(&mut guest, head, &ctx, "connect").await
    } else {
        // Logs each request itself.
        plain(&mut guest, head, &ctx).await
    };
    if let Some(o) = o {
        (ctx.log)(o.entry);
    }
}

async fn connect<S>(guest: &mut S, head: Head, ctx: &ProxyCtx, kind: &str) -> Option<Outcome>
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
    let mut o = Outcome::new(&ctx.pocket, kind, &host, port);
    o.entry.method = Some("CONNECT".into());
    let decision = ctx.policy.read().unwrap().decide(&host, port);
    if let Err(why) = decision {
        ctx.blocked(&host, port, &why);
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
    if let Some(m) = &ctx.mitm
        && m.hooks.intercepts(&host, port)
    {
        return crate::mitm::serve(guest, head, &host, port, ctx, m, o).await;
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

/// Transparent mode: a TCP stream the guest redirected to `host:port` (a name its DNS shim
/// handed out an address for, or an IP literal). It takes exactly the CONNECT path —
/// policy, resolution and always-denied ranges, SNI check, interception, logging — with
/// the proxy's HTTP replies swallowed, since the client never spoke to a proxy.
pub async fn serve_direct<S>(guest: S, ctx: Arc<ProxyCtx>, host: &str, port: u16)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host = normalize_host(host);
    let target = match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    };
    let head = Head {
        method: "CONNECT".into(),
        target,
        version: "HTTP/1.1".into(),
        headers: vec![],
        rest: vec![],
    };
    let mut g = Quiet::new(guest);
    if let Some(o) = connect(&mut g, head, &ctx, "direct").await {
        (ctx.log)(o.entry);
    }
}

/// Transparent-mode DNS: the name must be allowed, resolve, and not only to always-denied
/// addresses. Every query is logged.
pub async fn dns_check(ctx: &ProxyCtx, name: &str) -> Result<(), String> {
    let name = normalize_host(name);
    let mut o = Outcome::new(&ctx.pocket, "dns", &name, 53);
    o.entry.method = Some("A".into());
    let r = async {
        let decision = ctx.policy.read().unwrap().decide_name(&name);
        if let Err(why) = decision {
            ctx.blocked(&name, 443, &why);
            return Err(why);
        }
        let addrs = tokio::time::timeout(CONNECT_TIMEOUT, ctx.resolver.resolve(&name))
            .await
            .map_err(|_| format!("resolving {name} timed out"))?
            .map_err(|e| format!("cannot resolve {name}: {e}"))?;
        o.entry.ip = addrs.first().map(|a| a.to_string());
        if !addrs.is_empty() && addrs.iter().all(|a| forbidden_ip(*a).is_some()) {
            return Err(format!("{name} resolves only to always-denied addresses"));
        }
        if addrs.is_empty() {
            return Err(format!("{name} has no addresses"));
        }
        Ok(())
    }
    .await;
    match &r {
        Ok(()) => {
            o.entry.verdict = Verdict::Allowed;
            o.entry.reason = "allowed".into();
        }
        Err(why) => o.entry.reason = why.clone(),
    }
    (ctx.log)(o.entry);
    r
}

/// Writes through to the guest except the proxy's HTTP reply head; a non-200 reply (a
/// refusal) closes the stream without sending anything.
struct Quiet<S> {
    inner: S,
    head: Vec<u8>,
    state: u8, // 0 = in reply head, 1 = passing through, 2 = refused
}

impl<S> Quiet<S> {
    fn new(inner: S) -> Quiet<S> {
        Quiet {
            inner,
            head: vec![],
            state: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Quiet<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.state == 2 {
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Quiet<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::task::Poll;
        match self.state {
            1 => std::pin::Pin::new(&mut self.inner).poll_write(cx, buf),
            2 => Poll::Ready(Ok(buf.len())),
            _ => {
                let before = self.head.len();
                self.head.extend_from_slice(buf);
                let Some(end) = self.head.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if self.head.len() > 8192 {
                        self.state = 2;
                    }
                    return Poll::Ready(Ok(buf.len()));
                };
                self.state = if self.head.starts_with(b"HTTP/1.1 200") {
                    1
                } else {
                    2
                };
                // Report only the head bytes as written; the caller resends the rest.
                let used = (end + 4).saturating_sub(before).min(buf.len());
                self.head.clear();
                Poll::Ready(Ok(used.max(1).min(buf.len())))
            }
        }
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "upgrade",
    "te",
    "expect",
];
pub(crate) const IDLE: Duration = Duration::from_secs(60);
const MAX_LINE: usize = 8 * 1024;

pub(crate) fn bad_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A reader with bytes already pulled off the socket in front of it.
pub(crate) struct Src<'a, R> {
    pub(crate) r: &'a mut R,
    pub(crate) buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Src<'_, R> {
    pub(crate) async fn fill(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.r.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n > 0)
    }

    pub(crate) async fn line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let l = self.buf[..i + 2].to_vec();
                self.buf.drain(..i + 2);
                return Ok(l);
            }
            if self.buf.len() > MAX_LINE {
                return Err(bad_data("line too long"));
            }
            if !self.fill().await? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    pub(crate) async fn copy_n<W: AsyncWrite + Unpin>(
        &mut self,
        mut n: u64,
        w: &mut W,
    ) -> io::Result<u64> {
        let total = n;
        while n > 0 {
            if self.buf.is_empty() && !self.fill().await? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let k = (n as usize).min(self.buf.len());
            w.write_all(&self.buf[..k]).await?;
            self.buf.drain(..k);
            n -= k as u64;
        }
        Ok(total)
    }

    pub(crate) async fn copy_chunked<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
    ) -> io::Result<u64> {
        let mut total = 0;
        loop {
            let l = self.line().await?;
            let text = std::str::from_utf8(&l).map_err(|_| bad_data("bad chunk size"))?;
            let size = text.trim().split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size, 16).map_err(|_| bad_data("bad chunk size"))?;
            w.write_all(&l).await?;
            total += l.len() as u64;
            if size == 0 {
                loop {
                    let t = self.line().await?;
                    w.write_all(&t).await?;
                    total += t.len() as u64;
                    if t == b"\r\n" {
                        return Ok(total);
                    }
                }
            }
            total += self.copy_n(size + 2, w).await?;
        }
    }

    pub(crate) async fn copy_to_end<W: AsyncWrite + Unpin>(
        &mut self,
        w: &mut W,
    ) -> io::Result<u64> {
        let mut total = self.buf.len() as u64;
        w.write_all(&self.buf).await?;
        self.buf.clear();
        total += tokio::io::copy(self.r, w).await?;
        Ok(total)
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Framing {
    Empty,
    Length(u64),
    Chunked,
    UntilClose,
}

pub(crate) fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub(crate) fn has_token(h: &[(String, String)], name: &str, token: &str) -> bool {
    h.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
}

pub(crate) fn body_framing(h: &[(String, String)], request: bool) -> io::Result<Framing> {
    if has_token(h, "transfer-encoding", "chunked") {
        return Ok(Framing::Chunked);
    }
    if header(h, "transfer-encoding").is_some() {
        return Err(bad_data("unsupported transfer-encoding"));
    }
    let lens: Vec<&str> = h
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    match lens.as_slice() {
        [] if request => Ok(Framing::Empty),
        [] => Ok(Framing::UntilClose),
        [l] => l
            .trim()
            .parse()
            .map(Framing::Length)
            .map_err(|_| bad_data("bad content-length")),
        _ => Err(bad_data("several content-length headers")),
    }
}

pub(crate) struct RespHead {
    pub(crate) raw: Vec<u8>,
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
}

pub(crate) async fn read_resp_head<R: AsyncRead + Unpin>(
    src: &mut Src<'_, R>,
) -> io::Result<RespHead> {
    let mut raw = vec![];
    loop {
        let l = src.line().await?;
        raw.extend_from_slice(&l);
        if l == b"\r\n" {
            break;
        }
        if raw.len() > MAX_HEAD {
            return Err(bad_data("response head too large"));
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| bad_data("bad status line"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok(RespHead {
        raw,
        status,
        headers,
    })
}

struct UpstreamConn {
    host: String,
    port: u16,
    io: Box<dyn Upstream>,
    buf: Vec<u8>,
}

/// Plain-HTTP proxying with keep-alive: every request on the guest connection is checked
/// and logged on its own; upstream connections are reused while the target stays the same.
async fn plain<S>(guest: &mut S, first: Head, ctx: &ProxyCtx) -> Option<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut next = Some(first);
    let mut up: Option<UpstreamConn> = None;
    let mut leftover = Vec::new();
    loop {
        let head = match next.take() {
            Some(h) => h,
            None => {
                match tokio::time::timeout(
                    IDLE,
                    read_head_with(guest, std::mem::take(&mut leftover)),
                )
                .await
                {
                    Ok(Ok(Some(h))) => h,
                    _ => return None,
                }
            }
        };
        let (o, keep) = one_request(guest, head, ctx, &mut up, &mut leftover).await;
        if let Some(o) = o {
            (ctx.log)(o.entry);
        }
        if !keep {
            return None;
        }
    }
}

/// Returns the log entry and whether the guest connection stays open.
async fn one_request<S>(
    guest: &mut S,
    head: Head,
    ctx: &ProxyCtx,
    up: &mut Option<UpstreamConn>,
    leftover: &mut Vec<u8>,
) -> (Option<Outcome>, bool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(rest) = head.target.strip_prefix("http://") else {
        let why = if head.target.starts_with("https://") {
            "pocket proxy: this client sent an https:// URL without CONNECT; use curl or GNU wget\n"
        } else {
            "pocket proxy: only CONNECT and absolute http:// requests are proxied\n"
        };
        respond(guest, 400, "Bad Request", why).await;
        return (None, false);
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
        return (None, false);
    }
    let Some((host, port)) = split_authority(authority, Some(80)) else {
        respond(
            guest,
            400,
            "Bad Request",
            "pocket proxy: bad request target\n",
        )
        .await;
        return (None, false);
    };
    let mut o = Outcome::new(&ctx.pocket, "http", &host, port);
    o.entry.method = Some(head.method.clone());
    o.entry.path = Some(path.chars().take(512).collect());
    let deny = |o: &mut Outcome, why: String| {
        o.entry.reason = why;
    };
    // A Host header naming something else would let an allowed target route elsewhere.
    if let Some(h) = header(&head.headers, "host") {
        let matches = split_authority(h, Some(80)).is_some_and(|(hh, hp)| hh == host && hp == port);
        if !matches {
            deny(
                &mut o,
                format!("Host header {h:?} does not match request target {host}:{port}"),
            );
            respond(
                guest,
                403,
                "Forbidden",
                &format!("blocked by pocket: {}\n", o.entry.reason),
            )
            .await;
            return (Some(o), false);
        }
    }
    let req_body = match body_framing(&head.headers, true) {
        Ok(f) => f,
        Err(e) => {
            respond(guest, 400, "Bad Request", &format!("pocket proxy: {e}\n")).await;
            return (None, false);
        }
    };
    let decision = ctx.policy.read().unwrap().decide(&host, port);
    if let Err(why) = decision {
        ctx.blocked(&host, port, &why);
        deny(&mut o, why.clone());
        respond(
            guest,
            403,
            "Forbidden",
            &format!("blocked by pocket: {why}\n"),
        )
        .await;
        return (Some(o), false);
    }
    if up
        .as_ref()
        .is_some_and(|u| u.host != host || u.port != port)
    {
        *up = None;
    }
    if up.is_none() {
        match connect_checked(ctx, &host, port, &mut o).await {
            Ok(io) => {
                *up = Some(UpstreamConn {
                    host: host.clone(),
                    port,
                    io,
                    buf: vec![],
                })
            }
            Err(why) => {
                let code = if why.contains("always denied") {
                    403
                } else {
                    502
                };
                deny(&mut o, why.clone());
                respond(
                    guest,
                    code,
                    "Blocked",
                    &format!("blocked by pocket: {why}\n"),
                )
                .await;
                return (Some(o), false);
            }
        }
    }
    let u = up.as_mut().unwrap();
    let upgrade = header(&head.headers, "upgrade").map(String::from);
    let client_close = has_token(&head.headers, "connection", "close")
        || (head.version == "HTTP/1.0" && !has_token(&head.headers, "connection", "keep-alive"));
    let is_head = head.method == "HEAD";
    let mut req = format!("{} {path} HTTP/1.1\r\n", head.method);
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
    match &upgrade {
        Some(proto) => req.push_str(&format!("Connection: Upgrade\r\nUpgrade: {proto}\r\n\r\n")),
        None if client_close => req.push_str("Connection: close\r\n\r\n"),
        None => req.push_str("\r\n"),
    }
    if has_token(&head.headers, "expect", "100-continue")
        && guest
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .is_err()
    {
        return (None, false);
    }
    let mut gsrc = Src {
        r: &mut *guest,
        buf: head.rest,
    };
    let sent = async {
        u.io.write_all(req.as_bytes()).await?;
        let body = match req_body {
            Framing::Length(n) => gsrc.copy_n(n, &mut u.io).await?,
            Framing::Chunked => gsrc.copy_chunked(&mut u.io).await?,
            _ => 0,
        };
        Ok::<u64, io::Error>(req.len() as u64 + body)
    }
    .await;
    *leftover = std::mem::take(&mut gsrc.buf);
    let Ok(sent) = sent else {
        *up = None;
        return (None, false);
    };
    o.entry.bytes_up = sent;
    let mut usrc = Src {
        r: &mut u.io,
        buf: std::mem::take(&mut u.buf),
    };
    let resp = loop {
        match tokio::time::timeout(IDLE, read_resp_head(&mut usrc)).await {
            Ok(Ok(r)) if (100..200).contains(&r.status) && r.status != 101 => continue,
            Ok(Ok(r)) => break r,
            _ => {
                o.entry.reason = "upstream closed without a response".into();
                respond(guest, 502, "Bad Gateway", "pocket proxy: upstream closed\n").await;
                *up = None;
                return (Some(o), false);
            }
        }
    };
    o.entry.status = Some(resp.status);
    o.entry.verdict = Verdict::Allowed;
    o.entry.reason = "allowed".into();
    if guest.write_all(&resp.raw).await.is_err() {
        *up = None;
        return (Some(o), false);
    }
    let mut down = resp.raw.len() as u64;
    if resp.status == 101 && upgrade.is_some() {
        // Protocol switch (e.g. WebSocket): splice raw bytes until either side closes.
        let pending = std::mem::take(&mut usrc.buf);
        let _ = guest.write_all(&pending).await;
        let mut io = up.take().unwrap().io;
        if !leftover.is_empty() {
            let _ = io.write_all(leftover).await;
        }
        let (a, b) = tokio::io::copy_bidirectional(guest, &mut io)
            .await
            .unwrap_or((0, 0));
        o.entry.bytes_up += a;
        o.entry.bytes_down = down + pending.len() as u64 + b;
        return (Some(o), false);
    }
    let framing = if is_head || resp.status == 204 || resp.status == 304 {
        Ok(Framing::Empty)
    } else {
        body_framing(&resp.headers, false)
    };
    let until_close = matches!(framing, Ok(Framing::UntilClose));
    let copied = match framing {
        Ok(Framing::Empty) => Ok(0),
        Ok(Framing::Length(n)) => usrc.copy_n(n, guest).await,
        Ok(Framing::Chunked) => usrc.copy_chunked(guest).await,
        // The body ends at close: this connection cannot carry another response.
        Ok(Framing::UntilClose) => usrc.copy_to_end(guest).await,
        Err(e) => Err(e),
    };
    u.buf = std::mem::take(&mut usrc.buf);
    match copied {
        Ok(n) => down += n,
        Err(_) => {
            o.entry.bytes_down = down;
            *up = None;
            return (Some(o), false);
        }
    }
    o.entry.bytes_down = down;
    let upstream_close = until_close || has_token(&resp.headers, "connection", "close");
    if upstream_close {
        *up = None;
    }
    let _ = guest.flush().await;
    (Some(o), !(client_close || until_close))
}

#[cfg(test)]
mod quiet_tests {
    use super::Quiet;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn swallows_the_reply_head_and_refusals() {
        let (a, mut b) = tokio::io::duplex(4096);
        let mut q = Quiet::new(a);
        q.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nTLS-bytes")
            .await
            .unwrap();
        q.write_all(b" more").await.unwrap();
        drop(q);
        let mut got = vec![];
        b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"TLS-bytes more");

        let (a, mut b) = tokio::io::duplex(4096);
        let mut q = Quiet::new(a);
        q.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nblocked!\n")
            .await
            .unwrap();
        drop(q);
        let mut got = vec![];
        b.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn names_for_dns() {
        let mut p = crate::policy::Policy::profile("strict").unwrap();
        assert!(p.decide_name("api.anthropic.com").is_ok());
        assert!(p.decide_name("evil.example").is_err());
        p.allow
            .push(crate::policy::Rule::parse("db.internal.test:5432").unwrap());
        assert!(
            p.decide_name("db.internal.test").is_ok(),
            "any port counts for DNS"
        );
        p.deny
            .push(crate::policy::Rule::parse("api.anthropic.com").unwrap());
        assert!(p.decide_name("api.anthropic.com").is_err());
    }
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
