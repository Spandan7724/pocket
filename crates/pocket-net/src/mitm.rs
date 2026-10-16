//! Selective TLS interception (SECURITY.md §Network). Only destinations the pocket's hooks
//! claim (secret bindings, push guardrails) are terminated with a pocket-CA leaf and
//! re-encrypted upstream with full verification; everything else stays a pass-through
//! tunnel. Intercepted connections speak HTTP/1.1 only, so every request goes through the
//! same small parser and is checked, rewritten and logged on its own.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use pocket_proto::rpc::Verdict;
use rustls::client::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ca::Ca;
use crate::proxy::{
    Framing, HOP_BY_HOP, Head, IDLE, Outcome, ProxyCtx, Src, body_framing, connect_checked,
    has_token, header, read_head_with, read_resp_head, respond, split_authority,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest body prefix a hook may ask to see before deciding.
pub const MAX_BODY_PEEK: usize = 1 << 20;

/// A request as the hooks see it; header edits are forwarded upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqHead {
    pub method: String,
    /// Origin form (`/path?query`).
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl ReqHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    pub fn set_header(&mut self, name: &str, value: String) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value));
    }
}

/// An answer produced by pocket instead of the upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    pub status: u16,
    pub content_type: String,
    pub extra_headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Logged reason.
    pub reason: String,
    /// Logged as blocked (guardrails) rather than answered (e.g. a token refresh).
    pub denied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Forward { injected: bool },
    Respond(LocalResponse),
}

pub type HookFut<'a> = Pin<Box<dyn Future<Output = Action> + Send + 'a>>;

pub trait MitmHooks: Send + Sync {
    /// Whether connections to `host:port` are terminated at all.
    fn intercepts(&self, host: &str, port: u16) -> bool;
    /// Bytes of request body to read before [`MitmHooks::request`] decides (0 = none,
    /// capped at [`MAX_BODY_PEEK`]).
    fn body_needed(&self, _host: &str, _req: &ReqHead) -> usize {
        0
    }
    /// Rewrites `req` (credential injection) or answers it locally. `body` is the decoded
    /// prefix asked for; `complete` says whether it is the whole body.
    fn request<'a>(
        &'a self,
        host: &'a str,
        req: &'a mut ReqHead,
        body: &'a [u8],
        complete: bool,
    ) -> HookFut<'a>;
}

pub struct Mitm {
    pub ca: Arc<Ca>,
    pub client: Arc<ClientConfig>,
    pub hooks: Arc<dyn MitmHooks>,
}

/// Bytes the guest already sent after the CONNECT head, in front of the stream.
struct Prefixed<'a, S> {
    pre: Vec<u8>,
    inner: &'a mut S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pre.is_empty() {
            let n = self.pre.len().min(buf.remaining());
            buf.put_slice(&self.pre[..n]);
            self.pre.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Serves a CONNECT whose destination the hooks intercept. Logs each inner request itself;
/// returns an outcome only when the tunnel failed before any request.
pub(crate) async fn serve<S>(
    guest: &mut S,
    head: Head,
    host: &str,
    port: u16,
    ctx: &ProxyCtx,
    m: &Mitm,
    mut o: Outcome,
) -> Option<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let fail = |o: &mut Outcome, why: String| {
        o.entry.reason = why;
    };
    let tcp = match connect_checked(ctx, host, port, &mut o).await {
        Ok(s) => s,
        Err(why) => {
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
            fail(&mut o, why);
            return Some(o);
        }
    };
    let Ok(name) = ServerName::try_from(host.to_string()) else {
        respond(guest, 400, "Bad Request", "pocket proxy: bad host name\n").await;
        fail(&mut o, "bad host name".into());
        return Some(o);
    };
    let upstream = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(m.client.clone()).connect(name, tcp),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let why = format!("upstream TLS with {host}: {e}");
            respond(guest, 502, "Bad Gateway", &format!("pocket proxy: {why}\n")).await;
            fail(&mut o, why);
            return Some(o);
        }
        Err(_) => {
            respond(
                guest,
                504,
                "Gateway Timeout",
                "pocket proxy: upstream TLS timed out\n",
            )
            .await;
            fail(&mut o, "upstream TLS handshake timed out".into());
            return Some(o);
        }
    };
    let cfg = match m.ca.server_config(host) {
        Ok(c) => c,
        Err(e) => {
            respond(guest, 500, "Internal Error", "pocket proxy: CA error\n").await;
            fail(&mut o, format!("issue certificate for {host}: {e}"));
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
    let pre = Prefixed {
        pre: head.rest,
        inner: guest,
    };
    let mut gtls =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(cfg).accept(pre)).await {
            Ok(Ok(s)) => s,
            _ => {
                fail(&mut o, "guest TLS handshake failed".into());
                return Some(o);
            }
        };
    if let Some(sni) = gtls.get_ref().1.server_name()
        && crate::policy::normalize_host(sni) != host
    {
        fail(
            &mut o,
            format!("TLS SNI {sni} does not match CONNECT target {host}"),
        );
        return Some(o);
    }
    let mut up = upstream;
    let mut up_buf = Vec::new();
    let mut leftover = Vec::new();
    loop {
        let head = match tokio::time::timeout(
            IDLE,
            read_head_with(&mut gtls, std::mem::take(&mut leftover)),
        )
        .await
        {
            Ok(Ok(Some(h))) => h,
            Ok(Err(e)) => {
                respond(
                    &mut gtls,
                    400,
                    "Bad Request",
                    &format!("pocket proxy: {e}\n"),
                )
                .await;
                return None;
            }
            _ => break,
        };
        let (entry, keep) = request(
            &mut gtls,
            &mut up,
            &mut up_buf,
            &mut leftover,
            head,
            host,
            port,
            ctx,
            m,
        )
        .await;
        if let Some(e) = entry {
            (ctx.log)(e.entry);
        }
        if !keep {
            break;
        }
    }
    let _ = gtls.shutdown().await;
    None
}

/// Reads up to `need` decoded body bytes, keeping the raw (framed) bytes to forward.
/// Chunked bodies are read whole chunks at a time so the rest can still be copied by framing.
async fn peek_body<R: AsyncRead + Unpin>(
    src: &mut Src<'_, R>,
    framing: &Framing,
    need: usize,
) -> io::Result<(Vec<u8>, Vec<u8>, bool, u64)> {
    match framing {
        Framing::Length(n) => {
            let take = (*n).min(need as u64) as usize;
            while src.buf.len() < take {
                if !src.fill().await? {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            let raw: Vec<u8> = src.buf.drain(..take).collect();
            Ok((raw.clone(), raw, take as u64 == *n, n - take as u64))
        }
        Framing::Chunked => {
            let (mut raw, mut dec) = (Vec::new(), Vec::new());
            loop {
                let l = src.line().await?;
                let text = std::str::from_utf8(&l)
                    .map_err(|_| crate::proxy::bad_data("bad chunk size"))?;
                let size = text.trim().split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(size, 16)
                    .map_err(|_| crate::proxy::bad_data("bad chunk size"))?;
                raw.extend_from_slice(&l);
                if size == 0 {
                    loop {
                        let t = src.line().await?;
                        raw.extend_from_slice(&t);
                        if t == b"\r\n" {
                            return Ok((raw, dec, true, 0));
                        }
                    }
                }
                if size > MAX_BODY_PEEK as u64 * 4 {
                    return Err(crate::proxy::bad_data("chunk too large to inspect"));
                }
                let want = size as usize + 2;
                while src.buf.len() < want {
                    if !src.fill().await? {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                }
                let chunk: Vec<u8> = src.buf.drain(..want).collect();
                dec.extend_from_slice(&chunk[..size as usize]);
                raw.extend_from_slice(&chunk);
                if dec.len() >= need {
                    return Ok((raw, dec, false, 0));
                }
            }
        }
        _ => Ok((vec![], vec![], true, 0)),
    }
}

/// One request on an intercepted connection; returns its log entry and whether the
/// connection stays open.
#[allow(clippy::too_many_arguments)]
async fn request<G, U>(
    guest: &mut G,
    up: &mut U,
    up_buf: &mut Vec<u8>,
    leftover: &mut Vec<u8>,
    head: Head,
    host: &str,
    port: u16,
    ctx: &ProxyCtx,
    m: &Mitm,
) -> (Option<Outcome>, bool)
where
    G: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut o = Outcome::new(&ctx.pocket, "https", host, port);
    o.entry.method = Some(head.method.clone());
    let path = if head.target.starts_with('/') {
        head.target.clone()
    } else if let Some(rest) = head.target.strip_prefix("https://") {
        let (auth, p) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        if split_authority(auth, Some(443)) != Some((host.to_string(), port)) {
            respond(
                guest,
                400,
                "Bad Request",
                "pocket proxy: request target does not match the tunnel\n",
            )
            .await;
            return (None, false);
        }
        p
    } else {
        respond(
            guest,
            400,
            "Bad Request",
            "pocket proxy: unsupported request target\n",
        )
        .await;
        return (None, false);
    };
    o.entry.path = Some(
        path.split('?')
            .next()
            .unwrap_or("")
            .chars()
            .take(512)
            .collect(),
    );
    if head.method == "CONNECT" {
        respond(
            guest,
            405,
            "Method Not Allowed",
            "pocket proxy: CONNECT inside a tunnel\n",
        )
        .await;
        return (None, false);
    }
    let hosts: Vec<&str> = head
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .collect();
    if hosts.len() > 1
        || hosts
            .first()
            .is_some_and(|h| split_authority(h, Some(443)) != Some((host.to_string(), port)))
    {
        o.entry.reason =
            format!("Host header {hosts:?} does not match the tunnel to {host}:{port}");
        respond(
            guest,
            403,
            "Forbidden",
            &format!("blocked by pocket: {}\n", o.entry.reason),
        )
        .await;
        return (Some(o), false);
    }
    let framing = match body_framing(&head.headers, true) {
        Ok(f) => f,
        Err(e) => {
            respond(guest, 400, "Bad Request", &format!("pocket proxy: {e}\n")).await;
            return (None, false);
        }
    };
    let client_close = has_token(&head.headers, "connection", "close")
        || (head.version == "HTTP/1.0" && !has_token(&head.headers, "connection", "keep-alive"));
    let upgrade = header(&head.headers, "upgrade").map(String::from);
    let expect_continue = has_token(&head.headers, "expect", "100-continue");
    let mut req = ReqHead {
        method: head.method.clone(),
        path,
        headers: head
            .headers
            .iter()
            .filter(|(k, _)| !HOP_BY_HOP.contains(&k.to_ascii_lowercase().as_str()))
            .cloned()
            .collect(),
    };
    let need = m.hooks.body_needed(host, &req).min(MAX_BODY_PEEK);
    if need > 0
        && expect_continue
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
    let (raw, decoded, complete, remaining) = if need > 0 {
        match peek_body(&mut gsrc, &framing, need).await {
            Ok(v) => v,
            Err(_) => return (None, false),
        }
    } else {
        (
            vec![],
            vec![],
            matches!(framing, Framing::Empty),
            match framing {
                Framing::Length(n) => n,
                _ => 0,
            },
        )
    };
    let action = m.hooks.request(host, &mut req, &decoded, complete).await;
    match action {
        Action::Respond(lr) => {
            // Drain the rest of the request so the connection stays in sync.
            let drained = async {
                let mut sink = tokio::io::sink();
                match framing {
                    Framing::Length(_) => gsrc.copy_n(remaining, &mut sink).await.map(|_| ()),
                    Framing::Chunked if !complete => gsrc.copy_chunked(&mut sink).await.map(|_| ()),
                    _ => Ok(()),
                }
            }
            .await;
            *leftover = std::mem::take(&mut gsrc.buf);
            o.entry.status = Some(lr.status);
            o.entry.reason = lr.reason.clone();
            o.entry.verdict = if lr.denied {
                Verdict::Denied
            } else {
                Verdict::Allowed
            };
            let mut msg = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Pocket: 1\r\n",
                lr.status,
                if lr.status < 400 { "OK" } else { "Blocked" },
                lr.content_type,
                lr.body.len()
            );
            for (k, v) in &lr.extra_headers {
                msg.push_str(&format!("{k}: {v}\r\n"));
            }
            let keep = drained.is_ok() && !client_close;
            if !keep {
                msg.push_str("Connection: close\r\n");
            }
            msg.push_str("\r\n");
            o.entry.bytes_down = (msg.len() + lr.body.len()) as u64;
            let ok = guest.write_all(msg.as_bytes()).await.is_ok()
                && guest.write_all(&lr.body).await.is_ok()
                && guest.flush().await.is_ok();
            (Some(o), keep && ok)
        }
        Action::Forward { injected } => {
            o.entry.injected = injected;
            let mut out = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
            if req.header("host").is_none() {
                out.push_str(&format!(
                    "Host: {}\r\n",
                    if port == 443 {
                        host.to_string()
                    } else {
                        format!("{host}:{port}")
                    }
                ));
            }
            for (k, v) in &req.headers {
                if k.bytes().any(|b| b <= b' ' || b == b':')
                    || v.bytes().any(|b| b == b'\r' || b == b'\n')
                {
                    continue;
                }
                out.push_str(&format!("{k}: {v}\r\n"));
            }
            match &upgrade {
                Some(p) => out.push_str(&format!("Connection: Upgrade\r\nUpgrade: {p}\r\n\r\n")),
                None if client_close => out.push_str("Connection: close\r\n\r\n"),
                None => out.push_str("\r\n"),
            }
            if need == 0
                && expect_continue
                && gsrc
                    .r
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .await
                    .is_err()
            {
                return (None, false);
            }
            let sent = async {
                up.write_all(out.as_bytes()).await?;
                up.write_all(&raw).await?;
                let body = match framing {
                    Framing::Length(_) => gsrc.copy_n(remaining, up).await?,
                    Framing::Chunked if !complete => gsrc.copy_chunked(up).await?,
                    _ => 0,
                };
                Ok::<u64, io::Error>((out.len() + raw.len()) as u64 + body)
            }
            .await;
            *leftover = std::mem::take(&mut gsrc.buf);
            let Ok(sent) = sent else {
                return (None, false);
            };
            o.entry.bytes_up = sent;
            let mut usrc = Src {
                r: &mut *up,
                buf: std::mem::take(up_buf),
            };
            let resp = loop {
                match tokio::time::timeout(IDLE * 5, read_resp_head(&mut usrc)).await {
                    Ok(Ok(r)) if (100..200).contains(&r.status) && r.status != 101 => {
                        if r.status == 100 && need > 0 {
                            continue;
                        }
                        if guest.write_all(&r.raw).await.is_err() {
                            return (Some(o), false);
                        }
                    }
                    Ok(Ok(r)) => break r,
                    _ => {
                        o.entry.reason = "upstream closed without a response".into();
                        respond(guest, 502, "Bad Gateway", "pocket proxy: upstream closed\n").await;
                        return (Some(o), false);
                    }
                }
            };
            o.entry.status = Some(resp.status);
            o.entry.verdict = Verdict::Allowed;
            o.entry.reason = if injected {
                "allowed, credentials injected".into()
            } else {
                "allowed".into()
            };
            if guest.write_all(&resp.raw).await.is_err() {
                return (Some(o), false);
            }
            let mut down = resp.raw.len() as u64;
            if resp.status == 101 && upgrade.is_some() {
                let pending = std::mem::take(&mut usrc.buf);
                let _ = guest.write_all(&pending).await;
                if !leftover.is_empty() {
                    let _ = up.write_all(leftover).await;
                }
                let (a, b) = tokio::io::copy_bidirectional(guest, up)
                    .await
                    .unwrap_or((0, 0));
                o.entry.bytes_up += a;
                o.entry.bytes_down = down + pending.len() as u64 + b;
                return (Some(o), false);
            }
            let framing = if req.method == "HEAD" || resp.status == 204 || resp.status == 304 {
                Ok(Framing::Empty)
            } else {
                body_framing(&resp.headers, false)
            };
            let until_close = matches!(framing, Ok(Framing::UntilClose));
            let copied = match framing {
                Ok(Framing::Empty) => Ok(0),
                Ok(Framing::Length(n)) => usrc.copy_n(n, guest).await,
                Ok(Framing::Chunked) => usrc.copy_chunked(guest).await,
                Ok(Framing::UntilClose) => usrc.copy_to_end(guest).await,
                Err(e) => Err(e),
            };
            *up_buf = std::mem::take(&mut usrc.buf);
            match copied {
                Ok(n) => down += n,
                Err(_) => {
                    o.entry.bytes_down = down;
                    return (Some(o), false);
                }
            }
            o.entry.bytes_down = down;
            let _ = guest.flush().await;
            let upstream_close = until_close || has_token(&resp.headers, "connection", "close");
            (Some(o), !(client_close || upstream_close))
        }
    }
}
