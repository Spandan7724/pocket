//! A minimal HTTPS client for requests pocketd itself makes on a pocket's behalf (host-side
//! token refresh). It resolves, checks and connects exactly like the proxy does.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::policy::forbidden_ip;
use crate::proxy::{Connector, Resolver};

const MAX_RESPONSE: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub async fn request(
    resolver: &dyn Resolver,
    connector: &dyn Connector,
    tls: Arc<ClientConfig>,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<Response> {
    tokio::time::timeout(TIMEOUT, async {
        let addrs = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => resolver.resolve(host).await?,
        };
        let ip = *addrs
            .first()
            .ok_or_else(|| io::Error::other(format!("{host} has no addresses")))?;
        if let Some(why) = addrs.iter().find_map(|ip| forbidden_ip(*ip)) {
            return Err(io::Error::other(format!("{host} resolves to {why}")));
        }
        let tcp = connector.connect(std::net::SocketAddr::new(ip, 443)).await?;
        let name = ServerName::try_from(host.to_string()).map_err(io::Error::other)?;
        let mut s = TlsConnector::from(tls).connect(name, tcp).await?;
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;
        s.write_all(body).await?;
        s.flush().await?;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = match s.read(&mut chunk).await {
                Ok(n) => n,
                // Servers often close without close_notify after `Connection: close`.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(e),
            };
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() > MAX_RESPONSE {
                return Err(io::Error::other("response too large"));
            }
            if complete(&raw) {
                break;
            }
        }
        parse(&raw)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))?
}

/// Whether `raw` holds a whole response (by Content-Length or the last chunk).
fn complete(raw: &[u8]) -> bool {
    let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
    let body = &raw[end + 4..];
    if let Some(len) = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        return body.len() >= len;
    }
    head.contains("chunked") && body.ends_with(b"0\r\n\r\n")
}

fn parse(raw: &[u8]) -> io::Result<Response> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("no response head"))?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other("bad status line"))?;
    let chunked = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let mut body = raw[end + 4..].to_vec();
    if chunked {
        let mut out = Vec::new();
        let mut rest = &body[..];
        loop {
            let i = rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| io::Error::other("bad chunk"))?;
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&rest[..i])
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim(),
                16,
            )
            .map_err(|_| io::Error::other("bad chunk size"))?;
            if size == 0 {
                break;
            }
            let data = rest
                .get(i + 2..i + 2 + size)
                .ok_or_else(|| io::Error::other("short chunk"))?;
            out.extend_from_slice(data);
            rest = rest.get(i + 4 + size..).unwrap_or(&[]);
        }
        body = out;
    }
    Ok(Response { status, body })
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_plain_and_chunked() {
        let r = super::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hi"[..]));
        let r = super::parse(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1\r\nc\r\n0\r\n\r\n").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (201, &b"abc"[..]));
    }
}
