//! Opt-in ssh-agent forwarding (SECURITY.md §Secrets): the guest gets a socket whose
//! traffic reaches this filter, never the raw `SSH_AUTH_SOCK`. Listing identities passes;
//! every signature request waits for the user's approval; everything else (adding,
//! removing, locking keys, extensions) is refused.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pocket_proto::rpc::{ApprovalWhat, Decision};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::daemon::Daemon;

const REQUEST_IDENTITIES: u8 = 11;
const SIGN_REQUEST: u8 = 13;
const FAILURE: u8 = 5;
const MAX_MSG: usize = 256 * 1024;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// The agent pocketd forwards to (`POCKET_SSH_AUTH_SOCK`, else its `SSH_AUTH_SOCK`).
pub fn host_agent() -> Option<PathBuf> {
    std::env::var_os("POCKET_SSH_AUTH_SOCK")
        .or_else(|| std::env::var_os("SSH_AUTH_SOCK"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

async fn read_msg(s: &mut UnixStream) -> Option<Vec<u8>> {
    let len = s.read_u32().await.ok()? as usize;
    if len == 0 || len > MAX_MSG {
        return None;
    }
    let mut b = vec![0u8; len];
    s.read_exact(&mut b).await.ok()?;
    Some(b)
}

async fn write_msg(s: &mut UnixStream, body: &[u8]) -> bool {
    s.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .is_ok()
        && s.write_all(body).await.is_ok()
}

async fn ask_host(msg: &[u8]) -> Option<Vec<u8>> {
    let mut a = UnixStream::connect(host_agent()?).await.ok()?;
    if !write_msg(&mut a, msg).await {
        return None;
    }
    tokio::time::timeout(Duration::from_secs(30), read_msg(&mut a))
        .await
        .ok()
        .flatten()
}

/// `string` at `off` in an agent message: (bytes, next offset).
fn string(b: &[u8], off: usize) -> Option<(&[u8], usize)> {
    let len = u32::from_be_bytes(b.get(off..off + 4)?.try_into().ok()?) as usize;
    Some((b.get(off + 4..off + 4 + len)?, off + 4 + len))
}

fn fingerprint(blob: &[u8]) -> String {
    use base64::Engine as _;
    let d = Sha256::digest(blob);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(d)
    )
}

/// Comment of the key with this blob, from the host agent's identity list.
async fn comment_for(blob: &[u8]) -> String {
    let Some(r) = ask_host(&[REQUEST_IDENTITIES]).await else {
        return String::new();
    };
    let mut off = 5;
    let n = r
        .get(1..5)
        .and_then(|x| x.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    for _ in 0..n.min(1024) {
        let Some((k, o)) = string(&r, off) else { break };
        let Some((c, o2)) = string(&r, o) else { break };
        if k == blob {
            return String::from_utf8_lossy(c).chars().take(128).collect();
        }
        off = o2;
    }
    String::new()
}

async fn serve(d: Arc<Daemon>, pocket: String, mut s: UnixStream) {
    while let Some(msg) = read_msg(&mut s).await {
        let reply = match msg[0] {
            REQUEST_IDENTITIES => ask_host(&msg).await,
            SIGN_REQUEST => match string(&msg, 1) {
                Some((blob, _)) => {
                    let what = ApprovalWhat::SshSign {
                        key: fingerprint(blob),
                        comment: comment_for(blob).await,
                    };
                    match d.ask(&pocket, what, APPROVAL_TIMEOUT).await {
                        Decision::Deny => {
                            tracing::info!("{pocket}: ssh signature denied");
                            None
                        }
                        _ => {
                            tracing::info!("{pocket}: ssh signature approved");
                            ask_host(&msg).await
                        }
                    }
                }
                None => None,
            },
            other => {
                tracing::warn!("{pocket}: refused ssh-agent request type {other}");
                None
            }
        };
        if !write_msg(&mut s, &reply.unwrap_or_else(|| vec![FAILURE])).await {
            break;
        }
    }
}

pub fn listen(
    d: &Arc<Daemon>,
    pocket: &str,
    path: &std::path::Path,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    let (d, pocket) = (d.clone(), pocket.to_string());
    Ok(tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(serve(d.clone(), pocket.clone(), s));
        }
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_strings() {
        let mut m = vec![13u8, 0, 0, 0, 3, b'k', b'e', b'y'];
        m.extend_from_slice(&[0, 0, 0, 1, b'x']);
        let (k, o) = super::string(&m, 1).unwrap();
        assert_eq!((k, o), (&b"key"[..], 8));
        assert_eq!(super::string(&m, o).unwrap().0, b"x");
        assert!(super::string(&m, 12).is_none());
        assert!(super::fingerprint(b"key").starts_with("SHA256:"));
    }
}
