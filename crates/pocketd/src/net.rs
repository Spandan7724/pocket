//! Per-pocket host listeners for guest-initiated vsock streams: the egress proxy
//! (port 1026) and the read-only git transport (port 1027).

use std::path::Path;
use std::sync::{Arc, RwLock};

use pocket_net::mitm::Mitm;
use pocket_net::policy::{Policy, Rule};
use pocket_net::proxy::{Connector, ProxyCtx, Resolver, SystemResolver, TcpConnector};
use pocket_proto::frame::{MAX_FRAME, decode};
use pocket_proto::guest::{GIT_PORT, GitOpen, PROXY_PORT, ProxyOpen};
use pocket_proto::rpc::{ErrorCode, Event};
use pocket_store::PocketRecord;
use pocket_vmm::vsock::host_listener_path;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::daemon::{Daemon, R, err};

pub fn policy_for(profile: &str, allow: &[String]) -> R<Policy> {
    let mut p = Policy::profile(profile).ok_or_else(|| {
        err(
            ErrorCode::BadRequest,
            format!("unknown network profile {profile:?}"),
        )
        .hint(format!(
            "use one of: {}",
            pocket_net::policy::PROFILES.join(", ")
        ))
    })?;
    for a in allow {
        p.allow
            .push(Rule::parse(a).map_err(|e| err(ErrorCode::BadRequest, e.to_string()))?);
    }
    Ok(p)
}

/// Upstream resolver and connector. Debug builds honour `POCKETD_TEST_UPSTREAM`
/// (`host,host=127.0.0.1:port`) so integration tests can stand up fake HTTPS services on
/// loopback, which the always-denied ranges would otherwise (rightly) refuse.
pub fn upstream() -> (Arc<dyn Resolver>, Arc<dyn Connector>) {
    #[cfg(debug_assertions)]
    if let Ok(spec) = std::env::var("POCKETD_TEST_UPSTREAM")
        && let Some((hosts, addr)) = spec.split_once('=')
        && let Ok(addr) = addr.parse::<std::net::SocketAddr>()
    {
        let hosts: Vec<String> = hosts.split(',').map(String::from).collect();
        return (
            Arc::new(test_upstream::Dns(hosts)),
            Arc::new(test_upstream::Redirect(addr)),
        );
    }
    (Arc::new(SystemResolver), Arc::new(TcpConnector))
}

#[cfg(debug_assertions)]
mod test_upstream {
    use pocket_net::proxy::{ConnectFut, Connector, ResolveFut, Resolver, TcpConnector, Upstream};
    use std::net::{IpAddr, SocketAddr};

    /// TEST-NET-free public stand-in address for redirected names.
    const FAKE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 215, 14));

    pub struct Dns(pub Vec<String>);
    impl Resolver for Dns {
        fn resolve<'a>(&'a self, host: &'a str) -> ResolveFut<'a> {
            if self.0.iter().any(|h| h == host) {
                return Box::pin(async { Ok(vec![FAKE]) });
            }
            pocket_net::proxy::SystemResolver.resolve(host)
        }
    }

    pub struct Redirect(pub SocketAddr);
    impl Connector for Redirect {
        fn connect(&self, addr: SocketAddr) -> ConnectFut<'_> {
            if addr.ip() != FAKE {
                return TcpConnector.connect(addr);
            }
            let to = self.0;
            Box::pin(async move {
                Ok(Box::new(tokio::net::TcpStream::connect(to).await?) as Box<dyn Upstream>)
            })
        }
    }
}

pub fn proxy_ctx(
    d: &Arc<Daemon>,
    rec: &PocketRecord,
    allow: &[String],
    mitm: Option<Arc<Mitm>>,
) -> R<Arc<ProxyCtx>> {
    let policy = policy_for(&rec.info.net_profile, allow)?;
    let d2 = d.clone();
    let id = rec.info.id.clone();
    let (resolver, connector) = upstream();
    Ok(Arc::new(ProxyCtx {
        pocket: rec.info.name.clone(),
        policy: RwLock::new(policy),
        resolver,
        connector,
        log: Box::new(move |e| {
            tracing::info!(
                "net {}: {:?} {} {}:{} {}{}",
                e.pocket,
                e.verdict,
                e.kind,
                e.host,
                e.port,
                e.reason,
                e.path
                    .as_deref()
                    .map(|p| format!(" {p}"))
                    .unwrap_or_default()
            );
            let _ = d2.db(|s| s.log_net(&id, &e));
            d2.emit(Event::Net(e));
        }),
        mitm,
        on_block: {
            let d3 = d.clone();
            let name = rec.info.name.clone();
            Some(Box::new(move |host: &str, port: u16, why: &str| {
                d3.request_network_approval(&name, host, Some(port), why);
            }))
        },
    }))
}

fn bind(path: &Path) -> R<UnixListener> {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).map_err(|e| {
        err(
            ErrorCode::HostSetup,
            format!("listen on {}: {e}", path.display()),
        )
    })
}

async fn first_frame<T: serde::de::DeserializeOwned + pocket_proto::frame::Validate>(
    s: &mut UnixStream,
) -> Option<T> {
    let read = async {
        let len = s.read_u32().await.ok()? as usize;
        if len > MAX_FRAME.min(4096) {
            return None;
        }
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await.ok()?;
        decode(&buf).ok()
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), read)
        .await
        .ok()
        .flatten()
}

pub fn listen(
    d: &Arc<Daemon>,
    rec: &PocketRecord,
    vsock_uds: &Path,
    proxy: Arc<ProxyCtx>,
) -> R<Vec<JoinHandle<()>>> {
    let mut tasks = vec![];
    let l = bind(&host_listener_path(vsock_uds, PROXY_PORT))?;
    tasks.push(tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let ctx = proxy.clone();
            tokio::spawn(async move {
                match first_frame::<ProxyOpen>(&mut s).await {
                    Some(ProxyOpen::HttpProxy) => pocket_net::proxy::serve(s, ctx).await,
                    other => tracing::warn!("{}: rejected proxy stream {other:?}", ctx.pocket),
                }
            });
        }
    }));
    if let Some(repo) = rec.info.repo_path.clone() {
        let repo =
            pocket_git::git_dir(&repo).map_err(|e| err(ErrorCode::Workspace, e.to_string()))?;
        let l = bind(&host_listener_path(vsock_uds, GIT_PORT))?;
        let name = rec.info.name.clone();
        let _ = d;
        tasks.push(tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (repo, name) = (repo.clone(), name.clone());
                tokio::spawn(async move {
                    if first_frame::<GitOpen>(&mut s).await.is_none() {
                        tracing::warn!("{name}: rejected git stream");
                        return;
                    }
                    if let Err(e) = serve_upload_pack(s, &repo).await {
                        tracing::warn!("{name}: git upload-pack: {e}");
                    }
                });
            }
        }));
    }
    Ok(tasks)
}

/// Read-only `git upload-pack` on the pocket's own repository; the guest picks no path.
async fn serve_upload_pack(s: UnixStream, repo: &Path) -> std::io::Result<()> {
    let mut cmd = tokio::process::Command::from(pocket_git::upload_pack(repo));
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stderr = child.stderr.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (mut r, mut w) = s.into_split();
    let up = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut r, &mut stdin).await;
    });
    let _ = tokio::io::copy(&mut stdout, &mut w).await;
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut w).await;
    up.abort();
    let st = child.wait().await?;
    if !st.success() {
        let mut msg = String::new();
        let _ = tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut msg).await;
        return Err(std::io::Error::other(format!("{st}: {}", msg.trim())));
    }
    Ok(())
}
