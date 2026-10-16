//! Host integrations (M8): guest port events → runtime forwards on host loopback, URL
//! opening (http/https only, localhost URLs rewritten to their forwards), desktop
//! notifications, image paste, and the approvals queue shared by network requests and
//! ssh-agent signatures. Every guest event is hostile input and was validated on decode.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pocket_proto::guest::{ApprovalKind, GuestEvent, STREAM_PORT, StreamAck, StreamOpen};
use pocket_proto::rpc::{ApprovalInfo, ApprovalWhat, Decision, ErrorCode, Event, PortInfo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::daemon::{Daemon, Live, R, err, now_ms};

pub struct Forward {
    pub info: PortInfo,
    task: JoinHandle<()>,
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
pub struct HostState {
    pub ports: Mutex<BTreeMap<u16, Forward>>,
    pub auto_forward: bool,
    last_open: Mutex<Option<Instant>>,
}

impl HostState {
    pub fn new(auto_forward: bool) -> HostState {
        HostState {
            auto_forward,
            ..Default::default()
        }
    }
}

pub struct Pending {
    pub info: ApprovalInfo,
    pub waiter: Option<oneshot::Sender<Decision>>,
}

async fn splice(mut tcp: tokio::net::TcpStream, uds: std::path::PathBuf, port: u16) {
    let _ = tcp.set_nodelay(true);
    let Ok(mut s) = pocket_vmm::vsock::connect_async(&uds, STREAM_PORT).await else {
        return;
    };
    let Ok(frame) = pocket_proto::frame::encode(&StreamOpen::PortForward { port }) else {
        return;
    };
    if s.write_all(&frame).await.is_err() {
        return;
    }
    let ack = async {
        let len = s.read_u32().await.ok()? as usize;
        if len > 4096 {
            return None;
        }
        let mut b = vec![0u8; len];
        s.read_exact(&mut b).await.ok()?;
        pocket_proto::frame::decode::<StreamAck>(&b).ok()
    };
    match tokio::time::timeout(Duration::from_secs(10), ack).await {
        Ok(Some(StreamAck(Ok(())))) => {
            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut s).await;
        }
        _ => {
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    }
}

impl Daemon {
    /// Forwards host `127.0.0.1:<host>` (or a free port when taken and `auto`) to the guest.
    pub async fn forward_port(
        &self,
        live: &Arc<Live>,
        guest: u16,
        host: Option<u16>,
        process: Option<String>,
        auto: bool,
    ) -> R<PortInfo> {
        if let Some(f) = live.host.ports.lock().unwrap().get(&guest) {
            return Ok(f.info.clone());
        }
        let want = host.unwrap_or(guest);
        let l = match TcpListener::bind(("127.0.0.1", want)).await {
            Ok(l) => l,
            Err(_) if auto || host.is_none() => TcpListener::bind(("127.0.0.1", 0))
                .await
                .map_err(|e| err(ErrorCode::HostSetup, format!("bind a host port: {e}")))?,
            Err(e) => {
                return Err(err(
                    ErrorCode::BadRequest,
                    format!("host port {want} is not available: {e}"),
                )
                .hint("pick another host port: `pocket port POCKET GUEST:HOST`"));
            }
        };
        let hp = l.local_addr().map(|a| a.port()).unwrap_or(want);
        let uds = live.vm.vsock_uds.clone();
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                tokio::spawn(splice(tcp, uds.clone(), guest));
            }
        });
        let info = PortInfo {
            guest,
            host: hp,
            process,
            auto,
        };
        live.host.ports.lock().unwrap().insert(
            guest,
            Forward {
                info: info.clone(),
                task,
            },
        );
        tracing::info!("{}: forwarding 127.0.0.1:{hp} → guest :{guest}", live.name);
        self.emit(Event::Port {
            pocket: live.name.clone(),
            port: info.clone(),
            open: true,
        });
        Ok(info)
    }

    pub async fn guest_event(self: &Arc<Self>, live: &Arc<Live>, ev: GuestEvent) {
        match ev {
            GuestEvent::PortOpened { port, process, .. } => {
                if live.host.auto_forward
                    && let Err(e) = self.forward_port(live, port, None, process, true).await
                {
                    tracing::warn!("{}: forward port {port}: {}", live.name, e.message);
                }
            }
            GuestEvent::PortClosed { port, .. } => {
                let removed = {
                    let mut ports = live.host.ports.lock().unwrap();
                    match ports.get(&port) {
                        Some(f) if f.info.auto => ports.remove(&port),
                        _ => None,
                    }
                };
                if let Some(f) = removed {
                    self.emit(Event::Port {
                        pocket: live.name.clone(),
                        port: f.info.clone(),
                        open: false,
                    });
                }
            }
            GuestEvent::OpenUrl { url } => self.open_url(live, &url),
            GuestEvent::SessionBell { name } => {
                self.notice(live, Some(name), "bell", "pocket", "bell");
            }
            GuestEvent::Notify {
                session,
                title,
                body,
            } => {
                let title = if title.is_empty() {
                    format!("pocket · {}", live.name)
                } else {
                    title
                };
                self.notice(live, session, "notify", &title, &body);
            }
            GuestEvent::ApprovalRequest {
                kind: ApprovalKind::Host { host, port },
            } => {
                self.request_network_approval(
                    &live.name,
                    &host,
                    port,
                    "requested from inside the pocket",
                );
            }
            GuestEvent::ApprovalRequest {
                kind: ApprovalKind::File { path },
            } => {
                let info = ApprovalInfo {
                    id: self.next_approval(),
                    pocket: live.name.clone(),
                    what: ApprovalWhat::File { path },
                    created_ms: now_ms(),
                };
                self.approvals.lock().unwrap().push(Pending {
                    info: info.clone(),
                    waiter: None,
                });
                self.emit(Event::Approval(info));
            }
            GuestEvent::SessionExited { .. } | GuestEvent::Metrics { .. } => {}
        }
    }

    fn notice(&self, live: &Live, session: Option<String>, kind: &str, title: &str, body: &str) {
        self.emit(Event::Notice {
            pocket: live.name.clone(),
            session,
            kind: kind.into(),
            title: title.into(),
            body: body.into(),
        });
        if kind == "bell" {
            return;
        }
        let cmd = std::env::var("POCKET_NOTIFY_CMD").unwrap_or_else(|_| "notify-send".into());
        let _ = std::process::Command::new(cmd)
            .args(["-a", "pocket", title, body])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|mut c| {
                std::thread::spawn(move || c.wait());
            });
    }

    /// Opens an http(s) URL from the guest in the host browser, at most once a second;
    /// `localhost` URLs point at the matching host forward (OAuth callbacks, dev servers).
    fn open_url(&self, live: &Live, url: &str) {
        {
            let mut last = live.host.last_open.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                tracing::warn!("{}: URL open rate-limited", live.name);
                return;
            }
            *last = Some(Instant::now());
        }
        let url = rewrite_local(url, &live.host.ports.lock().unwrap());
        if !(url.starts_with("http://") || url.starts_with("https://"))
            || url.bytes().any(|b| !b.is_ascii_graphic())
        {
            return;
        }
        tracing::info!("{}: opening {url} on the host", live.name);
        let cmd = std::env::var("POCKET_OPEN_CMD").unwrap_or_else(|_| "xdg-open".into());
        let _ = std::process::Command::new(cmd)
            .arg(&url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|mut c| {
                std::thread::spawn(move || c.wait());
            });
        self.emit(Event::Notice {
            pocket: live.name.clone(),
            session: None,
            kind: "url".into(),
            title: "opened in your browser".into(),
            body: url,
        });
    }

    pub fn request_network_approval(&self, pocket: &str, host: &str, port: Option<u16>, why: &str) {
        let mut q = self.approvals.lock().unwrap();
        let dup = q.iter().any(|p| {
            p.info.pocket == pocket
                && matches!(&p.info.what, ApprovalWhat::Network { host: h, .. } if h == host)
        });
        if dup {
            return;
        }
        let info = ApprovalInfo {
            id: self.next_approval(),
            pocket: pocket.into(),
            what: ApprovalWhat::Network {
                host: host.into(),
                port,
                reason: why.chars().take(256).collect(),
            },
            created_ms: now_ms(),
        };
        q.push(Pending {
            info: info.clone(),
            waiter: None,
        });
        // Bounded: the oldest unanswered network requests fall off.
        while q.iter().filter(|p| p.info.pocket == pocket).count() > 64 {
            let i = q.iter().position(|p| p.info.pocket == pocket).unwrap();
            q.remove(i);
        }
        drop(q);
        self.emit(Event::Approval(info));
    }

    /// Queues a request that blocks its caller until answered (or `timeout`, = deny).
    pub async fn ask(&self, pocket: &str, what: ApprovalWhat, timeout: Duration) -> Decision {
        let (tx, rx) = oneshot::channel();
        let info = ApprovalInfo {
            id: self.next_approval(),
            pocket: pocket.into(),
            what,
            created_ms: now_ms(),
        };
        let id = info.id;
        self.approvals.lock().unwrap().push(Pending {
            info: info.clone(),
            waiter: Some(tx),
        });
        self.emit(Event::Approval(info));
        let d = tokio::time::timeout(timeout, rx).await;
        self.approvals.lock().unwrap().retain(|p| p.info.id != id);
        match d {
            Ok(Ok(d)) => d,
            _ => Decision::Deny,
        }
    }

    pub fn approvals_for(&self, pocket: Option<&str>) -> Vec<ApprovalInfo> {
        self.approvals
            .lock()
            .unwrap()
            .iter()
            .filter(|p| pocket.is_none_or(|n| p.info.pocket == n))
            .map(|p| p.info.clone())
            .collect()
    }

    pub async fn approve(self: &Arc<Self>, id: u64, decision: Decision) -> R<()> {
        let p = {
            let mut q = self.approvals.lock().unwrap();
            let i = q.iter().position(|p| p.info.id == id).ok_or_else(|| {
                err(ErrorCode::NotFound, format!("no pending request {id}"))
                    .hint("`pocket approvals` lists pending requests")
            })?;
            q.remove(i)
        };
        if let ApprovalWhat::Network { host, port, .. } = &p.info.what
            && decision != Decision::Deny
        {
            let rule = match port {
                Some(p) if *p != 443 && *p != 80 => format!("{host}:{p}"),
                _ => host.clone(),
            };
            self.net_allow(&p.info.pocket, &[rule], decision == Decision::Once)
                .await?;
        }
        if let ApprovalWhat::File { path } = &p.info.what
            && decision != Decision::Deny
        {
            self.copy_file_in(&p.info.pocket, path).await?;
        }
        if let Some(w) = p.waiter {
            let _ = w.send(decision);
        }
        self.emit(Event::ApprovalDone {
            id,
            pocket: p.info.pocket.clone(),
            decision,
        });
        Ok(())
    }

    pub async fn net_allow(self: &Arc<Self>, pocket: &str, hosts: &[String], once: bool) -> R<()> {
        let rec = self.find(pocket)?;
        let mut rules = vec![];
        for h in hosts {
            rules.push(
                pocket_net::policy::Rule::parse(h)
                    .map_err(|e| err(ErrorCode::BadRequest, e.to_string()))?,
            );
        }
        if let Some(live) = self.live(&rec.info.id) {
            live.proxy
                .policy
                .write()
                .unwrap()
                .allow
                .extend(rules.iter().cloned());
            if once {
                let (d, id, rules) = (self.clone(), rec.info.id.clone(), rules.clone());
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(120)).await;
                    if let Some(l) = d.live(&id) {
                        l.proxy
                            .policy
                            .write()
                            .unwrap()
                            .allow
                            .retain(|r| !rules.contains(r));
                    }
                });
            }
        }
        if !once {
            let mut meta = Daemon::meta(&rec);
            for h in hosts {
                if !meta.allow.contains(h) {
                    meta.allow.push(h.clone());
                }
            }
            self.save_meta(&rec.info.id, &meta)?;
        }
        let resolved: Vec<ApprovalInfo> = {
            let mut q = self.approvals.lock().unwrap();
            let (hit, keep): (Vec<_>, Vec<_>) =
                std::mem::take(&mut *q).into_iter().partition(|p| {
                    p.info.pocket == rec.info.name
                        && matches!(&p.info.what, ApprovalWhat::Network { host, port, .. }
                        if rules.iter().any(|r| r.allows(host, port.unwrap_or(443))))
                });
            *q = keep;
            hit.into_iter().map(|p| p.info).collect()
        };
        for i in resolved {
            self.emit(Event::ApprovalDone {
                id: i.id,
                pocket: i.pocket,
                decision: if once {
                    Decision::Once
                } else {
                    Decision::Pocket
                },
            });
        }
        tracing::info!(
            "{}: allowed {} ({})",
            rec.info.name,
            hosts.join(", "),
            if once { "2 min" } else { "pocket" }
        );
        Ok(())
    }

    pub async fn net_deny(&self, pocket: &str, hosts: &[String]) -> R<()> {
        let rec = self.find(pocket)?;
        let mut rules = vec![];
        for h in hosts {
            rules.push(
                pocket_net::policy::Rule::parse(h)
                    .map_err(|e| err(ErrorCode::BadRequest, e.to_string()))?,
            );
        }
        if let Some(live) = self.live(&rec.info.id) {
            let mut p = live.proxy.policy.write().unwrap();
            p.allow.retain(|r| !rules.contains(r));
            p.deny.extend(rules.iter().cloned());
        }
        let mut meta = Daemon::meta(&rec);
        meta.allow.retain(|a| !hosts.contains(a));
        for h in hosts {
            if !meta.deny.contains(h) {
                meta.deny.push(h.clone());
            }
        }
        self.save_meta(&rec.info.id, &meta)?;
        let mut q = self.approvals.lock().unwrap();
        let done: Vec<u64> = q
            .iter()
            .filter(|p| {
                p.info.pocket == rec.info.name
                    && matches!(&p.info.what, ApprovalWhat::Network { host, .. } if hosts.contains(host))
            })
            .map(|p| p.info.id)
            .collect();
        q.retain(|p| !done.contains(&p.info.id));
        drop(q);
        for id in done {
            self.emit(Event::ApprovalDone {
                id,
                pocket: rec.info.name.clone(),
                decision: Decision::Deny,
            });
        }
        Ok(())
    }

    /// Copies an approved host file to `/tmp/pocket-files/` in the pocket (regular files
    /// up to 64 MiB; the path the user approved is the one opened, symlinks resolved).
    async fn copy_file_in(&self, pocket: &str, path: &str) -> R<()> {
        let rec = self.find(pocket)?;
        let live = self.live(&rec.info.id).ok_or_else(|| {
            err(
                ErrorCode::InvalidState,
                format!("pocket {} is not running", rec.info.name),
            )
        })?;
        let real = std::fs::canonicalize(path)
            .map_err(|e| err(ErrorCode::NotFound, format!("{path}: {e}")))?;
        let meta = std::fs::metadata(&real)
            .map_err(|e| err(ErrorCode::NotFound, format!("{path}: {e}")))?;
        if !meta.is_file() || meta.len() > 64 << 20 {
            return Err(err(
                ErrorCode::BadRequest,
                format!("{path} is not a regular file up to 64 MiB"),
            ));
        }
        let data = std::fs::read(&real)
            .map_err(|e| err(ErrorCode::Internal, format!("read {path}: {e}")))?;
        let name: String = real
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into())
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let dest = format!("/tmp/pocket-files/{name}");
        crate::provision::sh_args(
            &live.guest,
            live.user.as_deref(),
            "set -e; mkdir -p /tmp/pocket-files; cat > \"$1.tmp\"; mv \"$1.tmp\" \"$1\"",
            &[&dest],
            data,
            "copy a host file in",
        )
        .await?;
        tracing::info!("{}: copied {} to {dest}", rec.info.name, real.display());
        self.emit(Event::Notice {
            pocket: rec.info.name.clone(),
            session: None,
            kind: "notify".into(),
            title: "copied into the pocket".into(),
            body: dest,
        });
        Ok(())
    }

    /// Writes a pasted image where the guest's clipboard shims serve it from.
    pub async fn paste_image(&self, pocket: &str, data: Vec<u8>) -> R<String> {
        let rec = self.find(pocket)?;
        let live = self.live(&rec.info.id).ok_or_else(|| {
            err(
                ErrorCode::InvalidState,
                format!("pocket {} is not running", rec.info.name),
            )
        })?;
        if data.len() > 32 << 20 || !data.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(err(
                ErrorCode::BadRequest,
                "only PNG images up to 32 MiB can be pasted",
            ));
        }
        let path = format!("/tmp/pocket-paste/paste-{}.png", now_ms());
        crate::provision::sh_args(
            &live.guest,
            live.user.as_deref(),
            "set -e; mkdir -p /tmp/pocket-paste; cat > \"$1.tmp\"; mv \"$1.tmp\" \"$1\"; ln -sfn \"$1\" /tmp/pocket-paste/latest.png",
            &[&path],
            data,
            "paste image",
        )
        .await?;
        Ok(path)
    }
}

/// `http://localhost:3000/cb` → `http://127.0.0.1:<host port>/cb` when 3000 is forwarded.
pub fn rewrite_local(url: &str, ports: &BTreeMap<u16, Forward>) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let Some((host, port)) = auth.rsplit_once(':') else {
        return url.to_string();
    };
    let Ok(port) = port.parse::<u16>() else {
        return url.to_string();
    };
    if !["localhost", "127.0.0.1", "[::1]", "0.0.0.0"].contains(&host) {
        return url.to_string();
    }
    match ports.get(&port) {
        Some(f) => format!("{scheme}://127.0.0.1:{}{path}", f.info.host),
        None => url.to_string(),
    }
}
