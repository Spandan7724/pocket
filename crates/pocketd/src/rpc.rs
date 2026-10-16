//! UDS RPC server (CONTRACTS.md §2): peer-cred check, `Hello` version handshake, requests
//! served concurrently, event subscriptions.

use std::sync::Arc;

use pocket_proto::rpc::{
    self, ClientMsg, DaemonMsg, ErrorCode, Event, RPC_VERSION, Request, Response, RpcError, Topic,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::daemon::{Daemon, err};
use crate::{doctor, presets, secrets};

pub async fn serve(d: Arc<Daemon>, l: UnixListener, stop: Arc<tokio::sync::Notify>) {
    loop {
        let s = match l.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!("accept: {e}");
                continue;
            }
        };
        // POCKETD_TEST_PEER_UID exercises the rejection path in tests (no second user).
        let uid = std::env::var("POCKETD_TEST_PEER_UID")
            .ok()
            .and_then(|u| u.parse().ok())
            .unwrap_or_else(|| unsafe { libc::getuid() });
        match s.peer_cred() {
            Ok(c) if c.uid() == uid => {}
            Ok(c) => {
                tracing::warn!("rejected connection from uid {}", c.uid());
                continue;
            }
            Err(e) => {
                tracing::warn!("peer credentials: {e}");
                continue;
            }
        }
        let (d, stop) = (d.clone(), stop.clone());
        tokio::spawn(async move {
            if let Err(e) = connection(d, s, stop).await {
                tracing::debug!("client connection: {e}");
            }
        });
    }
}

async fn read_msg(r: &mut tokio::net::unix::OwnedReadHalf) -> std::io::Result<Option<ClientMsg>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut buf = vec![0u8; rpc::frame_len(len)?];
    r.read_exact(&mut buf).await?;
    rpc::decode(&buf).map(Some)
}

async fn connection(
    d: Arc<Daemon>,
    s: UnixStream,
    stop: Arc<tokio::sync::Notify>,
) -> std::io::Result<()> {
    let (mut r, mut w) = s.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<DaemonMsg>();
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let Ok(frame) = rpc::encode(&m) else { continue };
            if w.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    match read_msg(&mut r).await? {
        Some(ClientMsg::Hello {
            proto_version,
            client,
        }) if proto_version == RPC_VERSION => {
            tracing::debug!("client {client}");
            let _ = tx.send(DaemonMsg::Hello {
                proto_version: RPC_VERSION,
                daemon_version: env!("CARGO_PKG_VERSION").into(),
            });
        }
        Some(ClientMsg::Hello { proto_version, .. }) => {
            let _ = tx.send(DaemonMsg::Response {
                id: 0,
                result: Err(err(
                    ErrorCode::VersionMismatch,
                    format!("pocket speaks RPC version {proto_version}, pocketd speaks {RPC_VERSION}"),
                )
                .hint("restart the daemon after upgrading: `pocket daemon stop`, then rerun your command")),
            });
            drop(tx);
            let _ = writer.await;
            return Ok(());
        }
        _ => return Ok(()),
    }
    while let Some(msg) = read_msg(&mut r).await? {
        match msg {
            ClientMsg::Hello { .. } | ClientMsg::Cancel { .. } => {}
            ClientMsg::Subscribe { id, topics } => {
                let mut ev = d.events.subscribe();
                let tx = tx.clone();
                let _ = tx.send(DaemonMsg::Response {
                    id,
                    result: Ok(Response::Done),
                });
                tokio::spawn(async move {
                    loop {
                        match ev.recv().await {
                            Ok((seq, event)) => {
                                let wanted = match &event {
                                    Event::Net(_) => topics.contains(&Topic::Net),
                                    _ => topics.contains(&Topic::Pockets),
                                };
                                if wanted && tx.send(DaemonMsg::Event { seq, event }).is_err() {
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        }
                    }
                });
            }
            ClientMsg::Request { id, req } => {
                let (d, tx, stop) = (d.clone(), tx.clone(), stop.clone());
                tokio::spawn(async move {
                    let ptx = tx.clone();
                    let progress = move |stage: &str| {
                        let _ = ptx.send(DaemonMsg::Progress {
                            id,
                            stage: stage.into(),
                            pct: None,
                        });
                    };
                    let is_stop = matches!(req, Request::DaemonStop);
                    let result = handle(&d, req, &progress).await;
                    let _ = tx.send(DaemonMsg::Response { id, result });
                    if is_stop {
                        stop.notify_one();
                    }
                });
            }
        }
    }
    drop(tx);
    writer.abort();
    Ok(())
}

async fn handle(
    d: &Arc<Daemon>,
    req: Request,
    progress: &(dyn Fn(&str) + Send + Sync),
) -> Result<Response, RpcError> {
    Ok(match req {
        Request::NewPocket(n) => Response::Pocket(d.new_pocket(n, progress).await?),
        Request::List => Response::Pockets(d.list()?),
        Request::Stop { pocket } => Response::Pocket(d.stop(&pocket).await?),
        Request::Start { pocket } => Response::Pocket(d.start(&pocket).await?),
        Request::Remove { pocket } => {
            d.remove(&pocket).await?;
            Response::Done
        }
        Request::Exec {
            pocket,
            argv,
            env,
            cwd,
            tty,
            root,
        } => {
            if argv.is_empty() {
                return Err(
                    err(ErrorCode::BadRequest, "nothing to run").hint("pass a command after `--`")
                );
            }
            let (exec_id, vsock_uds) = d.exec(&pocket, argv, env, cwd, tty, root).await?;
            Response::ExecStarted { exec_id, vsock_uds }
        }
        Request::SessionCreate {
            pocket,
            name,
            argv,
            rows,
            cols,
            term,
        } => Response::Session {
            name: d
                .session_create(&pocket, name, argv, rows, cols, term)
                .await?,
        },
        Request::SessionList { pocket } => Response::Sessions(d.sessions(&pocket).await?),
        Request::SessionKill {
            pocket,
            session,
            signal,
        } => {
            d.session_kill(&pocket, &session, signal).await?;
            Response::Done
        }
        Request::AttachAuthorize { pocket, session } => {
            let (session, vsock_uds, token) = d.attach_authorize(&pocket, session).await?;
            Response::Attach {
                session,
                vsock_uds,
                token,
            }
        }
        Request::NetLog { pocket, limit } => {
            let rec = d.find(&pocket)?;
            Response::NetLog(d.db(|s| s.net_log(&rec.info.id, &rec.info.name, limit))?)
        }
        Request::Pull { preset } => {
            let img = presets::pull(d, &preset, progress).await?;
            Response::Image {
                name: preset,
                digest: img.digest,
            }
        }
        Request::Diff {
            pocket,
            uncommitted,
            stat,
            color,
        } => Response::Text {
            text: crate::review::diff(d, &pocket, uncommitted, stat, color).await?,
            url: None,
        },
        Request::Apply {
            pocket,
            mode,
            onto,
            uncommitted,
            message,
        } => Response::Text {
            text: crate::review::apply(d, &pocket, mode, onto, uncommitted, message).await?,
            url: None,
        },
        Request::Pr {
            pocket,
            title,
            body,
            draft,
            base,
        } => {
            let (text, url) = crate::review::pr(d, &pocket, title, body, draft, base).await?;
            Response::Text {
                text,
                url: Some(url),
            }
        }
        Request::Sync { pocket, rebase } => Response::Text {
            text: crate::review::sync(d, &pocket, rebase).await?,
            url: None,
        },
        Request::ConfigPull { pocket, accept } => {
            Response::ConfigChanges(crate::agentcfg::pull(d, &pocket, accept).await?)
        }
        Request::SecretAdd(a) => Response::Secret(d.secret_add(a)?),
        Request::SecretList => Response::Secrets(
            d.db(|s| s.secrets())?
                .iter()
                .map(secrets::info_from_record)
                .collect(),
        ),
        Request::SecretRemove { name } => {
            d.secret_remove(&name)?;
            Response::Done
        }
        Request::SecretBind {
            name,
            hosts,
            env,
            header,
        } => Response::Secret(d.secret_bind(&name, &hosts, &env, &header)?),
        Request::Doctor => Response::Doctor(doctor::checks(d)),
        Request::DaemonStop => Response::Done,
    })
}
