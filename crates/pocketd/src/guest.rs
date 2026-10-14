//! Async client for a pocket's `pocket-init` control connection. Every guest frame goes
//! through `pocket_proto::frame::decode` (size limit, no trailing bytes, validation).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pocket_proto::frame::{MAX_FRAME, decode, encode};
use pocket_proto::guest::{
    CONTROL_PORT, GuestError, GuestEvent, GuestMsg, HostMsg, HostReq, PROTO_VERSION, Reply,
};
use pocket_vmm::vsock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::{Mutex, mpsc, oneshot};

#[derive(Debug, thiserror::Error)]
pub enum GuestConnError {
    #[error("guest connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("guest protocol: {0}")]
    Proto(#[from] pocket_proto::ProtoError),
    #[error("guest speaks protocol {0}, pocketd speaks {PROTO_VERSION}; rebuild the system image")]
    Version(u32),
    #[error("guest sent {0} before Hello/Ready")]
    Handshake(String),
    #[error("guest connection closed")]
    Closed,
    #[error("guest did not answer within {0:?}")]
    Timeout(Duration),
    #[error("{0}")]
    Guest(GuestError),
}

type Pending = Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<Result<Reply, GuestError>>>>>;

pub struct GuestConn {
    writer: Mutex<tokio::net::unix::OwnedWriteHalf>,
    pending: Pending,
    next_id: AtomicU64,
    pub vsock_uds: PathBuf,
    pub init_version: String,
    pub boot_ns: u64,
}

pub async fn read_msg(r: &mut OwnedReadHalf) -> Result<Option<GuestMsg>, GuestConnError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(pocket_proto::ProtoError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        }
        .into());
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(decode(&buf)?))
}

impl GuestConn {
    /// Connects (retrying until `timeout`), does the Hello/Ready handshake and starts the
    /// reader task. Guest events go to `events`; the channel closes when the guest does.
    pub async fn connect(
        vsock_uds: &Path,
        timeout: Duration,
        events: mpsc::UnboundedSender<GuestEvent>,
    ) -> Result<Arc<GuestConn>, GuestConnError> {
        let s: UnixStream = vsock::connect_retry_async(vsock_uds, CONTROL_PORT, timeout).await?;
        let (mut r, mut w) = s.into_split();
        let hs = async {
            let (init_version, boot_ns) = match read_msg(&mut r).await? {
                Some(GuestMsg::Hello {
                    proto_version,
                    init_version,
                }) if proto_version == PROTO_VERSION => {
                    let boot = match read_msg(&mut r).await? {
                        Some(GuestMsg::Ready {
                            boot_ns_since_kernel_start,
                            ..
                        }) => boot_ns_since_kernel_start,
                        other => return Err(GuestConnError::Handshake(format!("{other:?}"))),
                    };
                    (init_version, boot)
                }
                Some(GuestMsg::Hello { proto_version, .. }) => {
                    return Err(GuestConnError::Version(proto_version));
                }
                other => return Err(GuestConnError::Handshake(format!("{other:?}"))),
            };
            Ok::<_, GuestConnError>((init_version, boot_ns))
        };
        let (init_version, boot_ns) = tokio::time::timeout(Duration::from_secs(10), hs)
            .await
            .map_err(|_| GuestConnError::Timeout(Duration::from_secs(10)))??;
        w.write_all(&encode(&HostMsg::Hello {
            proto_version: PROTO_VERSION,
        })?)
        .await?;
        let pending: Pending = Default::default();
        let p2 = pending.clone();
        tokio::spawn(async move {
            loop {
                match read_msg(&mut r).await {
                    Ok(Some(GuestMsg::Reply { id, result })) => {
                        if let Some(tx) = p2.lock().unwrap().remove(&id) {
                            let _ = tx.send(result);
                        }
                    }
                    Ok(Some(GuestMsg::Event(e))) => {
                        let _ = events.send(e);
                    }
                    Ok(Some(other)) => tracing::warn!("unexpected guest message {other:?}"),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!("guest control connection: {e}");
                        break;
                    }
                }
            }
            // Fail every waiter; senders dropped → receivers error.
            p2.lock().unwrap().clear();
        });
        Ok(Arc::new(GuestConn {
            writer: Mutex::new(w),
            pending,
            next_id: AtomicU64::new(1),
            vsock_uds: vsock_uds.to_path_buf(),
            init_version,
            boot_ns,
        }))
    }

    /// Sends `req`; returns its id (the exec id for `Exec`) and the reply.
    pub async fn request_id(
        &self,
        req: HostReq,
        timeout: Duration,
    ) -> Result<(u64, Reply), GuestConnError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let frame = encode(&HostMsg::Request { id, req })?;
        if let Err(e) = self.writer.lock().await.write_all(&frame).await {
            self.pending.lock().unwrap().remove(&id);
            return Err(e.into());
        }
        match tokio::time::timeout(timeout, rx).await {
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(GuestConnError::Timeout(timeout))
            }
            Ok(Err(_)) => Err(GuestConnError::Closed),
            Ok(Ok(Err(e))) => Err(GuestConnError::Guest(e)),
            Ok(Ok(Ok(r))) => Ok((id, r)),
        }
    }

    pub async fn request(&self, req: HostReq) -> Result<Reply, GuestConnError> {
        self.request_id(req, Duration::from_secs(30))
            .await
            .map(|(_, r)| r)
    }
}

pub struct ExecOutput {
    pub status: pocket_proto::guest::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    pub fn ok(&self) -> bool {
        self.status == pocket_proto::guest::ExitStatus::Code(0)
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

pub struct ExecReq<'a> {
    pub argv: &'a [&'a str],
    pub env: Vec<(String, String)>,
    pub cwd: &'a str,
    pub user: Option<&'a str>,
    pub stdin: Option<Vec<u8>>,
}

async fn read_frame<T: serde::de::DeserializeOwned + pocket_proto::frame::Validate>(
    r: &mut (impl AsyncReadExt + Unpin),
) -> Result<Option<T>, GuestConnError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(pocket_proto::ProtoError::FrameTooLarge {
            len,
            max: MAX_FRAME,
        }
        .into());
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(decode(&buf)?))
}

impl GuestConn {
    /// Starts a process and opens its `ExecIo` stream.
    pub async fn exec_stream(&self, req: ExecReq<'_>) -> Result<UnixStream, GuestConnError> {
        use pocket_proto::guest::{STREAM_PORT, StreamAck, StreamOpen};
        let (id, reply) = self
            .request_id(
                HostReq::Exec {
                    argv: req.argv.iter().map(|s| s.to_string()).collect(),
                    env: req.env,
                    cwd: req.cwd.into(),
                    pty: None,
                    user: req.user.map(String::from),
                },
                Duration::from_secs(30),
            )
            .await?;
        if !matches!(reply, Reply::ExecStarted { .. }) {
            return Err(GuestConnError::Handshake(format!("{reply:?}")));
        }
        let mut s = vsock::connect_async(&self.vsock_uds, STREAM_PORT).await?;
        s.write_all(&encode(&StreamOpen::ExecIo { exec_id: id })?)
            .await?;
        match read_frame::<StreamAck>(&mut s).await? {
            Some(StreamAck(Ok(()))) => {}
            Some(StreamAck(Err(e))) => return Err(GuestConnError::Guest(e)),
            None => return Err(GuestConnError::Closed),
        }
        if let Some(data) = req.stdin {
            use pocket_proto::guest::{ExecIn, MAX_CHUNK};
            for c in data.chunks(MAX_CHUNK) {
                s.write_all(&encode(&ExecIn::Stdin(c.to_vec()))?).await?;
            }
            s.write_all(&encode(&ExecIn::CloseStdin)?).await?;
        } else {
            s.write_all(&encode(&pocket_proto::guest::ExecIn::CloseStdin)?)
                .await?;
        }
        Ok(s)
    }

    /// Runs a process to completion, collecting output (stdout capped at `max_out`).
    pub async fn exec(&self, req: ExecReq<'_>, max_out: usize) -> Result<ExecOutput, GuestConnError> {
        use pocket_proto::guest::{ExecOut, ExitStatus};
        let mut s = self.exec_stream(req).await?;
        let mut out = ExecOutput {
            status: ExitStatus::Code(-1),
            stdout: vec![],
            stderr: vec![],
        };
        while let Some(m) = read_frame::<ExecOut>(&mut s).await? {
            match m {
                ExecOut::Stdout(d) => {
                    if out.stdout.len() < max_out {
                        out.stdout.extend(d);
                    }
                }
                ExecOut::Stderr(d) => {
                    if out.stderr.len() < 1 << 20 {
                        out.stderr.extend(d);
                    }
                }
                ExecOut::Exited(st) => {
                    out.status = st;
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Runs a process, writing its stdout to `sink`.
    pub async fn exec_to(
        &self,
        req: ExecReq<'_>,
        sink: &mut (impl AsyncWriteExt + Unpin),
    ) -> Result<ExecOutput, GuestConnError> {
        use pocket_proto::guest::{ExecOut, ExitStatus};
        let mut s = self.exec_stream(req).await?;
        let mut out = ExecOutput {
            status: ExitStatus::Code(-1),
            stdout: vec![],
            stderr: vec![],
        };
        while let Some(m) = read_frame::<ExecOut>(&mut s).await? {
            match m {
                ExecOut::Stdout(d) => sink.write_all(&d).await?,
                ExecOut::Stderr(d) => {
                    if out.stderr.len() < 1 << 20 {
                        out.stderr.extend(d);
                    }
                }
                ExecOut::Exited(st) => {
                    out.status = st;
                    break;
                }
            }
        }
        sink.flush().await?;
        Ok(out)
    }
}
