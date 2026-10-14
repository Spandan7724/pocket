//! Blocking host-side client for the guest protocol, used by the integration tests.
//! Every guest frame goes through `pocket_proto::frame::recv` (size limit + validation),
//! the same decoders pocketd will use.

use std::io::ErrorKind as IoKind;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::*;
use pocket_vmm::vsock;

pub struct Control {
    conn: UnixStream,
    next_id: u64,
    pub init_version: String,
    pub boot_ns: u64,
    pub init_ns: u64,
    pub events: Vec<GuestEvent>,
}

impl Control {
    pub fn connect(vsock_uds: &Path, timeout: Duration) -> Control {
        let mut conn = vsock::connect_retry(vsock_uds, CONTROL_PORT, timeout)
            .unwrap_or_else(|e| panic!("control connect: {e}"));
        conn.set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let Some(GuestMsg::Hello {
            proto_version,
            init_version,
        }) = recv(&mut conn).unwrap()
        else {
            panic!("guest did not say Hello first");
        };
        assert_eq!(proto_version, PROTO_VERSION);
        let Some(GuestMsg::Ready {
            boot_ns_since_kernel_start,
            init_ns,
        }) = recv(&mut conn).unwrap()
        else {
            panic!("guest did not send Ready after Hello");
        };
        send(
            &mut conn,
            &HostMsg::Hello {
                proto_version: PROTO_VERSION,
            },
        )
        .unwrap();
        Control {
            conn,
            next_id: 1,
            init_version,
            boot_ns: boot_ns_since_kernel_start,
            init_ns,
            events: vec![],
        }
    }

    pub fn send_req(&mut self, req: HostReq) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        send(&mut self.conn, &HostMsg::Request { id, req }).unwrap();
        id
    }

    pub fn wait_reply(&mut self, id: u64) -> Result<Reply, GuestError> {
        loop {
            match recv(&mut self.conn).unwrap() {
                Some(GuestMsg::Reply { id: rid, result }) if rid == id => return result,
                Some(GuestMsg::Event(e)) => self.events.push(e),
                Some(other) => panic!("unexpected message: {other:?}"),
                None => panic!("guest closed the control connection"),
            }
        }
    }

    pub fn request(&mut self, req: HostReq) -> Result<Reply, GuestError> {
        let id = self.send_req(req);
        self.wait_reply(id)
    }

    pub fn wait_event(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&GuestEvent) -> bool,
    ) -> GuestEvent {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(i) = self.events.iter().position(&pred) {
                return self.events.remove(i);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "timed out waiting for event; have {:?}",
                self.events
            );
            self.conn.set_read_timeout(Some(left)).unwrap();
            match recv::<_, GuestMsg>(&mut self.conn) {
                Ok(Some(GuestMsg::Event(e))) => self.events.push(e),
                Ok(other) => panic!("unexpected message: {other:?}"),
                Err(pocket_proto::ProtoError::Io(e))
                    if matches!(e.kind(), IoKind::WouldBlock | IoKind::TimedOut) => {}
                Err(e) => panic!("control: {e}"),
            }
            self.conn
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
        }
    }
}

pub fn open_stream(vsock_uds: &Path, open: StreamOpen) -> Result<UnixStream, GuestError> {
    let mut s = vsock::connect(vsock_uds, STREAM_PORT).expect("stream connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    send(&mut s, &open).unwrap();
    let StreamAck(ack) = recv(&mut s)
        .unwrap()
        .expect("guest closed before StreamAck");
    ack.map(|()| s)
}

pub fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[derive(Debug)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: ExitStatus,
    /// Arrival time of each stdout chunk, relative to the exec request.
    pub stdout_times: Vec<Duration>,
}

impl ExecResult {
    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

pub struct Exec {
    pub stream: UnixStream,
    pub pid: u32,
    started: Instant,
}

impl Exec {
    pub fn start(
        ctl: &mut Control,
        vsock_uds: &Path,
        a: &[&str],
        env: &[(&str, &str)],
        cwd: &str,
    ) -> Result<Exec, GuestError> {
        Exec::start_with(ctl, vsock_uds, a, env, cwd, None)
    }

    pub fn start_with(
        ctl: &mut Control,
        vsock_uds: &Path,
        a: &[&str],
        env: &[(&str, &str)],
        cwd: &str,
        pty: Option<PtySize>,
    ) -> Result<Exec, GuestError> {
        let started = Instant::now();
        let env = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let id = ctl.send_req(HostReq::Exec {
            argv: argv(a),
            env,
            cwd: cwd.into(),
            pty,
            user: None,
        });
        let Reply::ExecStarted { pid } = ctl.wait_reply(id)? else {
            panic!("expected ExecStarted")
        };
        let stream = open_stream(vsock_uds, StreamOpen::ExecIo { exec_id: id })?;
        Ok(Exec {
            stream,
            pid,
            started,
        })
    }

    pub fn from_stream(stream: UnixStream) -> Exec {
        Exec {
            stream,
            pid: 0,
            started: Instant::now(),
        }
    }

    pub fn send(&mut self, m: ExecIn) {
        send(&mut self.stream, &m).unwrap();
    }

    pub fn next_out(&mut self) -> Option<ExecOut> {
        recv(&mut self.stream).unwrap()
    }

    pub fn finish(mut self) -> ExecResult {
        let mut r = ExecResult {
            stdout: vec![],
            stderr: vec![],
            status: ExitStatus::Code(-1),
            stdout_times: vec![],
        };
        while let Some(m) = self.next_out() {
            match m {
                ExecOut::Stdout(d) => {
                    r.stdout.extend(d);
                    r.stdout_times.push(self.started.elapsed());
                }
                ExecOut::Stderr(d) => r.stderr.extend(d),
                ExecOut::Exited(s) => {
                    r.status = s;
                    break;
                }
            }
        }
        r
    }
}

pub fn exec(ctl: &mut Control, vsock_uds: &Path, a: &[&str]) -> ExecResult {
    let e = Exec::start(ctl, vsock_uds, a, &[], "/").unwrap_or_else(|e| panic!("exec {a:?}: {e}"));
    e.finish()
}

/// `sh -c script`, asserting exit 0; returns stdout.
pub fn sh(ctl: &mut Control, vsock_uds: &Path, script: &str) -> String {
    let r = exec(ctl, vsock_uds, &["/bin/sh", "-c", script]);
    assert_eq!(
        r.status,
        ExitStatus::Code(0),
        "`{script}` failed: stdout={} stderr={}",
        r.out(),
        String::from_utf8_lossy(&r.stderr)
    );
    r.out()
}

pub fn new_token() -> Vec<u8> {
    let mut t = vec![0u8; ATTACH_TOKEN_LEN];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut t).unwrap();
    t
}

pub struct Attach {
    pub stream: UnixStream,
    pub seen: Vec<u8>,
    pub exited: Option<ExitStatus>,
}

impl Attach {
    /// Authorizes a one-time token over `ctl`, then attaches with it.
    pub fn open(
        ctl: &mut Control,
        vsock_uds: &Path,
        session: &str,
        size: PtySize,
        replay: bool,
    ) -> Result<Attach, GuestError> {
        let token = new_token();
        ctl.request(HostReq::AuthorizeAttach {
            session: session.into(),
            token: token.clone(),
        })?;
        Attach::open_with_token(vsock_uds, session, size, replay, token)
    }

    pub fn open_with_token(
        vsock_uds: &Path,
        session: &str,
        size: PtySize,
        replay: bool,
        token: Vec<u8>,
    ) -> Result<Attach, GuestError> {
        let stream = open_stream(
            vsock_uds,
            StreamOpen::Attach {
                session: session.into(),
                size,
                replay_scrollback: replay,
                token,
            },
        )?;
        Ok(Attach {
            stream,
            seen: vec![],
            exited: None,
        })
    }

    pub fn type_str(&mut self, s: &str) {
        send(&mut self.stream, &AttachIn::Data(s.as_bytes().to_vec())).unwrap();
    }

    pub fn resize(&mut self, size: PtySize) {
        send(&mut self.stream, &AttachIn::Resize(size)).unwrap();
    }

    /// Reads until `needle` appears in the output seen so far (after `from`).
    pub fn wait_for(&mut self, needle: &str, from: usize, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let text =
                String::from_utf8_lossy(&self.seen[from.min(self.seen.len())..]).into_owned();
            if text.contains(needle) {
                return text;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "timed out waiting for {needle:?}; output so far:\n{text}"
            );
            self.stream.set_read_timeout(Some(left)).unwrap();
            match recv::<_, AttachOut>(&mut self.stream) {
                Ok(Some(AttachOut::Data(d))) => self.seen.extend(d),
                Ok(Some(AttachOut::Exited(s))) => {
                    self.exited = Some(s);
                    assert!(
                        String::from_utf8_lossy(&self.seen).contains(needle),
                        "session exited before {needle:?}"
                    );
                }
                Ok(None) => panic!("attach stream closed while waiting for {needle:?}"),
                Err(pocket_proto::ProtoError::Io(e))
                    if matches!(e.kind(), IoKind::WouldBlock | IoKind::TimedOut) => {}
                Err(e) => panic!("attach: {e}"),
            }
        }
    }
}
