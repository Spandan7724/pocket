//! Host ↔ guest protocol over vsock (CONTRACTS.md §3).
//!
//! The host connects to [`CONTROL_PORT`]; the guest immediately sends [`GuestMsg::Hello`]
//! and [`GuestMsg::Ready`], the host answers [`HostMsg::Hello`], then sends requests and
//! receives replies and events. Each data stream is a separate connection to
//! [`STREAM_PORT`]: the host sends a [`StreamOpen`], the guest answers a [`StreamAck`],
//! then frames flow as [`AttachIn`]/[`AttachOut`] or [`ExecIn`]/[`ExecOut`].
//!
//! Guest-initiated streams go to the host (CID 2): [`PROXY_PORT`] starts with a
//! [`ProxyOpen`], [`GIT_PORT`] with a [`GitOpen`]; raw bytes follow.

use serde::{Deserialize, Serialize};

use crate::frame::Validate;
use crate::{ProtoError, invalid};

/// Bump on every change to the types in this module.
pub const PROTO_VERSION: u32 = 6;

pub const CONTROL_PORT: u32 = 1024;
pub const STREAM_PORT: u32 = 1025;
pub const PROXY_PORT: u32 = 1026;
pub const GIT_PORT: u32 = 1027;
/// Guest → host: raw ssh-agent protocol to pocketd's filtering agent (opt-in per pocket).
pub const SSH_AGENT_PORT: u32 = 1028;
/// Longest notification title / body.
pub const MAX_NOTIFY_TITLE: usize = 256;
pub const MAX_NOTIFY_BODY: usize = 1024;

pub const RNG_SEED_LEN: usize = 64;
/// `/etc/machine-id` format: 32 lowercase hex digits.
pub const MACHINE_ID_LEN: usize = 32;
pub const ATTACH_TOKEN_LEN: usize = 32;
/// Guest-side lifetime of an unused attach token.
pub const ATTACH_TOKEN_TTL_MS: u64 = 30_000;
pub const MAX_NAME: usize = 64;
pub const MAX_ARGS: usize = 4096;
pub const MAX_ENV: usize = 1024;
pub const MAX_STRING: usize = 64 * 1024;
pub const MAX_PATH: usize = 4096;
pub const MAX_URL: usize = 2048;
pub const MAX_HOSTNAME: usize = 253;
pub const MAX_ERROR_MESSAGE: usize = 4096;
pub const MAX_VERSION: usize = 64;
pub const MAX_SESSIONS: usize = 1024;
/// Largest output chunk the guest sends in one frame.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Largest file content in one `FileRead` reply or `FileWrite` request.
pub const MAX_FILE: usize = 960 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExitStatus {
    Code(i32),
    Signal(i32),
}

impl ExitStatus {
    /// Shell convention: 128 + signal number for signal deaths.
    pub fn code(self) -> i32 {
        match self {
            ExitStatus::Code(c) => c,
            ExitStatus::Signal(s) => 128 + s,
        }
    }
}

// ---- control connection, host → guest -------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostMsg {
    Hello { proto_version: u32 },
    Request { id: u64, req: HostReq },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostReq {
    Configure {
        hostname: String,
        rng_seed: Vec<u8>,
        time_unix_nanos: u128,
        env: Vec<(String, String)>,
        proxy_port: u16,
        machine_id: String,
        net_mode: NetMode,
    },
    /// The request id doubles as the exec id for [`StreamOpen::ExecIo`]. `user` is a
    /// guest account name (`None` = root).
    Exec {
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: String,
        pty: Option<PtySize>,
        user: Option<String>,
    },
    SessionCreate {
        name: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: String,
        size: PtySize,
        user: Option<String>,
    },
    /// One-time token for one [`StreamOpen::Attach`] to `session`, valid for
    /// [`ATTACH_TOKEN_TTL_MS`]. Every attach needs one, so only clients the daemon
    /// authorized can attach (the direct attach fast path skips the daemon otherwise).
    AuthorizeAttach {
        session: String,
        token: Vec<u8>,
    },
    SessionList,
    /// Signal 0 removes an exited session from the list.
    SessionKill {
        name: String,
        signal: i32,
    },
    FileRead {
        path: String,
        max_bytes: u64,
    },
    FileWrite {
        path: String,
        mode: u32,
        data: Vec<u8>,
    },
    /// Restore hook: first request after a restore (template clone, hibernation, pool).
    /// `clone` = the VM takes a new identity; sessions and processes from before are killed.
    Restored {
        generation: u64,
        rng_seed: Vec<u8>,
        time_unix_nanos: u128,
        hostname: String,
        machine_id: String,
        clone: bool,
    },
    /// Sent before a snapshot: until the next `Restored`, the guest refuses `Configure`,
    /// `Exec`, `SessionCreate` and `AuthorizeAttach`, so a restored VM runs nothing for a
    /// user before the restore hook.
    Seal,
    /// SIGTERM everything, SIGKILL after `timeout_ms`, unmount cleanly, reply, power off.
    Shutdown {
        timeout_ms: u32,
    },
}

// ---- control connection, guest → host -------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GuestMsg {
    Hello {
        proto_version: u32,
        init_version: String,
    },
    /// Boot measurement point. Both values are guest `CLOCK_BOOTTIME`-based.
    Ready {
        boot_ns_since_kernel_start: u64,
        init_ns: u64,
    },
    Reply {
        id: u64,
        result: Result<Reply, GuestError>,
    },
    Event(GuestEvent),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Done,
    ExecStarted { pid: u32 },
    SessionCreated { pid: u32 },
    Sessions(Vec<SessionInfo>),
    File { data: Vec<u8>, truncated: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub name: String,
    pub pid: u32,
    pub argv: Vec<String>,
    pub created_unix_ms: u64,
    pub size: PtySize,
    pub attached: u32,
    pub exited: Option<ExitStatus>,
    /// Last PTY output (0 = none yet); drives idle detection and session states.
    pub last_output_unix_ms: u64,
    /// Last bell / OSC 9 / OSC 777 from the session (an agent asking for attention).
    pub last_bell_unix_ms: u64,
    /// Last line of output, escape sequences stripped (≤ [`MAX_TAIL`] bytes): prompt check.
    pub tail: String,
}

pub const MAX_TAIL: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    InvalidRequest,
    NotFound,
    AlreadyExists,
    Io,
    Unsupported,
    VersionMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestError {
    pub kind: ErrorKind,
    pub message: String,
}

impl GuestError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_ERROR_MESSAGE {
            let mut cut = MAX_ERROR_MESSAGE;
            while !message.is_char_boundary(cut) {
                cut -= 1;
            }
            message.truncate(cut);
        }
        GuestError { kind, message }
    }
}

impl std::fmt::Display for GuestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for GuestError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalKind {
    Host {
        host: String,
        port: Option<u16>,
    },
    /// Copy this host file into the pocket (`pocket-guest request-file`).
    File {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GuestEvent {
    SessionExited {
        name: String,
        status: ExitStatus,
    },
    /// Bell / OSC 9 / OSC 777 → host notification.
    SessionBell {
        name: String,
    },
    /// OSC 9 / OSC 777 notification text from a session, or `pocket-guest notify`.
    Notify {
        session: Option<String>,
        title: String,
        body: String,
    },
    PortOpened {
        port: u16,
        proto: Proto,
        process: Option<String>,
    },
    PortClosed {
        port: u16,
        proto: Proto,
    },
    /// From the xdg-open shim; host also re-checks the scheme before opening anything.
    OpenUrl {
        url: String,
    },
    ApprovalRequest {
        kind: ApprovalKind,
    },
    Metrics {
        cpu_pct: f32,
        mem_used: u64,
        disk_used: u64,
    },
}

// ---- data streams -----------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamOpen {
    Attach {
        session: String,
        size: PtySize,
        replay_scrollback: bool,
        token: Vec<u8>,
    },
    ExecIo {
        exec_id: u64,
    },
    PortForward {
        port: u16,
    },
    GitUploadPack {
        repo: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamAck(pub Result<(), GuestError>);

/// How guest traffic leaves (ARCHITECTURE.md §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NetMode {
    /// Proxy environment variables only.
    #[default]
    Proxy,
    /// Also a TUN default route: every TCP connection and DNS query is redirected to
    /// pocket-init and leaves as a `ProxyOpen::Direct` / `Dns` stream.
    Transparent,
    /// A real NIC (passt); traffic outside the proxy variables is not policed.
    Full,
}

/// Host → guest answer on a `ProxyOpen::Dns` stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsReply(pub Result<(), String>);

pub const MAX_REASON: usize = 512;

/// First frame of a guest → host [`PROXY_PORT`] stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyOpen {
    /// Env-proxy mode: an HTTP proxy conversation (CONNECT or absolute-form) follows; the
    /// host parses it and applies the policy.
    HttpProxy,
    /// Transparent mode (M11): a TCP stream to this destination follows.
    Direct {
        host: String,
        port: u16,
        sni: Option<String>,
    },
    /// Transparent mode: may the guest resolve `name`? The host checks the policy, logs,
    /// resolves, and answers one [`DnsReply`]; the guest hands out a local address.
    Dns { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitService {
    UploadPack,
}

/// First frame of a guest → host [`GIT_PORT`] stream. The host serves only the pocket's
/// own repository, read-only; the guest cannot name a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitOpen {
    pub service: GitService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachIn {
    Data(Vec<u8>),
    Resize(PtySize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachOut {
    Data(Vec<u8>),
    Exited(ExitStatus),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecIn {
    Stdin(Vec<u8>),
    CloseStdin,
    Signal(i32),
    Resize(PtySize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecOut {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited(ExitStatus),
}

// ---- validation -------------------------------------------------------------------------

/// Session names: `[A-Za-z0-9._-]{1,64}`, not starting with `.` or `-`.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && !s.starts_with(['.', '-'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// RFC 1123 host name (also accepts a single label).
pub fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_HOSTNAME
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn valid_machine_id(s: &str) -> bool {
    s.len() == MACHINE_ID_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn check(ok: bool, what: &str) -> Result<(), ProtoError> {
    if ok { Ok(()) } else { Err(invalid(what)) }
}

fn text(s: &str, max: usize, what: &str) -> Result<(), ProtoError> {
    check(s.len() <= max && !s.contains('\0'), what)
}

fn signal(sig: i32) -> Result<(), ProtoError> {
    check((1..=64).contains(&sig), "signal out of range")
}

fn status(s: &ExitStatus) -> Result<(), ProtoError> {
    match *s {
        ExitStatus::Code(c) => check((0..=255).contains(&c), "exit code out of range"),
        ExitStatus::Signal(sig) => signal(sig),
    }
}

fn size(s: &PtySize) -> Result<(), ProtoError> {
    check(s.rows > 0 && s.cols > 0, "terminal size must be non-zero")
}

fn argv(a: &[String]) -> Result<(), ProtoError> {
    check(
        !a.is_empty() && a.len() <= MAX_ARGS,
        "argv must have 1..=4096 entries",
    )?;
    check(!a[0].is_empty(), "argv[0] is empty")?;
    a.iter()
        .try_for_each(|s| text(s, MAX_STRING, "argv entry too long or contains NUL"))
}

fn env(e: &[(String, String)]) -> Result<(), ProtoError> {
    check(e.len() <= MAX_ENV, "too many environment variables")?;
    for (k, v) in e {
        check(
            !k.is_empty() && !k.contains('=') && k.len() <= 256 && !k.contains('\0'),
            "invalid environment variable name",
        )?;
        text(v, MAX_STRING, "environment value too long or contains NUL")?;
    }
    Ok(())
}

fn abs_path(p: &str) -> Result<(), ProtoError> {
    check(p.starts_with('/'), "path must be absolute")?;
    text(p, MAX_PATH, "path too long or contains NUL")
}

fn seed(s: &[u8]) -> Result<(), ProtoError> {
    check(s.len() == RNG_SEED_LEN, "rng seed must be 64 bytes")
}

fn user(u: &Option<String>) -> Result<(), ProtoError> {
    u.as_deref()
        .map_or(Ok(()), |u| check(valid_name(u), "invalid user name"))
}

fn token(t: &[u8]) -> Result<(), ProtoError> {
    check(t.len() == ATTACH_TOKEN_LEN, "attach token must be 32 bytes")
}

fn error(e: &GuestError) -> Result<(), ProtoError> {
    text(&e.message, MAX_ERROR_MESSAGE, "error message too long")
}

/// Guest-side check of host requests (the host is trusted; this catches bugs early).
impl Validate for HostMsg {
    fn validate(&self) -> Result<(), ProtoError> {
        let HostMsg::Request { req, .. } = self else {
            return Ok(());
        };
        match req {
            HostReq::Configure {
                hostname,
                rng_seed,
                env: e,
                machine_id,
                ..
            } => {
                check(valid_hostname(hostname), "invalid hostname")?;
                check(valid_machine_id(machine_id), "invalid machine id")?;
                seed(rng_seed)?;
                env(e)
            }
            HostReq::Exec {
                argv: a,
                env: e,
                cwd,
                pty,
                user: u,
            } => {
                argv(a)?;
                env(e)?;
                abs_path(cwd)?;
                user(u)?;
                pty.as_ref().map_or(Ok(()), size)
            }
            HostReq::SessionCreate {
                name,
                argv: a,
                env: e,
                cwd,
                size: s,
                user: u,
            } => {
                check(valid_name(name), "invalid session name")?;
                argv(a)?;
                env(e)?;
                abs_path(cwd)?;
                user(u)?;
                size(s)
            }
            HostReq::AuthorizeAttach { session, token: t } => {
                check(valid_name(session), "invalid session name")?;
                token(t)
            }
            HostReq::SessionList => Ok(()),
            HostReq::SessionKill { name, signal: sig } => {
                check(valid_name(name), "invalid session name")?;
                if *sig == 0 { Ok(()) } else { signal(*sig) }
            }
            HostReq::FileRead { path, .. } => abs_path(path),
            HostReq::FileWrite { path, mode, data } => {
                abs_path(path)?;
                check(*mode <= 0o7777, "invalid file mode")?;
                check(data.len() <= MAX_FILE, "file too large")
            }
            HostReq::Restored {
                rng_seed,
                hostname,
                machine_id,
                ..
            } => {
                seed(rng_seed)?;
                check(valid_machine_id(machine_id), "invalid machine id")?;
                check(valid_hostname(hostname), "invalid hostname")
            }
            HostReq::Seal | HostReq::Shutdown { .. } => Ok(()),
        }
    }
}

impl Validate for GuestMsg {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            GuestMsg::Hello { init_version, .. } => check(
                !init_version.is_empty()
                    && init_version.len() <= MAX_VERSION
                    && init_version.bytes().all(|b| b.is_ascii_graphic()),
                "invalid init version",
            ),
            GuestMsg::Ready {
                boot_ns_since_kernel_start,
                init_ns,
            } => check(
                init_ns <= boot_ns_since_kernel_start,
                "init time exceeds boot time",
            ),
            GuestMsg::Reply { result: Err(e), .. } => error(e),
            GuestMsg::Reply { result: Ok(r), .. } => match r {
                Reply::Done | Reply::ExecStarted { .. } | Reply::SessionCreated { .. } => Ok(()),
                Reply::Sessions(list) => {
                    check(list.len() <= MAX_SESSIONS, "too many sessions")?;
                    for s in list {
                        check(valid_name(&s.name), "invalid session name")?;
                        check(
                            s.tail.len() <= MAX_TAIL && !s.tail.chars().any(char::is_control),
                            "invalid session tail",
                        )?;
                        argv(&s.argv)?;
                        size(&s.size)?;
                        s.exited.as_ref().map_or(Ok(()), status)?;
                    }
                    Ok(())
                }
                Reply::File { data, .. } => check(data.len() <= MAX_FILE, "file too large"),
            },
            GuestMsg::Event(e) => e.validate(),
        }
    }
}

impl Validate for GuestEvent {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            GuestEvent::SessionExited { name, status: s } => {
                check(valid_name(name), "invalid session name")?;
                status(s)
            }
            GuestEvent::SessionBell { name } => check(valid_name(name), "invalid session name"),
            GuestEvent::Notify {
                session,
                title,
                body,
            } => {
                session
                    .as_deref()
                    .map_or(Ok(()), |n| check(valid_name(n), "invalid session name"))?;
                let printable = |t: &str| !t.chars().any(|c| c.is_control() && c != '\n');
                check(
                    title.len() <= MAX_NOTIFY_TITLE && printable(title),
                    "invalid notification title",
                )?;
                check(
                    body.len() <= MAX_NOTIFY_BODY && printable(body),
                    "invalid notification body",
                )
            }
            GuestEvent::PortOpened { port, process, .. } => {
                check(*port != 0, "port 0")?;
                process
                    .as_deref()
                    .map_or(Ok(()), |p| text(p, 256, "process name too long"))
            }
            GuestEvent::PortClosed { port, .. } => check(*port != 0, "port 0"),
            GuestEvent::OpenUrl { url } => check(
                url.len() <= MAX_URL
                    && (url.starts_with("http://") || url.starts_with("https://"))
                    && url.bytes().all(|b| b.is_ascii_graphic()),
                "url must be printable http(s) and at most 2048 bytes",
            ),
            GuestEvent::ApprovalRequest {
                kind: ApprovalKind::Host { host, port },
            } => {
                check(valid_hostname(host), "invalid host")?;
                check(*port != Some(0), "port 0")
            }
            GuestEvent::ApprovalRequest {
                kind: ApprovalKind::File { path },
            } => {
                abs_path(path)?;
                check(
                    !path.chars().any(char::is_control),
                    "path contains control characters",
                )
            }
            GuestEvent::Metrics { cpu_pct, .. } => check(
                cpu_pct.is_finite() && (0.0..=100_000.0).contains(cpu_pct),
                "cpu percentage out of range",
            ),
        }
    }
}

impl Validate for StreamOpen {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            StreamOpen::Attach {
                session,
                size: s,
                token: t,
                ..
            } => {
                check(valid_name(session), "invalid session name")?;
                token(t)?;
                size(s)
            }
            StreamOpen::ExecIo { .. } => Ok(()),
            StreamOpen::PortForward { port } => check(*port != 0, "port 0"),
            StreamOpen::GitUploadPack { repo } => abs_path(repo),
        }
    }
}

/// Host-side check of the guest's proxy stream header (hostile input).
impl Validate for ProxyOpen {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            ProxyOpen::HttpProxy => Ok(()),
            ProxyOpen::Direct { host, port, sni } => {
                check(*port != 0, "port 0")?;
                check(
                    valid_hostname(host) || host.parse::<std::net::IpAddr>().is_ok(),
                    "invalid destination host",
                )?;
                sni.as_deref()
                    .map_or(Ok(()), |s| check(valid_hostname(s), "invalid SNI"))
            }
            ProxyOpen::Dns { name } => check(valid_hostname(name), "invalid DNS name"),
        }
    }
}

impl Validate for DnsReply {
    fn validate(&self) -> Result<(), ProtoError> {
        match &self.0 {
            Ok(()) => Ok(()),
            Err(r) => check(r.len() <= MAX_REASON, "reason too long"),
        }
    }
}

impl Validate for GitOpen {
    fn validate(&self) -> Result<(), ProtoError> {
        Ok(())
    }
}

impl Validate for StreamAck {
    fn validate(&self) -> Result<(), ProtoError> {
        self.0.as_ref().err().map_or(Ok(()), error)
    }
}

impl Validate for AttachIn {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            AttachIn::Data(d) => check(d.len() <= MAX_CHUNK, "chunk too large"),
            AttachIn::Resize(s) => size(s),
        }
    }
}

impl Validate for AttachOut {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            AttachOut::Data(d) => check(d.len() <= MAX_CHUNK, "chunk too large"),
            AttachOut::Exited(s) => status(s),
        }
    }
}

impl Validate for ExecIn {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            ExecIn::Stdin(d) => check(d.len() <= MAX_CHUNK, "chunk too large"),
            ExecIn::CloseStdin => Ok(()),
            ExecIn::Signal(s) => signal(*s),
            ExecIn::Resize(s) => size(s),
        }
    }
}

impl Validate for ExecOut {
    fn validate(&self) -> Result<(), ProtoError> {
        match self {
            ExecOut::Stdout(d) | ExecOut::Stderr(d) => {
                check(d.len() <= MAX_CHUNK, "chunk too large")
            }
            ExecOut::Exited(s) => status(s),
        }
    }
}

/// Every decoder the host runs on guest-controlled bytes; the fuzz target drives this.
pub fn decode_any_from_guest(payload: &[u8]) {
    use crate::frame::decode;
    let _ = decode::<GuestMsg>(payload);
    let _ = decode::<StreamAck>(payload);
    let _ = decode::<AttachOut>(payload);
    let _ = decode::<ExecOut>(payload);
    let _ = decode::<ProxyOpen>(payload);
    let _ = decode::<GitOpen>(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameReader, MAX_FRAME, decode, encode, read_frame};
    use std::fmt::Debug;

    fn roundtrip<T>(msg: T)
    where
        T: Serialize + serde::de::DeserializeOwned + Validate + PartialEq + Debug,
    {
        let frame = encode(&msg).unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, frame.len() - 4);
        let back: T = decode(&frame[4..]).unwrap();
        assert_eq!(back, msg);
    }

    fn sz() -> PtySize {
        PtySize { rows: 24, cols: 80 }
    }

    fn seed64() -> Vec<u8> {
        (0..64).collect()
    }

    #[test]
    fn host_messages_roundtrip() {
        let env = vec![("TERM".to_string(), "xterm-256color".to_string())];
        let reqs = vec![
            HostReq::Configure {
                hostname: "webapp-1".into(),
                rng_seed: seed64(),
                time_unix_nanos: 1_760_000_000_000_000_000,
                env: env.clone(),
                proxy_port: 3128,
                machine_id: "0123456789abcdef0123456789abcdef".into(),
                net_mode: NetMode::Transparent,
            },
            HostReq::Exec {
                argv: vec!["sh".into(), "-c".into(), "true".into()],
                env: env.clone(),
                cwd: "/work".into(),
                pty: Some(sz()),
                user: Some("dev".into()),
            },
            HostReq::SessionCreate {
                name: "claude".into(),
                argv: vec!["claude".into()],
                env,
                cwd: "/work".into(),
                size: sz(),
                user: None,
            },
            HostReq::AuthorizeAttach {
                session: "claude".into(),
                token: vec![7; ATTACH_TOKEN_LEN],
            },
            HostReq::SessionList,
            HostReq::SessionKill {
                name: "claude".into(),
                signal: 15,
            },
            HostReq::FileRead {
                path: "/etc/hostname".into(),
                max_bytes: 4096,
            },
            HostReq::FileWrite {
                path: "/tmp/x".into(),
                mode: 0o644,
                data: vec![1, 2, 3],
            },
            HostReq::Restored {
                generation: 7,
                rng_seed: seed64(),
                time_unix_nanos: u128::MAX,
                hostname: "a".into(),
                machine_id: "fedcba9876543210fedcba9876543210".into(),
                clone: true,
            },
            HostReq::Seal,
            HostReq::Shutdown { timeout_ms: 2000 },
        ];
        roundtrip(HostMsg::Hello {
            proto_version: PROTO_VERSION,
        });
        for (i, req) in reqs.into_iter().enumerate() {
            roundtrip(HostMsg::Request { id: i as u64, req });
        }
    }

    #[test]
    fn guest_messages_roundtrip() {
        let msgs = vec![
            GuestMsg::Hello {
                proto_version: PROTO_VERSION,
                init_version: "0.0.0".into(),
            },
            GuestMsg::Ready {
                boot_ns_since_kernel_start: 50_000_000,
                init_ns: 2_000_000,
            },
            GuestMsg::Reply {
                id: 1,
                result: Ok(Reply::Done),
            },
            GuestMsg::Reply {
                id: 2,
                result: Ok(Reply::ExecStarted { pid: 42 }),
            },
            GuestMsg::Reply {
                id: 3,
                result: Ok(Reply::Sessions(vec![SessionInfo {
                    name: "shell".into(),
                    pid: 7,
                    argv: vec!["/bin/sh".into()],
                    created_unix_ms: 1,
                    size: sz(),
                    attached: 1,
                    exited: Some(ExitStatus::Signal(9)),
                    last_output_unix_ms: 2,
                    last_bell_unix_ms: 1,
                    tail: "$ ".into(),
                }])),
            },
            GuestMsg::Reply {
                id: 4,
                result: Ok(Reply::File {
                    data: vec![0; 10],
                    truncated: true,
                }),
            },
            GuestMsg::Reply {
                id: 5,
                result: Err(GuestError::new(ErrorKind::NotFound, "no such session")),
            },
            GuestMsg::Event(GuestEvent::SessionExited {
                name: "shell".into(),
                status: ExitStatus::Code(0),
            }),
            GuestMsg::Event(GuestEvent::SessionBell {
                name: "shell".into(),
            }),
            GuestMsg::Event(GuestEvent::PortOpened {
                port: 5173,
                proto: Proto::Tcp,
                process: Some("node".into()),
            }),
            GuestMsg::Event(GuestEvent::PortClosed {
                port: 5173,
                proto: Proto::Udp,
            }),
            GuestMsg::Event(GuestEvent::OpenUrl {
                url: "https://example.com/a?b=c".into(),
            }),
            GuestMsg::Event(GuestEvent::ApprovalRequest {
                kind: ApprovalKind::Host {
                    host: "pypi.org".into(),
                    port: Some(443),
                },
            }),
            GuestMsg::Event(GuestEvent::Metrics {
                cpu_pct: 12.5,
                mem_used: 1 << 30,
                disk_used: 1 << 20,
            }),
        ];
        for m in msgs {
            roundtrip(m);
        }
    }

    #[test]
    fn stream_messages_roundtrip() {
        roundtrip(StreamOpen::Attach {
            session: "s".into(),
            size: sz(),
            replay_scrollback: true,
            token: vec![1; ATTACH_TOKEN_LEN],
        });
        roundtrip(ProxyOpen::HttpProxy);
        roundtrip(ProxyOpen::Direct {
            host: "example.com".into(),
            port: 443,
            sni: Some("example.com".into()),
        });
        roundtrip(GitOpen {
            service: GitService::UploadPack,
        });
        roundtrip(StreamOpen::ExecIo { exec_id: 9 });
        roundtrip(StreamOpen::PortForward { port: 8080 });
        roundtrip(StreamOpen::GitUploadPack {
            repo: "/work".into(),
        });
        roundtrip(StreamAck(Ok(())));
        roundtrip(StreamAck(Err(GuestError::new(
            ErrorKind::Unsupported,
            "later",
        ))));
        roundtrip(AttachIn::Data(b"ls\r".to_vec()));
        roundtrip(AttachIn::Resize(sz()));
        roundtrip(AttachOut::Data(vec![0x1b, b'[', b'H']));
        roundtrip(AttachOut::Exited(ExitStatus::Code(3)));
        roundtrip(ExecIn::Stdin(vec![1]));
        roundtrip(ExecIn::CloseStdin);
        roundtrip(ExecIn::Signal(2));
        roundtrip(ExecIn::Resize(sz()));
        roundtrip(ExecOut::Stdout(vec![1]));
        roundtrip(ExecOut::Stderr(vec![2]));
        roundtrip(ExecOut::Exited(ExitStatus::Signal(15)));
    }

    fn payload<T: Serialize>(m: &T) -> Vec<u8> {
        encode(m).unwrap()[4..].to_vec()
    }

    #[test]
    fn hostile_guest_messages_rejected() {
        let bad: Vec<Vec<u8>> = vec![
            payload(&GuestMsg::Event(GuestEvent::OpenUrl {
                url: "file:///etc/passwd".into(),
            })),
            payload(&GuestMsg::Event(GuestEvent::OpenUrl {
                url: "javascript:alert(1)".into(),
            })),
            payload(&GuestMsg::Event(GuestEvent::OpenUrl {
                url: format!("https://{}", "a".repeat(3000)),
            })),
            payload(&GuestMsg::Event(GuestEvent::OpenUrl {
                url: "https://x\n.com".into(),
            })),
            payload(&GuestMsg::Event(GuestEvent::SessionBell {
                name: "../../etc".into(),
            })),
            payload(&GuestMsg::Event(GuestEvent::SessionExited {
                name: "s".into(),
                status: ExitStatus::Code(-1),
            })),
            payload(&GuestMsg::Event(GuestEvent::SessionExited {
                name: "s".into(),
                status: ExitStatus::Signal(0),
            })),
            payload(&GuestMsg::Event(GuestEvent::PortOpened {
                port: 0,
                proto: Proto::Tcp,
                process: None,
            })),
            payload(&GuestMsg::Event(GuestEvent::Metrics {
                cpu_pct: f32::NAN,
                mem_used: 0,
                disk_used: 0,
            })),
            payload(&GuestMsg::Event(GuestEvent::ApprovalRequest {
                kind: ApprovalKind::Host {
                    host: "evil host".into(),
                    port: None,
                },
            })),
            payload(&GuestMsg::Hello {
                proto_version: 1,
                init_version: "\x1b[2J".into(),
            }),
            payload(&GuestMsg::Ready {
                boot_ns_since_kernel_start: 1,
                init_ns: 2,
            }),
            payload(&GuestMsg::Reply {
                id: 1,
                result: Err(GuestError {
                    kind: ErrorKind::Io,
                    message: "x".repeat(MAX_ERROR_MESSAGE + 1),
                }),
            }),
            payload(&GuestMsg::Reply {
                id: 1,
                result: Ok(Reply::File {
                    data: vec![0; MAX_FILE + 1],
                    truncated: false,
                }),
            }),
        ];
        for (i, p) in bad.iter().enumerate() {
            assert!(decode::<GuestMsg>(p).is_err(), "case {i} accepted");
        }
        assert!(decode::<AttachOut>(&payload(&AttachOut::Data(vec![0; MAX_CHUNK + 1]))).is_err());
        assert!(decode::<ExecOut>(&payload(&ExecOut::Stdout(vec![0; MAX_CHUNK + 1]))).is_err());
        for bad in [
            ProxyOpen::Direct {
                host: "a b".into(),
                port: 1,
                sni: None,
            },
            ProxyOpen::Direct {
                host: "a".into(),
                port: 0,
                sni: None,
            },
            ProxyOpen::Direct {
                host: "a".into(),
                port: 1,
                sni: Some("x\0".into()),
            },
        ] {
            assert!(decode::<ProxyOpen>(&payload(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn framing_limits_and_trailing_bytes() {
        let mut p = payload(&GuestMsg::Reply {
            id: 1,
            result: Ok(Reply::Done),
        });
        p.push(0);
        assert!(matches!(
            decode::<GuestMsg>(&p),
            Err(ProtoError::TrailingBytes(1))
        ));
        assert!(matches!(
            decode::<GuestMsg>(&[]),
            Err(ProtoError::EmptyFrame)
        ));

        let mut r = FrameReader::default();
        r.push(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert!(matches!(
            r.next_frame(),
            Err(ProtoError::FrameTooLarge { .. })
        ));

        let big = AttachIn::Data(vec![0; MAX_FRAME]);
        assert!(matches!(
            encode(&big),
            Err(ProtoError::FrameTooLarge { .. })
        ));

        let mut huge = ((MAX_FRAME as u32) + 1).to_be_bytes().to_vec();
        huge.extend_from_slice(&[0; 16]);
        assert!(matches!(
            read_frame(&mut huge.as_slice()),
            Err(ProtoError::FrameTooLarge { .. })
        ));
        assert!(matches!(
            read_frame(&mut &[0u8, 0, 0, 9, 1][..]),
            Err(ProtoError::Truncated)
        ));
        assert!(read_frame(&mut &[][..]).unwrap().is_none());
    }

    #[test]
    fn frame_reader_reassembles_split_frames() {
        let a = encode(&ExecOut::Stdout(b"hello".to_vec())).unwrap();
        let b = encode(&ExecOut::Exited(ExitStatus::Code(0))).unwrap();
        let all = [a, b].concat();
        let mut r = FrameReader::default();
        let mut got = vec![];
        for byte in all {
            r.push(&[byte]);
            while let Some(m) = r.next_msg::<ExecOut>().unwrap() {
                got.push(m);
            }
        }
        assert_eq!(
            got,
            [
                ExecOut::Stdout(b"hello".to_vec()),
                ExecOut::Exited(ExitStatus::Code(0))
            ]
        );
    }

    /// Deterministic stand-in for the fuzzer in plain `cargo test`.
    #[test]
    fn random_bytes_never_panic_host_decoders() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..200_000 {
            let len = (next() % 64) as usize;
            let buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            decode_any_from_guest(&buf);
            let mut r = FrameReader::default();
            r.push(&buf);
            while let Ok(Some(f)) = r.next_frame() {
                decode_any_from_guest(&f);
            }
        }
    }

    #[test]
    fn names_and_hostnames() {
        assert!(valid_name("claude-2") && valid_name("a.b_c"));
        assert!(!valid_name("") && !valid_name(".x") && !valid_name("-x") && !valid_name("a/b"));
        assert!(!valid_name(&"a".repeat(65)));
        assert!(valid_hostname("webapp-1") && valid_hostname("a.example.com"));
        assert!(!valid_hostname("-a") && !valid_hostname("a..b") && !valid_hostname("a b"));
    }
}
