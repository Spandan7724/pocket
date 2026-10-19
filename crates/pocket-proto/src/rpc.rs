//! CLI ↔ daemon RPC (CONTRACTS.md §2): UDS, frames of `u32` big-endian length + JSON.
//!
//! The client sends [`ClientMsg::Hello`] first; the daemon answers [`DaemonMsg::Hello`]
//! or closes after a `VersionMismatch` error response with id 0.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::guest::{ExitStatus, SessionInfo};

/// Bump on every incompatible change to the types in this module.
pub const RPC_VERSION: u32 = 4;
pub const MAX_RPC_FRAME: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientMsg {
    Hello { proto_version: u32, client: String },
    Request { id: u64, req: Request },
    Subscribe { id: u64, topics: Vec<Topic> },
    Cancel { id: u64 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DaemonMsg {
    Hello {
        proto_version: u32,
        daemon_version: String,
    },
    Response {
        id: u64,
        result: Result<Response, RpcError>,
    },
    Progress {
        id: u64,
        stage: String,
        pct: Option<u8>,
    },
    /// `seq` is monotonic per daemon run.
    Event { seq: u64, event: Event },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Topic {
    Pockets,
    Net,
    /// Ports, approvals, notifications, opened URLs.
    Notices,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPocket {
    pub name: Option<String>,
    pub preset: Option<String>,
    /// Host repository to clone in; `None` = scratch pocket.
    pub repo: Option<PathBuf>,
    /// Copy uncommitted host changes (tracked diffs + untracked files) into `/work`.
    pub carry_changes: bool,
    pub cpus: Option<u8>,
    pub memory_mib: Option<u32>,
    pub disk_mib: Option<u64>,
    pub net_profile: Option<String>,
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Default session command; `None` = login shell.
    pub command: Option<Vec<String>>,
    pub term: Option<String>,
    /// Secrets to inject as placeholders; `None` = every stored secret.
    #[serde(default)]
    pub secrets: Option<Vec<String>>,
    /// Secrets whose real value is copied into the guest (explicit opt-in).
    #[serde(default)]
    pub copy_secrets: Vec<String>,
    /// Copy host agent config (`~/.claude`, `~/.codex`) in, secrets stripped.
    #[serde(default = "yes")]
    pub sync_config: bool,
    /// Forward the host's ssh-agent, confirming every signature (opt-in).
    #[serde(default)]
    pub ssh_agent: bool,
    #[serde(default = "yes")]
    pub auto_forward: bool,
    /// Fixed forwards `(guest, host)`.
    #[serde(default)]
    pub forward: Vec<(u16, u16)>,
    /// Extra environment for every process in the pocket.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub git_protected: Vec<String>,
    #[serde(default)]
    pub git_allow_push: Vec<String>,
    /// `sandbox.setup` from pocket.toml: baked into a project template.
    #[serde(default)]
    pub setup: Option<Setup>,
    /// Host directories shared into the pocket over virtio-fs (explicit opt-in).
    #[serde(default)]
    pub share: Vec<ShareDir>,
    /// `[idle]` thresholds; `None` = daemon default, `Some(0)` = never.
    #[serde(default)]
    pub idle_pause_ms: Option<u64>,
    #[serde(default)]
    pub idle_hibernate_ms: Option<u64>,
    /// `proxy` (default), `transparent` (TUN shim, still policed) or `full` (passt NIC).
    #[serde(default)]
    pub net_mode: Option<String>,
    /// Saved template (`pocket save --as NAME`) to start from.
    #[serde(default)]
    pub template: Option<String>,
    /// The client's compiled terminfo entry for `term`, installed when the image lacks one.
    #[serde(default)]
    pub terminfo: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareDir {
    pub host: PathBuf,
    pub guest: String,
    pub read_only: bool,
}

/// A project setup step and the content hashes of its inputs (template key material).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setup {
    pub command: String,
    /// `(path, sha256)` of each `setup_inputs` file.
    pub inputs: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalWhat {
    /// A blocked destination (from the proxy or `pocket-guest allow`).
    Network {
        host: String,
        port: Option<u16>,
        reason: String,
    },
    /// An ssh-agent signature request.
    SshSign { key: String, comment: String },
    /// The pocket asks for a copy of a host file.
    File { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalInfo {
    pub id: u64,
    pub pocket: String,
    pub what: ApprovalWhat,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// This request (network: for two minutes).
    Once,
    /// Network: for the pocket's lifetime.
    Pocket,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortInfo {
    pub guest: u16,
    pub host: u16,
    pub process: Option<String>,
    pub auto: bool,
}

fn yes() -> bool {
    true
}

/// A stored credential (never its value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInfo {
    pub name: String,
    /// `anthropic`, `openai`, `github` or `custom`.
    pub provider: String,
    /// `api_key`, `oauth_token`, `chatgpt` (Codex ChatGPT login) or `token`.
    pub kind: String,
    /// Destinations the value is injected for (`host` or `*.domain`).
    pub hosts: Vec<String>,
    /// Guest environment variables that hold the placeholder.
    pub env: Vec<String>,
    /// `Header: template` with `{}` for the value, added when the guest sends none.
    pub header: Option<String>,
    /// `keyring` (Secret Service) or `file` (encrypted file).
    pub storage: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAdd {
    pub name: String,
    /// `None` = guessed from the value.
    pub provider: Option<String>,
    pub kind: Option<String>,
    pub value: String,
    /// Empty = the provider's default destinations.
    pub hosts: Vec<String>,
    pub env: Vec<String>,
    pub header: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    NewPocket(NewPocket),
    List,
    Stop {
        pocket: String,
    },
    Start {
        pocket: String,
    },
    Remove {
        pocket: String,
    },
    /// Starts a one-shot process; the client then opens `ExecIo` on `vsock_uds`.
    Exec {
        pocket: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        tty: Option<(u16, u16)>,
        root: bool,
    },
    SessionCreate {
        pocket: String,
        name: Option<String>,
        argv: Option<Vec<String>>,
        rows: u16,
        cols: u16,
        term: Option<String>,
        #[serde(default)]
        terminfo: Option<Vec<u8>>,
    },
    SessionList {
        pocket: String,
        /// Don't resume a paused / hibernated pocket to answer (the dashboard's polling).
        #[serde(default)]
        peek: bool,
    },
    SessionKill {
        pocket: String,
        session: String,
        signal: i32,
    },
    /// One-time token for the direct attach fast path; `session` `None` = most recent.
    AttachAuthorize {
        pocket: String,
        session: Option<String>,
    },
    NetLog {
        pocket: String,
        limit: u32,
    },
    Pull {
        preset: String,
    },
    /// Agent config changed in the pocket: `accept` `None` previews; `Some` writes exactly
    /// those `(path, sha256)` versions to the host.
    ConfigPull {
        pocket: String,
        accept: Option<Vec<(String, String)>>,
    },
    /// Fetches the pocket's work into `refs/pocket/<name>/*` (hardened) and diffs it.
    Diff {
        pocket: String,
        uncommitted: bool,
        stat: bool,
        color: bool,
    },
    Apply {
        pocket: String,
        mode: ApplyMode,
        onto: Option<String>,
        uncommitted: bool,
        message: Option<String>,
    },
    /// Pushes the pocket branch from the host and opens a pull request.
    Pr {
        pocket: String,
        title: Option<String>,
        body: Option<String>,
        draft: bool,
        base: Option<String>,
    },
    /// Brings the latest host branch into the pocket (merge, or rebase).
    Sync {
        pocket: String,
        rebase: bool,
    },
    Approvals {
        pocket: Option<String>,
    },
    Approve {
        id: u64,
        decision: Decision,
    },
    /// Allows destinations (`once` = for two minutes) and resolves matching approvals.
    NetAllow {
        pocket: String,
        hosts: Vec<String>,
        once: bool,
    },
    NetDeny {
        pocket: String,
        hosts: Vec<String>,
    },
    Ports {
        pocket: String,
    },
    PortAdd {
        pocket: String,
        guest: u16,
        host: Option<u16>,
    },
    /// An image pasted in `pocket attach`, offered to the guest's clipboard shims.
    PasteImage {
        pocket: String,
        data: Vec<u8>,
    },
    SecretAdd(SecretAdd),
    SecretList,
    SecretRemove {
        name: String,
    },
    /// Adds destinations / env vars / a header template to a secret.
    SecretBind {
        name: String,
        hosts: Vec<String>,
        env: Vec<String>,
        header: Option<String>,
    },
    Doctor,
    /// Stops the daemon (VMs keep running and are re-adopted on the next start).
    DaemonStop,
    /// v3 (M9) below.
    Templates,
    /// Builds (or confirms) the snapshot template for a preset and VM shape.
    TemplateBuild {
        preset: String,
        cpus: Option<u8>,
        memory_mib: Option<u32>,
    },
    Pause {
        pocket: String,
    },
    /// Resumes a paused or hibernated pocket.
    Resume {
        pocket: String,
    },
    Hibernate {
        pocket: String,
    },
    Pool,
    /// `pocket cp HOST POCKET:PATH`.
    CopyIn {
        pocket: String,
        src: PathBuf,
        dst: String,
    },
    /// `pocket cp POCKET:PATH HOST` (unpacked with path and type checks on the host).
    CopyOut {
        pocket: String,
        src: String,
        dst: PathBuf,
    },
    /// `pocket save P --as NAME`: snapshot a configured pocket as a named template.
    Save {
        pocket: String,
        name: String,
    },
    /// Starts the pocket's sshd (vsock only) with pocket's key authorized; returns how to
    /// reach it (`pocket ssh-proxy`).
    SshPrepare {
        pocket: String,
        public_key: String,
    },
    /// Start-path measurements (PERFORMANCE.md §4); the reply is a JSON report.
    Bench {
        runs: u32,
        preset: String,
        density: u32,
        #[serde(default)]
        memory_mib: Option<u32>,
    },
    /// Every built preset image version, with what still uses it.
    Images,
    /// Removes image versions nothing uses (also from a shared `POCKET_PRESET_CACHE`) and
    /// the snapshot templates built on them.
    Gc {
        dry_run: bool,
        /// Only these versions (what the user confirmed); `None`: everything unused.
        #[serde(default)]
        only: Option<Vec<String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Done,
    Pocket(PocketInfo),
    Pockets(Vec<PocketInfo>),
    ExecStarted {
        exec_id: u64,
        vsock_uds: PathBuf,
    },
    Session {
        name: String,
    },
    Sessions(Vec<SessionInfo>),
    Attach {
        session: String,
        vsock_uds: PathBuf,
        token: Vec<u8>,
    },
    NetLog(Vec<NetEntry>),
    Image {
        name: String,
        digest: String,
    },
    Doctor(Vec<Check>),
    Secret(SecretInfo),
    Secrets(Vec<SecretInfo>),
    ConfigChanges(Vec<ConfigChange>),
    Approvals(Vec<ApprovalInfo>),
    Ports(Vec<PortInfo>),
    /// Human-readable result (diff text, apply summary, PR URL …) plus structured fields.
    Text {
        text: String,
        url: Option<String>,
    },
    Templates(Vec<TemplateInfo>),
    Pool(PoolInfo),
    /// A JSON document (bench report).
    Json(String),
    Ssh {
        vsock_uds: PathBuf,
        user: String,
        /// The guest's host key line (`ssh-ed25519 AAAA…`), pinned in known_hosts.
        host_key: String,
    },
    Images(Vec<ImageInfo>),
    Gc(GcReport),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub preset: String,
    /// First 16 hex digits of the image key; also in the file name.
    pub version: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    /// Unknown for files found without a database record.
    pub built_at: Option<u64>,
    /// The version this pocket build uses for new pockets.
    pub current: bool,
    /// Pockets (`pocket NAME`) and saved templates (`template NAME`) that need this version.
    pub used_by: Vec<String>,
    /// In `POCKET_PRESET_CACHE`, which other daemons may share; only `pocket gc` removes
    /// versions there.
    pub shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcReport {
    pub dry_run: bool,
    pub removed: Vec<ImageInfo>,
    /// Keys of snapshot templates removed with their image.
    pub templates: Vec<String>,
    pub freed_bytes: u64,
}

pub fn valid_term(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

/// This process's compiled terminfo entry for `term` (`$TERMINFO`, `~/.terminfo`,
/// `$TERMINFO_DIRS`, system dirs; `x/name` and `78/name` layouts). Terminals like Ghostty
/// point `TERMINFO` at their own entries, so the client sends it along.
pub fn find_terminfo(term: &str) -> Option<Vec<u8>> {
    use std::path::PathBuf;
    if !valid_term(term) {
        return None;
    }
    let first = term.chars().next()?;
    let mut dirs: Vec<PathBuf> = vec![];
    if let Some(t) = std::env::var_os("TERMINFO") {
        dirs.push(t.into());
    }
    if let Some(h) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(h).join(".terminfo"));
    }
    if let Some(d) = std::env::var_os("TERMINFO_DIRS") {
        dirs.extend(std::env::split_paths(&d));
    }
    dirs.extend(
        [
            "/etc/terminfo",
            "/lib/terminfo",
            "/usr/share/terminfo",
            "/usr/lib/terminfo",
        ]
        .map(PathBuf::from),
    );
    for d in dirs {
        for sub in [first.to_string(), format!("{:02x}", first as u32)] {
            if let Ok(data) = std::fs::read(d.join(&sub).join(term))
                && data.len() <= MAX_TERMINFO
            {
                return Some(data);
            }
        }
    }
    None
}

pub const MAX_TERMINFO: usize = 64 * 1024;

/// Derived session state (CONTRACTS.md §4), from what the guest reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Output in the last 2 s.
    Working,
    /// An agent rang the bell / sent a notification after its last output, or sits quiet
    /// at something that looks like a prompt.
    Waiting,
    Idle,
    Exited,
}

const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "ash", "ksh", "tcsh", "nu",
];

/// The session runs a shell (the default session) rather than an agent or other program.
pub fn is_shell(argv: &[String]) -> bool {
    let base = |a: &str| {
        a.rsplit('/')
            .next()
            .unwrap_or(a)
            .trim_start_matches('-')
            .to_string()
    };
    match argv {
        [] => true,
        [first, rest @ ..] => {
            SHELLS.contains(&base(first).as_str())
                && (rest.is_empty()
                    || rest[0] == "-l"
                    || rest[0] == "-i"
                    || rest.iter().any(|a| a.contains("${SHELL")))
        }
    }
}

fn looks_like_prompt(tail: &str) -> bool {
    let t = tail.trim_end();
    let lower = t.to_ascii_lowercase();
    ["?", ">", "❯", "›", ":", "$", "#", "»"]
        .iter()
        .any(|p| t.ends_with(p))
        || ["[y/n]", "(y/n)", "[y/n]:", "(yes/no)", "press enter"]
            .iter()
            .any(|p| lower.ends_with(p) || lower.contains(p))
}

pub fn session_state(s: &crate::guest::SessionInfo, now_ms: u64) -> SessionState {
    if s.exited.is_some() {
        return SessionState::Exited;
    }
    let out = s.last_output_unix_ms;
    // A shell's bell is a beep (failed completion), not a question.
    let agent = !is_shell(&s.argv);
    if agent && s.last_bell_unix_ms > 0 && s.last_bell_unix_ms + 1500 >= out {
        return SessionState::Waiting;
    }
    let quiet = now_ms.saturating_sub(out);
    if out > 0 && quiet < 2000 {
        return SessionState::Working;
    }
    if agent && out > 0 && quiet >= 3000 && looks_like_prompt(&s.tail) {
        return SessionState::Waiting;
    }
    SessionState::Idle
}

/// `500ms`, `30s`, `30m`, `2h`, `1d`; `0` or `never` = disabled (`Some(0)`).
pub fn parse_duration_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    if s == "never" || s == "0" {
        return Some(0);
    }
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (n, unit) = s.split_at(split);
    let n: u64 = n.parse().ok()?;
    let mul = match unit {
        "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return None,
    };
    n.checked_mul(mul)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub key: String,
    /// `base` (preset + VM shape), `project` (`sandbox.setup`), `saved` (`pocket save`).
    pub kind: String,
    pub name: Option<String>,
    pub preset: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_bytes: u64,
    pub built_at: u64,
    pub last_used_at: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PoolInfo {
    pub enabled: bool,
    /// Target VMs for the hot template.
    pub size: u32,
    pub max_total_memory_mib: u64,
    /// Template the pool fills for (most recently used).
    pub template: Option<String>,
    /// Paused, restored VMs ready to claim.
    pub ready: u32,
    pub memory_mib: u64,
    pub claimed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyMode {
    Squash,
    Merge,
    CherryPick,
}

/// One agent config file that differs between the pocket and the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigChange {
    /// Relative to the home directory, e.g. `.claude/settings.json`.
    pub path: String,
    /// Current host content for display (`None` = new file); secrets masked.
    pub host: Option<String>,
    /// What would be written, for display; secrets masked.
    pub guest: String,
    /// SHA-256 of the exact content that would be written (redactions restored).
    pub sha256: String,
    /// Why it can't be applied, if so.
    pub blocked: Option<String>,
    /// Security-relevant keys this change touches (hooks, MCP servers, commands …).
    pub risky: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PocketState {
    Creating,
    Running,
    Paused,
    Hibernated,
    Stopped,
    Broken { reason: String },
}

impl PocketState {
    pub fn label(&self) -> &str {
        match self {
            PocketState::Creating => "creating",
            PocketState::Running => "running",
            PocketState::Paused => "paused",
            PocketState::Hibernated => "hibernated",
            PocketState::Stopped => "stopped",
            PocketState::Broken { .. } => "broken",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocketInfo {
    pub id: String,
    pub name: String,
    pub state: PocketState,
    pub preset: String,
    pub image_digest: String,
    pub repo_path: Option<PathBuf>,
    pub base_ref: Option<String>,
    pub branch: Option<String>,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_bytes: u64,
    /// Bytes actually allocated by the pocket disk (sparse file).
    pub disk_used_bytes: u64,
    pub net_profile: String,
    pub created_at: u64,
    pub last_active_at: u64,
    /// How the VM last started: `cold`, `template`, `pool`, `hibernation`.
    #[serde(default)]
    pub started_from: Option<String>,
    /// Snapshot template the pocket was created from.
    #[serde(default)]
    pub template: Option<String>,
    /// `proxy` (env proxy), `transparent` or `full` (passt NIC, unfiltered).
    #[serde(default)]
    pub net_mode: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetEntry {
    pub pocket: String,
    pub ts_ms: u64,
    /// `connect` (HTTPS tunnel) or `http` (plain request).
    pub kind: String,
    pub host: String,
    pub ip: Option<String>,
    pub port: u16,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub verdict: Verdict,
    pub reason: String,
    /// A credential was substituted into this request.
    #[serde(default)]
    pub injected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    /// Warnings don't fail `doctor`.
    pub warn: bool,
    pub detail: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Event {
    PocketState {
        name: String,
        from: PocketState,
        to: PocketState,
        at: u64,
    },
    Net(NetEntry),
    SessionExited {
        pocket: String,
        session: String,
        status: ExitStatus,
    },
    Port {
        pocket: String,
        port: PortInfo,
        open: bool,
    },
    Approval(ApprovalInfo),
    ApprovalDone {
        id: u64,
        pocket: String,
        decision: Decision,
    },
    /// Something for the user's attention: `kind` is `notify`, `bell` or `url`.
    Notice {
        pocket: String,
        session: Option<String>,
        kind: String,
        title: String,
        body: String,
    },
}

impl Event {
    pub fn topic(&self) -> Topic {
        match self {
            Event::Net(_) => Topic::Net,
            Event::Port { .. }
            | Event::Approval(_)
            | Event::ApprovalDone { .. }
            | Event::Notice { .. } => Topic::Notices,
            _ => Topic::Pockets,
        }
    }
}

/// Stable error codes; each maps to a documented CLI exit code (CLI.md §Exit codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    NotFound,
    AlreadyExists,
    VersionMismatch,
    InvalidState,
    HostSetup,
    Vmm,
    Guest,
    Image,
    Workspace,
    Internal,
}

impl ErrorCode {
    pub fn exit_code(self) -> u8 {
        match self {
            ErrorCode::BadRequest => 2,
            ErrorCode::NotFound => 3,
            ErrorCode::AlreadyExists => 4,
            ErrorCode::InvalidState => 5,
            ErrorCode::VersionMismatch => 6,
            ErrorCode::HostSetup => 7,
            ErrorCode::Vmm | ErrorCode::Guest => 8,
            ErrorCode::Image => 9,
            ErrorCode::Workspace => 10,
            ErrorCode::Internal => 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: ErrorCode,
    /// What happened.
    pub message: String,
    /// How to fix it.
    pub hint: Option<String>,
}

impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            hint: None,
        }
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RpcError {}

pub fn encode<T: Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg).map_err(io::Error::other)?;
    if json.len() > MAX_RPC_FRAME {
        return Err(io::Error::other("rpc frame too large"));
    }
    let mut out = (json.len() as u32).to_be_bytes().to_vec();
    out.extend(json);
    Ok(out)
}

pub fn decode<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    serde_json::from_slice(payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Length of the frame starting with this prefix, rejecting oversized frames.
pub fn frame_len(prefix: [u8; 4]) -> io::Result<usize> {
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_RPC_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rpc frame too large",
        ));
    }
    Ok(len)
}

pub fn write<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    w.write_all(&encode(msg)?)
}

/// `Ok(None)` on a clean EOF.
pub fn read<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut buf = vec![0u8; frame_len(len)?];
    r.read_exact(&mut buf)?;
    decode(&buf).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_states() {
        use crate::guest::{PtySize, SessionInfo};
        let s = |argv: &[&str], out: u64, bell: u64, tail: &str| SessionInfo {
            name: "s".into(),
            pid: 1,
            argv: argv.iter().map(|a| a.to_string()).collect(),
            created_unix_ms: 0,
            size: PtySize { rows: 24, cols: 80 },
            attached: 0,
            exited: None,
            last_output_unix_ms: out,
            last_bell_unix_ms: bell,
            tail: tail.into(),
        };
        let now = 100_000;
        let shell = ["/bin/sh", "-c", "exec \"${SHELL:-/bin/sh}\" -l"];
        assert!(is_shell(&shell.map(String::from)));
        assert!(!is_shell(&["claude".to_string()]));
        assert_eq!(
            session_state(&s(&shell, now - 500, 0, ""), now),
            SessionState::Working
        );
        assert_eq!(
            session_state(&s(&shell, now - 9000, 0, "$ "), now),
            SessionState::Idle
        );
        assert_eq!(
            session_state(&s(&["claude"], now - 9000, now - 9000, ""), now),
            SessionState::Waiting
        );
        assert_eq!(
            session_state(
                &s(&["codex"], now - 9000, 0, "Allow this command? [y/n]"),
                now
            ),
            SessionState::Waiting
        );
        assert_eq!(
            session_state(&s(&["codex"], now - 9000, 0, "compiling 3/9"), now),
            SessionState::Idle
        );
        assert_eq!(
            session_state(&s(&["claude"], now - 100, now - 60_000, ""), now),
            SessionState::Working
        );
    }

    #[test]
    fn roundtrip_and_limits() {
        let msgs = vec![
            ClientMsg::Hello {
                proto_version: RPC_VERSION,
                client: "pocket 0.0.0".into(),
            },
            ClientMsg::Request {
                id: 1,
                req: Request::NewPocket(NewPocket {
                    name: Some("a".into()),
                    preset: None,
                    repo: Some("/r".into()),
                    carry_changes: true,
                    cpus: Some(2),
                    memory_mib: None,
                    disk_mib: None,
                    net_profile: Some("dev".into()),
                    allow: vec!["x.com".into()],
                    deny: vec![],
                    command: None,
                    term: Some("xterm".into()),
                    secrets: None,
                    copy_secrets: vec![],
                    sync_config: true,
                    ssh_agent: false,
                    auto_forward: true,
                    forward: vec![],
                    env: vec![],
                    git_protected: vec![],
                    git_allow_push: vec![],
                    setup: None,
                    share: vec![],
                    idle_pause_ms: None,
                    idle_hibernate_ms: None,
                    net_mode: None,
                    template: None,
                    terminfo: None,
                }),
            },
            ClientMsg::Subscribe {
                id: 2,
                topics: vec![Topic::Net],
            },
        ];
        for m in msgs {
            let mut buf = vec![];
            write(&mut buf, &m).unwrap();
            let back: ClientMsg = read(&mut buf.as_slice()).unwrap().unwrap();
            assert_eq!(back, m);
        }
        let err = DaemonMsg::Response {
            id: 3,
            result: Err(RpcError::new(ErrorCode::NotFound, "no pocket x").hint("pocket ls")),
        };
        let mut buf = vec![];
        write(&mut buf, &err).unwrap();
        assert_eq!(
            read::<_, DaemonMsg>(&mut buf.as_slice()).unwrap().unwrap(),
            err
        );
        assert!(frame_len(((MAX_RPC_FRAME + 1) as u32).to_be_bytes()).is_err());
        assert!(read::<_, DaemonMsg>(&mut &[][..]).unwrap().is_none());
    }
}
