//! Pocket supervisor: owns the state machine (CONTRACTS.md §4). Every state change goes
//! through here and emits an event.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pocket_proto::guest::{GuestEvent, HostReq, PtySize, RNG_SEED_LEN, Reply, SessionInfo};
use pocket_proto::rpc::{ErrorCode, Event, NewPocket, PocketInfo, PocketState, RpcError};
use pocket_store::{PocketRecord, Store};
use pocket_vmm::{CgroupSpec, StopMode, VmHandle, VmSpec, VmmBackend, guest_devices};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::guest::{ExecReq, GuestConn};
use crate::inject::{InjectedSecret, PocketHooks};
use crate::paths::Paths;
use crate::{inject, net, presets, provision, secrets, workspace};

pub const BOOT_ARGS: &str = "root=/dev/vda ro rootfstype=erofs init=/pocket-init reboot=k \
    panic=-1 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.dumbkbd quiet rcupdate.rcu_expedited=1";
pub const GUEST_PROXY_PORT: u16 = 3128;
pub const DEFAULT_CPUS: u8 = 2;
pub const DEFAULT_MEMORY_MIB: u32 = 2048;
pub const DEFAULT_DISK_MIB: u64 = 20 << 10;
/// Allowed on top of guest RAM in the cgroup memory limit: the VMM itself plus base-image
/// pages the guest reads through DAX, which are charged to the scope as file memory (an
/// agent like Claude Code maps a few hundred MiB of it).
const VMM_OVERHEAD: u64 = 1 << 30;

pub type R<T> = Result<T, RpcError>;

pub fn err(code: ErrorCode, msg: impl Into<String>) -> RpcError {
    RpcError::new(code, msg)
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").expect("/dev/urandom"),
        &mut v,
    )
    .expect("read /dev/urandom");
    v
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `[a-z0-9][a-z0-9-]{0,39}`: also a valid hostname, cgroup unit and session prefix.
pub fn valid_pocket_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 40
        && n.as_bytes()[0].is_ascii_alphanumeric()
        && !n.ends_with('-')
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn sanitize(s: &str) -> String {
    let mut out: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches('-').to_string();
    let mut out: String = out.chars().take(32).collect();
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { "pocket".into() } else { out }
}

const ADJECTIVES: &[&str] = &[
    "brave", "calm", "eager", "fancy", "gentle", "happy", "jolly", "keen", "lucky", "merry",
    "nimble", "proud", "quiet", "rapid", "shy", "swift", "tidy", "witty", "zesty", "bold",
];
const ANIMALS: &[&str] = &[
    "heron", "lynx", "otter", "falcon", "badger", "panda", "koala", "gecko", "bison", "crane",
    "dingo", "egret", "ferret", "ibis", "jackal", "lemur", "marten", "newt", "okapi", "puffin",
];

pub struct Live {
    pub id: String,
    pub name: String,
    pub vm: VmHandle,
    pub guest: Arc<GuestConn>,
    pub user: Option<String>,
    pub proxy: Arc<pocket_net::proxy::ProxyCtx>,
    pub hooks: Arc<PocketHooks>,
    pub host: crate::host::HostState,
    pub stopping: AtomicBool,
    pub paused: AtomicBool,
    pub tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for Live {
    fn drop(&mut self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

pub struct Daemon {
    pub paths: Paths,
    pub store: Mutex<Store>,
    pub backend: Arc<dyn VmmBackend>,
    pub(crate) live: Mutex<HashMap<String, Arc<Live>>>,
    op_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Host-side traffic per pocket id (proxy streams, port forwards): idle detection.
    activity: Mutex<HashMap<String, Arc<Activity>>>,
    pub pool: crate::pool::Pool,
    pub config: crate::config::DaemonConfig,
    pub events: broadcast::Sender<(u64, Event)>,
    seq: AtomicU64,
    pub vault: secrets::Vault,
    pub approvals: Mutex<Vec<crate::host::Pending>>,
    approval_seq: AtomicU64,
    ca: Mutex<Option<Arc<pocket_net::ca::Ca>>>,
    tls: std::sync::OnceLock<Arc<rustls::ClientConfig>>,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct Meta {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<InjectedSecret>,
    /// Copy host agent config in on first boot.
    #[serde(default)]
    pub sync_config: bool,
    #[serde(default)]
    pub provisioned: bool,
    /// Host branch the pocket started from (PR base, `sync` source).
    #[serde(default)]
    pub base_branch: Option<String>,
    /// Host of the guest's `origin` (HTTPS), push-guarded at the proxy.
    #[serde(default)]
    pub origin_host: Option<String>,
    /// `git.protected` / `git.allow_push` (pocket.toml); empty = defaults.
    #[serde(default)]
    pub git_protected: Vec<String>,
    #[serde(default)]
    pub git_allow_push: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ssh_agent: bool,
    #[serde(default = "yes")]
    pub auto_forward: bool,
    #[serde(default)]
    pub forward: Vec<(u16, u16)>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Project template the pocket disk came from (`sandbox.setup`).
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub shares: Vec<pocket_proto::rpc::ShareDir>,
    /// `/etc/machine-id`, stable for the pocket's life.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Restore hooks run so far (template clone, pool claim, hibernation, resume).
    #[serde(default)]
    pub restore_generation: u64,
    /// Snapshot template the pocket was restored from.
    #[serde(default)]
    pub snapshot_template: Option<String>,
    /// `cold`, `template`, `pool` or `hibernation`.
    #[serde(default)]
    pub started_from: Option<String>,
    /// Hibernation snapshot directory name inside the pocket dir, with its host.
    #[serde(default)]
    pub hibernation: Option<(String, pocket_vmm::HostFingerprint)>,
    #[serde(default)]
    pub idle_pause_ms: Option<u64>,
    #[serde(default)]
    pub idle_hibernate_ms: Option<u64>,
    #[serde(default)]
    pub net_mode: Option<String>,
}

pub type EventRx = tokio::sync::mpsc::UnboundedReceiver<GuestEvent>;

/// How `attach_guest` brings a started VM into service.
pub struct GuestSetup {
    /// Send `Configure` and provision (every boot or restore that takes an identity).
    pub configure: bool,
    /// Run the restore hook first.
    pub restore: Option<Restore>,
    /// An already connected control connection (warm pool).
    pub pre: Option<(Arc<GuestConn>, EventRx)>,
}

pub enum Launch<'a> {
    Cold,
    Template(&'a crate::templates::Template),
    /// The pocket's own hibernation snapshot.
    Hibernation(pocket_vmm::SnapshotRef),
    /// Claimed from the warm pool: restored from a template, connected and paused.
    Pool(crate::pool::PoolVm),
}

/// How a VM got its memory: booted, or restored (then the restore hook runs first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restore {
    /// From a template or another pocket: takes a new identity.
    Clone,
    /// Its own snapshot or pause (hibernate/resume): keeps its identity and sessions.
    Own,
}

fn yes() -> bool {
    true
}

/// Open host-side streams of a pocket and when the last one started or ended.
#[derive(Default)]
pub struct Activity {
    pub open: std::sync::atomic::AtomicUsize,
    pub last_ms: AtomicU64,
}

impl Activity {
    pub fn begin(self: &Arc<Self>) -> ActivityGuard {
        self.open.fetch_add(1, Ordering::SeqCst);
        self.last_ms.store(now_ms(), Ordering::SeqCst);
        ActivityGuard(self.clone())
    }
}

pub struct ActivityGuard(Arc<Activity>);

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
        self.0.last_ms.store(now_ms(), Ordering::SeqCst);
    }
}

impl Daemon {
    pub fn new(paths: Paths, store: Store, backend: Arc<dyn VmmBackend>) -> Arc<Daemon> {
        let paths_data = paths.data.clone();
        Arc::new(Daemon {
            paths,
            store: Mutex::new(store),
            backend,
            live: Mutex::new(HashMap::new()),
            op_locks: Mutex::new(HashMap::new()),
            events: broadcast::channel(4096).0,
            seq: AtomicU64::new(1),
            vault: secrets::Vault::new(secrets::choose_backend(&paths_data)),
            approvals: Mutex::new(vec![]),
            approval_seq: AtomicU64::new(1),
            ca: Mutex::new(None),
            tls: std::sync::OnceLock::new(),
            activity: Mutex::new(HashMap::new()),
            pool: Default::default(),
            config: crate::config::DaemonConfig::load(),
        })
    }

    pub fn activity(&self, id: &str) -> Arc<Activity> {
        self.activity
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    pub fn next_approval(&self) -> u64 {
        self.approval_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn ca(&self) -> R<Arc<pocket_net::ca::Ca>> {
        let mut g = self.ca.lock().unwrap();
        if let Some(c) = &*g {
            return Ok(c.clone());
        }
        let dir = self.paths.data.join("ca");
        let ca = Arc::new(pocket_net::ca::Ca::load_or_create(&dir).map_err(|e| {
            err(
                ErrorCode::HostSetup,
                format!("pocket CA in {}: {e}", dir.display()),
            )
        })?);
        *g = Some(ca.clone());
        Ok(ca)
    }

    pub fn upstream_tls(&self) -> Arc<rustls::ClientConfig> {
        self.tls
            .get_or_init(|| pocket_net::tls::client_config(pocket_net::tls::upstream_roots()))
            .clone()
    }

    pub fn meta(rec: &PocketRecord) -> Meta {
        serde_json::from_str(&rec.meta_json).unwrap_or_default()
    }

    pub fn save_meta(&self, id: &str, meta: &Meta) -> R<()> {
        let mj = serde_json::to_string(meta).unwrap();
        self.db(|s| s.set_meta(id, &mj))
    }

    /// Persists a refreshed ChatGPT login and keeps the host's own Codex login in step when
    /// it still holds the tokens pocket imported (refresh tokens rotate).
    pub fn chatgpt_refreshed(&self, name: &str, old: &inject::ChatGpt, new: &inject::ChatGpt) {
        if let Err(e) = self.vault.set(name, &new.to_json()) {
            tracing::warn!("{name}: store refreshed login: {}", e.message);
        }
        let host = provision::home().join(".codex/auth.json");
        if let Ok(text) = std::fs::read_to_string(&host)
            && let Ok(cur) = inject::ChatGpt::parse(&text)
            && cur.refresh_token == old.refresh_token
        {
            let mut upd = cur;
            upd.id_token = new.id_token.clone();
            upd.access_token = new.access_token.clone();
            upd.refresh_token = new.refresh_token.clone();
            if let Err(e) = provision::write_private(&host, upd.to_json().as_bytes()) {
                tracing::warn!("{name}: update {}: {e}", host.display());
            } else {
                tracing::info!("{name}: refreshed login written back to {}", host.display());
            }
        }
    }

    pub fn update_injected(&self, pocket_id: &str, s: &InjectedSecret) {
        let Ok(Some(rec)) = self
            .db(|st| st.pockets())
            .map(|v| v.into_iter().find(|r| r.info.id == pocket_id))
        else {
            return;
        };
        let mut meta = Self::meta(&rec);
        if let Some(m) = meta.secrets.iter_mut().find(|m| m.name == s.name) {
            *m = s.clone();
            let _ = self.save_meta(pocket_id, &meta);
        }
    }

    pub fn emit(&self, event: Event) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let _ = self.events.send((seq, event));
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn db<T>(&self, f: impl FnOnce(&Store) -> pocket_store::Result<T>) -> R<T> {
        f(&self.store()).map_err(|e| err(ErrorCode::Internal, e.to_string()))
    }

    pub(crate) fn op_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.op_locks
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_default()
            .clone()
    }

    pub fn all_live(&self) -> Vec<Arc<Live>> {
        self.live.lock().unwrap().values().cloned().collect()
    }

    pub fn live(&self, id: &str) -> Option<Arc<Live>> {
        self.live.lock().unwrap().get(id).cloned()
    }

    pub(crate) fn set_state(&self, rec: &PocketRecord, to: PocketState) -> R<()> {
        let from = self
            .db(|s| s.pocket(&rec.info.name))?
            .map(|r| r.info.state)
            .unwrap_or(PocketState::Creating);
        self.db(|s| s.set_state(&rec.info.id, &to))?;
        tracing::info!("{}: {} → {}", rec.info.name, from.label(), to.label());
        self.emit(Event::PocketState {
            name: rec.info.name.clone(),
            from,
            to,
            at: now_ms(),
        });
        Ok(())
    }

    /// Exact name, else a unique prefix.
    pub fn find(&self, name: &str) -> R<PocketRecord> {
        if let Some(r) = self.db(|s| s.pocket(name))? {
            return Ok(r);
        }
        let all = self.db(|s| s.pockets())?;
        let m: Vec<_> = all
            .into_iter()
            .filter(|r| r.info.name.starts_with(name))
            .collect();
        match m.len() {
            1 => Ok(m.into_iter().next().unwrap()),
            0 => Err(
                err(ErrorCode::NotFound, format!("no pocket named {name:?}"))
                    .hint("`pocket ls` lists pockets"),
            ),
            _ => Err(err(
                ErrorCode::BadRequest,
                format!(
                    "{name:?} matches several pockets: {}",
                    m.iter()
                        .map(|r| r.info.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .hint("type more of the name")),
        }
    }

    pub(crate) fn info(&self, mut r: PocketRecord) -> PocketInfo {
        r.info.disk_used_bytes = pocket_image::disk::allocated_bytes(
            &self.paths.pocket_dir(&r.info.id).join("disk.raw"),
        );
        let m = Self::meta(&r);
        r.info.started_from = m.started_from;
        r.info.template = m.snapshot_template;
        r.info.net_mode = Some(m.net_mode.unwrap_or_else(|| "proxy".into()));
        r.info
    }

    pub fn list(&self) -> R<Vec<PocketInfo>> {
        Ok(self
            .db(|s| s.pockets())?
            .into_iter()
            .map(|r| self.info(r))
            .collect())
    }

    pub(crate) fn running(&self, rec: &PocketRecord) -> R<Arc<Live>> {
        self.live(&rec.info.id).ok_or_else(|| {
            err(
                ErrorCode::InvalidState,
                format!("pocket {} is {}", rec.info.name, rec.info.state.label()),
            )
            .hint(format!("start it with `pocket start {}`", rec.info.name))
        })
    }

    fn pick_name(&self, req: &NewPocket, repo: Option<&Path>) -> R<String> {
        let taken = |n: &str| self.db(|s| s.pocket(n)).map(|r| r.is_some());
        if let Some(n) = &req.name {
            if !valid_pocket_name(n) {
                return Err(err(ErrorCode::BadRequest, format!("invalid pocket name {n:?}"))
                    .hint("use 1–40 lowercase letters, digits and dashes, starting with a letter or digit"));
            }
            if taken(n)? {
                return Err(err(
                    ErrorCode::AlreadyExists,
                    format!("a pocket named {n} exists"),
                )
                .hint("pick another name or `pocket rm` the old one"));
            }
            return Ok(n.clone());
        }
        if let Some(repo) = repo {
            let base = sanitize(&repo.file_name().unwrap_or_default().to_string_lossy());
            for i in 1.. {
                let n = format!("{base}-{i}");
                if !taken(&n)? {
                    return Ok(n);
                }
            }
        }
        loop {
            let r = random_bytes(2);
            let n = format!(
                "{}-{}",
                ADJECTIVES[r[0] as usize % ADJECTIVES.len()],
                ANIMALS[r[1] as usize % ANIMALS.len()]
            );
            if !taken(&n)? {
                return Ok(n);
            }
        }
    }

    pub async fn new_pocket(
        self: &Arc<Self>,
        req: NewPocket,
        progress: &(dyn Fn(&str) + Send + Sync),
    ) -> R<PocketInfo> {
        let repo = match &req.repo {
            Some(p) => Some(pocket_git::repo_info(p).map_err(|e| {
                err(ErrorCode::Workspace, e.to_string())
                    .hint("run inside a git repository, pass --repo PATH, or use --no-repo")
            })?),
            None => None,
        };
        let preset = req.preset.clone().unwrap_or_else(|| "base".into());
        let image = match presets::resolve(self, &preset) {
            Ok(i) => i,
            Err(e) if e.code == ErrorCode::NotFound => {
                presets::pull(self, &preset, progress).await?
            }
            Err(e) => return Err(e),
        };
        let profile = req.net_profile.clone().unwrap_or_else(|| "dev".into());
        net::policy_for(&profile, &req.allow)?;
        for d in &req.deny {
            pocket_net::policy::Rule::parse(d)
                .map_err(|e| err(ErrorCode::BadRequest, e.to_string()))?;
        }
        let injected = self.select_secrets(&req)?;
        let name = self.pick_name(&req, repo.as_ref().map(|r| r.toplevel.as_path()))?;
        let shape = crate::templates::Shape {
            vcpus: req.cpus.unwrap_or(DEFAULT_CPUS).clamp(1, 64),
            memory_mib: req
                .memory_mib
                .unwrap_or(DEFAULT_MEMORY_MIB)
                .clamp(256, 1 << 20),
            disk_bytes: req
                .disk_mib
                .unwrap_or(DEFAULT_DISK_MIB)
                .clamp(1024, 1 << 24)
                << 20,
        };
        let net_mode = req.net_mode.clone().unwrap_or_else(|| "proxy".into());
        // Shared folders need shared guest memory (no copy-on-write restore); a project
        // setup builds its own template; full networking adds a NIC the template lacks.
        let snapshot_eligible =
            crate::templates::templates_enabled() && req.share.is_empty() && net_mode != "full";
        let base_key = crate::templates::base_key(self, &image.digest, shape);
        // A real secret copied in would end up in the snapshot's memory.
        let project_key = req
            .setup
            .as_ref()
            .filter(|_| snapshot_eligible && req.copy_secrets.is_empty())
            .filter(|_| repo.as_ref().is_some_and(|r| r.head.is_some()))
            .map(|s| crate::templates::project_key(&base_key, s));
        let pooled = if snapshot_eligible && req.setup.is_none() {
            self.pool.take(&base_key)
        } else {
            None
        };
        let id = match &pooled {
            Some(p) => p.id.clone(),
            None => hex(&random_bytes(8)),
        };
        let cid = self.db(|s| s.free_cid())?;
        let now = now_ms();
        let rec = PocketRecord {
            info: PocketInfo {
                id: id.clone(),
                name: name.clone(),
                state: PocketState::Creating,
                preset: preset.clone(),
                image_digest: image.digest.clone(),
                repo_path: repo.as_ref().map(|r| r.toplevel.clone()),
                base_ref: repo.as_ref().and_then(|r| r.head.clone()),
                branch: None,
                vcpus: shape.vcpus,
                memory_mib: shape.memory_mib,
                disk_bytes: shape.disk_bytes,
                disk_used_bytes: 0,
                net_profile: profile,
                created_at: now,
                last_active_at: now,
                started_from: None,
                template: None,
                net_mode: None,
            },
            vsock_cid: cid,
            vm_json: None,
            meta_json: serde_json::to_string(&Meta {
                allow: req.allow.clone(),
                secrets: injected,
                sync_config: req.sync_config,
                ssh_agent: req.ssh_agent,
                auto_forward: req.auto_forward,
                forward: req.forward.clone(),
                env: req.env.clone(),
                git_protected: req.git_protected.clone(),
                git_allow_push: req.git_allow_push.clone(),
                deny: req.deny.clone(),
                shares: crate::share::validate(&req.share)?,
                idle_pause_ms: req.idle_pause_ms,
                idle_hibernate_ms: req.idle_hibernate_ms,
                net_mode: Some(net_mode.clone()),
                base_branch: repo.as_ref().and_then(|r| r.branch.clone()),
                origin_host: repo
                    .as_ref()
                    .and_then(|r| r.origin.as_deref())
                    .and_then(pocket_git::github_repo)
                    .map(|(h, _, _)| h),
                ..Default::default()
            })
            .unwrap(),
        };
        self.db(|s| s.insert_pocket(&rec))?;
        self.emit(Event::PocketState {
            name: name.clone(),
            from: PocketState::Creating,
            to: PocketState::Creating,
            at: now,
        });
        let lock = self.op_lock(&id);
        let _g = lock.lock().await;
        let mut restored = false;
        let mut pooled = pooled;
        let result = async {
            let dir = self.paths.pocket_dir(&id);
            std::fs::create_dir_all(&dir).map_err(|e| {
                err(
                    ErrorCode::Internal,
                    format!("create {}: {e}", dir.display()),
                )
            })?;
            let template = req
                .setup
                .as_ref()
                .filter(|_| repo.as_ref().is_some_and(|r| r.head.is_some()))
                .map(|s| {
                    let key = template_key(&image.digest, s, rec.info.disk_bytes);
                    (
                        self.paths.templates().join(format!("project-{key}.raw")),
                        key,
                    )
                });
            let project_snap = project_key
                .as_deref()
                .and_then(|k| crate::templates::find(self, k));
            let from_template = project_snap.is_some()
                || (project_key.is_none() && template.as_ref().is_some_and(|(p, _)| p.exists()));
            let snap = match project_snap {
                Some(t) => Some(t),
                None => snapshot_eligible
                    .then(|| crate::templates::find(self, &base_key))
                    .flatten(),
            };
            if pooled.is_some() && snap.as_ref().is_none_or(|t| t.meta.key != base_key) {
                // Template retired between claim and now: the pooled VM is stale.
                pooled = None;
            }
            progress(if pooled.is_some() {
                "claiming a warm VM"
            } else {
                "creating disk"
            });
            if let (Some(t), true) = (&snap, pooled.is_some()) {
                let mut m = Self::meta(&rec);
                m.snapshot_template = Some(t.meta.key.clone());
                self.save_meta(&id, &m)?;
                let _ = self.db(|s| s.touch_template(&t.meta.key, now_ms()));
            } else if let Some(t) = &snap {
                let mode = pocket_image::disk::clone_disk(&t.disk(), &dir.join("disk.raw"))
                    .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
                tracing::info!("{name}: disk from template {} via {mode:?}", t.meta.key);
                let mut m = Self::meta(&rec);
                m.snapshot_template = Some(t.meta.key.clone());
                self.save_meta(&id, &m)?;
                let _ = self.db(|s| s.touch_template(&t.meta.key, now_ms()));
            } else if let (true, Some((tpl, key))) = (from_template, &template) {
                // D24 disk template (pockets that cannot use snapshots).
                let mode = pocket_image::disk::clone_disk(tpl, &dir.join("disk.raw"))
                    .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
                tracing::info!("{name}: disk from project template {key} via {mode:?}");
                let mut m = Self::meta(&rec);
                m.template = Some(key.clone());
                self.save_meta(&id, &m)?;
            } else {
                let mode = pocket_image::disk::create_pocket_disk(
                    &self.paths.templates(),
                    rec.info.disk_bytes,
                    &dir.join("disk.raw"),
                )
                .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
                tracing::info!("{name}: disk via {mode:?}");
            }
            restored = snap.is_some();
            if pooled.is_none() {
                progress(if restored { "restoring" } else { "booting" });
            }
            let rec = self.find(&name)?;
            let launch = match (pooled.take(), &snap) {
                (Some(p), _) => {
                    crate::pool::claimed(self, &p.id);
                    Launch::Pool(p)
                }
                (None, Some(t)) => Launch::Template(t),
                (None, None) => Launch::Cold,
            };
            let live = self.boot(&rec, &image.path, launch).await?;
            if let Some(info) = &repo {
                let branch = if from_template {
                    progress("updating the template's repository");
                    workspace::refresh(self, &live, info, req.carry_changes).await?
                } else {
                    progress("cloning repository");
                    workspace::clone_in(self, &live, info, req.carry_changes).await?
                };
                self.db(|s| s.set_workspace(&id, info.head.as_deref(), Some(&branch)))?;
            }
            if let (false, Some((tpl, key)), Some(setup)) = (from_template, &template, &req.setup) {
                progress(&format!("running setup: {}", setup.command));
                let snapshot = project_key
                    .as_ref()
                    .map(|k| (k.as_str(), shape, &image, preset.as_str()));
                self.build_template(&live, setup, tpl, key, snapshot)
                    .await?;
            }
            progress("starting session");
            self.create_session(
                &live,
                Some("shell"),
                req.command.clone(),
                24,
                80,
                req.term.clone(),
            )
            .await?;
            Ok::<_, RpcError>(())
        }
        .await;
        match result {
            Ok(()) => {
                self.set_state(&rec, PocketState::Running)?;
                if snapshot_eligible && !restored {
                    crate::templates::ensure_background(self, &preset, &image, shape);
                }
                self.pool.kick();
                let r = self.find(&name)?;
                Ok(self.info(r))
            }
            Err(e) => {
                tracing::warn!("{name}: creation failed: {}", e.message);
                let removed = self.live.lock().unwrap().remove(&id);
                if let Some(l) = removed {
                    l.stopping.store(true, Ordering::SeqCst);
                    let _ = self.backend.stop(&l.vm, StopMode::Kill).await;
                }
                self.set_state(
                    &rec,
                    PocketState::Broken {
                        reason: format!("creation failed: {}", e.message),
                    },
                )?;
                Err(e)
            }
        }
    }

    /// The VM spec of a pocket (shares are added by `boot`).
    pub(crate) fn vm_spec(&self, rec: &PocketRecord, image: &Path) -> VmSpec {
        let id = &rec.info.id;
        let disks = crate::templates::template_disks(
            self,
            image,
            &self.paths.pocket_dir(id).join("disk.raw"),
        );
        let dev = guest_devices(&disks);
        VmSpec {
            id: id.clone(),
            vcpus: rec.info.vcpus,
            memory_mib: rec.info.memory_mib,
            kernel: self.paths.kernel(),
            cmdline: format!(
                "{BOOT_ARGS} pocket.base={} pocket.disk={} pocket.hostname={}",
                dev[1], dev[2], rec.info.name
            ),
            disks,
            vsock_cid: rec.vsock_cid,
            cgroup: Some(CgroupSpec {
                unit: format!("pocket-{}", rec.info.name),
                slice: "pocket.slice".into(),
                cpu_quota_pct: rec.info.vcpus as u32 * 100,
                memory_max_bytes: ((rec.info.memory_mib as u64) << 20) + VMM_OVERHEAD,
                tasks_max: 4096,
            }),
            runtime_dir: self.paths.pocket_runtime(id),
            log_path: self.paths.pocket_dir(id).join("vmm.log"),
            serial_log: std::env::var_os("POCKET_SERIAL_LOG")
                .map(|_| self.paths.pocket_dir(id).join("serial.log")),
            shared_fs: vec![],
        }
    }

    /// Starts the pocket's VM from `launch`; returns once the restore hook ran (restores)
    /// and the guest is configured.
    pub(crate) async fn boot(
        self: &Arc<Self>,
        rec: &PocketRecord,
        image: &Path,
        launch: Launch<'_>,
    ) -> R<Arc<Live>> {
        let id = &rec.info.id;
        let mut spec = self.vm_spec(rec, image);
        let rt = spec.runtime_dir.clone();
        if !matches!(launch, Launch::Pool(_)) {
            let _ = std::fs::remove_dir_all(&rt);
            std::fs::create_dir_all(&rt).map_err(|e| {
                err(
                    ErrorCode::HostSetup,
                    format!("create {}: {e}", rt.display()),
                )
            })?;
        }
        let meta = Self::meta(rec);
        let mut fs_tasks = vec![];
        for (i, sh) in meta.shares.iter().enumerate() {
            let (sock, task) = crate::share::start_virtiofsd(&self.paths, &rt, i, sh).await?;
            spec.shared_fs.push((format!("pocketfs{i}"), sock));
            fs_tasks.push(task);
        }
        for p in [&spec.kernel, &self.paths.system_image(), &self.paths.vmm()] {
            if !p.exists() {
                return Err(err(ErrorCode::HostSetup, format!("{} is missing", p.display()))
                    .hint("install the pocket assets (`cargo xtask assets` in a source checkout) or set POCKET_ASSETS_DIR"));
            }
        }
        let vsock_uds = rt.join("vsock.sock");
        let (proxy, hooks) = self.egress(rec)?;
        let mut tasks = net::listen(self, rec, &vsock_uds, proxy.clone())?;
        tasks.extend(fs_tasks);
        self.agent_listener(rec, &vsock_uds, &mut tasks)?;
        let (kind, restore, configure) = match &launch {
            Launch::Cold => ("cold", None, true),
            Launch::Template(_) => ("template", Some(Restore::Clone), true),
            Launch::Hibernation(_) => ("hibernation", Some(Restore::Own), false),
            // The restore hook runs right after the resume below.
            Launch::Pool(_) => ("pool", None, true),
        };
        let (vm, pre) = match launch {
            Launch::Pool(p) => {
                let (vm, guest, rx) = p.into_parts();
                let mut m = Self::meta(rec);
                let mid = m
                    .machine_id
                    .get_or_insert_with(|| hex(&random_bytes(16)))
                    .clone();
                m.restore_generation += 1;
                let claim = std::time::Instant::now();
                let hooked = async {
                    self.backend
                        .resume(&vm)
                        .await
                        .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
                    let resumed = claim.elapsed();
                    restore_hook(
                        &guest,
                        &rec.info.name,
                        &mid,
                        m.restore_generation,
                        Restore::Clone,
                    )
                    .await?;
                    Ok::<_, RpcError>(resumed)
                }
                .await;
                let resumed = match hooked {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = self.backend.stop(&vm, StopMode::Kill).await;
                        return Err(e);
                    }
                };
                tracing::info!(
                    "{}: pool claim ready in {:.2} ms (VMM resume {:.2} ms, restore hook {:.2} ms)",
                    rec.info.name,
                    claim.elapsed().as_secs_f64() * 1e3,
                    resumed.as_secs_f64() * 1e3,
                    (claim.elapsed() - resumed).as_secs_f64() * 1e3,
                );
                self.save_meta(id, &m)?;
                (vm, Some((guest, rx)))
            }
            other => {
                let vm = match &other {
                    Launch::Template(t) => self.backend.restore(&t.snapshot(), &spec).await,
                    Launch::Hibernation(snap) => self.backend.restore(snap, &spec).await,
                    _ => self.backend.create(&spec).await,
                }
                .map_err(|e| {
                    err(ErrorCode::Vmm, e.to_string())
                        .hint(format!("see {}", spec.log_path.display()))
                })?;
                (vm, None)
            }
        };
        self.db(|s| s.set_vm(id, Some(&serde_json::to_string(&vm).unwrap())))?;
        let live = match self
            .attach_guest(
                rec,
                vm.clone(),
                proxy,
                hooks,
                &mut tasks,
                GuestSetup {
                    configure,
                    restore,
                    pre,
                },
            )
            .await
        {
            Ok(l) => l,
            Err(e) => {
                let _ = self.backend.stop(&vm, StopMode::Kill).await;
                for t in tasks {
                    t.abort();
                }
                return Err(e);
            }
        };
        if let Ok(Some(r)) = self.db(|s| s.pocket(&rec.info.name)) {
            let mut m = Self::meta(&r);
            m.started_from = Some(kind.into());
            let _ = self.save_meta(id, &m);
        }
        Ok(live)
    }

    async fn attach_guest(
        self: &Arc<Self>,
        rec: &PocketRecord,
        vm: VmHandle,
        proxy: Arc<pocket_net::proxy::ProxyCtx>,
        hooks: Arc<PocketHooks>,
        tasks: &mut Vec<JoinHandle<()>>,
        how: GuestSetup,
    ) -> R<Arc<Live>> {
        let GuestSetup {
            configure,
            restore,
            pre,
        } = how;
        let (guest, mut rx) = match pre {
            Some(p) => p,
            None => {
                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                let g = GuestConn::connect(&vm.vsock_uds, Duration::from_secs(15), tx)
                    .await
                    .map_err(|e| err(ErrorCode::Guest, format!("guest did not come up: {e}")))?;
                (g, rx)
            }
        };
        tracing::info!(
            "{}: guest ready (pocket-init {}, {:.1} ms after kernel start)",
            rec.info.name,
            guest.init_version,
            guest.boot_ns as f64 / 1e6
        );
        let mut meta: Meta = serde_json::from_str(&rec.meta_json).unwrap_or_default();
        let machine_id = meta
            .machine_id
            .get_or_insert_with(|| hex(&random_bytes(16)))
            .clone();
        if let Some(kind) = restore {
            meta.restore_generation += 1;
            restore_hook(
                &guest,
                &rec.info.name,
                &machine_id,
                meta.restore_generation,
                kind,
            )
            .await?;
            if !configure {
                let mj = serde_json::to_string(&meta).unwrap();
                self.db(|s| s.set_meta(&rec.info.id, &mj))?;
            }
        }
        if configure {
            let mut env = proxy_env();
            env.extend(provision::guest_env(&hooks));
            if meta.ssh_agent {
                env.push(("SSH_AUTH_SOCK".into(), "/run/pocket/ssh-agent.sock".into()));
            }
            env.push(("BROWSER".into(), "pocket-guest open".into()));
            env.extend(meta.env.iter().cloned());
            guest
                .request(HostReq::Configure {
                    hostname: rec.info.name.clone(),
                    rng_seed: random_bytes(RNG_SEED_LEN),
                    time_unix_nanos: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0),
                    env,
                    proxy_port: GUEST_PROXY_PORT,
                    machine_id: machine_id.clone(),
                })
                .await
                .map_err(|e| err(ErrorCode::Guest, format!("configure guest: {e}")))?;
            let probe = guest
                .exec(
                    ExecReq {
                        argv: &["/bin/sh", "-c", "id -u dev >/dev/null 2>&1 && echo dev"],
                        env: vec![],
                        cwd: "/",
                        user: None,
                        stdin: None,
                    },
                    4096,
                )
                .await
                .map_err(|e| err(ErrorCode::Guest, format!("probe guest user: {e}")))?;
            meta.user =
                (String::from_utf8_lossy(&probe.stdout).trim() == "dev").then(|| "dev".into());
            crate::share::mount_all(&guest, &meta.shares).await?;
            provision::provision(self, &guest, rec, &mut meta, &hooks).await?;
            let mj = serde_json::to_string(&meta).unwrap();
            self.db(|s| {
                s.set_vm(&rec.info.id, Some(&serde_json::to_string(&vm).unwrap()))?;
                // meta_json is only rewritten here; keep the update local to this column.
                s.set_meta(&rec.info.id, &mj)
            })?;
        }
        let auto_forward = meta.auto_forward;
        let fixed = meta.forward.clone();
        let live = Arc::new(Live {
            id: rec.info.id.clone(),
            name: rec.info.name.clone(),
            vm: vm.clone(),
            guest,
            user: meta.user,
            proxy,
            hooks,
            host: crate::host::HostState::new(auto_forward),
            stopping: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            tasks: Mutex::new(std::mem::take(tasks)),
        });
        let d = self.clone();
        let pname = rec.info.name.clone();
        let weak = Arc::downgrade(&live);
        live.tasks.lock().unwrap().push(tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                if let GuestEvent::SessionExited { name, status } = e {
                    d.emit(Event::SessionExited {
                        pocket: pname.clone(),
                        session: name,
                        status,
                    });
                } else if let Some(l) = weak.upgrade() {
                    d.guest_event(&l, e).await;
                }
            }
        }));
        for (g, h) in fixed {
            if let Err(e) = self.forward_port(&live, g, Some(h), None, false).await {
                tracing::warn!("{}: forward {g}:{h}: {}", rec.info.name, e.message);
            }
        }
        self.live
            .lock()
            .unwrap()
            .insert(rec.info.id.clone(), live.clone());
        let d = self.clone();
        let (id, name) = (rec.info.id.clone(), rec.info.name.clone());
        tokio::spawn(async move {
            let _ = d.backend.wait_exit(&vm).await;
            d.on_vm_exit(&id, &name);
        });
        Ok(live)
    }

    fn on_vm_exit(&self, id: &str, name: &str) {
        let Some(live) = self.live.lock().unwrap().remove(id) else {
            return;
        };
        if let Some(u) = &live.vm.cgroup_unit {
            pocket_vmm::cgroup::stop_scope(u);
        }
        if live.stopping.load(Ordering::SeqCst) {
            return;
        }
        tracing::warn!("{name}: VMM exited unexpectedly");
        if let Ok(Some(rec)) = self.db(|s| s.pocket(name)) {
            let _ = self.db(|s| s.set_vm(id, None));
            let _ = self.set_state(
                &rec,
                PocketState::Broken {
                    reason: format!(
                        "the VM exited unexpectedly (log: {})",
                        self.paths.pocket_dir(id).join("vmm.log").display()
                    ),
                },
            );
        }
    }

    /// After a daemon restart: re-adopt VMs that still run, mark the rest broken.
    pub async fn readopt(self: &Arc<Self>) {
        let recs = match self.db(|s| s.pockets()) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("readopt: {}", e.message);
                return;
            }
        };
        for rec in recs {
            match rec.info.state {
                PocketState::Running | PocketState::Paused => {}
                PocketState::Creating => {
                    let _ = self.set_state(
                        &rec,
                        PocketState::Broken {
                            reason: "pocketd stopped while the pocket was being created".into(),
                        },
                    );
                    continue;
                }
                _ => continue,
            }
            let result = async {
                let vm: VmHandle = rec
                    .vm_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str(j).ok())
                    .ok_or_else(|| err(ErrorCode::Internal, "no VM recorded"))?;
                self.backend
                    .adopt(&vm)
                    .await
                    .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
                if rec.info.state == PocketState::Paused {
                    // A paused guest cannot accept the control connection; the idle manager
                    // pauses it again if it stays idle.
                    self.backend
                        .resume(&vm)
                        .await
                        .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
                }
                let (proxy, hooks) = self.egress(&rec)?;
                let mut tasks = net::listen(self, &rec, &vm.vsock_uds, proxy.clone())?;
                self.agent_listener(&rec, &vm.vsock_uds, &mut tasks)?;
                self.attach_guest(
                    &rec,
                    vm,
                    proxy,
                    hooks,
                    &mut tasks,
                    GuestSetup {
                        configure: false,
                        restore: None,
                        pre: None,
                    },
                )
                .await
            }
            .await;
            match result {
                Ok(_) => {
                    if rec.info.state == PocketState::Paused {
                        let _ = self.set_state(&rec, PocketState::Running);
                    }
                    tracing::info!("{}: re-adopted running VM", rec.info.name)
                }
                Err(e) => {
                    let _ = self.db(|s| s.set_vm(&rec.info.id, None));
                    let _ = self.set_state(
                        &rec,
                        PocketState::Broken {
                            reason: format!(
                                "could not re-adopt the VM after a daemon restart: {}",
                                e.message
                            ),
                        },
                    );
                }
            }
        }
    }

    /// Runs `setup` in `/work` and keeps the resulting disk as the project template.
    async fn build_template(
        self: &Arc<Self>,
        live: &Live,
        setup: &pocket_proto::rpc::Setup,
        tpl: &Path,
        key: &str,
        snapshot: Option<(&str, crate::templates::Shape, &crate::presets::Image, &str)>,
    ) -> R<()> {
        let started = std::time::Instant::now();
        let out = tokio::time::timeout(
            Duration::from_secs(1800),
            live.guest.exec(
                crate::guest::ExecReq {
                    argv: &["/bin/sh", "-c", &setup.command],
                    env: vec![],
                    cwd: "/work",
                    user: live.user.as_deref(),
                    stdin: None,
                },
                1 << 20,
            ),
        )
        .await
        .map_err(|_| err(ErrorCode::Workspace, "setup ran for more than 30 minutes"))?
        .map_err(guest_err)?;
        if !out.ok() {
            let tail: String = {
                let t = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    out.stderr_text()
                );
                let lines: Vec<&str> = t.lines().collect();
                lines[lines.len().saturating_sub(20)..].join("\n")
            };
            return Err(err(
                ErrorCode::Workspace,
                format!(
                    "setup `{}` failed ({:?}):\n{tail}",
                    setup.command, out.status
                ),
            )
            .hint("fix sandbox.setup in pocket.toml; nothing was cached"));
        }
        tracing::info!("{}: setup done in {:.1?}", live.name, started.elapsed());
        // Nothing pocket-specific (placeholders, copied agent config) goes into the template.
        let _ = crate::provision::sh(
            &live.guest,
            None,
            "rm -rf /home/*/.codex/auth.json /root/.codex/auth.json /tmp/pocket-paste; sync",
            vec![],
            "clean the template",
        )
        .await;
        if let Some((pkey, shape, image, preset)) = snapshot {
            let rec = self.find(&live.name)?;
            match crate::templates::snapshot_pocket(
                self, live, &rec, pkey, shape, image, preset, "project", None,
            )
            .await
            {
                Ok(()) => {
                    let mut m = Self::meta(&self.find(&live.name)?);
                    m.snapshot_template = Some(pkey.to_string());
                    m.template = Some(key.to_string());
                    let _ = self.save_meta(&live.id, &m);
                    return Ok(());
                }
                Err(e) => tracing::warn!(
                    "{}: project snapshot: {}; keeping a disk template",
                    live.name,
                    e.message
                ),
            }
        }
        let disk = self.paths.pocket_dir(&live.id).join("disk.raw");
        let tmp = tpl.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        self.backend
            .pause(&live.vm)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        let copied = pocket_image::disk::clone_disk(&disk, &tmp);
        self.backend
            .resume(&live.vm)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        let saved = copied.map_err(|e| e.to_string()).and_then(|m| {
            std::fs::rename(&tmp, tpl)
                .map(|()| m)
                .map_err(|e| e.to_string())
        });
        match saved {
            Ok(mode) => tracing::info!("{}: project template {key} saved via {mode:?}", live.name),
            Err(e) => tracing::warn!("{}: save project template: {e}", live.name),
        }
        if let Ok(Some(rec)) = self.db(|s| s.pocket(&live.name)) {
            let mut m = Self::meta(&rec);
            m.template = Some(key.to_string());
            let _ = self.save_meta(&live.id, &m);
        }
        Ok(())
    }

    /// Injected secrets for a new pocket: placeholders generated now and kept in its meta.
    fn select_secrets(&self, req: &NewPocket) -> R<Vec<InjectedSecret>> {
        let all = self.db(|s| s.secrets())?;
        let names: Vec<String> = match &req.secrets {
            None => all.iter().map(|r| r.name.clone()).collect(),
            Some(v) => v.clone(),
        };
        let mut out: Vec<InjectedSecret> = vec![];
        for n in names.iter().chain(req.copy_secrets.iter()) {
            if out.iter().any(|o| &o.name == n) {
                continue;
            }
            let rec = all.iter().find(|r| &r.name == n).ok_or_else(|| {
                err(ErrorCode::NotFound, format!("no secret named {n:?}"))
                    .hint("`pocket secrets ls` lists secrets; add one with `pocket login` or `pocket secrets add`")
            })?;
            let info = secrets::info_from_record(rec);
            let value = self.vault.get(n)?.ok_or_else(|| {
                err(
                    ErrorCode::HostSetup,
                    format!("secret {n} has no stored value ({})", info.storage),
                )
                .hint(format!(
                    "store it again with `pocket secrets add {n}` or `pocket login`"
                ))
            })?;
            let mut s = InjectedSecret {
                name: n.clone(),
                copy_in: req.copy_secrets.contains(n),
                ..Default::default()
            };
            if info.kind == "chatgpt" {
                let c = inject::ChatGpt::parse(&value)?;
                s.placeholder = secrets::placeholder(&c.refresh_token);
                s.access_placeholder = Some(inject::placeholder_jwt(&c.access_token));
                s.id_placeholder = Some(inject::placeholder_jwt(&c.id_token));
            } else {
                s.placeholder = secrets::placeholder(&value);
            }
            if s.copy_in {
                tracing::warn!("secret {n}: real value copied into the new pocket (--copy-secret)");
            }
            out.push(s);
        }
        Ok(out)
    }

    fn agent_listener(
        self: &Arc<Self>,
        rec: &PocketRecord,
        vsock_uds: &Path,
        tasks: &mut Vec<JoinHandle<()>>,
    ) -> R<()> {
        if !Self::meta(rec).ssh_agent {
            return Ok(());
        }
        let path =
            pocket_vmm::vsock::host_listener_path(vsock_uds, pocket_proto::guest::SSH_AGENT_PORT);
        tasks.push(
            crate::sshagent::listen(self, &rec.info.name, &path).map_err(|e| {
                err(
                    ErrorCode::HostSetup,
                    format!("listen on {}: {e}", path.display()),
                )
            })?,
        );
        Ok(())
    }

    /// The pocket's proxy context with its interception hooks.
    fn egress(
        self: &Arc<Self>,
        rec: &PocketRecord,
    ) -> R<(Arc<pocket_net::proxy::ProxyCtx>, Arc<PocketHooks>)> {
        let meta = Self::meta(rec);
        let all = self.db(|s| s.secrets())?;
        let mut items = vec![];
        for m in &meta.secrets {
            let Some(r) = all.iter().find(|r| r.name == m.name) else {
                tracing::warn!(
                    "{}: secret {} no longer exists; not injected",
                    rec.info.name,
                    m.name
                );
                continue;
            };
            let info = secrets::info_from_record(r);
            let real = match self.vault.get(&m.name) {
                Ok(Some(v)) => v,
                Ok(None) => {
                    tracing::warn!(
                        "{}: secret {} has no value; not injected",
                        rec.info.name,
                        m.name
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };
            let chat = (info.kind == "chatgpt")
                .then(|| inject::ChatGpt::parse(&real).ok())
                .flatten();
            items.push(inject::Item {
                info,
                real,
                meta: m.clone(),
                chat,
                old_access: vec![],
            });
        }
        let (resolver, connector) = net::upstream();
        let hooks = Arc::new(PocketHooks::new(
            rec.info.id.clone(),
            items,
            inject::Net {
                resolver,
                connector,
                tls: self.upstream_tls(),
            },
            Arc::downgrade(self),
        ));
        *hooks.guard.write().unwrap() = crate::guard::for_pocket(&meta, &hooks);
        let mitm = Arc::new(pocket_net::mitm::Mitm {
            ca: self.ca()?,
            client: self.upstream_tls(),
            hooks: hooks.clone(),
        });
        let proxy = net::proxy_ctx(self, rec, &meta.allow, Some(mitm))?;
        for d in &meta.deny {
            if let Ok(r) = pocket_net::policy::Rule::parse(d) {
                proxy.policy.write().unwrap().deny.push(r);
            }
        }
        Ok((proxy, hooks))
    }

    pub async fn start(self: &Arc<Self>, name: &str) -> R<PocketInfo> {
        let rec = self.find(name)?;
        let lock = self.op_lock(&rec.info.id);
        let _g = lock.lock().await;
        if self.live(&rec.info.id).is_some() || rec.info.state == PocketState::Hibernated {
            drop(_g);
            return self.resume(&rec.info.name).await;
        }
        let image = presets::resolve(self, &rec.info.preset)?;
        let live = self.boot(&rec, &image.path, Launch::Cold).await?;
        self.create_session(&live, Some("shell"), None, 24, 80, None)
            .await?;
        self.set_state(&rec, PocketState::Running)?;
        Ok(self.info(self.find(&rec.info.name)?))
    }

    async fn shutdown_live(&self, live: &Live) -> R<()> {
        live.stopping.store(true, Ordering::SeqCst);
        if live.paused.load(Ordering::SeqCst) {
            let _ = self.backend.resume(&live.vm).await;
        }
        let asked = tokio::time::timeout(
            Duration::from_secs(8),
            live.guest.request_id(
                HostReq::Shutdown { timeout_ms: 3000 },
                Duration::from_secs(8),
            ),
        )
        .await;
        let mode = if matches!(asked, Ok(Ok(_))) {
            StopMode::Graceful { timeout_ms: 5000 }
        } else {
            StopMode::Kill
        };
        self.backend
            .stop(&live.vm, mode)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))
    }

    pub async fn stop(self: &Arc<Self>, name: &str) -> R<PocketInfo> {
        let rec = self.find(name)?;
        let lock = self.op_lock(&rec.info.id);
        let _g = lock.lock().await;
        let rec = self.find(&rec.info.name)?;
        if rec.info.state != PocketState::Hibernated {
            let live = self.running(&rec)?;
            self.shutdown_live(&live).await?;
            self.live.lock().unwrap().remove(&rec.info.id);
        }
        self.db(|s| s.set_vm(&rec.info.id, None))?;
        crate::lifecycle::remove_hibernations(self, &rec.info.id, None);
        let mut m = Self::meta(&rec);
        m.hibernation = None;
        self.save_meta(&rec.info.id, &m)?;
        self.set_state(&rec, PocketState::Stopped)?;
        Ok(self.info(self.find(&rec.info.name)?))
    }

    pub async fn remove(self: &Arc<Self>, name: &str) -> R<()> {
        let rec = self.find(name)?;
        let lock = self.op_lock(&rec.info.id);
        let _g = lock.lock().await;
        if let Some(live) = self.live(&rec.info.id) {
            if self.shutdown_live(&live).await.is_err() {
                let _ = self.backend.stop(&live.vm, StopMode::Kill).await;
            }
            self.live.lock().unwrap().remove(&rec.info.id);
        } else if let Some(vm) = rec
            .vm_json
            .as_deref()
            .and_then(|j| serde_json::from_str::<VmHandle>(j).ok())
        {
            let _ = self.backend.stop(&vm, StopMode::Kill).await;
        }
        let _ = std::fs::remove_dir_all(self.paths.pocket_runtime(&rec.info.id));
        let dir = self.paths.pocket_dir(&rec.info.id);
        std::fs::remove_dir_all(&dir)
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(|e| {
                err(
                    ErrorCode::Internal,
                    format!("remove {}: {e}", dir.display()),
                )
            })?;
        self.db(|s| s.delete_pocket(&rec.info.id))?;
        self.emit(Event::PocketState {
            name: rec.info.name.clone(),
            from: rec.info.state.clone(),
            to: PocketState::Stopped,
            at: now_ms(),
        });
        tracing::info!("{}: removed", rec.info.name);
        Ok(())
    }

    pub async fn exec(
        &self,
        name: &str,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        tty: Option<(u16, u16)>,
        root: bool,
    ) -> R<(u64, PathBuf)> {
        let rec = self.find(name)?;
        let live = self.running(&rec)?;
        let _ = self.db(|s| s.touch(&rec.info.id, now_ms()));
        let (id, reply) = live
            .guest
            .request_id(
                HostReq::Exec {
                    argv,
                    env,
                    cwd: cwd.unwrap_or_else(|| "/work".into()),
                    pty: tty.map(|(rows, cols)| PtySize { rows, cols }),
                    user: if root { None } else { live.user.clone() },
                },
                Duration::from_secs(30),
            )
            .await
            .map_err(guest_err)?;
        match reply {
            Reply::ExecStarted { .. } => Ok((id, live.vm.vsock_uds.clone())),
            other => Err(err(ErrorCode::Guest, format!("unexpected reply {other:?}"))),
        }
    }

    pub async fn sessions(&self, name: &str) -> R<Vec<SessionInfo>> {
        let rec = self.find(name)?;
        let live = self.running(&rec)?;
        list_sessions(&live).await
    }

    pub async fn create_session(
        &self,
        live: &Live,
        name: Option<&str>,
        argv: Option<Vec<String>>,
        rows: u16,
        cols: u16,
        term: Option<String>,
    ) -> R<String> {
        let existing = list_sessions(live).await?;
        let name = match name {
            Some(n) => n.to_string(),
            None => (1..)
                .map(|i| {
                    if i == 1 {
                        "shell".to_string()
                    } else {
                        format!("shell-{i}")
                    }
                })
                .find(|n| !existing.iter().any(|s| &s.name == n))
                .unwrap(),
        };
        let argv = argv.unwrap_or_else(|| {
            ["/bin/sh", "-c", "exec \"${SHELL:-/bin/sh}\" -l"]
                .map(String::from)
                .to_vec()
        });
        let env = vec![(
            "TERM".to_string(),
            term.unwrap_or_else(|| "xterm-256color".into()),
        )];
        live.guest
            .request(HostReq::SessionCreate {
                name: name.clone(),
                argv,
                env,
                cwd: "/work".into(),
                size: PtySize {
                    rows: rows.max(1),
                    cols: cols.max(1),
                },
                user: live.user.clone(),
            })
            .await
            .map_err(guest_err)?;
        Ok(name)
    }

    pub async fn session_create(
        &self,
        pocket: &str,
        name: Option<String>,
        argv: Option<Vec<String>>,
        rows: u16,
        cols: u16,
        term: Option<String>,
    ) -> R<String> {
        let rec = self.find(pocket)?;
        let live = self.running(&rec)?;
        if let Some(n) = &name
            && !pocket_proto::guest::valid_name(n)
        {
            return Err(err(
                ErrorCode::BadRequest,
                format!("invalid session name {n:?}"),
            ));
        }
        self.create_session(&live, name.as_deref(), argv, rows, cols, term)
            .await
    }

    pub async fn session_kill(&self, pocket: &str, session: &str, signal: i32) -> R<()> {
        let rec = self.find(pocket)?;
        let live = self.running(&rec)?;
        live.guest
            .request(HostReq::SessionKill {
                name: session.into(),
                signal,
            })
            .await
            .map_err(guest_err)?;
        Ok(())
    }

    pub async fn attach_authorize(
        &self,
        pocket: &str,
        session: Option<String>,
    ) -> R<(String, PathBuf, Vec<u8>)> {
        let rec = self.find(pocket)?;
        let live = self.running(&rec)?;
        let session = match session {
            Some(s) => s,
            None => {
                let list = list_sessions(&live).await?;
                match list.iter().rev().find(|s| s.exited.is_none()) {
                    Some(s) => s.name.clone(),
                    None => self.create_session(&live, None, None, 24, 80, None).await?,
                }
            }
        };
        let token = random_bytes(pocket_proto::guest::ATTACH_TOKEN_LEN);
        live.guest
            .request(HostReq::AuthorizeAttach {
                session: session.clone(),
                token: token.clone(),
            })
            .await
            .map_err(guest_err)?;
        let _ = self.db(|s| s.touch(&rec.info.id, now_ms()));
        Ok((session, live.vm.vsock_uds.clone(), token))
    }

    pub async fn boot_builder(self: &Arc<Self>, rec: &PocketRecord, image: &Path) -> R<Arc<Live>> {
        self.boot(rec, image, Launch::Cold).await
    }

    pub async fn stop_builder(&self, live: &Live) {
        if self.shutdown_live(live).await.is_err() {
            let _ = self.backend.stop(&live.vm, StopMode::Kill).await;
        }
        self.live.lock().unwrap().remove(&live.id);
    }

    /// Stops every live VM's supervision without stopping VMs (daemon shutdown).
    pub fn detach_all(&self) {
        for (_, l) in self.live.lock().unwrap().drain() {
            l.stopping.store(true, Ordering::SeqCst);
        }
    }
}

/// Project template key: base image, setup command and the content of its inputs, disk size.
pub fn template_key(image: &str, s: &pocket_proto::rpc::Setup, disk_bytes: u64) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"pocket-project-template-v1\0");
    h.update(image.as_bytes());
    h.update(b"\0");
    h.update(s.command.as_bytes());
    for (p, d) in &s.inputs {
        h.update(format!("\0{p}\0{d}").as_bytes());
    }
    h.update(disk_bytes.to_le_bytes());
    hex(&h.finalize()[..8])
}

/// The restore hook (CONTRACTS.md invariant): new RNG seed, clock and identity before the
/// guest serves anything else. A sealed guest refuses sessions and execs until it ran.
pub async fn restore_hook(
    guest: &GuestConn,
    hostname: &str,
    machine_id: &str,
    generation: u64,
    kind: Restore,
) -> R<()> {
    guest
        .request_id(
            HostReq::Restored {
                generation,
                rng_seed: random_bytes(RNG_SEED_LEN),
                time_unix_nanos: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0),
                hostname: hostname.to_string(),
                machine_id: machine_id.to_string(),
                clone: kind == Restore::Clone,
            },
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| err(ErrorCode::Guest, format!("restore hook: {e}")))?;
    Ok(())
}

pub fn guest_err(e: crate::guest::GuestConnError) -> RpcError {
    use crate::guest::GuestConnError as G;
    use pocket_proto::guest::ErrorKind as K;
    match e {
        G::Guest(g) => {
            let code = match g.kind {
                K::NotFound => ErrorCode::NotFound,
                K::AlreadyExists => ErrorCode::AlreadyExists,
                K::InvalidRequest => ErrorCode::BadRequest,
                _ => ErrorCode::Guest,
            };
            err(code, g.message)
        }
        other => err(ErrorCode::Guest, other.to_string()),
    }
}

async fn list_sessions(live: &Live) -> R<Vec<SessionInfo>> {
    match live
        .guest
        .request(HostReq::SessionList)
        .await
        .map_err(guest_err)?
    {
        Reply::Sessions(s) => Ok(s),
        other => Err(err(ErrorCode::Guest, format!("unexpected reply {other:?}"))),
    }
}

/// Environment for every guest process: route HTTP(S) through the in-guest shim.
pub fn proxy_env() -> Vec<(String, String)> {
    let url = format!("http://127.0.0.1:{GUEST_PROXY_PORT}");
    let mut v = vec![];
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        v.push((k.to_string(), url.clone()));
    }
    for k in ["NO_PROXY", "no_proxy"] {
        v.push((k.to_string(), "localhost,127.0.0.1,::1".to_string()));
    }
    v.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
    // Node 22 warns on every start that the env-proxy agent is experimental.
    v.push((
        "NODE_OPTIONS".into(),
        "--disable-warning=UNDICI-EHPA".into(),
    ));
    v.push(("POCKET".into(), "1".into()));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_pocket_name("webapp-1") && valid_pocket_name("a"));
        assert!(!valid_pocket_name("-a") && !valid_pocket_name("a-") && !valid_pocket_name("A"));
        assert!(!valid_pocket_name(&"a".repeat(41)) && !valid_pocket_name("a_b"));
        assert_eq!(sanitize("My_Repo.rs"), "my-repo-rs");
        assert_eq!(sanitize("..."), "pocket");
    }
}
