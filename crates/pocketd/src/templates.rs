//! Snapshot templates (PERFORMANCE.md §Tier 2, CONTRACTS.md §5 Template key): a VM booted
//! once, sealed, paused and snapshotted with its pocket disk. New pockets restore from it
//! with a reflinked copy of the disk and always get the restore hook first.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use pocket_proto::guest::HostReq;
use pocket_proto::rpc::ErrorCode;
use pocket_store::TemplateRecord;
use pocket_vmm::{
    CgroupSpec, DiskRole, DiskSpec, DiskTransport, HostFingerprint, SnapshotRef, StopMode, VmSpec,
    guest_devices,
};
use serde::{Deserialize, Serialize};

use crate::daemon::{BOOT_ARGS, Daemon, R, err, now_ms, random_bytes};
use crate::guest::GuestConn;

/// Bump when the template layout or the state a template is taken in changes.
const FORMAT: &str = "pocket-template-v2";
const BUILD_CPU_PCT: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Shape {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disk_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub key: String,
    pub kind: String,
    pub preset: String,
    pub image_digest: String,
    pub shape: Shape,
    pub fingerprint: HostFingerprint,
    pub backend: String,
    pub vsock_cid: u32,
    pub built_at: u64,
}

pub struct Template {
    pub dir: PathBuf,
    pub meta: TemplateMeta,
}

impl Template {
    pub fn disk(&self) -> PathBuf {
        self.dir.join("disk.raw")
    }

    pub fn snapshot(&self) -> SnapshotRef {
        SnapshotRef {
            dir: self.dir.clone(),
            backend: self.meta.backend.clone(),
            host_fingerprint: self.meta.fingerprint.clone(),
            disks: vec![],
        }
    }
}

/// Builds in progress, by key (a key is built once at a time).
static BUILDING: Mutex<Option<HashSet<String>>> = Mutex::new(None);
/// sha256 of assets, by (path, size, mtime).
type AssetId = (PathBuf, u64, i128);
static ASSET_HASH: Mutex<Option<HashMap<AssetId, String>>> = Mutex::new(None);

fn hash_file(path: &Path) -> String {
    use sha2::Digest;
    let Ok(md) = std::fs::metadata(path) else {
        return "missing".into();
    };
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(-1);
    let k = (path.to_path_buf(), md.len(), mtime);
    if let Some(h) = ASSET_HASH.lock().unwrap().as_ref().and_then(|m| m.get(&k)) {
        return h.clone();
    }
    let mut h = sha2::Sha256::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut buf = vec![0u8; 1 << 20];
        while let Ok(n) = f.read(&mut buf) {
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
    }
    let out: String = h.finalize()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    ASSET_HASH
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(k, out.clone());
    out
}

pub fn fingerprint(d: &Daemon) -> HostFingerprint {
    d.backend.host_fingerprint()
}

/// Every input that makes a snapshot unusable when it changes (CONTRACTS.md §5), plus the
/// VM shape baked into the snapshot.
pub fn base_key(d: &Daemon, image_digest: &str, shape: Shape) -> String {
    use sha2::Digest;
    let fp = fingerprint(d);
    let mut h = sha2::Sha256::new();
    for part in [
        FORMAT,
        image_digest,
        &hash_file(&d.paths.kernel()),
        &hash_file(&d.paths.system_image()),
        d.backend.name(),
        d.backend.version(),
        &fp.cpu_model,
        &fp.cpu_flags_hash,
        &fp.host_kernel,
        &fp.vmm_version,
        BOOT_ARGS,
        &format!("{}:{}:{}", shape.vcpus, shape.memory_mib, shape.disk_bytes),
    ] {
        h.update(part.as_bytes());
        h.update(b"\0");
    }
    h.finalize()[..10]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn family(preset: &str, shape: Shape) -> String {
    format!(
        "base:{preset}:{}:{}:{}",
        shape.vcpus, shape.memory_mib, shape.disk_bytes
    )
}

pub fn dir(d: &Daemon, key: &str) -> PathBuf {
    d.paths.templates().join(format!("snap-{key}"))
}

/// The ready template for `key`, if any.
pub fn find(d: &Daemon, key: &str) -> Option<Template> {
    let dir = dir(d, key);
    let meta: TemplateMeta =
        serde_json::from_slice(&std::fs::read(dir.join("meta.json")).ok()?).ok()?;
    (meta.key == key && meta.fingerprint == fingerprint(d)).then_some(Template { dir, meta })
}

pub fn templates_enabled() -> bool {
    !matches!(
        std::env::var("POCKET_TEMPLATES").as_deref(),
        Ok("off") | Ok("0")
    )
}

/// Starts a background build of `key` unless one runs or it exists.
pub fn ensure_background(
    d: &Arc<Daemon>,
    preset: &str,
    image: &crate::presets::Image,
    shape: Shape,
) {
    if !templates_enabled() {
        return;
    }
    let key = base_key(d, &image.digest, shape);
    if find(d, &key).is_some() {
        return;
    }
    {
        let mut b = BUILDING.lock().unwrap();
        if !b.get_or_insert_with(HashSet::new).insert(key.clone()) {
            return;
        }
    }
    let (d, preset, image) = (d.clone(), preset.to_string(), image.clone());
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        match build(&d, &preset, &image, shape, &key).await {
            Ok(t) => {
                tracing::info!(
                    "template {key} ({preset}) built in {:.1?}",
                    started.elapsed()
                );
                retire_family(&d, &t.meta);
            }
            Err(e) => tracing::warn!("template {key} ({preset}): build failed: {}", e.message),
        }
        if let Some(b) = BUILDING.lock().unwrap().as_mut() {
            b.remove(&key);
        }
    });
}

/// Waits for a background build of `key` (tests, `pocket pull`, bench).
pub async fn wait_built(d: &Daemon, key: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if find(d, key).is_some() {
            return true;
        }
        let building = BUILDING
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|b| b.contains(key));
        if !building || std::time::Instant::now() > deadline {
            return find(d, key).is_some();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Older templates of the same family are stale once a new key is built. Unlinking is safe
/// even for pockets restored from them: their copy-on-write mapping keeps the file alive.
fn retire_family(d: &Daemon, new: &TemplateMeta) {
    let fam = family(&new.preset, new.shape);
    let Ok(all) = d.db(|s| s.templates()) else {
        return;
    };
    for t in all
        .iter()
        .filter(|t| t.family == fam && t.key != new.key && t.kind == "base")
    {
        let _ = std::fs::remove_dir_all(dir(d, &t.key));
        let _ = d.db(|s| s.delete_template(&t.key));
        tracing::info!("template {}: replaced by {} (key changed)", t.key, new.key);
    }
}

pub fn template_disks(d: &Daemon, image: &Path, pocket_disk: &Path) -> Vec<DiskSpec> {
    vec![
        DiskSpec {
            role: DiskRole::System,
            path: d.paths.system_image(),
            read_only: true,
            transport: DiskTransport::Blk,
        },
        DiskSpec {
            role: DiskRole::Base,
            path: image.to_path_buf(),
            read_only: true,
            transport: DiskTransport::Pmem { dax: true },
        },
        DiskSpec {
            role: DiskRole::Pocket,
            path: pocket_disk.to_path_buf(),
            read_only: false,
            transport: DiskTransport::Blk,
        },
    ]
}

async fn build(
    d: &Arc<Daemon>,
    preset: &str,
    image: &crate::presets::Image,
    shape: Shape,
    key: &str,
) -> R<Template> {
    let final_dir = dir(d, key);
    let staging = d.paths.templates().join(format!(
        "snap-{key}.tmp-{}",
        crate::daemon::hex(&random_bytes(4))
    ));
    let rt = d.paths.runtime.join("t").join(&key[..8]);
    let result = async {
        std::fs::create_dir_all(&staging).map_err(|e| {
            err(
                ErrorCode::HostSetup,
                format!("create {}: {e}", staging.display()),
            )
        })?;
        set_private(&staging);
        pocket_image::disk::create_pocket_disk(
            &d.paths.templates(),
            shape.disk_bytes,
            &staging.join("disk.raw"),
        )
        .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
        let _ = std::fs::remove_dir_all(&rt);
        std::fs::create_dir_all(&rt).map_err(|e| {
            err(
                ErrorCode::HostSetup,
                format!("create {}: {e}", rt.display()),
            )
        })?;
        let disks = template_disks(d, &image.path, &staging.join("disk.raw"));
        let dev = guest_devices(&disks);
        let vsock_cid = 3;
        let spec = VmSpec {
            id: format!("tpl-{key}"),
            vcpus: shape.vcpus,
            memory_mib: shape.memory_mib,
            kernel: d.paths.kernel(),
            cmdline: format!(
                "{BOOT_ARGS} pocket.base={} pocket.disk={} pocket.hostname=pocket",
                dev[1], dev[2]
            ),
            disks,
            vsock_cid,
            cgroup: Some(CgroupSpec {
                // Unit names are per user, not per daemon: two daemons may build one key.
                unit: format!(
                    "pocket-template-{}-{}",
                    &key[..8],
                    crate::daemon::hex(&random_bytes(3))
                ),
                slice: "pocket.slice".into(),
                cpu_quota_pct: BUILD_CPU_PCT,
                memory_max_bytes: ((shape.memory_mib as u64) << 20) + (1 << 30),
                tasks_max: 4096,
            }),
            runtime_dir: rt.clone(),
            log_path: staging.join("vmm.log"),
            serial_log: None,
            shared_fs: vec![],
            net_vhost: None,
        };
        let vm = d
            .backend
            .create(&spec)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        let snap = async {
            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let guest = GuestConn::connect(&vm.vsock_uds, Duration::from_secs(15), tx)
                .await
                .map_err(|e| err(ErrorCode::Guest, format!("template guest: {e}")))?;
            guest
                .request(HostReq::Seal)
                .await
                .map_err(|e| err(ErrorCode::Guest, format!("seal template: {e}")))?;
            drop(guest);
            d.backend
                .pause(&vm)
                .await
                .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
            d.backend
                .snapshot(&vm, &staging)
                .await
                .map_err(|e| err(ErrorCode::Vmm, e.to_string()))
        }
        .await;
        let _ = d.backend.stop(&vm, StopMode::Kill).await;
        snap?;
        let meta = TemplateMeta {
            key: key.to_string(),
            kind: "base".into(),
            preset: preset.to_string(),
            image_digest: image.digest.clone(),
            shape,
            fingerprint: fingerprint(d),
            backend: d.backend.name().into(),
            vsock_cid,
            built_at: now_ms(),
        };
        std::fs::write(
            staging.join("meta.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .map_err(|e| err(ErrorCode::HostSetup, format!("write template meta: {e}")))?;
        let _ = std::fs::remove_dir_all(&final_dir);
        std::fs::rename(&staging, &final_dir)
            .map_err(|e| err(ErrorCode::HostSetup, format!("save template: {e}")))?;
        let size = du(&final_dir);
        d.db(|s| {
            s.put_template(&TemplateRecord {
                key: key.to_string(),
                kind: "base".into(),
                family: family(preset, shape),
                name: None,
                image_digest: image.digest.clone(),
                built_at: meta.built_at,
                host_fingerprint: serde_json::to_string(&meta.fingerprint).unwrap(),
                size_bytes: size,
                last_used_at: meta.built_at,
                meta_json: serde_json::to_string(&meta).unwrap(),
            })
        })?;
        Ok(Template {
            dir: final_dir.clone(),
            meta,
        })
    }
    .await;
    let _ = std::fs::remove_dir_all(&rt);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

/// Snapshots hold guest memory (SECURITY.md §Snapshots): owner-only.
pub fn set_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

/// Allocated bytes under `dir` (sparse files count what they use).
pub fn du(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.blocks() * 512)
        .sum()
}

fn info(t: &TemplateRecord) -> pocket_proto::rpc::TemplateInfo {
    let meta: Option<TemplateMeta> = serde_json::from_str(&t.meta_json).ok();
    let shape = meta.as_ref().map(|m| m.shape);
    pocket_proto::rpc::TemplateInfo {
        key: t.key.clone(),
        kind: t.kind.clone(),
        name: t.name.clone(),
        preset: meta.as_ref().map(|m| m.preset.clone()).unwrap_or_default(),
        vcpus: shape.map_or(0, |s| s.vcpus),
        memory_mib: shape.map_or(0, |s| s.memory_mib),
        disk_bytes: shape.map_or(0, |s| s.disk_bytes),
        built_at: t.built_at,
        last_used_at: t.last_used_at,
        size_bytes: t.size_bytes,
    }
}

pub fn list(d: &Daemon) -> R<Vec<pocket_proto::rpc::TemplateInfo>> {
    Ok(d.db(|s| s.templates())?.iter().map(info).collect())
}

/// `pocket pull` / `pocket bench`: the template for a preset and shape, built now if needed.
pub async fn build_now(
    d: &Arc<Daemon>,
    preset: &str,
    cpus: Option<u8>,
    memory_mib: Option<u32>,
    progress: &(dyn Fn(&str) + Send + Sync),
) -> R<pocket_proto::rpc::TemplateInfo> {
    if !templates_enabled() {
        return Err(err(
            ErrorCode::BadRequest,
            "templates are disabled (POCKET_TEMPLATES=off)",
        ));
    }
    let image = match crate::presets::resolve(d, preset) {
        Ok(i) => i,
        Err(e) if e.code == ErrorCode::NotFound => {
            crate::presets::pull(d, preset, progress).await?
        }
        Err(e) => return Err(e),
    };
    let shape = Shape {
        vcpus: cpus.unwrap_or(crate::daemon::DEFAULT_CPUS),
        memory_mib: memory_mib.unwrap_or(crate::daemon::DEFAULT_MEMORY_MIB),
        disk_bytes: crate::daemon::DEFAULT_DISK_MIB << 20,
    };
    let key = base_key(d, &image.digest, shape);
    if find(d, &key).is_none() {
        progress("building the snapshot template");
        ensure_background(d, preset, &image, shape);
        wait_built(d, &key, Duration::from_secs(300)).await;
    }
    let all = d.db(|s| s.templates())?;
    all.iter().find(|t| t.key == key).map(info).ok_or_else(|| {
        err(
            ErrorCode::Vmm,
            format!("building the template for {preset} failed"),
        )
        .hint("see pocketd.log (`pocket doctor` shows where it is)")
    })
}

/// Project template key: the base key (image, assets, host, shape) plus the setup command
/// and the content of its inputs.
pub fn project_key(base_key: &str, setup: &pocket_proto::rpc::Setup) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for part in [FORMAT, "project", base_key, &setup.command] {
        h.update(part.as_bytes());
        h.update(b"\0");
    }
    for (p, digest) in &setup.inputs {
        h.update(format!("{p}\0{digest}\0").as_bytes());
    }
    h.finalize()[..10]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Snapshots a running pocket into a template (`project` after `sandbox.setup`, `saved` for
/// `pocket save`). The pocket is sealed and paused for the snapshot and its disk copy, then
/// resumed through the restore hook (it shares RNG state with every future clone otherwise).
#[allow(clippy::too_many_arguments)]
pub async fn snapshot_pocket(
    d: &Arc<Daemon>,
    live: &crate::daemon::Live,
    rec: &pocket_store::PocketRecord,
    key: &str,
    shape: Shape,
    image: &crate::presets::Image,
    preset: &str,
    kind: &str,
    name: Option<&str>,
) -> R<()> {
    let started = std::time::Instant::now();
    let staging = d.paths.templates().join(format!(
        "snap-{key}.tmp-{}",
        crate::daemon::hex(&random_bytes(4))
    ));
    std::fs::create_dir_all(&staging).map_err(|e| {
        err(
            ErrorCode::HostSetup,
            format!("create {}: {e}", staging.display()),
        )
    })?;
    set_private(&staging);
    live.guest
        .request(HostReq::Seal)
        .await
        .map_err(|e| err(ErrorCode::Guest, format!("seal for the snapshot: {e}")))?;
    let taken = async {
        d.backend
            .pause(&live.vm)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        let snap = d
            .backend
            .snapshot(&live.vm, &staging)
            .await
            .map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
        pocket_image::disk::clone_disk(
            &d.paths.pocket_dir(&rec.info.id).join("disk.raw"),
            &staging.join("disk.raw"),
        )
        .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
        Ok::<_, pocket_proto::rpc::RpcError>(snap)
    }
    .await;
    let resumed = d.backend.resume(&live.vm).await;
    let mut m = Daemon::meta(&d.find(&rec.info.name)?);
    m.restore_generation += 1;
    let mid = m.machine_id.clone().unwrap_or_else(|| "0".repeat(32));
    let hook = crate::daemon::restore_hook(
        &live.guest,
        &rec.info.name,
        &mid,
        m.restore_generation,
        crate::daemon::Restore::Own,
    )
    .await;
    d.save_meta(&rec.info.id, &m)?;
    let snap = match (taken, resumed, hook) {
        (Ok(s), Ok(()), Ok(())) => s,
        (t, r, h) => {
            let _ = std::fs::remove_dir_all(&staging);
            r.map_err(|e| err(ErrorCode::Vmm, e.to_string()))?;
            h?;
            t?;
            unreachable!()
        }
    };
    let meta = TemplateMeta {
        key: key.to_string(),
        kind: kind.to_string(),
        preset: preset.to_string(),
        image_digest: image.digest.clone(),
        shape,
        fingerprint: snap.host_fingerprint,
        backend: d.backend.name().into(),
        vsock_cid: rec.vsock_cid,
        built_at: now_ms(),
    };
    let result = (|| {
        std::fs::write(
            staging.join("meta.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )?;
        let final_dir = dir(d, key);
        let _ = std::fs::remove_dir_all(&final_dir);
        std::fs::rename(&staging, &final_dir)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(err(ErrorCode::HostSetup, format!("save template: {e}")));
    }
    let family = match name {
        Some(n) => format!("saved:{n}"),
        None => format!(
            "{kind}:{}:{}:{}:{}",
            rec.info
                .repo_path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            shape.vcpus,
            shape.memory_mib,
            shape.disk_bytes
        ),
    };
    let size = du(&dir(d, key));
    d.db(|s| {
        s.put_template(&TemplateRecord {
            key: key.to_string(),
            kind: kind.to_string(),
            family: family.clone(),
            name: name.map(String::from),
            image_digest: image.digest.clone(),
            built_at: meta.built_at,
            host_fingerprint: serde_json::to_string(&meta.fingerprint).unwrap(),
            size_bytes: size,
            last_used_at: meta.built_at,
            meta_json: serde_json::to_string(&meta).unwrap(),
        })
    })?;
    if let Ok(all) = d.db(|s| s.templates()) {
        for t in all.iter().filter(|t| t.family == family && t.key != key) {
            let _ = std::fs::remove_dir_all(dir(d, &t.key));
            let _ = d.db(|s| s.delete_template(&t.key));
            tracing::info!("template {}: replaced by {key}", t.key);
        }
    }
    tracing::info!(
        "{}: {kind} snapshot template {key} saved in {:.1?} ({} MiB)",
        rec.info.name,
        started.elapsed(),
        size >> 20
    );
    Ok(())
}

/// `pocket save P --as NAME`.
pub async fn save(d: &Arc<Daemon>, pocket: &str, name: &str) -> R<pocket_proto::rpc::TemplateInfo> {
    if !crate::daemon::valid_pocket_name(name) {
        return Err(err(
            ErrorCode::BadRequest,
            format!("invalid template name {name:?}"),
        )
        .hint("use 1–40 lowercase letters, digits and dashes"));
    }
    if !templates_enabled() {
        return Err(err(
            ErrorCode::BadRequest,
            "templates are disabled (POCKET_TEMPLATES=off)",
        ));
    }
    let rec = d.find(pocket)?;
    let live = d.running(&rec)?;
    let meta = Daemon::meta(&rec);
    if !meta.shares.is_empty() || meta.net_mode.as_deref() == Some("full") {
        return Err(err(
            ErrorCode::InvalidState,
            format!("{} has shared folders or full networking", rec.info.name),
        )
        .hint("only pockets without --share-dir and --net full can be saved"));
    }
    if meta.secrets.iter().any(|s| s.copy_in) {
        return Err(err(
            ErrorCode::InvalidState,
            format!("{} holds a real secret (--copy-secret)", rec.info.name),
        )
        .hint("a template contains the pocket's memory; save a pocket without --copy-secret"));
    }
    let image = crate::presets::resolve(d, &rec.info.preset)?;
    if image.digest != rec.info.image_digest {
        return Err(err(
            ErrorCode::InvalidState,
            format!(
                "{}'s image is older than the current {} image",
                rec.info.name, rec.info.preset
            ),
        )
        .hint("restart it from a fresh pocket first"));
    }
    let key = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(format!("{FORMAT}\0saved\0{name}\0{}\0{}", rec.info.id, now_ms()).as_bytes());
        h.finalize()[..10]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let shape = Shape {
        vcpus: rec.info.vcpus,
        memory_mib: rec.info.memory_mib,
        disk_bytes: rec.info.disk_bytes,
    };
    snapshot_pocket(
        d,
        &live,
        &rec,
        &key,
        shape,
        &image,
        &rec.info.preset,
        "saved",
        Some(name),
    )
    .await?;
    let all = d.db(|s| s.templates())?;
    all.iter()
        .find(|t| t.key == key)
        .map(info)
        .ok_or_else(|| err(ErrorCode::Internal, "saved template vanished"))
}

/// A saved template by name.
pub fn saved(d: &Daemon, name: &str) -> R<Template> {
    let rec = d
        .db(|s| s.templates())?
        .into_iter()
        .filter(|t| t.kind == "saved" && t.name.as_deref() == Some(name))
        .max_by_key(|t| t.built_at)
        .ok_or_else(|| {
            err(
                ErrorCode::NotFound,
                format!("no saved template named {name:?}"),
            )
            .hint("`pocket templates` lists them; `pocket save P --as NAME` makes one")
        })?;
    find(d, &rec.key).ok_or_else(|| {
        err(
            ErrorCode::InvalidState,
            format!("template {name} no longer matches this host, kernel or VMM"),
        )
        .hint("save it again from a running pocket")
    })
}
