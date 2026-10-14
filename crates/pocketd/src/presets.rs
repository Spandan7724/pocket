//! Preset images (CONTRACTS.md §5 Presets): resolution, and building them in a builder
//! pocket (`guest/presets/*.sh`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pocket_image::oci::{ImageStore, build_erofs_from_tar, hex};
use pocket_proto::guest::ExitStatus;
use pocket_proto::rpc::{ErrorCode, PocketInfo, PocketState};
use pocket_store::{ImageRecord, PocketRecord};
use sha2::{Digest, Sha256};

use crate::daemon::{Daemon, R, err, now_ms, random_bytes};
use crate::guest::ExecReq;

/// Bump to rebuild every preset (e.g. when the export format changes).
const FORMAT: &str = "1";

enum Parent {
    Oci(&'static str),
    Preset(&'static str),
}

struct Preset {
    name: &'static str,
    parent: Parent,
    script: &'static str,
}

const PRESETS: &[Preset] = &[
    Preset {
        name: "base",
        parent: Parent::Oci("docker.io/library/ubuntu:24.04"),
        script: include_str!("../../../guest/presets/base.sh"),
    },
    Preset {
        name: "claude",
        parent: Parent::Preset("base"),
        script: include_str!("../../../guest/presets/claude.sh"),
    },
    Preset {
        name: "codex",
        parent: Parent::Preset("base"),
        script: include_str!("../../../guest/presets/codex.sh"),
    },
];

/// Minimal Alpine image from the assets dir, for tests (no git, root only).
pub const TEST_PRESET: &str = "test";

pub struct Image {
    pub path: PathBuf,
    pub digest: String,
}

fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

pub fn names() -> Vec<&'static str> {
    PRESETS.iter().map(|p| p.name).collect()
}

fn key(p: &Preset) -> String {
    let mut h = Sha256::new();
    h.update(FORMAT);
    h.update(p.name);
    h.update([0]);
    h.update(p.script);
    h.update([0]);
    match p.parent {
        Parent::Oci(r) => h.update(r),
        Parent::Preset(parent) => h.update(key(find(parent).unwrap())),
    }
    hex(&h.finalize())
}

/// Optional directory of prebuilt presets (`<name>-<key>.erofs`), shared across data dirs
/// (CI caches it).
fn cache_path(name: &str, key: &str) -> Option<PathBuf> {
    std::env::var_os("POCKET_PRESET_CACHE")
        .filter(|v| !v.is_empty())
        .map(|d| PathBuf::from(d).join(format!("{name}-{}.erofs", &key[..16])))
}

pub fn resolve(d: &Daemon, name: &str) -> R<Image> {
    if name == TEST_PRESET {
        let path = d.paths.assets.join("test-base.erofs");
        if !path.exists() {
            return Err(
                err(ErrorCode::Image, format!("{} is missing", path.display()))
                    .hint("run `cargo xtask test-base`"),
            );
        }
        let stamp = std::fs::read_to_string(path.with_extension("sha256")).unwrap_or_default();
        return Ok(Image {
            path,
            digest: format!("sha256:{}", stamp.trim()),
        });
    }
    let Some(p) = find(name) else {
        return Err(
            err(ErrorCode::BadRequest, format!("unknown preset {name:?}"))
                .hint(format!("available presets: {}", names().join(", "))),
        );
    };
    let k = key(p);
    let digest = format!("sha256:{k}");
    if let Some(img) = d.db(|s| s.image(name))?
        && img.digest == digest
        && img.path.exists()
    {
        return Ok(Image {
            path: img.path,
            digest,
        });
    }
    if let Some(c) = cache_path(name, &k)
        && c.exists()
    {
        return Ok(Image { path: c, digest });
    }
    Err(err(
        ErrorCode::NotFound,
        format!("preset image {name} is not built yet"),
    )
    .hint(format!(
        "run `pocket pull {name}` (builds it from Ubuntu 24.04; takes a few minutes)"
    )))
}

pub async fn pull(
    d: &Arc<Daemon>,
    name: &str,
    progress: &(dyn Fn(&str) + Send + Sync),
) -> R<Image> {
    if let Ok(img) = resolve(d, name) {
        progress(&format!("{name} is up to date"));
        return Ok(img);
    }
    let p = find(name).ok_or_else(|| {
        err(ErrorCode::BadRequest, format!("unknown preset {name:?}"))
            .hint(format!("available presets: {}", names().join(", ")))
    })?;
    let parent = match p.parent {
        Parent::Oci(r) => {
            progress(&format!("pulling {r}"));
            let store = ImageStore {
                images_dir: d.paths.images(),
                blobs_dir: d.paths.blobs(),
                mkfs_erofs: d.paths.tool("mkfs.erofs"),
            };
            let r = r.to_string();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            let job = tokio::task::spawn_blocking(move || {
                store.pull(&r, &|s| {
                    let _ = tx.send(s.to_string());
                })
            });
            while let Some(s) = rx.recv().await {
                progress(&s);
            }
            let img = job
                .await
                .map_err(|e| err(ErrorCode::Internal, e.to_string()))?
                .map_err(|e| err(ErrorCode::Image, e.to_string()))?;
            Image {
                path: img.path,
                digest: img.digest,
            }
        }
        Parent::Preset(parent) => Box::pin(pull(d, parent, progress)).await?,
    };
    let k = key(p);
    let out = d
        .paths
        .images()
        .join(format!("preset-{name}-{}.erofs", &k[..16]));
    build(d, p, &parent, &out, progress).await?;
    let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    let digest = format!("sha256:{k}");
    d.db(|s| {
        s.put_image(&ImageRecord {
            name: name.into(),
            digest: digest.clone(),
            path: out.clone(),
            source: format!("preset:{name}"),
            built_at: now_ms(),
            size_bytes: size,
        })
    })?;
    if let Some(c) = cache_path(name, &k) {
        if let Some(dir) = c.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if !c.exists()
            && let Err(e) = pocket_image::disk::clone_disk(&out, &c)
        {
            tracing::warn!("copy {name} to the preset cache {}: {e}", c.display());
        }
    }
    progress(&format!(
        "{name}: built ({:.0} MiB)",
        size as f64 / 1048576.0
    ));
    Ok(Image { path: out, digest })
}

async fn build(
    d: &Arc<Daemon>,
    p: &Preset,
    parent: &Image,
    out: &std::path::Path,
    progress: &(dyn Fn(&str) + Send + Sync),
) -> R<()> {
    let id = format!("b{}", hex(&random_bytes(7)));
    let rec = PocketRecord {
        info: PocketInfo {
            id: id.clone(),
            name: format!("build-{}", p.name),
            state: PocketState::Creating,
            preset: p.name.into(),
            image_digest: parent.digest.clone(),
            repo_path: None,
            base_ref: None,
            branch: None,
            vcpus: 4,
            memory_mib: 4096,
            disk_bytes: 32 << 30,
            disk_used_bytes: 0,
            net_profile: "dev".into(),
            created_at: now_ms(),
            last_active_at: now_ms(),
        },
        vsock_cid: 3,
        vm_json: None,
        meta_json: "{}".into(),
    };
    let dir = d.paths.pocket_dir(&id);
    std::fs::create_dir_all(&dir).map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
    let result = async {
        pocket_image::disk::create_pocket_disk(
            &d.paths.templates(),
            rec.info.disk_bytes,
            &dir.join("disk.raw"),
        )
        .map_err(|e| err(ErrorCode::HostSetup, e.to_string()))?;
        progress(&format!("booting builder for {}", p.name));
        let live = d.boot_builder(&rec, &parent.path).await?;
        progress(&format!("running guest/presets/{}.sh", p.name));
        let r = live
            .guest
            .exec(
                ExecReq {
                    argv: &["/bin/bash", "-c", p.script],
                    env: vec![],
                    cwd: "/",
                    user: None,
                    stdin: None,
                },
                1 << 20,
            )
            .await
            .map_err(|e| err(ErrorCode::Image, format!("preset script: {e}")))?;
        if r.status != ExitStatus::Code(0) {
            let tail: Vec<&str> = std::str::from_utf8(&r.stderr)
                .unwrap_or("")
                .lines()
                .rev()
                .take(30)
                .collect();
            let tail: Vec<&str> = tail.into_iter().rev().collect();
            return Err(err(
                ErrorCode::Image,
                format!(
                    "guest/presets/{}.sh failed ({:?}):\n{}",
                    p.name,
                    r.status,
                    tail.join("\n")
                ),
            ));
        }
        progress("exporting root filesystem");
        let tar = dir.join("rootfs.tar");
        let mut f = tokio::io::BufWriter::new(
            tokio::fs::File::create(&tar)
                .await
                .map_err(|e| err(ErrorCode::Internal, e.to_string()))?,
        );
        let r = live
            .guest
            .exec_to(
                ExecReq {
                    argv: &[
                        "/bin/sh",
                        "-c",
                        // GNU tar exits 1 when mount points change under it; that is fine.
                        "tar --numeric-owner --xattrs '--xattrs-include=*' --acls --one-file-system \
                         --warning=no-file-changed -C / -cf - . ; [ $? -le 1 ]",
                    ],
                    env: vec![],
                    cwd: "/",
                    user: None,
                    stdin: None,
                },
                &mut f,
            )
            .await
            .map_err(|e| err(ErrorCode::Image, format!("export: {e}")))?;
        if r.status != ExitStatus::Code(0) {
            return Err(err(
                ErrorCode::Image,
                format!("export failed: {}", r.stderr_text()),
            ));
        }
        d.stop_builder(&live).await;
        progress("building erofs");
        let (mkfs, tar2, out2) = (d.paths.tool("mkfs.erofs"), tar.clone(), out.to_path_buf());
        tokio::task::spawn_blocking(move || build_erofs_from_tar(&mkfs, &tar2, &out2))
            .await
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?
            .map_err(|e| err(ErrorCode::Image, e.to_string()))?;
        Ok(())
    }
    .await;
    if let Some(l) = d.live(&id) {
        d.stop_builder(&l).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(d.paths.pocket_runtime(&id));
    result
}
