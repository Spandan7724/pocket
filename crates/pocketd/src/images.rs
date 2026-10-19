//! Built preset image versions and their removal (D29). A new build gets a new file; older
//! versions stay only while something needs that exact image: a pocket whose VM state refers
//! to it (running, paused, hibernated) or a saved template. Stopped pockets boot whatever
//! version is current, so they hold nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use pocket_proto::rpc::{GcReport, ImageInfo, PocketState};
use pocket_store::{PocketRecord, TemplateRecord};

use crate::daemon::{Daemon, R};
use crate::presets;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    preset: String,
    version: String,
    path: PathBuf,
    size_bytes: u64,
    built_at: Option<u64>,
    shared: bool,
}

/// `<preset>-<16 hex>` → (preset, version).
fn parse_stem(stem: &str) -> Option<(&str, &str)> {
    let (name, v) = stem.rsplit_once('-')?;
    (!name.is_empty() && v.len() == 16 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .then_some((name, v))
}

fn files(dir: &Path, prefix: &str, shared: bool, out: &mut Vec<Version>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(stem) = name
            .to_str()
            .and_then(|n| n.strip_prefix(prefix))
            .and_then(|n| n.strip_suffix(".erofs"))
        else {
            continue;
        };
        let Some((preset, version)) = parse_stem(stem) else {
            continue;
        };
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        out.push(Version {
            preset: preset.into(),
            version: version.into(),
            path: e.path(),
            size_bytes: md.len(),
            built_at: None,
            shared,
        });
    }
}

/// Every preset version on disk: the data dir's `preset-<name>-<v>.erofs` and the shared
/// cache's `<name>-<v>.erofs`, with build times from the database where recorded.
fn scan(d: &Daemon) -> R<Vec<Version>> {
    let mut out = vec![];
    files(&d.paths.images(), "preset-", false, &mut out);
    let cache = presets::cache_dir();
    if let Some(c) = &cache {
        files(c, "", true, &mut out);
    }
    // One directory may be both (POCKET_PRESET_CACHE pointed into the data dir).
    let mut seen = BTreeSet::new();
    out.retain(|v| seen.insert(v.path.clone()));
    let recs = d.db(|s| s.images())?;
    for v in &mut out {
        if let Some(r) = recs.iter().find(|r| r.path == v.path) {
            v.built_at = Some(r.built_at);
        }
    }
    out.sort_by(|a, b| {
        (&a.preset, a.built_at.unwrap_or(0), &a.path).cmp(&(
            &b.preset,
            b.built_at.unwrap_or(0),
            &b.path,
        ))
    });
    Ok(out)
}

/// Versions something still needs, with who needs them.
fn pins(pockets: &[PocketRecord], templates: &[TemplateRecord]) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in pockets {
        if p.info.state != PocketState::Stopped {
            m.entry(presets::version(&p.info.image_digest).into())
                .or_default()
                .push(format!("pocket {}", p.info.name));
        }
    }
    for t in templates.iter().filter(|t| t.kind == "saved") {
        m.entry(presets::version(&t.image_digest).into())
            .or_default()
            .push(format!(
                "template {}",
                t.name.clone().unwrap_or_else(|| t.key.clone())
            ));
    }
    m
}

fn is_current(v: &Version) -> bool {
    presets::current_digest(&v.preset).is_some_and(|c| presets::version(&c) == v.version)
}

/// What a collection removes. Shared-cache versions only go when asked for (`pocket gc`):
/// other daemons and checkouts may use them, and this daemon cannot see their pockets.
fn plan<'a>(
    versions: &'a [Version],
    pins: &BTreeMap<String, Vec<String>>,
    include_shared: bool,
) -> Vec<&'a Version> {
    versions
        .iter()
        .filter(|v| !is_current(v) && !pins.contains_key(&v.version))
        .filter(|v| include_shared || !v.shared)
        .collect()
}

fn info(v: &Version, pins: &BTreeMap<String, Vec<String>>) -> ImageInfo {
    ImageInfo {
        preset: v.preset.clone(),
        version: v.version.clone(),
        path: v.path.clone(),
        size_bytes: v.size_bytes,
        built_at: v.built_at,
        current: is_current(v),
        used_by: pins.get(&v.version).cloned().unwrap_or_default(),
        shared: v.shared,
    }
}

pub fn list(d: &Daemon) -> R<Vec<ImageInfo>> {
    let versions = scan(d)?;
    let pins = pins(&d.db(|s| s.pockets())?, &d.db(|s| s.templates())?);
    Ok(versions.iter().map(|v| info(v, &pins)).collect())
}

pub fn gc(d: &Daemon, dry_run: bool, include_shared: bool, only: Option<&[String]>) -> R<GcReport> {
    let versions = scan(d)?;
    let templates = d.db(|s| s.templates())?;
    let pins = pins(&d.db(|s| s.pockets())?, &templates);
    let mut report = GcReport {
        dry_run,
        removed: vec![],
        templates: vec![],
        freed_bytes: 0,
    };
    let mut gone = BTreeSet::new();
    for v in plan(&versions, &pins, include_shared)
        .into_iter()
        .filter(|v| only.is_none_or(|o| o.contains(&v.version)))
    {
        if !dry_run {
            match std::fs::remove_file(&v.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!("image {}: cannot remove: {e}", v.path.display());
                    continue;
                }
            }
            tracing::info!(
                "image {} {}: removed ({} bytes, nothing uses it)",
                v.preset,
                v.version,
                v.size_bytes
            );
        }
        gone.insert(v.version.clone());
        report.freed_bytes += v.size_bytes;
        report.removed.push(info(v, &pins));
    }
    if !dry_run {
        for r in d.db(|s| s.images())? {
            if !r.path.exists() {
                let _ = d.db(|s| s.delete_image(&r.digest));
            }
        }
    }
    // Base and project templates are caches keyed by the image; without it they are dead.
    for t in templates
        .iter()
        .filter(|t| t.kind != "saved" && gone.contains(presets::version(&t.image_digest)))
    {
        if !dry_run {
            let _ = std::fs::remove_dir_all(crate::templates::dir(d, &t.key));
            let _ = d.db(|s| s.delete_template(&t.key));
            tracing::info!("template {}: removed with its image", t.key);
        }
        report.freed_bytes += t.size_bytes;
        report.templates.push(t.key.clone());
    }
    Ok(report)
}

/// Automatic collection (after a build, at daemon start, after `rm`): the data dir only.
pub fn auto(d: &Daemon) {
    match gc(d, false, false, None) {
        Ok(r) if !r.removed.is_empty() => tracing::info!(
            "removed {} unused image version(s), {} MiB freed",
            r.removed.len(),
            r.freed_bytes >> 20
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!("image cleanup: {}", e.message),
    }
}

/// `auto` off the async runtime (removing a multi-GiB file can take a moment).
pub fn spawn_auto(d: &std::sync::Arc<Daemon>) {
    let d = d.clone();
    tokio::task::spawn_blocking(move || auto(&d));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pocket_proto::rpc::PocketInfo;

    fn ver(preset: &str, version: &str, shared: bool) -> Version {
        Version {
            preset: preset.into(),
            version: version.into(),
            path: format!("/i/{preset}-{version}.erofs").into(),
            size_bytes: 7 << 30,
            built_at: None,
            shared,
        }
    }

    fn pocket(name: &str, state: PocketState, digest: &str) -> PocketRecord {
        PocketRecord {
            info: PocketInfo {
                id: name.into(),
                name: name.into(),
                state,
                preset: "base".into(),
                image_digest: digest.into(),
                repo_path: None,
                base_ref: None,
                branch: None,
                vcpus: 2,
                memory_mib: 2048,
                disk_bytes: 1 << 30,
                disk_used_bytes: 0,
                net_profile: "dev".into(),
                created_at: 0,
                last_active_at: 0,
                started_from: None,
                template: None,
                net_mode: None,
            },
            vsock_cid: 3,
            vm_json: None,
            meta_json: "{}".into(),
        }
    }

    fn template(kind: &str, name: Option<&str>, digest: &str) -> TemplateRecord {
        TemplateRecord {
            key: format!("k-{kind}"),
            kind: kind.into(),
            family: String::new(),
            name: name.map(Into::into),
            image_digest: digest.into(),
            built_at: 0,
            host_fingerprint: String::new(),
            size_bytes: 1 << 20,
            last_used_at: 0,
            meta_json: "{}".into(),
        }
    }

    #[test]
    fn file_names_parse_to_preset_and_version() {
        assert_eq!(
            parse_stem("base-9f8a93e24979b90e"),
            Some(("base", "9f8a93e24979b90e"))
        );
        assert_eq!(
            parse_stem("my-preset-0123456789abcdef"),
            Some(("my-preset", "0123456789abcdef"))
        );
        assert_eq!(parse_stem("base-9f8a"), None);
        assert_eq!(parse_stem("base-zzzzzzzzzzzzzzzz"), None);
        assert_eq!(parse_stem("-0123456789abcdef"), None);
    }

    #[test]
    fn keeps_current_and_needed_versions_removes_the_rest() {
        let current = presets::version(&presets::current_digest("base").unwrap()).to_string();
        let versions = vec![
            ver("base", &current, false),
            ver("base", "1111111111111111", false),
            ver("base", "2222222222222222", false),
            ver("base", "3333333333333333", false),
            ver("base", "4444444444444444", false),
            ver("base", "5555555555555555", true),
            ver("claude", "6666666666666666", false),
        ];
        let pockets = vec![
            pocket(
                "hib",
                PocketState::Hibernated,
                "sha256:1111111111111111aaaa",
            ),
            pocket("run", PocketState::Running, "sha256:2222222222222222bbbb"),
            pocket("off", PocketState::Stopped, "sha256:4444444444444444cccc"),
        ];
        let templates = vec![
            template("saved", Some("mine"), "sha256:3333333333333333dddd"),
            template("base", None, "sha256:4444444444444444eeee"),
        ];
        let pins = pins(&pockets, &templates);
        assert_eq!(pins["1111111111111111"], vec!["pocket hib"]);
        assert_eq!(pins["3333333333333333"], vec!["template mine"]);
        assert!(!pins.contains_key("4444444444444444"));

        let gone = |include_shared| {
            plan(&versions, &pins, include_shared)
                .iter()
                .map(|v| v.version.clone())
                .collect::<Vec<_>>()
        };
        // A stopped pocket boots the current version, a base template is a cache, and a
        // preset this build no longer has (claude, before D19) has no current version.
        assert_eq!(gone(false), vec!["4444444444444444", "6666666666666666"]);
        assert_eq!(
            gone(true),
            vec!["4444444444444444", "5555555555555555", "6666666666666666"]
        );
    }
}
