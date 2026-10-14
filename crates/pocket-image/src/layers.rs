//! Flattens OCI layers (uncompressed tar files, bottom first) into one tarball for
//! `mkfs.erofs --tar=f`, applying whiteouts (`.wh.<name>`) and opaque markers
//! (`.wh..wh..opq`) per the OCI image spec. Entries keep their owner, mode, device numbers
//! and PAX xattrs, which an unprivileged unpack to disk would lose.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use tar::{EntryType, Header};

const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

#[derive(Debug, Clone)]
struct Meta {
    kind: EntryType,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    size: u64,
    link: Option<String>,
    dev: (u32, u32),
    xattrs: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone)]
struct Winner {
    layer: usize,
    data_offset: u64,
    meta: Meta,
}

/// Relative, normalized path; `None` for the root or anything escaping it.
fn normalize(p: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str()?.to_string()),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeStats {
    pub entries: usize,
    pub whiteouts: usize,
    pub opaque_dirs: usize,
    pub hidden: usize,
}

/// Writes the merged tarball of `layers` (bottom first) to `out`.
pub fn merge(layers: &[PathBuf], out: &Path) -> io::Result<MergeStats> {
    let mut winners: BTreeMap<String, Winner> = BTreeMap::new();
    let mut deleted: HashSet<String> = HashSet::new();
    let mut opaque: HashSet<String> = HashSet::new();
    let mut stats = MergeStats::default();

    for (li, layer) in layers.iter().enumerate().rev() {
        let mut layer_deleted = vec![];
        let mut layer_opaque = vec![];
        let mut ar = tar::Archive::new(File::open(layer)?);
        for e in ar.entries()? {
            let mut e = e?;
            let raw = e.path()?.into_owned();
            let Some(path) = normalize(&raw) else {
                continue;
            };
            let (dir, base) = match path.rsplit_once('/') {
                Some((d, b)) => (Some(d), b),
                None => (None, path.as_str()),
            };
            if base == OPAQUE {
                if let Some(d) = dir {
                    layer_opaque.push(d.to_string());
                } else {
                    layer_opaque.push(String::new());
                }
                stats.opaque_dirs += 1;
                continue;
            }
            if let Some(name) = base.strip_prefix(WHITEOUT) {
                let target = match dir {
                    Some(d) => format!("{d}/{name}"),
                    None => name.to_string(),
                };
                layer_deleted.push(target);
                stats.whiteouts += 1;
                continue;
            }
            let masked = winners.contains_key(&path)
                || deleted.contains(&path)
                || opaque.contains("")
                || ancestors(&path).any(|a| {
                    deleted.contains(a)
                        || opaque.contains(a)
                        || winners
                            .get(a)
                            .is_some_and(|w| w.meta.kind != EntryType::Directory)
                });
            if masked {
                stats.hidden += 1;
                continue;
            }
            let h = e.header();
            let kind = h.entry_type();
            if !matches!(
                kind,
                EntryType::Regular
                    | EntryType::Continuous
                    | EntryType::Directory
                    | EntryType::Symlink
                    | EntryType::Link
                    | EntryType::Char
                    | EntryType::Block
                    | EntryType::Fifo
            ) {
                continue;
            }
            let link = e.link_name()?.map(|l| l.to_string_lossy().into_owned());
            let mut meta = Meta {
                kind: if kind == EntryType::Continuous {
                    EntryType::Regular
                } else {
                    kind
                },
                mode: h.mode().unwrap_or(0o644),
                uid: h.uid().unwrap_or(0),
                gid: h.gid().unwrap_or(0),
                mtime: h.mtime().unwrap_or(0),
                size: if kind.is_file() || kind == EntryType::Continuous {
                    e.size()
                } else {
                    0
                },
                link,
                dev: (
                    h.device_major().ok().flatten().unwrap_or(0),
                    h.device_minor().ok().flatten().unwrap_or(0),
                ),
                xattrs: vec![],
            };
            if let Some(pax) = e.pax_extensions()? {
                for ext in pax {
                    let ext = ext?;
                    if let Ok(k) = ext.key()
                        && k.starts_with("SCHILY.xattr.")
                    {
                        meta.xattrs
                            .push((k.to_string(), ext.value_bytes().to_vec()));
                    }
                }
            }
            winners.insert(
                path,
                Winner {
                    layer: li,
                    data_offset: e.raw_file_position(),
                    meta,
                },
            );
        }
        deleted.extend(layer_deleted);
        opaque.extend(layer_opaque);
    }

    let mut files: Vec<File> = layers.iter().map(File::open).collect::<io::Result<_>>()?;
    let mut b = tar::Builder::new(BufWriter::new(File::create(out)?));
    b.mode(tar::HeaderMode::Complete);
    let mut links = vec![];
    for (path, w) in &winners {
        if w.meta.kind == EntryType::Link {
            links.push((path, w));
            continue;
        }
        let mut h = header(&w.meta);
        if !w.meta.xattrs.is_empty() {
            b.append_pax_extensions(
                w.meta
                    .xattrs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_slice())),
            )?;
        }
        match w.meta.kind {
            EntryType::Symlink => {
                b.append_link(&mut h, path, w.meta.link.as_deref().unwrap_or(""))?;
            }
            EntryType::Regular => {
                let f = &mut files[w.layer];
                f.seek(SeekFrom::Start(w.data_offset))?;
                b.append_data(&mut h, path, f.take(w.meta.size))?;
            }
            _ => b.append_data(&mut h, path, io::empty())?,
        }
        stats.entries += 1;
    }
    // Hard links last, so their targets already exist; drop links whose target is gone.
    for (path, w) in links {
        let Some(target) = w.meta.link.as_deref().and_then(|l| normalize(Path::new(l))) else {
            continue;
        };
        if !winners
            .get(&target)
            .is_some_and(|t| t.meta.kind == EntryType::Regular)
        {
            continue;
        }
        let mut h = header(&w.meta);
        b.append_link(&mut h, path, &target)?;
        stats.entries += 1;
    }
    b.into_inner()?.flush()?;
    Ok(stats)
}

fn header(m: &Meta) -> Header {
    let mut h = Header::new_gnu();
    h.set_entry_type(m.kind);
    h.set_mode(m.mode);
    h.set_uid(m.uid);
    h.set_gid(m.gid);
    h.set_mtime(m.mtime);
    h.set_size(if m.kind == EntryType::Regular {
        m.size
    } else {
        0
    });
    if matches!(m.kind, EntryType::Char | EntryType::Block) {
        let _ = h.set_device_major(m.dev.0);
        let _ = h.set_device_minor(m.dev.1);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    enum E<'a> {
        File(&'a str, &'a str),
        Dir(&'a str),
        Sym(&'a str, &'a str),
        Hard(&'a str, &'a str),
        Owned(&'a str, &'a str, u64, u32),
    }

    fn layer(dir: &Path, name: &str, entries: &[E]) -> PathBuf {
        let p = dir.join(name);
        let mut b = tar::Builder::new(File::create(&p).unwrap());
        for e in entries {
            let mut h = Header::new_gnu();
            h.set_mtime(1);
            h.set_uid(0);
            h.set_gid(0);
            h.set_mode(0o777);
            match e {
                E::File(path, data) if path.contains("..") => {
                    h.set_entry_type(EntryType::Regular);
                    h.set_mode(0o644);
                    h.set_size(data.len() as u64);
                    h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
                    h.set_cksum();
                    b.append(&h, data.as_bytes()).unwrap();
                }
                E::File(path, data) => {
                    h.set_entry_type(EntryType::Regular);
                    h.set_mode(0o644);
                    h.set_size(data.len() as u64);
                    b.append_data(&mut h, path, data.as_bytes()).unwrap();
                }
                E::Owned(path, data, uid, mode) => {
                    h.set_entry_type(EntryType::Regular);
                    h.set_mode(*mode);
                    h.set_uid(*uid);
                    h.set_size(data.len() as u64);
                    b.append_data(&mut h, path, data.as_bytes()).unwrap();
                }
                E::Dir(path) => {
                    h.set_entry_type(EntryType::Directory);
                    h.set_mode(0o755);
                    h.set_size(0);
                    b.append_data(&mut h, path, io::empty()).unwrap();
                }
                E::Sym(path, target) => {
                    h.set_entry_type(EntryType::Symlink);
                    h.set_size(0);
                    b.append_link(&mut h, path, target).unwrap();
                }
                E::Hard(path, target) => {
                    h.set_entry_type(EntryType::Link);
                    h.set_size(0);
                    b.append_link(&mut h, path, target).unwrap();
                }
            }
        }
        b.finish().unwrap();
        p
    }

    fn read(p: &Path) -> BTreeMap<String, (EntryType, String, u64, u32)> {
        let mut out = BTreeMap::new();
        let mut ar = tar::Archive::new(File::open(p).unwrap());
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let path = e.path().unwrap().to_string_lossy().into_owned();
            let kind = e.header().entry_type();
            let (uid, mode) = (e.header().uid().unwrap(), e.header().mode().unwrap());
            let mut s = String::new();
            if kind.is_file() {
                e.read_to_string(&mut s).unwrap();
            } else if let Some(l) = e.link_name().unwrap() {
                s = l.to_string_lossy().into_owned();
            }
            out.insert(path, (kind, s, uid, mode));
        }
        out
    }

    #[test]
    fn whiteouts_opaque_dirs_and_replacements() {
        let dir = std::env::temp_dir().join(format!("pocket-layers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let l0 = layer(
            &dir,
            "l0.tar",
            &[
                E::Dir("etc"),
                E::File("etc/keep", "base"),
                E::File("etc/gone", "x"),
                E::Dir("opq"),
                E::File("opq/old", "x"),
                E::Dir("becomes-file"),
                E::File("becomes-file/child", "x"),
                E::File("bin/tool", "v1"),
                E::Hard("bin/tool-link", "bin/tool"),
                E::Owned("usr/bin/sudo", "s", 0, 0o4755),
                E::Owned("home/dev/.profile", "p", 1000, 0o644),
                E::File("../escape", "evil"),
            ],
        );
        let l1 = layer(
            &dir,
            "l1.tar",
            &[
                E::File("etc/.wh.gone", ""),
                E::File("opq/.wh..wh..opq", ""),
                E::File("opq/new", "fresh"),
                E::File("becomes-file", "now a file"),
                E::File("bin/tool", "v2"),
                E::Sym("lib", "usr/lib"),
            ],
        );
        let l2 = layer(
            &dir,
            "l2.tar",
            &[E::File("etc/.wh.keep", ""), E::File("etc/keep", "re-added")],
        );
        let out = dir.join("merged.tar");
        let stats = merge(&[l0, l1, l2], &out).unwrap();
        let m = read(&out);
        assert_eq!(m["etc/keep"].1, "re-added");
        assert!(
            !m.contains_key("etc/gone"),
            "whiteout must delete lower file"
        );
        assert!(
            !m.contains_key("opq/old"),
            "opaque dir hides lower children"
        );
        assert_eq!(m["opq/new"].1, "fresh");
        assert!(m.contains_key("opq"));
        assert_eq!(m["becomes-file"].1, "now a file");
        assert!(!m.contains_key("becomes-file/child"));
        assert_eq!(m["bin/tool"].1, "v2");
        assert_eq!(m["bin/tool-link"].0, EntryType::Link);
        assert_eq!(
            m["lib"],
            (EntryType::Symlink, "usr/lib".into(), 0, m["lib"].3)
        );
        assert_eq!((m["usr/bin/sudo"].2, m["usr/bin/sudo"].3), (0, 0o4755));
        assert_eq!(m["home/dev/.profile"].2, 1000);
        assert!(!m.keys().any(|k| k.contains("escape") || k.contains(".wh.")));
        assert_eq!((stats.whiteouts, stats.opaque_dirs), (2, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
