//! `pocket cp` (M11): tar streams over exec. Into a pocket, the host's own files go in as
//! they are. Out of a pocket the archive is hostile input: only regular files and
//! directories are unpacked, every path stays inside the destination, nothing is written
//! through a symlink, mode bits are masked, sizes are capped, and `.git` is never created
//! (a guest-written `.git` would run guest code the next time the user runs git there).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use pocket_proto::guest::{ExecIn, ExecOut, MAX_CHUNK};
use pocket_proto::rpc::ErrorCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::daemon::{Daemon, R, err, guest_err, hex, random_bytes};
use crate::guest::ExecReq;

const MAX_BYTES: u64 = 16 << 30;
const MAX_ENTRIES: u64 = 1_000_000;

fn io_err(what: impl std::fmt::Display) -> impl FnOnce(io::Error) -> pocket_proto::rpc::RpcError {
    move |e| err(ErrorCode::BadRequest, format!("{what}: {e}"))
}

/// Guest paths are absolute or relative to `/work`; no NUL, no `..`.
pub fn guest_path(p: &str) -> R<String> {
    if p.is_empty() || p.contains('\0') || p.len() > 4096 {
        return Err(err(
            ErrorCode::BadRequest,
            format!("invalid pocket path {p:?}"),
        ));
    }
    let full = if p.starts_with('/') {
        p.to_string()
    } else {
        format!("/work/{p}")
    };
    let mut parts = vec![];
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                return Err(
                    err(ErrorCode::BadRequest, format!("{p:?}: `..` is not allowed"))
                        .hint("give the path from / or from /work"),
                );
            }
            c => parts.push(c),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

fn split(guest: &str) -> (String, String) {
    match guest.rsplit_once('/') {
        Some(("", b)) => ("/".into(), b.into()),
        Some((a, b)) => (a.into(), b.into()),
        None => ("/".into(), guest.into()),
    }
}

fn tmp_file(d: &Daemon) -> R<PathBuf> {
    let dir = d.paths.data.join("tmp");
    fs::create_dir_all(&dir).map_err(io_err(dir.display()))?;
    Ok(dir.join(format!("cp-{}.tar", hex(&random_bytes(6)))))
}

async fn guest_test_dir(live: &crate::daemon::Live, p: &str) -> R<bool> {
    let o = live
        .guest
        .exec(
            ExecReq {
                argv: &["test", "-d", p],
                env: vec![],
                cwd: "/",
                user: live.user.as_deref(),
                stdin: None,
            },
            0,
        )
        .await
        .map_err(guest_err)?;
    Ok(o.ok())
}

/// Host → pocket. `dst` an existing directory = copy into it, else the copy's new name.
pub async fn copy_in(d: &Arc<Daemon>, pocket: &str, src: &Path, dst: &str) -> R<String> {
    let rec = d.find(pocket)?;
    let live = d.running(&rec)?;
    let src = src
        .canonicalize()
        .map_err(io_err(format!("{}", src.display())))?;
    let dst = guest_path(dst)?;
    let (dir, name) = if guest_test_dir(&live, &dst).await? {
        let base = src
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "copy".into());
        (dst.clone(), base)
    } else {
        split(&dst)
    };
    let tmp = tmp_file(d)?;
    let (s2, t2, n2) = (src.clone(), tmp.clone(), name.clone());
    let packed = tokio::task::spawn_blocking(move || -> io::Result<u64> {
        let mut b = tar::Builder::new(File::create(&t2)?);
        b.follow_symlinks(false);
        if s2.is_dir() {
            b.append_dir_all(&n2, &s2)?;
        } else {
            b.append_path_with_name(&s2, &n2)?;
        }
        b.into_inner()?.sync_all()?;
        Ok(fs::metadata(&t2)?.len())
    })
    .await
    .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
    let size = match packed {
        Ok(n) => n,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(format!("read {}", src.display()))(e));
        }
    };
    let out = stream_stdin(
        &live,
        &["tar", "-x", "--no-same-owner", "-f", "-", "-C", &dir],
        &tmp,
    )
    .await;
    let _ = fs::remove_file(&tmp);
    let (ok, stderr) = out?;
    if !ok {
        return Err(err(
            ErrorCode::BadRequest,
            format!("unpacking into {pocket}:{dir} failed: {stderr}"),
        )
        .hint("check that the directory exists and the pocket's user can write there"));
    }
    Ok(format!(
        "copied {} → {pocket}:{}/{name} ({} KiB)",
        src.display(),
        dir.trim_end_matches('/'),
        size >> 10
    ))
}

/// Runs `argv` in the guest with `file` as its stdin, streamed.
async fn stream_stdin(live: &crate::daemon::Live, argv: &[&str], file: &Path) -> R<(bool, String)> {
    let mut s = live
        .guest
        .exec_stream_open(ExecReq {
            argv,
            env: vec![],
            cwd: "/",
            user: live.user.as_deref(),
            stdin: None,
        })
        .await
        .map_err(guest_err)?;
    let mut f = tokio::fs::File::open(file)
        .await
        .map_err(io_err(file.display()))?;
    let (mut rd, mut wr) = s.split();
    let send = async {
        let mut buf = vec![0u8; MAX_CHUNK];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let frame = pocket_proto::frame::encode(&ExecIn::Stdin(buf[..n].to_vec()))
                .map_err(io::Error::other)?;
            wr.write_all(&frame).await?;
        }
        let frame = pocket_proto::frame::encode(&ExecIn::CloseStdin).map_err(io::Error::other)?;
        wr.write_all(&frame).await?;
        Ok::<_, io::Error>(())
    };
    let recv = async {
        let mut stderr = vec![];
        let mut status = None;
        while let Some(m) = crate::guest::read_exec_out(&mut rd).await? {
            match m {
                ExecOut::Stderr(d) if stderr.len() < 8192 => stderr.extend(d),
                ExecOut::Exited(st) => {
                    status = Some(st);
                    break;
                }
                _ => {}
            }
        }
        Ok::<_, crate::guest::GuestConnError>((status, stderr))
    };
    let (sent, got) = tokio::join!(send, recv);
    let (status, stderr) = got.map_err(guest_err)?;
    sent.map_err(io_err("send to the pocket"))?;
    Ok((
        status == Some(pocket_proto::guest::ExitStatus::Code(0)),
        String::from_utf8_lossy(&stderr).trim().to_string(),
    ))
}

/// Pocket → host.
pub async fn copy_out(d: &Arc<Daemon>, pocket: &str, src: &str, dst: &Path) -> R<String> {
    let rec = d.find(pocket)?;
    let live = d.running(&rec)?;
    let src = guest_path(src)?;
    let (parent, base) = split(&src);
    if base.is_empty() {
        return Err(err(
            ErrorCode::BadRequest,
            "copy a file or directory, not /",
        ));
    }
    let (into, name) = match fs::symlink_metadata(dst) {
        Ok(m) if m.is_dir() => (dst.to_path_buf(), base.clone()),
        Ok(m) if m.file_type().is_symlink() => {
            return Err(err(
                ErrorCode::BadRequest,
                format!("{} is a symlink; give the real path", dst.display()),
            ));
        }
        _ => {
            let parent = dst
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let name = dst
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| {
                    err(
                        ErrorCode::BadRequest,
                        format!("bad destination {}", dst.display()),
                    )
                })?;
            (parent.to_path_buf(), name)
        }
    };
    let into = into
        .canonicalize()
        .map_err(io_err(format!("destination {}", into.display())))?;
    if into.components().any(|c| c.as_os_str() == ".git") || name == ".git" {
        return Err(err(
            ErrorCode::BadRequest,
            "pocket files are never copied into a .git directory",
        )
        .hint("files from a pocket there could run code the next time you use git"));
    }
    let tmp = tmp_file(d)?;
    let fetched = async {
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .map_err(io_err(tmp.display()))?;
        let mut capped = Capped {
            inner: &mut f,
            left: MAX_BYTES,
        };
        let o = live
            .guest
            .exec_to(
                ExecReq {
                    argv: &["tar", "-c", "-f", "-", "-C", &parent, "--", &base],
                    env: vec![],
                    cwd: "/",
                    user: live.user.as_deref(),
                    stdin: None,
                },
                &mut capped,
            )
            .await
            .map_err(guest_err)?;
        if !o.ok() {
            return Err(err(
                ErrorCode::NotFound,
                format!("{pocket}:{src}: {}", o.stderr_text()),
            ));
        }
        Ok(())
    }
    .await;
    if let Err(e) = fetched {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    let (t2, i2, n2, b2) = (tmp.clone(), into.clone(), name.clone(), base.clone());
    let report = tokio::task::spawn_blocking(move || unpack(&t2, &i2, &b2, &n2))
        .await
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
    let _ = fs::remove_file(&tmp);
    let r = report.map_err(io_err("unpack"))?;
    let mut msg = format!(
        "copied {pocket}:{src} → {} ({} files, {} KiB)",
        into.join(&name).display(),
        r.files,
        r.bytes >> 10
    );
    if r.skipped > 0 {
        msg.push_str(&format!(
            "; skipped {} entries that are not plain files or directories (symlinks, devices, .git)",
            r.skipped
        ));
    }
    Ok(msg)
}

struct Capped<'a, W> {
    inner: &'a mut W,
    left: u64,
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Capped<'_, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if buf.len() as u64 > self.left {
            return std::task::Poll::Ready(Err(io::Error::other("more than 16 GiB")));
        }
        let this = &mut *self;
        let r = std::pin::Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            this.left -= *n as u64;
        }
        r
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Unpacked {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
}

/// Unpacks `archive` (rooted at `base`) into `into/name`, by the rules in the module docs.
pub fn unpack(archive: &Path, into: &Path, base: &str, name: &str) -> io::Result<Unpacked> {
    let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let mut a = tar::Archive::new(File::open(archive)?);
    let mut r = Unpacked::default();
    let mut n = 0u64;
    for e in a.entries()? {
        let mut e = e?;
        n += 1;
        if n > MAX_ENTRIES {
            return Err(bad("more than a million entries".into()));
        }
        let raw = e.path()?.into_owned();
        let mut parts: Vec<String> = vec![];
        for c in raw.components() {
            match c {
                Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
                Component::CurDir => {}
                _ => return Err(bad(format!("unsafe path {}", raw.display()))),
            }
        }
        if parts.first().map(String::as_str) != Some(base) {
            return Err(bad(format!("unexpected entry {}", raw.display())));
        }
        parts[0] = name.to_string();
        if parts.iter().any(|p| p == ".git") {
            r.skipped += 1;
            continue;
        }
        let kind = e.header().entry_type();
        let mut path = into.to_path_buf();
        // Every existing component must be a real directory: never write through a link.
        for (i, p) in parts.iter().enumerate() {
            path.push(p);
            if i + 1 < parts.len() {
                match fs::symlink_metadata(&path) {
                    Ok(m) if m.is_dir() => {}
                    Ok(_) => return Err(bad(format!("{} is not a directory", path.display()))),
                    Err(_) => fs::create_dir(&path)?,
                }
            }
        }
        let mode = e.header().mode().unwrap_or(0o644) & 0o777;
        if kind.is_dir() {
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    return Err(bad(format!(
                        "{} exists and is not a directory",
                        path.display()
                    )));
                }
                Err(_) => fs::create_dir(&path)?,
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(mode | 0o700))?;
        } else if kind.is_file() {
            if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
                return Err(bad(format!("{} exists and is not a file", path.display())));
            }
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let k = e.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                r.bytes += k as u64;
                if r.bytes > MAX_BYTES {
                    return Err(bad("more than 16 GiB".into()));
                }
                f.write_all(&buf[..k])?;
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            r.files += 1;
        } else {
            r.skipped += 1;
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(dir: &Path, build: impl FnOnce(&mut tar::Builder<File>)) -> PathBuf {
        let p = dir.join("a.tar");
        let mut b = tar::Builder::new(File::create(&p).unwrap());
        build(&mut b);
        b.finish().unwrap();
        p
    }

    fn file(b: &mut tar::Builder<File>, path: &str, data: &[u8], mode: u32) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(tar::EntryType::Regular);
        // set_path refuses `..`; a hostile guest would write raw names.
        h.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pocket-cp-{}-{}",
            std::process::id(),
            hex(&random_bytes(4))
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn guest_paths() {
        assert_eq!(guest_path("src/x").unwrap(), "/work/src/x");
        assert_eq!(guest_path("/tmp//a/./b").unwrap(), "/tmp/a/b");
        assert!(guest_path("../etc").is_err() && guest_path("a\0b").is_err());
    }

    #[test]
    fn unpacks_files_and_refuses_escapes() {
        let d = scratch();
        let out = d.join("out");
        fs::create_dir(&out).unwrap();
        let ok = archive(&d, |b| {
            file(b, "res/a.txt", b"hello", 0o4755);
            file(b, "res/.git/hooks/pre-commit", b"#!/bin/sh\nevil", 0o755);
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_path("res/link").unwrap();
            h.set_link_name("/etc/passwd").unwrap();
            h.set_size(0);
            h.set_cksum();
            b.append(&h, &b""[..]).unwrap();
        });
        let r = unpack(&ok, &out, "res", "copy").unwrap();
        assert_eq!((r.files, r.skipped), (1, 2));
        assert_eq!(fs::read(out.join("copy/a.txt")).unwrap(), b"hello");
        let mode = fs::metadata(out.join("copy/a.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755, "setuid bit kept");
        assert!(!out.join("copy/.git").exists() && !out.join("copy/link").exists());

        for evil in ["res/../../escape", "/abs/path", "other/x"] {
            let a = archive(&d, |b| file(b, evil, b"x", 0o644));
            assert!(unpack(&a, &out, "res", "copy").is_err(), "{evil} accepted");
        }
        assert!(!d.join("escape").exists());
        // An existing symlink in the destination is never written through.
        std::os::unix::fs::symlink(&d, out.join("copy/sub")).unwrap();
        let a = archive(&d, |b| file(b, "res/sub/f", b"x", 0o644));
        assert!(unpack(&a, &out, "res", "copy").is_err());
        assert!(!d.join("f").exists());
        let _ = fs::remove_dir_all(&d);
    }
}
