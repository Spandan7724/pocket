use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// Set to anything but `0` to skip reflink and always sparse-copy (tests, odd filesystems).
pub const NO_REFLINK_ENV: &str = "POCKET_NO_REFLINK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneMode {
    Reflink,
    SparseCopy,
}

#[derive(Debug, thiserror::Error)]
#[error("{op} {}: {source}", path.display())]
pub struct DiskError {
    pub op: &'static str,
    pub path: PathBuf,
    #[source]
    pub source: io::Error,
}

fn err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> DiskError {
    let path = path.to_path_buf();
    move |source| DiskError { op, path, source }
}

pub fn reflink_disabled(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// Copies `src` to a new file `dst`: reflink when the filesystem supports it, otherwise a
/// copy that preserves holes. Honours [`NO_REFLINK_ENV`].
pub fn clone_disk(src: &Path, dst: &Path) -> Result<CloneMode, DiskError> {
    let force_copy = reflink_disabled(std::env::var_os(NO_REFLINK_ENV).as_deref());
    let s = File::open(src).map_err(err("open", src))?;
    let d = File::options()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(err("create", dst))?;
    if !force_copy {
        // SAFETY: both descriptors are open for the duration of the call.
        let r = unsafe { libc::ioctl(d.as_raw_fd(), libc::FICLONE, s.as_raw_fd()) };
        if r == 0 {
            return Ok(CloneMode::Reflink);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY | libc::ENOSYS) => {}
            _ => {
                let _ = fs::remove_file(dst);
                return Err(err("reflink", dst)(e));
            }
        }
    }
    sparse_copy(&s, &d, src, dst).inspect_err(|_| {
        let _ = fs::remove_file(dst);
    })?;
    Ok(CloneMode::SparseCopy)
}

fn sparse_copy(s: &File, d: &File, src: &Path, dst: &Path) -> Result<(), DiskError> {
    let len = s.metadata().map_err(err("stat", src))?.len();
    d.set_len(len).map_err(err("truncate", dst))?;
    let (sfd, dfd) = (s.as_raw_fd(), d.as_raw_fd());
    let mut pos: i64 = 0;
    while (pos as u64) < len {
        // SAFETY: lseek on an open descriptor.
        let data = unsafe { libc::lseek(sfd, pos, libc::SEEK_DATA) };
        if data < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break; // only a hole remains
            }
            return Err(err("seek data", src)(e));
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(sfd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(err("seek hole", src)(io::Error::last_os_error()));
        }
        let (mut off_in, mut off_out) = (data, data);
        while off_in < hole {
            // SAFETY: valid descriptors and offset pointers owned by this frame.
            let n = unsafe {
                libc::copy_file_range(
                    sfd,
                    &mut off_in,
                    dfd,
                    &mut off_out,
                    (hole - off_in) as usize,
                    0,
                )
            };
            if n < 0 {
                return Err(err("copy", dst)(io::Error::last_os_error()));
            }
            if n == 0 {
                break;
            }
        }
        pos = hole;
    }
    d.sync_all().map_err(err("sync", dst))
}

/// Bytes actually allocated to a (sparse) file.
pub fn allocated_bytes(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).map(|m| m.blocks() * 512).unwrap_or(0)
}

/// Formatted, empty, sparse ext4 template for `size_bytes` disks, created once in
/// `templates_dir` and then cloned for every pocket.
pub fn empty_ext4_template(templates_dir: &Path, size_bytes: u64) -> Result<PathBuf, DiskError> {
    let t = templates_dir.join(format!("empty-ext4-{}m.raw", size_bytes >> 20));
    if t.exists() {
        return Ok(t);
    }
    fs::create_dir_all(templates_dir).map_err(err("create", templates_dir))?;
    let tmp = t.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    File::create(&tmp)
        .and_then(|f| f.set_len(size_bytes))
        .map_err(err("create", &tmp))?;
    // Lazy init keeps the image sparse; the guest finishes inode table init in background.
    let out = std::process::Command::new("mkfs.ext4")
        .args([
            "-q",
            "-F",
            "-m",
            "0",
            "-E",
            "lazy_itable_init=1,lazy_journal_init=1",
        ])
        .args(["-L", "pocket", "-U", "clear"])
        .arg(&tmp)
        .output()
        .map_err(err("run mkfs.ext4 for", &tmp))?;
    if !out.status.success() {
        let _ = fs::remove_file(&tmp);
        return Err(DiskError {
            op: "mkfs.ext4",
            path: tmp,
            source: io::Error::other(String::from_utf8_lossy(&out.stderr).into_owned()),
        });
    }
    fs::rename(&tmp, &t).map_err(err("rename", &t))?;
    Ok(t)
}

/// Creates the pocket disk at `dest`: a reflink (or sparse copy) of the empty template.
pub fn create_pocket_disk(
    templates_dir: &Path,
    size_bytes: u64,
    dest: &Path,
) -> Result<CloneMode, DiskError> {
    let t = empty_ext4_template(templates_dir, size_bytes)?;
    clone_disk(&t, dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_value_parsing() {
        assert!(!reflink_disabled(None));
        assert!(!reflink_disabled(Some(OsStr::new(""))));
        assert!(!reflink_disabled(Some(OsStr::new("0"))));
        assert!(reflink_disabled(Some(OsStr::new("1"))));
    }
}
