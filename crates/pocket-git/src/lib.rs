//! Host-side git (SECURITY.md §Git). Host git only ever runs in the user's own repository,
//! which no guest can write; the guest only gets read-only `upload-pack` on it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("{path} is not inside a git work tree")]
    NotARepo { path: PathBuf },
    #[error("git {args}: {msg}")]
    Failed { args: String, msg: String },
    #[error("could not run git: {0}")]
    Spawn(#[from] std::io::Error),
}

/// Config forced on every host git invocation: no fsmonitor daemons, no hooks, no
/// optional index writes (so `pocket new` leaves `git status` exactly as it was).
const HARDEN: &[&str] = &[
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.file.allow=always",
];

pub fn git(repo: &Path) -> Command {
    let mut c = Command::new("git");
    c.args(HARDEN)
        .arg("-C")
        .arg(repo)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdin(Stdio::null());
    c
}

fn run(repo: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let o = git(repo).args(args).output()?;
    if !o.status.success() {
        return Err(GitError::Failed {
            args: args.join(" "),
            msg: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        });
    }
    Ok(o.stdout)
}

fn text(repo: &Path, args: &[&str]) -> Result<String, GitError> {
    Ok(String::from_utf8_lossy(&run(repo, args)?)
        .trim()
        .to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoInfo {
    pub toplevel: PathBuf,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub origin: Option<String>,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
}

pub fn repo_info(path: &Path) -> Result<RepoInfo, GitError> {
    let top = text(path, &["rev-parse", "--show-toplevel"]).map_err(|_| GitError::NotARepo {
        path: path.to_path_buf(),
    })?;
    let toplevel = PathBuf::from(top);
    let opt = |args: &[&str]| text(&toplevel, args).ok().filter(|s| !s.is_empty());
    Ok(RepoInfo {
        head: opt(&["rev-parse", "--verify", "-q", "HEAD"]),
        branch: opt(&["symbolic-ref", "--short", "-q", "HEAD"]),
        origin: opt(&["config", "--get", "remote.origin.url"]),
        user_name: opt(&["config", "--get", "user.name"]),
        user_email: opt(&["config", "--get", "user.email"]),
        toplevel,
    })
}

/// Absolute git directory of the work tree at `repo` (`upload-pack --strict` needs it).
pub fn git_dir(repo: &Path) -> Result<PathBuf, GitError> {
    text(repo, &["rev-parse", "--absolute-git-dir"]).map(PathBuf::from)
}

/// `git upload-pack` serving the git directory `git_dir` read-only on stdin/stdout.
pub fn upload_pack(git_dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.args(HARDEN)
        .args([
            "-c",
            "uploadpack.allowFilter=true",
            "-c",
            "uploadpack.allowAnySHA1InWant=false",
        ])
        .arg("upload-pack")
        .arg("--strict")
        .arg("--timeout=600")
        .arg(git_dir)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_PROTOCOL");
    c
}

/// HTTPS form of a remote URL, so the guest's `origin` goes through the egress proxy:
/// `git@host:o/r.git` and `ssh://git@host/o/r` become `https://host/o/r.git`.
pub fn https_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.starts_with("https://") {
        return Some(url.to_string());
    }
    if let Some(rest) = url.strip_prefix("http://") {
        return Some(format!("https://{rest}"));
    }
    let (host, path) = if let Some(rest) = url.strip_prefix("ssh://") {
        let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
        let (h, p) = rest.split_once('/')?;
        (h.split(':').next()?.to_string(), p.to_string())
    } else if !url.contains("://") && url.contains(':') {
        let (userhost, p) = url.split_once(':')?;
        let h = userhost.split_once('@').map_or(userhost, |(_, h)| h);
        (h.to_string(), p.trim_start_matches('/').to_string())
    } else {
        return None;
    };
    let ok_host = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !ok_host || path.is_empty() || path.contains("..") {
        return None;
    }
    let path = if path.ends_with(".git") {
        path
    } else {
        format!("{path}.git")
    };
    Some(format!("https://{host}/{path}"))
}

/// Uncommitted host changes: a binary diff of tracked files against HEAD and the
/// untracked, non-ignored files (path, content). Nothing in the repo is written.
pub struct Changes {
    pub patch: Vec<u8>,
    pub untracked: Vec<(String, Vec<u8>, u32)>,
}

pub fn uncommitted(repo: &Path, max_file: u64) -> Result<Changes, GitError> {
    let patch = run(
        repo,
        &["diff", "--binary", "--no-ext-diff", "--no-textconv", "HEAD"],
    )?;
    let list = run(repo, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut untracked = vec![];
    for p in list.split(|b| *b == 0).filter(|p| !p.is_empty()) {
        let rel = String::from_utf8_lossy(p).into_owned();
        let full = repo.join(&rel);
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            continue;
        };
        if !meta.is_file() || meta.len() > max_file {
            continue;
        }
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        untracked.push((rel, std::fs::read(&full)?, mode));
    }
    Ok(Changes { patch, untracked })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_urls_become_https() {
        assert_eq!(
            https_url("git@github.com:Spandan7724/pocket.git").as_deref(),
            Some("https://github.com/Spandan7724/pocket.git")
        );
        assert_eq!(
            https_url("ssh://git@gitlab.com:2222/a/b").as_deref(),
            Some("https://gitlab.com/a/b.git")
        );
        assert_eq!(
            https_url("https://github.com/a/b").as_deref(),
            Some("https://github.com/a/b")
        );
        assert_eq!(https_url("/local/path"), None);
        assert_eq!(https_url("file:///x"), None);
        assert_eq!(https_url("git@evil host:a"), None);
    }

    #[test]
    fn repo_info_and_changes() {
        let d = std::env::temp_dir().join(format!("pocket-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let g = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .arg("-C")
                    .arg(&d)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            )
        };
        g(&["init", "-q", "-b", "main"]);
        g(&["config", "user.name", "T"]);
        g(&["config", "user.email", "t@x"]);
        std::fs::write(d.join("a.txt"), "one\n").unwrap();
        g(&["add", "a.txt"]);
        g(&["commit", "-qm", "init"]);
        g(&["remote", "add", "origin", "git@github.com:o/r.git"]);
        std::fs::write(d.join("a.txt"), "two\n").unwrap();
        std::fs::write(d.join("new.txt"), "new\n").unwrap();
        let info = repo_info(&d.join(".")).unwrap();
        assert_eq!(info.branch.as_deref(), Some("main"));
        assert_eq!(info.origin.as_deref(), Some("git@github.com:o/r.git"));
        assert_eq!(info.head.as_ref().map(|h| h.len()), Some(40));
        let c = uncommitted(&info.toplevel, 1 << 20).unwrap();
        assert!(String::from_utf8_lossy(&c.patch).contains("+two"));
        assert_eq!(c.untracked.len(), 1);
        assert_eq!(c.untracked[0].0, "new.txt");
        assert!(matches!(
            repo_info(Path::new("/")),
            Err(GitError::NotARepo { .. })
        ));
        let _ = std::fs::remove_dir_all(&d);
    }
}
