//! The review loop (ARCHITECTURE.md §5): `diff`, `apply`, `pr`, `sync`. The host only ever
//! *fetches* from a pocket, with the hardened invocation, into `refs/pocket/<name>/*`; `apply`
//! and `pr` then work from those refs with the user's own git (hooks the guest never saw).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pocket_proto::rpc::{ApplyMode, ErrorCode};
use pocket_store::PocketRecord;

use crate::daemon::{Daemon, Live, R, err};
use crate::guest::ExecReq;

const FETCH_TIMEOUT: Duration = Duration::from_secs(600);

/// Snapshot of uncommitted work as a commit at `refs/pocket/uncommitted`, built with a
/// temporary index so the guest's own index and branch stay untouched.
const SNAPSHOT: &str = r#"set -e
cd /work
idx=$(mktemp)
trap 'rm -f "$idx"' EXIT
[ -f .git/index ] && cp .git/index "$idx"
export GIT_INDEX_FILE="$idx"
git -c core.fsmonitor=false -c core.untrackedCache=false add -A
tree=$(git write-tree)
parent=$(git rev-parse -q --verify HEAD || true)
commit=$(echo "pocket: uncommitted changes" | git commit-tree "$tree" ${parent:+-p "$parent"})
git update-ref refs/pocket/uncommitted "$commit"
"#;

fn ws_err(e: impl std::fmt::Display) -> pocket_proto::rpc::RpcError {
    err(ErrorCode::Workspace, e.to_string())
}

pub struct Fetched {
    pub repo: PathBuf,
    pub base: Option<String>,
    /// Full ref of the pocket's work (branch, or the uncommitted snapshot).
    pub head: String,
}

fn repo_of(rec: &PocketRecord) -> R<PathBuf> {
    rec.info.repo_path.clone().ok_or_else(|| {
        err(
            ErrorCode::BadRequest,
            format!("pocket {} has no repository", rec.info.name),
        )
        .hint("this pocket was created with --no-repo; copy files out with `pocket exec … cat`")
    })
}

fn running(d: &Daemon, rec: &PocketRecord) -> R<Arc<Live>> {
    d.live(&rec.info.id).ok_or_else(|| {
        err(
            ErrorCode::InvalidState,
            format!("pocket {} is {}", rec.info.name, rec.info.state.label()),
        )
        .hint(format!("start it with `pocket start {}`", rec.info.name))
    })
}

pub async fn fetch(d: &Arc<Daemon>, rec: &PocketRecord, uncommitted: bool) -> R<Fetched> {
    let repo = repo_of(rec)?;
    let live = running(d, rec)?;
    if uncommitted {
        let out = live
            .guest
            .exec(
                ExecReq {
                    argv: &["/bin/sh", "-c", SNAPSHOT],
                    env: vec![],
                    cwd: "/",
                    user: live.user.as_deref(),
                    stdin: None,
                },
                4096,
            )
            .await
            .map_err(|e| ws_err(format!("snapshot uncommitted changes: {e}")))?;
        if !out.ok() {
            return Err(ws_err(format!(
                "snapshot uncommitted changes in the pocket: {}",
                out.stderr_text()
            )));
        }
    }
    let exe = std::env::current_exe().map_err(|e| ws_err(format!("pocketd path: {e}")))?;
    let uds = live.vm.vsock_uds.clone();
    let name = rec.info.name.clone();
    let r2 = repo.clone();
    let job = tokio::task::spawn_blocking(move || {
        let exe = exe.to_string_lossy().into_owned();
        let uds = uds.to_string_lossy().into_owned();
        pocket_git::fetch_from_guest(
            &r2,
            &[&exe, "git-bridge", &uds, "/work/.git"],
            &name,
            uncommitted,
        )
    });
    tokio::time::timeout(FETCH_TIMEOUT, job)
        .await
        .map_err(|_| {
            ws_err(format!(
                "fetch from the pocket timed out after {FETCH_TIMEOUT:?}"
            ))
        })?
        .map_err(|e| ws_err(format!("fetch task: {e}")))?
        .map_err(|e| {
            ws_err(e).hint("check the pocket's repository with `pocket exec POCKET -- git status`")
        })?;
    let ns = pocket_git::pocket_ns(&rec.info.name);
    let head = if uncommitted {
        format!("{ns}__uncommitted")
    } else {
        let branch = rec
            .info
            .branch
            .clone()
            .unwrap_or_else(|| format!("pocket/{}", rec.info.name));
        let refs = pocket_git::pocket_refs(&repo, &rec.info.name).map_err(ws_err)?;
        if !refs.iter().any(|(r, _)| *r == branch) {
            return Err(ws_err(format!(
                "the pocket has no branch {branch} (it has: {})",
                refs.iter()
                    .map(|(r, _)| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .hint("commit inside the pocket, or use --uncommitted"));
        }
        format!("{ns}{branch}")
    };
    Ok(Fetched {
        repo,
        base: rec.info.base_ref.clone(),
        head,
    })
}

pub async fn diff(
    d: &Arc<Daemon>,
    pocket: &str,
    uncommitted: bool,
    stat: bool,
    color: bool,
) -> R<String> {
    let rec = d.find(pocket)?;
    let f = fetch(d, &rec, uncommitted).await?;
    let text = tokio::task::spawn_blocking(move || {
        pocket_git::diff(&f.repo, f.base.as_deref(), &f.head, stat, color)
    })
    .await
    .map_err(|e| ws_err(format!("diff task: {e}")))?
    .map_err(ws_err)?;
    Ok(text)
}

fn clean_or_err(repo: &Path) -> R<()> {
    let st = pocket_git::user_git(repo, &["status", "--porcelain", "--untracked-files=no"])
        .map_err(ws_err)?;
    if !st.trim().is_empty() {
        return Err(err(
            ErrorCode::InvalidState,
            format!("{} has uncommitted changes", repo.display()),
        )
        .hint("commit or stash them first, so applying a pocket can't mix with your edits"));
    }
    Ok(())
}

pub async fn apply(
    d: &Arc<Daemon>,
    pocket: &str,
    mode: ApplyMode,
    onto: Option<String>,
    uncommitted: bool,
    message: Option<String>,
) -> R<String> {
    let rec = d.find(pocket)?;
    let f = fetch(d, &rec, uncommitted).await?;
    let name = rec.info.name.clone();
    tokio::task::spawn_blocking(move || {
        let g = |args: &[&str]| pocket_git::user_git(&f.repo, args);
        clean_or_err(&f.repo)?;
        if let Some(b) = &onto {
            if b.starts_with('-') || b.contains("..") {
                return Err(err(ErrorCode::BadRequest, format!("invalid branch {b:?}")));
            }
            g(&["switch", b]).map_err(ws_err)?;
        }
        let range = match &f.base {
            Some(b) => format!("{b}..{}", f.head),
            None => f.head.clone(),
        };
        let commits = g(&["rev-list", "--count", &range]).map_err(ws_err)?;
        if commits.trim() == "0" {
            return Ok(format!("nothing to apply: {name} has no changes on top of its base"));
        }
        let subjects = g(&["log", "--format=- %s", "--reverse", &range]).map_err(ws_err)?;
        let conflict = |e: pocket_git::GitError| {
            ws_err(e).hint("resolve the conflicts and commit, or abort (`git merge --abort` / `git cherry-pick --abort`)")
        };
        match mode {
            ApplyMode::Squash => {
                g(&["merge", "--squash", "--no-commit", &f.head]).map_err(conflict)?;
                let msg = message.unwrap_or_else(|| format!("Changes from pocket {name}\n\n{subjects}"));
                g(&["commit", "-q", "-m", &msg]).map_err(ws_err)?;
            }
            ApplyMode::Merge => {
                let msg = message.unwrap_or_else(|| format!("Merge pocket {name}"));
                g(&["merge", "--no-ff", "-q", "-m", &msg, &f.head]).map_err(conflict)?;
            }
            ApplyMode::CherryPick => {
                g(&["cherry-pick", &range]).map_err(conflict)?;
            }
        }
        let head = g(&["log", "-1", "--format=%h %s"]).map_err(ws_err)?;
        let branch = g(&["symbolic-ref", "--short", "-q", "HEAD"]).unwrap_or_default();
        Ok(format!(
            "applied {} commit(s) from {name} ({}) onto {}: {}",
            commits.trim(),
            match mode {
                ApplyMode::Squash => "squashed",
                ApplyMode::Merge => "merged",
                ApplyMode::CherryPick => "cherry-picked",
            },
            branch.trim(),
            head.trim()
        ))
    })
    .await
    .map_err(|e| ws_err(format!("apply task: {e}")))?
}

/// GitHub API base (`POCKET_GITHUB_API` for GitHub Enterprise).
fn github_api() -> (String, String) {
    let base =
        std::env::var("POCKET_GITHUB_API").unwrap_or_else(|_| "https://api.github.com".into());
    let rest = base
        .trim_end_matches('/')
        .strip_prefix("https://")
        .unwrap_or("api.github.com");
    match rest.split_once('/') {
        Some((h, p)) => (h.to_string(), format!("/{p}")),
        None => (rest.to_string(), String::new()),
    }
}

fn github_token(d: &Daemon) -> Option<String> {
    let from_store = d.db(|s| s.secrets()).ok().and_then(|all| {
        all.iter()
            .find(|r| r.provider == "github")
            .and_then(|r| d.vault.get(&r.name).ok().flatten())
    });
    from_store
        .or_else(|| std::env::var("GH_TOKEN").ok())
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .or_else(|| {
            std::process::Command::new("gh")
                .args(["auth", "token"])
                .stdin(std::process::Stdio::null())
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .filter(|t| !t.is_empty())
}

pub async fn pr(
    d: &Arc<Daemon>,
    pocket: &str,
    title: Option<String>,
    body: Option<String>,
    draft: bool,
    base: Option<String>,
) -> R<(String, String)> {
    let rec = d.find(pocket)?;
    let f = fetch(d, &rec, false).await?;
    let meta = Daemon::meta(&rec);
    let branch = rec
        .info
        .branch
        .clone()
        .unwrap_or_else(|| format!("pocket/{}", rec.info.name));
    let base = base
        .or(meta.base_branch.clone())
        .unwrap_or_else(|| "main".into());
    let repo = f.repo.clone();
    let (head, origin, first) = {
        let head = f.head.clone();
        let branch = branch.clone();
        let base_ref = f.base.clone();
        tokio::task::spawn_blocking(move || -> R<(String, String, String)> {
            let g = |args: &[&str]| pocket_git::user_git(&repo, args);
            let origin = g(&["config", "--get", "remote.origin.url"]).map_err(|e| {
                ws_err(e).hint("the host repository needs an `origin` remote to open a PR")
            })?;
            let range = match &base_ref {
                Some(b) => format!("{b}..{head}"),
                None => head.clone(),
            };
            let first = g(&["log", "--reverse", "--format=%s", &range]).map_err(ws_err)?;
            g(&["push", "--quiet", "origin", &format!("{head}:refs/heads/{branch}")]).map_err(|e| {
                ws_err(e).hint("the push runs on the host with your git credentials; check `git push` works there")
            })?;
            Ok((head, origin.trim().to_string(), first.lines().next().unwrap_or("").to_string()))
        })
        .await
        .map_err(|e| ws_err(format!("push task: {e}")))??
    };
    let _ = head;
    let (_host, owner, repo_name) = pocket_git::github_repo(&origin).ok_or_else(|| {
        err(
            ErrorCode::BadRequest,
            format!("origin {origin} is not a GitHub repository"),
        )
        .hint(format!(
            "the branch {branch} was pushed; open the pull request on your forge"
        ))
    })?;
    let token = github_token(d).ok_or_else(|| {
        err(
            ErrorCode::HostSetup,
            "no GitHub token for opening the pull request",
        )
        .hint(format!(
            "branch {branch} was pushed; run `pocket login github` (or `gh auth login`) and retry"
        ))
    })?;
    let (api_host, api_path) = github_api();
    let req = serde_json::json!({
        "title": title.unwrap_or_else(|| if first.is_empty() { format!("Changes from pocket {}", rec.info.name) } else { first.clone() }),
        "head": branch,
        "base": base,
        "body": body.unwrap_or_else(|| format!("Created with `pocket pr` from pocket `{}`.", rec.info.name)),
        "draft": draft,
    });
    let (resolver, connector) = crate::net::upstream();
    let auth = format!("Bearer {token}");
    let r = pocket_net::client::request(
        &*resolver,
        &*connector,
        d.upstream_tls(),
        &api_host,
        "POST",
        &format!("{api_path}/repos/{owner}/{repo_name}/pulls"),
        &[
            ("Authorization", auth.as_str()),
            ("Accept", "application/vnd.github+json"),
            ("Content-Type", "application/json"),
            ("User-Agent", "pocket"),
            ("X-GitHub-Api-Version", "2022-11-28"),
        ],
        &serde_json::to_vec(&req).unwrap(),
    )
    .await
    .map_err(|e| ws_err(format!("GitHub API: {e}")))?;
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
    if r.status != 201 {
        let msg = v["message"].as_str().unwrap_or("unexpected reply");
        return Err(ws_err(format!(
            "GitHub refused the pull request ({}): {msg}",
            r.status
        ))
        .hint(format!("branch {branch} was pushed; open the PR on GitHub")));
    }
    let url = v["html_url"].as_str().unwrap_or_default().to_string();
    Ok((format!("pushed {branch} and opened {url}"), url))
}

pub async fn sync(d: &Arc<Daemon>, pocket: &str, rebase: bool) -> R<String> {
    let rec = d.find(pocket)?;
    repo_of(&rec)?;
    let live = running(d, &rec)?;
    let base = Daemon::meta(&rec)
        .base_branch
        .unwrap_or_else(|| "HEAD".into());
    if base.starts_with('-') {
        return Err(err(ErrorCode::BadRequest, "invalid base branch"));
    }
    let op = if rebase { "rebase" } else { "merge --no-edit" };
    let script = format!(
        "set -e; cd /work; git fetch --quiet host \"$1\"; git {op} FETCH_HEAD 2>&1; git log -1 --format='%h %s'"
    );
    let out = live
        .guest
        .exec(
            ExecReq {
                argv: &["/bin/sh", "-c", &script, "sh", &base],
                env: vec![("GIT_TERMINAL_PROMPT".into(), "0".into())],
                cwd: "/",
                user: live.user.as_deref(),
                stdin: None,
            },
            1 << 20,
        )
        .await
        .map_err(|e| ws_err(format!("sync: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.ok() {
        return Err(ws_err(format!(
            "sync failed in the pocket: {}{}",
            text,
            out.stderr_text()
        ))
        .hint(format!(
            "resolve it inside the pocket (`pocket sh {}`)",
            rec.info.name
        )));
    }
    Ok(format!(
        "synced {} with the host's {base}:\n{text}",
        rec.info.name
    ))
}
