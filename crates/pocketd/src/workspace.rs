//! Clone-in (ARCHITECTURE.md §5): the guest clones the host repo over the vsock git
//! transport (`pocket://host` → host `upload-pack`, read-only). Host git never runs in a
//! directory the guest can write; nothing is written to the host repo.

use pocket_git::RepoInfo;
use pocket_proto::rpc::ErrorCode;

use crate::daemon::{Daemon, Live, R, err};
use crate::guest::ExecReq;

/// Largest untracked file carried over.
const MAX_CARRY_FILE: u64 = 16 << 20;

/// Clone-in steps must never hang pocket creation (the per-pocket lock is held).
const STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

async fn run(live: &Live, argv: &[&str], stdin: Option<Vec<u8>>, what: &str) -> R<String> {
    let exec = live.guest.exec(
        ExecReq {
            argv,
            env: vec![("GIT_TERMINAL_PROMPT".into(), "0".into())],
            cwd: "/",
            user: live.user.as_deref(),
            stdin,
        },
        1 << 20,
    );
    let out = tokio::time::timeout(STEP_TIMEOUT, exec)
        .await
        .map_err(|_| {
            err(
                ErrorCode::Workspace,
                format!("{what} timed out after {STEP_TIMEOUT:?}"),
            )
        })?
        .map_err(|e| err(ErrorCode::Workspace, format!("{what}: {e}")))?;
    if !out.ok() {
        let mut e = err(
            ErrorCode::Workspace,
            format!(
                "{what} failed in the pocket ({:?}): {}",
                out.status,
                out.stderr_text()
            ),
        );
        if out.status == pocket_proto::guest::ExitStatus::Code(127)
            || out.stderr_text().contains("not found")
        {
            e = e.hint("the pocket image has no git; use a preset with git (`--preset base`) or `--no-repo`");
        }
        return Err(e);
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
        && !p.contains('\0')
}

/// Returns the branch created in the guest.
pub async fn clone_in(_d: &Daemon, live: &Live, info: &RepoInfo, carry: bool) -> R<String> {
    let branch = format!("pocket/{}", live.name);
    run(
        live,
        &[
            "git",
            "clone",
            "--quiet",
            "--no-checkout",
            "pocket://host",
            "/work",
        ],
        None,
        "git clone",
    )
    .await?;
    fn g<'a>(args: &[&'a str]) -> Vec<&'a str> {
        let mut v = vec!["git", "-C", "/work"];
        v.extend_from_slice(args);
        v
    }
    match &info.head {
        Some(head) => {
            run(
                live,
                &g(&["checkout", "--quiet", "-B", &branch, head]),
                None,
                "git checkout",
            )
            .await?
        }
        None => {
            run(
                live,
                &g(&["checkout", "--quiet", "--orphan", &branch]),
                None,
                "git checkout",
            )
            .await?
        }
    };
    run(
        live,
        &g(&["remote", "rename", "origin", "host"]),
        None,
        "git remote rename",
    )
    .await?;
    if let Some(url) = info.origin.as_deref().and_then(pocket_git::https_url) {
        run(
            live,
            &g(&["remote", "add", "origin", &url]),
            None,
            "git remote add origin",
        )
        .await?;
    }
    if let Some(n) = &info.user_name {
        run(live, &g(&["config", "user.name", n]), None, "git config").await?;
    }
    if let Some(e) = &info.user_email {
        run(live, &g(&["config", "user.email", e]), None, "git config").await?;
    }
    if carry && info.head.is_some() {
        let changes = pocket_git::uncommitted(&info.toplevel, MAX_CARRY_FILE).map_err(|e| {
            err(
                ErrorCode::Workspace,
                format!("read uncommitted changes: {e}"),
            )
        })?;
        if !changes.patch.is_empty() {
            run(
                live,
                &g(&["apply", "--binary", "--whitespace=nowarn", "-"]),
                Some(changes.patch),
                "apply uncommitted changes",
            )
            .await?;
        }
        for (path, data, mode) in changes.untracked {
            if !safe_rel(&path) {
                continue;
            }
            let full = format!("/work/{path}");
            let mode = format!("{:o}", mode & 0o777);
            run(
                live,
                &[
                    "/bin/sh",
                    "-c",
                    "mkdir -p \"$(dirname \"$1\")\" && cat > \"$1\" && chmod \"$2\" \"$1\"",
                    "sh",
                    &full,
                    &mode,
                ],
                Some(data),
                "copy untracked file",
            )
            .await?;
        }
    }
    Ok(branch)
}

#[cfg(test)]
mod tests {
    #[test]
    fn relative_paths() {
        assert!(super::safe_rel("a/b.txt"));
        for bad in ["", "/etc", "../x", "a/../b", "a//b", "./a"] {
            assert!(!super::safe_rel(bad), "{bad}");
        }
    }
}
