//! Guest setup after every configured boot: the pocket CA in the guest trust stores, git
//! credential helpers and SSH→HTTPS rewrites, placeholder credentials, and (first boot only)
//! the user's agent config.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pocket_proto::rpc::ErrorCode;
use pocket_store::PocketRecord;

use crate::daemon::{Daemon, Meta, R, err};
use crate::guest::{ExecReq, GuestConn};
use crate::inject::PocketHooks;

pub const GUEST_CA: &str = "/etc/pocket/ca.crt";

pub fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| "/".into()))
}

/// Atomic write of a host file with mode 0600.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("pocket-tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Environment for every guest process: CA bundle locations and each injected secret's
/// variables holding its placeholder (the real value only for explicit copy-ins).
pub fn guest_env(hooks: &PocketHooks) -> Vec<(String, String)> {
    let mut v = vec![
        ("NODE_EXTRA_CA_CERTS".to_string(), GUEST_CA.to_string()),
        (
            "REQUESTS_CA_BUNDLE".to_string(),
            "/etc/ssl/certs/ca-certificates.crt".to_string(),
        ),
    ];
    for it in hooks.items.read().unwrap().iter() {
        if it.chat.is_some() {
            continue;
        }
        let value = if it.meta.copy_in {
            it.real.clone()
        } else {
            it.meta.placeholder.clone()
        };
        for e in &it.info.env {
            v.push((e.clone(), value.clone()));
        }
    }
    v
}

const CA_SCRIPT: &str = r#"set -e
mkdir -p /etc/pocket
cat > /etc/pocket/ca.crt
chmod 644 /etc/pocket/ca.crt
key=$(sed -n 2p /etc/pocket/ca.crt)
add() { if [ -f "$1" ] && ! grep -qF "$key" "$1"; then { echo; cat /etc/pocket/ca.crt; } >> "$1"; fi; }
for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
  [ -L "$b" ] || add "$b"
done
if [ -d /usr/local/share/ca-certificates ]; then cp /etc/pocket/ca.crt /usr/local/share/ca-certificates/pocket-ca.crt; fi
for f in /usr/lib/python3/dist-packages/certifi/cacert.pem /usr/lib/python3/dist-packages/pip/_vendor/certifi/cacert.pem \
         /usr/local/lib/python3*/dist-packages/certifi/cacert.pem /usr/lib/python3*/site-packages/certifi/cacert.pem \
         /usr/local/lib/python3*/site-packages/certifi/cacert.pem /etc/ssl/certs/java/cacerts.pem; do
  add "$f"
done
"#;

/// System git config: tokens come from the env placeholders; SSH remotes of the common
/// forges go over HTTPS through the proxy (unless SSH agent forwarding is on).
fn git_script(github: bool, rewrite_ssh: bool) -> String {
    let mut s = String::from("command -v git >/dev/null 2>&1 || exit 0\nset -e\n");
    if github {
        s.push_str(
            "git config --system credential.https://github.com.helper \
             '!f() { test \"$1\" = get && echo username=x-access-token && echo \"password=${GH_TOKEN:-$GITHUB_TOKEN}\"; }; f'\n",
        );
    }
    if rewrite_ssh {
        for h in ["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"] {
            s.push_str(&format!(
                "git config --system --replace-all url.https://{h}/.insteadOf git@{h}: '^git@{h}:$'\n\
                 git config --system --replace-all url.https://{h}/.insteadOf ssh://git@{h}/ '^ssh://git@{h}/$'\n"
            ));
        }
    }
    s
}

pub async fn sh(
    guest: &GuestConn,
    user: Option<&str>,
    script: &str,
    stdin: Vec<u8>,
    what: &str,
) -> R<String> {
    let out = guest
        .exec(
            ExecReq {
                argv: &["/bin/sh", "-c", script],
                env: vec![],
                cwd: "/",
                user,
                stdin: Some(stdin),
            },
            1 << 20,
        )
        .await
        .map_err(|e| err(ErrorCode::Guest, format!("{what}: {e}")))?;
    if !out.ok() {
        return Err(err(
            ErrorCode::Guest,
            format!(
                "{what} failed in the pocket ({:?}): {}",
                out.status,
                out.stderr_text()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Writes `$HOME/<rel>` as `user` (mode 0600) unless it exists.
pub async fn write_home_file(
    guest: &GuestConn,
    user: Option<&str>,
    rel: &str,
    data: &[u8],
    overwrite: bool,
) -> R<()> {
    let script = format!(
        "set -e; f=\"$HOME/$1\"; {} mkdir -p \"$(dirname \"$f\")\"; umask 077; cat > \"$f.pocket-tmp\"; mv \"$f.pocket-tmp\" \"$f\"",
        if overwrite {
            ""
        } else {
            "[ -e \"$f\" ] && { cat >/dev/null; exit 0; };"
        }
    );
    let out = guest
        .exec(
            ExecReq {
                argv: &["/bin/sh", "-c", &script, "sh", rel],
                env: vec![],
                cwd: "/",
                user,
                stdin: Some(data.to_vec()),
            },
            4096,
        )
        .await
        .map_err(|e| err(ErrorCode::Guest, format!("write ~/{rel}: {e}")))?;
    if !out.ok() {
        return Err(err(
            ErrorCode::Guest,
            format!("write ~/{rel}: {}", out.stderr_text()),
        ));
    }
    Ok(())
}

pub async fn provision(
    d: &Arc<Daemon>,
    guest: &GuestConn,
    rec: &PocketRecord,
    meta: &mut Meta,
    hooks: &PocketHooks,
) -> R<()> {
    let user = meta.user.clone();
    let ca = d.ca()?;
    sh(
        guest,
        None,
        CA_SCRIPT,
        ca.cert_pem().as_bytes().to_vec(),
        "install the pocket CA",
    )
    .await?;
    let (github, chat) = {
        let items = hooks.items.read().unwrap();
        (
            items
                .iter()
                .any(|i| i.info.provider == "github" && !i.info.env.is_empty()),
            items
                .iter()
                .find(|i| i.chat.is_some())
                .map(|i| match i.meta.copy_in {
                    true => i.real.clone(),
                    false => i.chat.as_ref().unwrap().guest_auth_json(&i.meta),
                }),
        )
    };
    sh(
        guest,
        None,
        &git_script(github, true),
        vec![],
        "configure git",
    )
    .await?;
    if let Some(auth) = chat {
        write_home_file(
            guest,
            user.as_deref(),
            ".codex/auth.json",
            auth.as_bytes(),
            false,
        )
        .await?;
    }
    if !meta.provisioned {
        if meta.sync_config {
            crate::agentcfg::copy_in(d, guest, rec, meta, hooks).await?;
        }
        meta.provisioned = true;
    }
    Ok(())
}
