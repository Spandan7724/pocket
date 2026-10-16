//! Agent config sync (SECURITY.md §Agent config sync): `~/.claude` and `~/.codex` are copied
//! into a pocket at creation (never mounted) with credentials stripped, and come back only
//! through `pocket config pull`, which shows a diff and writes nothing without the user's
//! confirmation of exactly the content shown. Guest-modified config can carry hooks and MCP
//! commands that would run on the host, so everything read back is hostile input.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path};
use std::sync::Arc;

use pocket_proto::rpc::{ConfigChange, ErrorCode};
use pocket_store::PocketRecord;
use sha2::{Digest, Sha256};

use crate::daemon::{Daemon, Meta, R, err};
use crate::guest::{ExecReq, GuestConn};
use crate::inject::PocketHooks;
use crate::provision::{home, write_private};

pub const REDACTED: &str = "<redacted by pocket>";
const MAX_FILE: u64 = 1 << 20;
const MAX_TOTAL: u64 = 32 << 20;

/// Synced paths relative to `$HOME`: whole directories end in `/`.
const SYNCED: &[&str] = &[
    ".claude/settings.json",
    ".claude/CLAUDE.md",
    ".claude/keybindings.json",
    ".claude/commands/",
    ".claude/agents/",
    ".claude/skills/",
    ".claude/output-styles/",
    ".claude/hooks/",
    ".codex/config.toml",
    ".codex/AGENTS.md",
    ".codex/prompts/",
    ".codex/skills/",
    ".codex/rules/",
];

/// `~/.claude.json` keys worth carrying (onboarding state, preferences); everything else
/// (account, per-project history, keys) stays on the host.
const CLAUDE_JSON_KEYS: &[&str] = &[
    "theme",
    "hasCompletedOnboarding",
    "lastOnboardingVersion",
    "editorMode",
    "verbose",
    "preferredNotifChannel",
    "autoCompactEnabled",
    "hasAcknowledgedCostThreshold",
    "bypassPermissionsModeAccepted",
    "mcpServers",
];

const RISKY: &[&str] = &[
    "hooks",
    "mcpServers",
    "mcp_servers",
    "statusLine",
    "apiKeyHelper",
    "command",
    "env",
    "permissions",
    "notify",
    "otelHeadersHelper",
];

fn secretish(key: &str) -> bool {
    let k = key.to_ascii_lowercase().replace(['-', '_'], "");
    [
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "authorization",
        "credential",
        "privatekey",
        "cookie",
        "bearer",
    ]
    .iter()
    .any(|w| k.contains(w))
}

fn synced(rel: &str) -> bool {
    let safe = Path::new(rel)
        .components()
        .all(|c| matches!(c, Component::Normal(_)));
    safe && SYNCED.iter().any(|s| match s.strip_suffix('/') {
        Some(dir) => rel.starts_with(&format!("{dir}/")),
        None => rel == *s,
    })
}

fn walk(base: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>, u32)>, total: &mut u64) {
    let p = base.join(rel);
    let Ok(meta) = std::fs::symlink_metadata(&p) else {
        return;
    };
    if meta.is_dir() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            return;
        };
        let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for n in names {
            let n = n.to_string_lossy();
            if n == ".git" || n == "node_modules" {
                continue;
            }
            walk(base, &format!("{rel}/{n}"), out, total);
        }
    } else if meta.is_file()
        && meta.len() <= MAX_FILE
        && *total + meta.len() <= MAX_TOTAL
        && let Ok(data) = std::fs::read(&p)
    {
        use std::os::unix::fs::PermissionsExt;
        *total += data.len() as u64;
        out.push((rel.to_string(), data, meta.permissions().mode() & 0o755));
    }
}

/// Every known secret value → what the guest may see instead.
fn replacements(d: &Daemon, hooks: &PocketHooks) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = vec![];
    let items = hooks.items.read().unwrap();
    for it in items.iter().filter(|i| !i.meta.copy_in) {
        match &it.chat {
            Some(c) => {
                v.push((c.refresh_token.clone(), it.meta.placeholder.clone()));
                v.push((c.access_token.clone(), REDACTED.into()));
                v.push((c.id_token.clone(), REDACTED.into()));
            }
            None => v.push((it.real.clone(), it.meta.placeholder.clone())),
        }
    }
    if let Ok(all) = d.db(|s| s.secrets()) {
        for r in all {
            if items.iter().any(|i| i.info.name == r.name) {
                continue;
            }
            if let Ok(Some(val)) = d.vault.get(&r.name) {
                v.push((val, REDACTED.into()));
            }
        }
    }
    v.retain(|(real, _)| real.len() >= 8);
    v.sort_by_key(|(real, _)| std::cmp::Reverse(real.len()));
    v
}

/// Redacts string values under secret-looking keys, except pocket's own placeholders.
fn redact_json(v: &mut serde_json::Value, keep: &[&str]) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                match val {
                    serde_json::Value::String(s)
                        if secretish(k)
                            && !s.is_empty()
                            && !s.starts_with('$')
                            && s != REDACTED
                            && !keep.contains(&s.as_str()) =>
                    {
                        *s = REDACTED.into();
                    }
                    _ => redact_json(val, keep),
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| redact_json(x, keep)),
        _ => {}
    }
}

fn redact_toml(text: &str, keep: &[&str]) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        match line.split_once('=') {
            Some((k, v))
                if secretish(k.trim().trim_matches('"'))
                    && v.trim_start().starts_with('"')
                    && !keep.iter().any(|p| v.trim().trim_matches('"') == *p) =>
            {
                out.push_str(&format!("{k}= \"{REDACTED}\"\n"));
            }
            _ => out.push_str(line),
        }
    }
    out
}

/// What a host file looks like inside the pocket.
pub fn strip(rel: &str, data: &[u8], repl: &[(String, String)]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(data) else {
        return data.to_vec();
    };
    let mut text = text.to_string();
    for (real, with) in repl {
        if text.contains(real.as_str()) {
            text = text.replace(real.as_str(), with);
        }
    }
    let keep: Vec<&str> = repl
        .iter()
        .map(|(_, w)| w.as_str())
        .filter(|w| *w != REDACTED)
        .collect();
    if rel.ends_with(".json") {
        if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&text) {
            redact_json(&mut v, &keep);
            return serde_json::to_vec_pretty(&v).unwrap();
        }
    } else if rel.ends_with(".toml") {
        return redact_toml(&text, &keep).into_bytes();
    }
    text.into_bytes()
}

fn claude_json(
    src: Option<&[u8]>,
    hooks: &PocketHooks,
    repl: &[(String, String)],
) -> Option<Vec<u8>> {
    let mut out = serde_json::Map::new();
    if let Some(v) = src.and_then(|s| serde_json::from_slice::<serde_json::Value>(s).ok())
        && let Some(m) = v.as_object()
    {
        for k in CLAUDE_JSON_KEYS {
            if let Some(x) = m.get(*k) {
                out.insert((*k).into(), x.clone());
            }
        }
    }
    // Pre-approve the placeholder API key so Claude Code doesn't ask about it.
    let approved: Vec<String> = hooks
        .items
        .read()
        .unwrap()
        .iter()
        .filter(|i| {
            i.info.provider == "anthropic" && i.info.env.iter().any(|e| e == "ANTHROPIC_API_KEY")
        })
        .map(|i| {
            let v = if i.meta.copy_in {
                &i.real
            } else {
                &i.meta.placeholder
            };
            v[v.len().saturating_sub(20)..].to_string()
        })
        .collect();
    if !approved.is_empty() {
        out.insert(
            "customApiKeyResponses".into(),
            serde_json::json!({ "approved": approved, "rejected": [] }),
        );
    }
    if out.is_empty() {
        return None;
    }
    let text = serde_json::to_string_pretty(&serde_json::Value::Object(out)).unwrap();
    Some(strip(".claude.json", text.as_bytes(), repl))
}

pub async fn copy_in(
    d: &Arc<Daemon>,
    guest: &GuestConn,
    rec: &PocketRecord,
    meta: &Meta,
    hooks: &PocketHooks,
) -> R<()> {
    let home = home();
    let mut files = vec![];
    let mut total = 0;
    for s in SYNCED {
        walk(&home, s.trim_end_matches('/'), &mut files, &mut total);
    }
    let repl = replacements(d, hooks);
    let mut tar = tar::Builder::new(Vec::new());
    let mut n = 0;
    let mut add = |rel: &str, data: &[u8], mode: u32| {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_cksum();
        tar.append_data(&mut h, rel, data)
            .map_err(|e| err(ErrorCode::Internal, format!("pack {rel}: {e}")))
    };
    for (rel, data, mode) in &files {
        add(rel, &strip(rel, data, &repl), *mode | 0o600)?;
        n += 1;
    }
    let cj = std::fs::read(home.join(".claude.json")).ok();
    if let Some(data) = claude_json(cj.as_deref(), hooks, &repl) {
        add(".claude.json", &data, 0o600)?;
        n += 1;
    }
    if n == 0 {
        return Ok(());
    }
    let data = tar
        .into_inner()
        .map_err(|e| err(ErrorCode::Internal, format!("pack agent config: {e}")))?;
    crate::provision::sh(
        guest,
        meta.user.as_deref(),
        "cd \"$HOME\" && tar -x -o -f -",
        data,
        "copy agent config in",
    )
    .await?;
    tracing::info!("{}: copied {n} agent config files in", rec.info.name);
    Ok(())
}

fn restore_json(guest: &mut serde_json::Value, host: Option<&serde_json::Value>) -> bool {
    match guest {
        serde_json::Value::String(s) if s == REDACTED => match host {
            Some(h @ serde_json::Value::String(_)) => {
                *guest = h.clone();
                true
            }
            _ => false,
        },
        serde_json::Value::Object(m) => {
            let mut ok = true;
            for (k, v) in m.iter_mut() {
                ok &= restore_json(v, host.and_then(|h| h.get(k)));
            }
            ok
        }
        serde_json::Value::Array(a) => {
            let mut ok = true;
            for (i, v) in a.iter_mut().enumerate() {
                ok &= restore_json(v, host.and_then(|h| h.get(i)));
            }
            ok
        }
        _ => true,
    }
}

/// The guest version with redactions put back from the host and placeholders mapped to the
/// values they stood for; `Err` when something redacted can't be restored.
fn restore(
    rel: &str,
    guest: &str,
    host: Option<&str>,
    back: &[(String, String)],
) -> Result<String, String> {
    let mut text = guest.to_string();
    for (ph, real) in back {
        if text.contains(ph.as_str()) {
            text = text.replace(ph.as_str(), real);
        }
    }
    if !text.contains(REDACTED) {
        return Ok(text);
    }
    if rel.ends_with(".json") {
        let mut g: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| "invalid JSON".to_string())?;
        let h = host.and_then(|h| serde_json::from_str::<serde_json::Value>(h).ok());
        if restore_json(&mut g, h.as_ref()) {
            return Ok(serde_json::to_string_pretty(&g).unwrap() + "\n");
        }
    } else {
        let host_lines: BTreeMap<String, String> = host
            .unwrap_or("")
            .lines()
            .filter_map(|l| {
                l.split_once('=')
                    .map(|(k, _)| (k.trim().to_string(), l.to_string()))
            })
            .collect();
        let mut out = String::new();
        let mut ok = true;
        for line in text.split_inclusive('\n') {
            if line.contains(REDACTED) {
                match line
                    .split_once('=')
                    .and_then(|(k, _)| host_lines.get(k.trim()))
                {
                    Some(h) => {
                        out.push_str(h);
                        out.push('\n');
                    }
                    None => ok = false,
                }
            } else {
                out.push_str(line);
            }
        }
        if ok {
            return Ok(out);
        }
    }
    Err(
        "contains values pocket redacted that are not on the host; edit this file on the host"
            .into(),
    )
}

/// Security-relevant keys whose lines changed.
fn risky_keys(host: Option<&str>, guest: &str) -> Vec<String> {
    let h = host.unwrap_or("");
    let changed: Vec<&str> = guest
        .lines()
        .filter(|l| !h.lines().any(|x| x == *l))
        .chain(h.lines().filter(|l| !guest.lines().any(|x| x == *l)))
        .collect();
    RISKY
        .iter()
        .filter(|k| changed.iter().any(|l| l.contains(*k)))
        .map(|k| k.to_string())
        .collect()
}

/// Reads the synced files back from the guest (hostile tar, strictly checked).
async fn read_guest(guest: &GuestConn, user: Option<&str>) -> R<Vec<(String, Vec<u8>)>> {
    let paths = SYNCED
        .iter()
        .map(|s| s.trim_end_matches('/'))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "cd \"$HOME\" || exit 1; for p in {paths}; do [ -e \"$p\" ] && echo \"$p\"; done | tar -c -f - -T - 2>/dev/null; exit 0"
    );
    let out = guest
        .exec(
            ExecReq {
                argv: &["/bin/sh", "-c", &script],
                env: vec![],
                cwd: "/",
                user,
                stdin: None,
            },
            MAX_TOTAL as usize + (4 << 20),
        )
        .await
        .map_err(|e| err(ErrorCode::Guest, format!("read agent config: {e}")))?;
    let mut files = vec![];
    let mut total = 0u64;
    let mut ar = tar::Archive::new(out.stdout.as_slice());
    let entries = ar.entries().map_err(|e| {
        err(
            ErrorCode::Guest,
            format!("agent config archive from the pocket: {e}"),
        )
    })?;
    for e in entries {
        let Ok(mut e) = e else { break };
        if e.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let Ok(path) = e.path() else { continue };
        let rel = path.to_string_lossy().trim_start_matches("./").to_string();
        if !synced(&rel) || e.size() > MAX_FILE {
            continue;
        }
        total += e.size();
        if total > MAX_TOTAL {
            break;
        }
        let mut data = vec![];
        if e.by_ref().take(MAX_FILE).read_to_end(&mut data).is_ok() {
            files.push((rel, data));
        }
    }
    Ok(files)
}

pub async fn pull(
    d: &Arc<Daemon>,
    pocket: &str,
    accept: Option<Vec<(String, String)>>,
) -> R<Vec<ConfigChange>> {
    let rec = d.find(pocket)?;
    let live = d.live(&rec.info.id).ok_or_else(|| {
        err(
            ErrorCode::InvalidState,
            format!("pocket {} is not running", rec.info.name),
        )
        .hint(format!("start it with `pocket start {}`", rec.info.name))
    })?;
    let files = read_guest(&live.guest, live.user.as_deref()).await?;
    let back: Vec<(String, String)> = {
        let items = live.hooks.items.read().unwrap();
        let mut v: Vec<(String, String)> = items
            .iter()
            .filter(|i| !i.meta.copy_in && i.chat.is_none())
            .map(|i| (i.meta.placeholder.clone(), i.real.clone()))
            .collect();
        v.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        v
    };
    let mask: Vec<(String, String)> = replacements(d, &live.hooks)
        .into_iter()
        .map(|(real, _)| (real, REDACTED.to_string()))
        .collect();
    let home = home();
    let mut changes = vec![];
    let mut pending: Vec<(String, String)> = vec![];
    for (rel, data) in files {
        let host = std::fs::read(home.join(&rel)).ok();
        let host_text = host
            .as_deref()
            .map(|h| String::from_utf8_lossy(h).into_owned());
        let Ok(gtext) = String::from_utf8(data) else {
            continue;
        };
        let (content, blocked) = match restore(&rel, &gtext, host_text.as_deref(), &back) {
            Ok(c) => (c, None),
            Err(why) => (gtext.clone(), Some(why)),
        };
        if host_text.as_deref() == Some(content.as_str()) {
            continue;
        }
        // Same as the host apart from pocket's own normalisation (pretty-printed JSON).
        if let Some(h) = &host
            && blocked.is_none()
            && rel.ends_with(".json")
            && serde_json::from_slice::<serde_json::Value>(h).ok()
                == serde_json::from_str::<serde_json::Value>(&content).ok()
        {
            continue;
        }
        let sha = Sha256::digest(content.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // Shown to the user: both sides normalised and every secret masked the same way.
        let show =
            |t: &str| String::from_utf8_lossy(&strip(&rel, t.as_bytes(), &mask)).into_owned();
        let host_show = host_text.as_deref().map(show);
        let guest_show = show(&content);
        let risky = risky_keys(host_show.as_deref(), &guest_show);
        pending.push((rel.clone(), content));
        changes.push(ConfigChange {
            path: rel,
            host: host_show,
            guest: guest_show,
            sha256: sha,
            blocked,
            risky,
        });
    }
    let Some(accept) = accept else {
        return Ok(changes);
    };
    let mut written = vec![];
    for (path, sha) in accept {
        let c = changes
            .iter()
            .find(|c| c.path == path && c.sha256 == sha && c.blocked.is_none())
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidState,
                    format!("{path} changed in the pocket since it was shown"),
                )
                .hint("run `pocket config pull` again and review the new diff")
            })?;
        let content = &pending.iter().find(|(p, _)| p == &c.path).unwrap().1;
        let dest = home.join(&c.path);
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).map_err(|e| {
                err(
                    ErrorCode::Internal,
                    format!("create {}: {e}", dir.display()),
                )
            })?;
        }
        write_private(&dest, content.as_bytes()).map_err(|e| {
            err(
                ErrorCode::Internal,
                format!("write {}: {e}", dest.display()),
            )
        })?;
        tracing::info!("{}: config pull wrote {}", rec.info.name, dest.display());
        written.push(c.clone());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_and_restore_roundtrip() {
        let repl = vec![(
            "sk-ant-api03-REAL".to_string(),
            "sk-ant-api03-PH".to_string(),
        )];
        let host = r#"{"env":{"ANTHROPIC_API_KEY":"sk-ant-api03-REAL","GITHUB_TOKEN":"ghp_x"},"model":"opus"}"#;
        let g = String::from_utf8(strip("settings.json", host.as_bytes(), &repl)).unwrap();
        assert!(!g.contains("REAL") && !g.contains("ghp_x"), "{g}");
        assert!(g.contains(REDACTED));
        let edited = g.replace("opus", "sonnet");
        let back = vec![(
            "sk-ant-api03-PH".to_string(),
            "sk-ant-api03-REAL".to_string(),
        )];
        let r = restore(".claude/settings.json", &edited, Some(host), &back).unwrap();
        let v: serde_json::Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["env"]["GITHUB_TOKEN"], "ghp_x");
        assert_eq!(v["model"], "sonnet");
        let toml = "model = \"o3\"\nbearer_token = \"abc123\"\n";
        let gt = redact_toml(toml, &[]);
        assert!(!gt.contains("abc123"));
        assert_eq!(
            restore(".codex/config.toml", &gt, Some(toml), &[]).unwrap(),
            toml
        );
        assert!(restore(".codex/config.toml", &gt, None, &[]).is_err());
        assert_eq!(risky_keys(Some("{}"), "{\"hooks\": 1}"), vec!["hooks"]);
    }

    #[test]
    fn only_synced_paths() {
        assert!(synced(".claude/settings.json") && synced(".claude/commands/a/b.md"));
        for bad in [
            ".claude/.credentials.json",
            ".codex/auth.json",
            ".claude/../.ssh/id",
            "/etc/x",
            ".claude/projects/x",
        ] {
            assert!(!synced(bad), "{bad}");
        }
    }
}
