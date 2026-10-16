//! `pocket.toml` (CONTRACTS.md §5): parsing with strict validation and "did you mean" hints,
//! applying it to `pocket new`, `pocket init` project detection, and "allow for project".

use std::path::{Path, PathBuf};

use pocket_proto::rpc::{NewPocket, Request, Response, Setup};
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, Item, Value};

use crate::client::Client;
use crate::error::{CliError, Result};

pub const FILE: &str = "pocket.toml";

/// Known keys per table (`""` = top level).
const SCHEMA: &[(&str, &[&str])] = &[
    (
        "",
        &[
            "version", "sandbox", "agents", "network", "secrets", "git", "ports", "idle",
        ],
    ),
    (
        "sandbox",
        &[
            "preset",
            "image",
            "cpus",
            "memory",
            "disk",
            "setup",
            "setup_inputs",
            "env",
            "default_session",
        ],
    ),
    ("agents", &["install", "sync_config"]),
    ("network", &["profile", "allow", "deny", "allow_host_ports"]),
    ("secrets", &["inject"]),
    (
        "git",
        &["branch_prefix", "protected", "allow_push", "ssh_agent"],
    ),
    ("ports", &["auto_forward", "forward"]),
    ("idle", &["pause_after", "hibernate_after"]),
];

fn lev(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push(
                (prev[j] + usize::from(ca != *cb))
                    .min(prev[j + 1] + 1)
                    .min(cur[j] + 1),
            );
        }
        prev = cur;
    }
    prev[b.len()]
}

fn suggest(key: &str, known: &[&str]) -> Option<String> {
    known
        .iter()
        .map(|k| (lev(key, k), *k))
        .filter(|(d, k)| *d <= 2.max(k.len() / 3))
        .min()
        .map(|(_, k)| k.to_string())
}

fn bad(path: &Path, msg: impl Into<String>) -> CliError {
    CliError::new(
        "bad_request",
        2,
        format!("{}: {}", path.display(), msg.into()),
    )
}

/// The validated project config.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Project {
    pub preset: Option<String>,
    pub cpus: Option<u8>,
    pub memory: Option<String>,
    pub disk: Option<String>,
    pub setup: Option<String>,
    pub setup_inputs: Vec<String>,
    pub env: Vec<(String, String)>,
    pub default_session: Option<String>,
    pub sync_config: Option<bool>,
    pub profile: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub inject: Option<Vec<String>>,
    pub protected: Vec<String>,
    pub allow_push: Vec<String>,
    pub ssh_agent: Option<bool>,
    pub auto_forward: Option<bool>,
    pub forward: Vec<(u16, u16)>,
    pub notes: Vec<String>,
}

fn strings(path: &Path, key: &str, v: &Item) -> Result<Vec<String>> {
    let arr = v
        .as_array()
        .ok_or_else(|| bad(path, format!("`{key}` must be an array of strings")))?;
    arr.iter()
        .map(|x| {
            x.as_str()
                .map(String::from)
                .ok_or_else(|| bad(path, format!("`{key}` must be an array of strings")))
        })
        .collect()
}

fn string(path: &Path, key: &str, v: &Item) -> Result<String> {
    v.as_str()
        .map(String::from)
        .ok_or_else(|| bad(path, format!("`{key}` must be a string")))
}

fn boolean(path: &Path, key: &str, v: &Item) -> Result<bool> {
    v.as_bool()
        .ok_or_else(|| bad(path, format!("`{key}` must be true or false")))
}

pub fn parse(path: &Path, text: &str) -> Result<Project> {
    let doc: DocumentMut = text
        .parse()
        .map_err(|e: toml_edit::TomlError| bad(path, format!("invalid TOML: {}", e.message())))?;
    for (k, v) in doc.iter() {
        let known = SCHEMA[0].1;
        if !known.contains(&k) {
            let mut e = bad(path, format!("unknown key `{k}`"));
            if let Some(s) = suggest(k, known) {
                e = e.hint(format!("did you mean `{s}`?"));
            }
            return Err(e);
        }
        if k != "version" {
            let table = v
                .as_table_like()
                .ok_or_else(|| bad(path, format!("`{k}` must be a table ([{k}])")))?;
            let keys = SCHEMA.iter().find(|(t, _)| *t == k).unwrap().1;
            for (sk, _) in table.iter() {
                if !keys.contains(&sk) {
                    let mut e = bad(path, format!("unknown key `{k}.{sk}`"));
                    if let Some(s) = suggest(sk, keys) {
                        e = e.hint(format!("did you mean `{k}.{s}`?"));
                    } else {
                        e = e.hint(format!("[{k}] accepts: {}", keys.join(", ")));
                    }
                    return Err(e);
                }
            }
        }
    }
    match doc.get("version").and_then(|v| v.as_integer()) {
        Some(1) => {}
        Some(n) => {
            return Err(bad(
                path,
                format!("version {n} is newer than this pocket understands"),
            )
            .hint("upgrade pocket"));
        }
        None => return Err(bad(path, "missing `version = 1`")),
    }
    let mut p = Project::default();
    let get = |t: &str, k: &str| doc.get(t).and_then(|t| t.get(k));
    if let Some(v) = get("sandbox", "preset") {
        p.preset = Some(string(path, "sandbox.preset", v)?);
    }
    if let Some(v) = get("sandbox", "image") {
        let img = string(path, "sandbox.image", v)?;
        return Err(
            bad(path, format!("sandbox.image ({img}) is not supported yet"))
                .hint("use `preset = \"base\"` and install extras in `sandbox.setup`"),
        );
    }
    if let Some(v) = get("sandbox", "cpus") {
        let n = v.as_integer().filter(|n| (1..=64).contains(n));
        p.cpus = Some(n.ok_or_else(|| bad(path, "`sandbox.cpus` must be 1–64"))? as u8);
    }
    if let Some(v) = get("sandbox", "memory") {
        p.memory = Some(string(path, "sandbox.memory", v)?);
    }
    if let Some(v) = get("sandbox", "disk") {
        p.disk = Some(string(path, "sandbox.disk", v)?);
    }
    if let Some(v) = get("sandbox", "setup") {
        p.setup = Some(string(path, "sandbox.setup", v)?);
    }
    if let Some(v) = get("sandbox", "setup_inputs") {
        p.setup_inputs = strings(path, "sandbox.setup_inputs", v)?;
        for i in &p.setup_inputs {
            if i.starts_with('/') || i.split('/').any(|c| c == "..") {
                return Err(bad(
                    path,
                    format!("setup input {i:?} must be inside the project"),
                ));
            }
        }
    }
    if let Some(v) = get("sandbox", "env") {
        let t = v
            .as_table_like()
            .ok_or_else(|| bad(path, "`sandbox.env` must be a table of strings"))?;
        for (k, v) in t.iter() {
            p.env
                .push((k.to_string(), string(path, &format!("sandbox.env.{k}"), v)?));
        }
    }
    if let Some(v) = get("sandbox", "default_session") {
        p.default_session = Some(string(path, "sandbox.default_session", v)?);
    }
    if let Some(v) = get("agents", "sync_config") {
        p.sync_config = Some(!strings(path, "agents.sync_config", v)?.is_empty());
    }
    if get("agents", "install").is_some() {
        p.notes
            .push("agents.install: the base image already carries every supported agent".into());
    }
    if let Some(v) = get("network", "profile") {
        let prof = string(path, "network.profile", v)?;
        if !["dev", "strict", "offline", "full"].contains(&prof.as_str()) {
            let mut e = bad(path, format!("unknown network profile {prof:?}"));
            if let Some(s) = suggest(&prof, &["dev", "strict", "offline", "full"]) {
                e = e.hint(format!("did you mean `{s}`?"));
            }
            return Err(e);
        }
        p.profile = Some(prof);
    }
    if let Some(v) = get("network", "allow") {
        p.allow = strings(path, "network.allow", v)?;
    }
    if let Some(v) = get("network", "deny") {
        p.deny = strings(path, "network.deny", v)?;
    }
    if get("network", "allow_host_ports").is_some() {
        p.notes.push(
            "network.allow_host_ports is not supported yet; host services stay unreachable".into(),
        );
    }
    if let Some(v) = get("secrets", "inject") {
        p.inject = Some(strings(path, "secrets.inject", v)?);
    }
    if let Some(v) = get("git", "protected") {
        p.protected = strings(path, "git.protected", v)?;
    }
    if let Some(v) = get("git", "allow_push") {
        p.allow_push = strings(path, "git.allow_push", v)?;
    }
    if let Some(v) = get("git", "ssh_agent") {
        p.ssh_agent = Some(boolean(path, "git.ssh_agent", v)?);
    }
    if let Some(v) = get("git", "branch_prefix")
        && string(path, "git.branch_prefix", v)? != "pocket/"
    {
        p.notes
            .push("git.branch_prefix: only \"pocket/\" is supported for now".into());
    }
    if let Some(v) = get("ports", "auto_forward") {
        p.auto_forward = Some(boolean(path, "ports.auto_forward", v)?);
    }
    if let Some(v) = get("ports", "forward") {
        let arr = v.as_array().ok_or_else(|| {
            bad(
                path,
                "`ports.forward` must be an array of { guest, host } tables",
            )
        })?;
        for f in arr.iter() {
            let t = f.as_inline_table().ok_or_else(|| {
                bad(
                    path,
                    "`ports.forward` entries look like { guest = 5173, host = 5173 }",
                )
            })?;
            for k in t.iter().map(|(k, _)| k) {
                if k != "guest" && k != "host" {
                    let mut e = bad(path, format!("unknown key `ports.forward.{k}`"));
                    if let Some(s) = suggest(k, &["guest", "host"]) {
                        e = e.hint(format!("did you mean `{s}`?"));
                    }
                    return Err(e);
                }
            }
            let port = |k: &str| -> Result<u16> {
                t.get(k)
                    .and_then(Value::as_integer)
                    .filter(|n| (1..=65535).contains(n))
                    .map(|n| n as u16)
                    .ok_or_else(|| bad(path, format!("`ports.forward` needs a valid `{k}` port")))
            };
            let g = port("guest")?;
            let h = t.get("host").map_or(Ok(g), |_| port("host"))?;
            p.forward.push((g, h));
        }
    }
    if doc.get("idle").is_some() {
        p.notes
            .push("[idle] takes effect with pause/hibernate support (M9)".into());
    }
    Ok(p)
}

pub fn load(repo: &Path) -> Result<Option<(PathBuf, Project)>> {
    let path = repo.join(FILE);
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(Some((path.clone(), parse(&path, &t)?))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::io(&path.display().to_string(), e)),
    }
}

/// Fills unset fields of `req` (CLI flags win) from the project config.
pub fn apply(p: &Project, repo: &Path, req: &mut NewPocket, flags_secrets: bool) -> Result<()> {
    if req.preset.is_none() {
        req.preset = p.preset.clone();
    }
    if req.cpus.is_none() {
        req.cpus = p.cpus;
    }
    if req.memory_mib.is_none()
        && let Some(m) = &p.memory
    {
        req.memory_mib = Some(crate::parse_size_mib(m)? as u32);
    }
    if req.disk_mib.is_none()
        && let Some(d) = &p.disk
    {
        req.disk_mib = Some(crate::parse_size_mib(d)?);
    }
    if req.net_profile.is_none() {
        req.net_profile = p.profile.clone();
    }
    req.allow.extend(p.allow.iter().cloned());
    req.deny.extend(p.deny.iter().cloned());
    if !flags_secrets && p.inject.is_some() {
        req.secrets = p.inject.clone();
    }
    req.git_protected = p.protected.clone();
    req.git_allow_push = p.allow_push.clone();
    if let Some(a) = p.ssh_agent {
        req.ssh_agent |= a;
    }
    if p.auto_forward == Some(false) {
        req.auto_forward = false;
    }
    req.forward.extend(p.forward.iter().copied());
    let mut env = p.env.clone();
    env.append(&mut req.env);
    req.env = env;
    if p.sync_config == Some(false) {
        req.sync_config = false;
    }
    if req.command.is_none()
        && let Some(s) = &p.default_session
        && s != "shell"
    {
        req.command = Some(vec![s.clone()]);
    }
    if let Some(cmd) = &p.setup {
        let mut inputs = vec![];
        for i in &p.setup_inputs {
            // The pocket clones HEAD (plus the working tree with --carry): hash what it gets.
            let committed = (!req.carry_changes)
                .then(|| {
                    std::process::Command::new("git")
                        .args(["-c", "core.fsmonitor=false", "-C"])
                        .arg(repo)
                        .args(["show", &format!("HEAD:{i}")])
                        .stdin(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .output()
                        .ok()
                        .filter(|o| o.status.success())
                        .map(|o| o.stdout)
                })
                .flatten();
            let data = committed
                .map(Ok)
                .unwrap_or_else(|| std::fs::read(repo.join(i)))
                .map_err(|e| {
                    CliError::io(&format!("setup input {i}"), e)
                        .hint("list files that exist in the repository under sandbox.setup_inputs")
                })?;
            let h = Sha256::digest(&data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            inputs.push((i.clone(), h));
        }
        req.setup = Some(Setup {
            command: cmd.clone(),
            inputs,
        });
    }
    Ok(())
}

/// A starter `pocket.toml` for what the repository looks like.
pub fn detect(repo: &Path) -> (String, Vec<&'static str>) {
    let has = |f: &str| repo.join(f).exists();
    let mut found = vec![];
    let (setup, inputs): (Option<&str>, Vec<&str>) = if has("package.json") {
        found.push("Node.js");
        if has("pnpm-lock.yaml") {
            (
                Some("pnpm install --frozen-lockfile"),
                vec!["pnpm-lock.yaml"],
            )
        } else if has("yarn.lock") {
            (Some("yarn install --frozen-lockfile"), vec!["yarn.lock"])
        } else if has("bun.lockb") || has("bun.lock") {
            (
                Some("bun install"),
                vec![if has("bun.lock") {
                    "bun.lock"
                } else {
                    "bun.lockb"
                }],
            )
        } else if has("package-lock.json") {
            (Some("npm ci"), vec!["package-lock.json"])
        } else {
            (Some("npm install"), vec!["package.json"])
        }
    } else if has("Cargo.toml") {
        found.push("Rust");
        (
            Some("cargo fetch"),
            if has("Cargo.lock") {
                vec!["Cargo.lock"]
            } else {
                vec!["Cargo.toml"]
            },
        )
    } else if has("uv.lock") {
        found.push("Python (uv)");
        (Some("uv sync"), vec!["uv.lock"])
    } else if has("requirements.txt") {
        found.push("Python");
        (
            Some("python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"),
            vec!["requirements.txt"],
        )
    } else if has("go.mod") {
        found.push("Go");
        (
            Some("go mod download"),
            if has("go.sum") {
                vec!["go.sum"]
            } else {
                vec!["go.mod"]
            },
        )
    } else if has("Gemfile") {
        found.push("Ruby");
        (
            Some("bundle install"),
            if has("Gemfile.lock") {
                vec!["Gemfile.lock"]
            } else {
                vec!["Gemfile"]
            },
        )
    } else {
        (None, vec![])
    };
    let mut t = String::from(
        "# pocket project config — https://github.com/Spandan7724/pocket\nversion = 1\n\n[sandbox]\npreset = \"base\"\n",
    );
    match setup {
        Some(s) => {
            t.push_str(&format!(
                "# Runs once per change of the inputs and is baked into a template for every new pocket.\nsetup = {:?}\nsetup_inputs = [{}]\n",
                s,
                inputs.iter().map(|i| format!("{i:?}")).collect::<Vec<_>>().join(", ")
            ));
        }
        None => t.push_str("# setup = \"make deps\"\n# setup_inputs = [\"Makefile\"]\n"),
    }
    t.push_str(
        "\n[network]\nprofile = \"dev\"\nallow = []\n\n[git]\nprotected = [\"main\", \"master\", \"release/*\"]\nallow_push = [\"pocket/*\"]\n\n[ports]\nauto_forward = true\n",
    );
    (t, found)
}

/// Adds hosts to `network.allow` in the pocket's project `pocket.toml` (created if needed),
/// keeping the rest of the file as written.
pub fn allow_in_project(c: &mut Client, pocket: &str, hosts: &[String]) -> Result<PathBuf> {
    let Response::Pockets(list) = c.request(Request::List)? else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    let repo = list
        .into_iter()
        .find(|p| p.name == pocket)
        .and_then(|p| p.repo_path)
        .ok_or_else(|| CliError::usage(format!("{pocket} has no project repository")))?;
    let path = repo.join(FILE);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| "version = 1\n".into());
    parse(&path, &text)?;
    let mut doc: DocumentMut = text.parse().map_err(|_| bad(&path, "invalid TOML"))?;
    if doc.get("network").is_none() {
        doc["network"] = toml_edit::table();
    }
    if doc["network"].get("allow").is_none() {
        doc["network"]["allow"] = toml_edit::value(toml_edit::Array::new());
    }
    let arr = doc["network"]["allow"]
        .as_array_mut()
        .ok_or_else(|| bad(&path, "`network.allow` must be an array"))?;
    for h in hosts {
        if !arr.iter().any(|v| v.as_str() == Some(h)) {
            arr.push(h.as_str());
        }
    }
    std::fs::write(&path, doc.to_string())
        .map_err(|e| CliError::io(&path.display().to_string(), e))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(t: &str) -> std::result::Result<Project, (String, Option<String>)> {
        parse(Path::new("pocket.toml"), t).map_err(|e| (e.message.clone(), e.hint.clone()))
    }

    #[test]
    fn schema_and_hints() {
        let ok = p(r#"version = 1
[sandbox]
preset = "base"
cpus = 4
memory = "4G"
setup = "npm ci"
setup_inputs = ["package-lock.json"]
env = { NODE_ENV = "development" }
[network]
profile = "strict"
allow = ["registry.npmjs.org"]
[git]
protected = ["main"]
[ports]
forward = [{ guest = 5173, host = 5174 }]
"#)
        .unwrap();
        assert_eq!(ok.cpus, Some(4));
        assert_eq!(ok.forward, vec![(5173, 5174)]);
        assert_eq!(ok.env, vec![("NODE_ENV".into(), "development".into())]);
        let e = p("version = 1\n[sandbox]\nprest = \"base\"\n").unwrap_err();
        assert!(e.0.contains("unknown key `sandbox.prest`"));
        assert_eq!(e.1.as_deref(), Some("did you mean `sandbox.preset`?"));
        let e = p("version = 1\n[netwrok]\n").unwrap_err();
        assert_eq!(e.1.as_deref(), Some("did you mean `network`?"));
        let e = p("version = 1\n[network]\nprofile = \"strikt\"\n").unwrap_err();
        assert_eq!(e.1.as_deref(), Some("did you mean `strict`?"));
        assert!(
            p("[sandbox]\n")
                .unwrap_err()
                .0
                .contains("missing `version = 1`")
        );
        assert!(p("version = 2\n").unwrap_err().0.contains("newer"));
        assert!(p("version = 1\n[sandbox]\ncpus = \"two\"\n").is_err());
        assert!(
            p("version = 1\n[ports]\nforward = [{ guest = 1, hots = 2 }]\n")
                .unwrap_err()
                .1
                .unwrap()
                .contains("host")
        );
        assert!(p("version = 1\n[sandbox]\nsetup_inputs = [\"../x\"]\n").is_err());
    }

    #[test]
    fn detection() {
        let d = std::env::temp_dir().join(format!("pocket-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("package.json"), "{}").unwrap();
        std::fs::write(d.join("package-lock.json"), "{}").unwrap();
        let (t, found) = detect(&d);
        assert_eq!(found, ["Node.js"]);
        let parsed = parse(Path::new("x"), &t).unwrap();
        assert_eq!(parsed.setup.as_deref(), Some("npm ci"));
        assert_eq!(parsed.setup_inputs, ["package-lock.json"]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
