//! Host-side secret store (SECURITY.md §Secrets). Values live in the Secret Service
//! (through `secret-tool`, one item per secret) when one answers, else in an encrypted file
//! (`secrets.enc`, ChaCha20-Poly1305) whose key is a 0600 file next to it. Metadata (provider,
//! bindings) is in the state DB; values are never logged, never in RPC replies, and reach a
//! guest only as placeholders unless the user opts in to copying one.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use pocket_proto::rpc::{ErrorCode, SecretAdd, SecretInfo};

use crate::daemon::{R, err, now_ms, random_bytes};

const MAGIC: &[u8; 4] = b"PKS1";
pub const MAX_VALUE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// Secret Service items tagged with the data dir, so separate installs never mix.
    Keyring {
        tag: String,
    },
    File {
        dir: PathBuf,
    },
}

impl Backend {
    pub fn label(&self) -> &'static str {
        match self {
            Backend::Keyring { .. } => "keyring",
            Backend::File { .. } => "file",
        }
    }
}

/// `POCKET_SECRET_STORE=keyring|file`, default: the Secret Service when it answers.
pub fn choose_backend(data: &Path) -> Backend {
    let file = Backend::File {
        dir: data.to_path_buf(),
    };
    let keyring = Backend::Keyring {
        tag: data.to_string_lossy().into_owned(),
    };
    match std::env::var("POCKET_SECRET_STORE").as_deref() {
        Ok("file") => file,
        Ok("keyring") => keyring,
        _ if secret_service_available() => keyring,
        _ => file,
    }
}

fn secret_service_available() -> bool {
    Command::new("secret-tool")
        .args(["lookup", "service", "pocket", "probe", "probe"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .is_ok_and(|o| o.stderr.is_empty())
}

fn store_err(what: &str, e: impl std::fmt::Display) -> pocket_proto::rpc::RpcError {
    err(ErrorCode::HostSetup, format!("secret store: {what}: {e}"))
}

pub struct Vault {
    pub backend: Backend,
}

impl Vault {
    pub fn new(backend: Backend) -> Vault {
        Vault { backend }
    }

    pub fn get(&self, name: &str) -> R<Option<String>> {
        match &self.backend {
            Backend::Keyring { tag } => {
                let o = Command::new("secret-tool")
                    .args(["lookup", "service", "pocket", "store", tag, "secret", name])
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|e| store_err("run secret-tool", e))?;
                if !o.stderr.is_empty() {
                    return Err(store_err(
                        "secret-tool lookup",
                        String::from_utf8_lossy(&o.stderr).trim(),
                    ));
                }
                Ok((o.status.success() && !o.stdout.is_empty())
                    .then(|| String::from_utf8_lossy(&o.stdout).into_owned()))
            }
            Backend::File { dir } => Ok(read_file(dir)?.remove(name)),
        }
    }

    pub fn set(&self, name: &str, value: &str) -> R<()> {
        match &self.backend {
            Backend::Keyring { tag } => {
                let mut c = Command::new("secret-tool")
                    .args([
                        "store",
                        &format!("--label=pocket: {name}"),
                        "service",
                        "pocket",
                        "store",
                        tag,
                        "secret",
                        name,
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|e| store_err("run secret-tool", e))?;
                c.stdin
                    .take()
                    .unwrap()
                    .write_all(value.as_bytes())
                    .map_err(|e| store_err("secret-tool store", e))?;
                let o = c
                    .wait_with_output()
                    .map_err(|e| store_err("secret-tool store", e))?;
                if !o.status.success() {
                    return Err(store_err(
                        "secret-tool store",
                        String::from_utf8_lossy(&o.stderr).trim(),
                    ));
                }
                Ok(())
            }
            Backend::File { dir } => {
                let mut m = read_file(dir)?;
                m.insert(name.to_string(), value.to_string());
                write_file(dir, &m)
            }
        }
    }

    pub fn remove(&self, name: &str) -> R<()> {
        match &self.backend {
            Backend::Keyring { tag } => {
                let _ = Command::new("secret-tool")
                    .args(["clear", "service", "pocket", "store", tag, "secret", name])
                    .stdin(Stdio::null())
                    .output()
                    .map_err(|e| store_err("run secret-tool", e))?;
                Ok(())
            }
            Backend::File { dir } => {
                let mut m = read_file(dir)?;
                if m.remove(name).is_some() {
                    write_file(dir, &m)?;
                }
                Ok(())
            }
        }
    }
}

fn key(dir: &Path) -> R<[u8; 32]> {
    let p = dir.join("secrets.key");
    match std::fs::read(&p) {
        Ok(k) if k.len() == 32 => {
            let mode = std::fs::metadata(&p)
                .map(|m| m.permissions().mode())
                .unwrap_or(0);
            if mode & 0o077 != 0 {
                return Err(err(
                    ErrorCode::HostSetup,
                    format!("{} is readable by other users", p.display()),
                )
                .hint(format!("chmod 600 {}", p.display())));
            }
            Ok(k.try_into().unwrap())
        }
        Ok(_) => Err(
            err(ErrorCode::HostSetup, format!("{} is corrupt", p.display()))
                .hint("remove it and secrets.enc, then log in again"),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k: [u8; 32] = random_bytes(32).try_into().unwrap();
            write_private(&p, &k)?;
            Ok(k)
        }
        Err(e) => Err(store_err("read key", e)),
    }
}

fn write_private(p: &Path, data: &[u8]) -> R<()> {
    let tmp = p.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| store_err("write", e))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| store_err("write", e))?;
    std::fs::rename(&tmp, p).map_err(|e| store_err("write", e))
}

fn read_file(dir: &Path) -> R<BTreeMap<String, String>> {
    let p = dir.join("secrets.enc");
    let data = match std::fs::read(&p) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(store_err("read secrets.enc", e)),
    };
    if data.len() < 16 || &data[..4] != MAGIC {
        return Err(err(
            ErrorCode::HostSetup,
            format!("{} is not a pocket secret file", p.display()),
        ));
    }
    let k = key(dir)?;
    let plain = ChaCha20Poly1305::new(Key::from_slice(&k))
        .decrypt(Nonce::from_slice(&data[4..16]), &data[16..])
        .map_err(|_| {
            err(
                ErrorCode::HostSetup,
                format!("cannot decrypt {} (wrong secrets.key?)", p.display()),
            )
        })?;
    serde_json::from_slice(&plain).map_err(|e| store_err("parse secrets.enc", e))
}

fn write_file(dir: &Path, m: &BTreeMap<String, String>) -> R<()> {
    let k = key(dir)?;
    let nonce = random_bytes(12);
    let plain = serde_json::to_vec(m).unwrap();
    let ct = ChaCha20Poly1305::new(Key::from_slice(&k))
        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
        .map_err(|_| store_err("encrypt", "failed"))?;
    let mut out = MAGIC.to_vec();
    out.extend(nonce);
    out.extend(ct);
    write_private(&dir.join("secrets.enc"), &out)
}

/// `[a-z0-9][a-z0-9_-]{0,39}`.
pub fn valid_secret_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 40
        && n.as_bytes()[0].is_ascii_alphanumeric()
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub fn valid_env(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && !n.as_bytes()[0].is_ascii_digit()
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub const ANTHROPIC_HOSTS: &[&str] = &["api.anthropic.com"];
pub const OPENAI_HOSTS: &[&str] = &["api.openai.com"];
pub const CHATGPT_HOSTS: &[&str] = &["chatgpt.com", "auth.openai.com", "api.openai.com"];
pub const GITHUB_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "uploads.github.com",
    "codeload.github.com",
];

/// Provider and kind from what the value looks like.
pub fn guess(value: &str) -> (&'static str, &'static str) {
    let v = value.trim();
    if v.starts_with("sk-ant-oat") {
        ("anthropic", "oauth_token")
    } else if v.starts_with("sk-ant-") {
        ("anthropic", "api_key")
    } else if v.starts_with('{') && v.contains("\"tokens\"") {
        ("openai", "chatgpt")
    } else if v.starts_with("sk-") {
        ("openai", "api_key")
    } else if ["ghp_", "gho_", "ghu_", "ghs_", "github_pat_"]
        .iter()
        .any(|p| v.starts_with(p))
    {
        ("github", "token")
    } else {
        ("custom", "token")
    }
}

/// Default destinations and env vars per provider/kind.
pub fn defaults(provider: &str, kind: &str) -> (Vec<String>, Vec<String>) {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match (provider, kind) {
        ("anthropic", "oauth_token") => (s(ANTHROPIC_HOSTS), s(&["CLAUDE_CODE_OAUTH_TOKEN"])),
        ("anthropic", _) => (s(ANTHROPIC_HOSTS), s(&["ANTHROPIC_API_KEY"])),
        ("openai", "chatgpt") => (s(CHATGPT_HOSTS), vec![]),
        ("openai", _) => (s(OPENAI_HOSTS), s(&["OPENAI_API_KEY"])),
        ("github", _) => (s(GITHUB_HOSTS), s(&["GH_TOKEN", "GITHUB_TOKEN"])),
        _ => (vec![], vec![]),
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Bindings {
    kind: String,
    hosts: Vec<String>,
    env: Vec<String>,
    header: Option<String>,
    created_at: u64,
}

pub fn info_from_record(r: &pocket_store::SecretRecord) -> SecretInfo {
    let b: Bindings = serde_json::from_str(&r.bindings_json).unwrap_or_default();
    SecretInfo {
        name: r.name.clone(),
        provider: r.provider.clone(),
        kind: b.kind,
        hosts: b.hosts,
        env: b.env,
        header: b.header,
        storage: r.storage.clone(),
        created_at: b.created_at,
    }
}

pub fn record_from_info(i: &SecretInfo) -> pocket_store::SecretRecord {
    pocket_store::SecretRecord {
        name: i.name.clone(),
        provider: i.provider.clone(),
        bindings_json: serde_json::to_string(&Bindings {
            kind: i.kind.clone(),
            hosts: i.hosts.clone(),
            env: i.env.clone(),
            header: i.header.clone(),
            created_at: i.created_at,
        })
        .unwrap(),
        storage: i.storage.clone(),
    }
}

fn validate_hosts(hosts: &[String]) -> R<()> {
    for h in hosts {
        let r = pocket_net::policy::Rule::parse(h)
            .map_err(|e| err(ErrorCode::BadRequest, e.to_string()))?;
        if !matches!(
            r.pattern,
            pocket_net::policy::Pattern::Exact(_) | pocket_net::policy::Pattern::Subdomains(_)
        ) || r.port.is_some()
        {
            return Err(
                err(ErrorCode::BadRequest, format!("{h:?} is not a host name")).hint(
                    "bind secrets to `host` or `*.domain` (no ports, wildcards or addresses)",
                ),
            );
        }
    }
    Ok(())
}

pub fn validate_header(h: &Option<String>) -> R<()> {
    if let Some(h) = h {
        let ok = h.split_once(':').is_some_and(|(k, v)| {
            !k.trim().is_empty()
                && k.trim()
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && v.contains("{}")
        }) && !h.contains(['\r', '\n']);
        if !ok {
            return Err(
                err(ErrorCode::BadRequest, format!("bad header template {h:?}"))
                    .hint("use e.g. `X-Api-Key: {}` or `Authorization: Bearer {}`"),
            );
        }
    }
    Ok(())
}

/// Validated metadata for a new secret.
pub fn new_info(req: &SecretAdd, storage: &str) -> R<SecretInfo> {
    if !valid_secret_name(&req.name) {
        return Err(err(
            ErrorCode::BadRequest,
            format!("invalid secret name {:?}", req.name),
        )
        .hint("use 1–40 lowercase letters, digits, `-` and `_`"));
    }
    let value = req.value.trim();
    if value.is_empty() || value.len() > MAX_VALUE || value.contains('\0') {
        return Err(err(
            ErrorCode::BadRequest,
            "the secret value is empty or too large",
        ));
    }
    let (gp, gk) = guess(value);
    let provider = req.provider.clone().unwrap_or_else(|| gp.to_string());
    if !["anthropic", "openai", "github", "custom"].contains(&provider.as_str()) {
        return Err(err(
            ErrorCode::BadRequest,
            format!("unknown provider {provider:?}"),
        )
        .hint("use anthropic, openai, github or custom"));
    }
    let kind = req.kind.clone().unwrap_or_else(|| {
        if provider == gp {
            gk.to_string()
        } else {
            "token".to_string()
        }
    });
    if kind == "chatgpt" {
        crate::inject::ChatGpt::parse(value)?;
    } else if value.contains(char::is_whitespace) {
        return Err(err(
            ErrorCode::BadRequest,
            "the secret value contains whitespace",
        )
        .hint("paste only the key or token"));
    }
    let (dh, de) = defaults(&provider, &kind);
    let hosts = if req.hosts.is_empty() {
        dh
    } else {
        req.hosts.clone()
    };
    let env = if req.env.is_empty() {
        de
    } else {
        req.env.clone()
    };
    validate_hosts(&hosts)?;
    if let Some(e) = env.iter().find(|e| !valid_env(e)) {
        return Err(err(
            ErrorCode::BadRequest,
            format!("invalid environment variable name {e:?}"),
        ));
    }
    validate_header(&req.header)?;
    if hosts.is_empty() {
        return Err(err(
            ErrorCode::BadRequest,
            format!("secret {} has no destination", req.name),
        )
        .hint("pass --host HOST: a secret is only ever sent to the hosts it is bound to"));
    }
    Ok(SecretInfo {
        name: req.name.clone(),
        provider,
        kind,
        hosts,
        env,
        header: req.header.clone(),
        storage: storage.to_string(),
        created_at: now_ms(),
    })
}

pub fn bind(
    info: &mut SecretInfo,
    hosts: &[String],
    env: &[String],
    header: &Option<String>,
) -> R<()> {
    validate_hosts(hosts)?;
    if let Some(e) = env.iter().find(|e| !valid_env(e)) {
        return Err(err(
            ErrorCode::BadRequest,
            format!("invalid environment variable name {e:?}"),
        ));
    }
    validate_header(header)?;
    for h in hosts {
        let h = pocket_net::policy::normalize_host(h);
        if !info.hosts.contains(&h) {
            info.hosts.push(h);
        }
    }
    for e in env {
        if !info.env.contains(e) {
            info.env.push(e.clone());
        }
    }
    if header.is_some() {
        info.header = header.clone();
    }
    Ok(())
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn random_alnum(n: usize) -> String {
    random_bytes(n)
        .into_iter()
        .map(|b| ALNUM[b as usize % ALNUM.len()] as char)
        .collect()
}

/// A stand-in with the real value's shape (known prefix, length, separators) so clients
/// that validate formats accept it; useless anywhere but through the pocket proxy.
pub fn placeholder(real: &str) -> String {
    const PREFIXES: &[&str] = &[
        "sk-ant-oat01-",
        "sk-ant-api03-",
        "sk-ant-",
        "sk-proj-",
        "sk-svcacct-",
        "sk-",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
    ];
    let prefix = PREFIXES
        .iter()
        .find(|p| real.starts_with(**p))
        .copied()
        .unwrap_or("pocket-");
    let len = real.len().max(prefix.len() + 32);
    loop {
        let rnd = random_alnum(len);
        let mut out = String::from(prefix);
        for (i, c) in rnd.chars().enumerate().skip(prefix.len()) {
            match real.as_bytes().get(i) {
                Some(&b) if !b.is_ascii_alphanumeric() && b.is_ascii_graphic() => {
                    out.push(b as char)
                }
                _ => out.push(c),
            }
        }
        if out != real {
            return out;
        }
    }
}

impl crate::daemon::Daemon {
    fn secret_info(&self, name: &str) -> R<SecretInfo> {
        self.db(|s| s.secrets())?
            .iter()
            .find(|r| r.name == name)
            .map(info_from_record)
            .ok_or_else(|| {
                err(ErrorCode::NotFound, format!("no secret named {name:?}"))
                    .hint("`pocket secrets ls` lists secrets")
            })
    }

    /// Running pockets pick up a changed value or binding at once (their placeholders stay).
    fn refresh_live_secret(&self, name: &str, info: Option<&SecretInfo>, value: Option<&str>) {
        for live in self.all_live() {
            let mut items = live.hooks.items.write().unwrap();
            match info {
                None => items.retain(|i| i.info.name != name),
                Some(info) => {
                    for it in items.iter_mut().filter(|i| i.info.name == name) {
                        it.info = info.clone();
                        if let Some(v) = value {
                            it.real = v.to_string();
                            if info.kind == "chatgpt" {
                                it.chat = crate::inject::ChatGpt::parse(v).ok();
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn secret_add(&self, a: SecretAdd) -> R<SecretInfo> {
        let mut info = new_info(&a, self.vault.backend.label())?;
        if let Ok(old) = self.secret_info(&a.name)
            && a.hosts.is_empty()
            && a.env.is_empty()
            && old.provider == info.provider
            && old.kind == info.kind
        {
            info.hosts = old.hosts;
            info.env = old.env;
            info.header = info.header.or(old.header);
        }
        let value = a.value.trim();
        self.vault.set(&info.name, value)?;
        self.db(|s| s.put_secret(&record_from_info(&info)))?;
        self.refresh_live_secret(&info.name, Some(&info), Some(value));
        tracing::info!(
            "secret {} stored ({}, {})",
            info.name,
            info.provider,
            info.storage
        );
        Ok(info)
    }

    pub fn secret_remove(&self, name: &str) -> R<()> {
        self.secret_info(name)?;
        self.vault.remove(name)?;
        self.db(|s| s.delete_secret(name))?;
        self.refresh_live_secret(name, None, None);
        Ok(())
    }

    pub fn secret_bind(
        &self,
        name: &str,
        hosts: &[String],
        env: &[String],
        header: &Option<String>,
    ) -> R<SecretInfo> {
        let mut info = self.secret_info(name)?;
        bind(&mut info, hosts, env, header)?;
        self.db(|s| s.put_secret(&record_from_info(&info)))?;
        self.refresh_live_secret(name, Some(&info), None);
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_backend_roundtrip_is_encrypted_and_private() {
        let d = std::env::temp_dir().join(format!("pocket-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let v = Vault::new(Backend::File { dir: d.clone() });
        assert_eq!(v.get("a").unwrap(), None);
        v.set("a", "sk-ant-api03-SECRETVALUE").unwrap();
        v.set("b", "two").unwrap();
        assert_eq!(
            v.get("a").unwrap().as_deref(),
            Some("sk-ant-api03-SECRETVALUE")
        );
        let raw = std::fs::read(d.join("secrets.enc")).unwrap();
        assert!(!raw.windows(11).any(|w| w == b"SECRETVALUE"));
        for f in ["secrets.enc", "secrets.key"] {
            let m = std::fs::metadata(d.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600, "{f}");
        }
        v.remove("a").unwrap();
        assert_eq!(v.get("a").unwrap(), None);
        assert_eq!(v.get("b").unwrap().as_deref(), Some("two"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn placeholders_keep_shape_not_value() {
        for real in [
            "sk-ant-api03-abcDEF123_xyz-0000",
            "ghp_0123456789abcdef0123456789abcdef0123",
            "plain",
        ] {
            let p = placeholder(real);
            assert_ne!(p, real);
            assert!(p.len() >= real.len());
            assert!(!p.contains(&real[real.len().min(10)..]) || real.len() <= 10);
        }
        assert!(placeholder("sk-ant-oat01-xyz").starts_with("sk-ant-oat01-"));
        assert_eq!(guess("sk-ant-oat01-x"), ("anthropic", "oauth_token"));
        assert_eq!(guess("github_pat_x"), ("github", "token"));
    }
}
