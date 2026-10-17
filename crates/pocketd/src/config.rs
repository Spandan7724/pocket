//! Daemon-side settings from `~/.config/pocket/config.toml` (`[pool]`, `[idle]`), with
//! environment overrides (`POCKET_POOL_SIZE`, `POCKET_POOL_MAX_MEMORY`, `POCKET_IDLE_PAUSE`,
//! `POCKET_IDLE_HIBERNATE`, `POCKET_IDLE_TICK`; the tick also drives session-state notifications).

use pocket_proto::rpc::parse_duration_ms;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub pool_enabled: bool,
    pub pool_size: u32,
    pub pool_max_memory_mib: u64,
    /// 0 = never.
    pub idle_pause_ms: u64,
    pub idle_hibernate_ms: u64,
    pub idle_tick_ms: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            pool_enabled: true,
            pool_size: 2,
            pool_max_memory_mib: 8 << 10,
            idle_pause_ms: 30 * 60_000,
            idle_hibernate_ms: 2 * 3_600_000,
            idle_tick_ms: 2_000,
        }
    }
}

/// `8G`, `512M`, `1024` (MiB).
fn parse_mib(s: &str) -> Option<u64> {
    let s = s.trim();
    let (n, mul) = match s.as_bytes().last()? {
        b'G' | b'g' => (&s[..s.len() - 1], 1024),
        b'M' | b'm' => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    n.parse::<u64>().ok()?.checked_mul(mul)
}

impl DaemonConfig {
    pub fn load() -> DaemonConfig {
        let mut c = DaemonConfig::default();
        let dir = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                    .join(".config")
            });
        let path = dir.join("pocket/config.toml");
        if let Ok(text) = std::fs::read_to_string(&path) {
            match text.parse::<toml_edit::DocumentMut>() {
                Ok(doc) => c.apply_toml(&doc),
                Err(e) => tracing::warn!("{}: {e}; using defaults", path.display()),
            }
        }
        c.apply_env(|k| std::env::var(k).ok());
        c
    }

    fn apply_toml(&mut self, doc: &toml_edit::DocumentMut) {
        let get = |t: &str, k: &str| doc.get(t).and_then(|t| t.get(k)).cloned();
        if let Some(v) = get("pool", "enabled").and_then(|v| v.as_bool()) {
            self.pool_enabled = v;
        }
        if let Some(v) = get("pool", "size").and_then(|v| v.as_integer()) {
            self.pool_size = v.clamp(0, 16) as u32;
        }
        if let Some(v) =
            get("pool", "max_total_memory").and_then(|v| v.as_str().and_then(parse_mib))
        {
            self.pool_max_memory_mib = v;
        }
        if let Some(v) =
            get("idle", "pause_after").and_then(|v| v.as_str().and_then(parse_duration_ms))
        {
            self.idle_pause_ms = v;
        }
        if let Some(v) =
            get("idle", "hibernate_after").and_then(|v| v.as_str().and_then(parse_duration_ms))
        {
            self.idle_hibernate_ms = v;
        }
    }

    fn apply_env(&mut self, var: impl Fn(&str) -> Option<String>) {
        if let Some(n) = var("POCKET_POOL_SIZE").and_then(|v| v.parse::<u32>().ok()) {
            self.pool_size = n.min(16);
            self.pool_enabled = n > 0;
        }
        if let Some(m) = var("POCKET_POOL_MAX_MEMORY").and_then(|v| parse_mib(&v)) {
            self.pool_max_memory_mib = m;
        }
        if let Some(ms) = var("POCKET_IDLE_PAUSE").and_then(|v| parse_duration_ms(&v)) {
            self.idle_pause_ms = ms;
        }
        if let Some(ms) = var("POCKET_IDLE_HIBERNATE").and_then(|v| parse_duration_ms(&v)) {
            self.idle_hibernate_ms = ms;
        }
        if let Some(ms) = var("POCKET_IDLE_TICK").and_then(|v| parse_duration_ms(&v)) {
            self.idle_tick_ms = ms.max(100);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_then_env() {
        let mut c = DaemonConfig::default();
        let doc: toml_edit::DocumentMut =
            "[pool]\nsize = 3\nmax_total_memory = \"4G\"\n[idle]\npause_after = \"10m\"\nhibernate_after = \"never\"\n"
                .parse()
                .unwrap();
        c.apply_toml(&doc);
        assert_eq!((c.pool_size, c.pool_max_memory_mib), (3, 4096));
        assert_eq!((c.idle_pause_ms, c.idle_hibernate_ms), (600_000, 0));
        c.apply_env(|k| (k == "POCKET_POOL_SIZE").then(|| "0".to_string()));
        assert!(!c.pool_enabled);
        assert_eq!(parse_duration_ms("500ms"), Some(500));
        assert_eq!(parse_duration_ms("2x"), None);
    }
}
