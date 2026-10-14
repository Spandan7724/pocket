//! Drives the real `pocket` / `pocketd` binaries in an isolated environment (own XDG dirs,
//! own daemon). Dropping the env removes every pocket and stops the daemon.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

pub fn bin_dir() -> PathBuf {
    std::env::var_os("POCKET_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/debug"))
}

pub struct Env {
    pub root: PathBuf,
    pub assets: PathBuf,
    pub extra: Vec<(String, String)>,
}

impl Env {
    pub fn new(tag: &str, assets: &Path) -> Env {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "pkc-{}-{}-{tag}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["config", "data", "state", "cache", "run", "home"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.join("run"), std::fs::Permissions::from_mode(0o700)).unwrap();
        for b in ["pocket", "pocketd"] {
            assert!(
                bin_dir().join(b).exists(),
                "{} missing; run `cargo build -p pocket-cli -p pocketd`",
                bin_dir().join(b).display()
            );
        }
        let mut extra = vec![];
        if let Some(c) = std::env::var_os("POCKET_PRESET_CACHE") {
            extra.push((
                "POCKET_PRESET_CACHE".into(),
                c.to_string_lossy().into_owned(),
            ));
        } else {
            extra.push((
                "POCKET_PRESET_CACHE".into(),
                assets.join("presets").to_string_lossy().into_owned(),
            ));
        }
        Env {
            root,
            assets: assets.to_path_buf(),
            extra,
        }
    }

    pub fn cmd(&self, bin: &str) -> Command {
        let mut c = Command::new(bin_dir().join(bin));
        c.env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("POCKET_ASSETS_DIR", &self.assets)
            .env("POCKETD", bin_dir().join("pocketd"))
            .env_remove("TERM");
        for (k, v) in &self.extra {
            c.env(k, v);
        }
        c
    }

    pub fn pocket(&self, args: &[&str]) -> Output {
        let o = self
            .cmd("pocket")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        eprintln!(
            "$ pocket {}\n{}{}[exit {:?}]",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
            o.status.code()
        );
        o
    }

    /// Runs `pocket args`, asserting success; returns stdout.
    pub fn ok(&self, args: &[&str]) -> String {
        let o = self.pocket(args);
        assert!(o.status.success(), "pocket {args:?} failed");
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    pub fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut a = vec!["--json"];
        a.extend_from_slice(args);
        serde_json::from_str(&self.ok(&a)).unwrap()
    }

    pub fn socket(&self) -> PathBuf {
        self.root.join("run/pocket/pocketd.sock")
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.root.join("state/pocket/pocketd.log")).unwrap_or_default()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if self.socket().exists() {
            let list = self
                .cmd("pocket")
                .args(["--json", "ls"])
                .output()
                .ok()
                .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok());
            for p in list
                .as_ref()
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(n) = p["name"].as_str() {
                    let _ = self.cmd("pocket").args(["rm", "-f", n]).output();
                }
            }
            let _ = self.cmd("pocket").args(["daemon", "stop"]).output();
        }
        if std::thread::panicking() {
            eprintln!("--- pocketd.log\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
