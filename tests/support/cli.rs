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
        // Never touch the user's keyring from tests. Snapshot templates and the warm pool
        // are opt-in (`with_templates`): a snapshot briefly writes all guest RAM to disk.
        let mut extra = vec![
            ("POCKET_SECRET_STORE".to_string(), "file".to_string()),
            ("POCKET_TEMPLATES".to_string(), "off".to_string()),
            ("POCKET_POOL_SIZE".to_string(), "0".to_string()),
        ];
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

    /// Enables snapshot templates and a warm pool of `pool` VMs.
    pub fn with_templates(mut self, pool: u32) -> Env {
        self.extra
            .retain(|(k, _)| k != "POCKET_TEMPLATES" && k != "POCKET_POOL_SIZE");
        self.extra
            .push(("POCKET_POOL_SIZE".into(), pool.to_string()));
        self
    }

    pub fn set(mut self, k: &str, v: &str) -> Env {
        self.extra.retain(|(key, _)| key != k);
        self.extra.push((k.into(), v.into()));
        self
    }

    /// Polls `pocket --json templates` until `ok` holds (templates build in the background).
    pub fn wait_templates(
        &self,
        what: &str,
        timeout: std::time::Duration,
        ok: impl Fn(&serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let o = self
                .cmd("pocket")
                .args(["--json", "templates"])
                .output()
                .unwrap();
            let v: serde_json::Value =
                serde_json::from_slice(&o.stdout).unwrap_or(serde_json::Value::Null);
            if ok(&v) {
                return v;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}: {v}\n{}",
                self.log()
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    pub fn cmd(&self, bin: &str) -> Command {
        let mut c = Command::new(bin_dir().join(bin));
        c.env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("HOME", self.root.join("home"))
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

    /// `pocket args` with `input` on stdin.
    pub fn pocket_stdin(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write;
        let mut c = self
            .cmd("pocket")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let o = c.wait_with_output().unwrap();
        eprintln!(
            "$ pocket {} <<< (stdin)\n{}{}[exit {:?}]",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
            o.status.code()
        );
        o
    }

    /// Cloud Hypervisor API socket of a running pocket.
    pub fn api_socket(&self, pocket: &str) -> PathBuf {
        let list = self.json(&["ls"]);
        let id = list
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == pocket)
            .and_then(|p| p["id"].as_str())
            .unwrap()
            .to_string();
        self.root
            .join("run/pocket/p")
            .join(&id[..12])
            .join("api.sock")
    }

    /// Guest memory snapshot (pause, snapshot to `dest`, resume); returns the memory file.
    pub fn memory_dump(&self, pocket: &str, dest: &Path) -> PathBuf {
        let sock = self.api_socket(pocket);
        let _ = std::fs::remove_dir_all(dest);
        std::fs::create_dir_all(dest).unwrap();
        let api = |call: &str, body: Option<String>| {
            let mut c = Command::new("curl");
            c.args(["-sS", "-f", "--unix-socket"]).arg(&sock).args([
                "-X",
                "PUT",
                &format!("http://localhost/api/v1/{call}"),
            ]);
            if let Some(b) = body {
                c.args(["-H", "Content-Type: application/json", "-d", &b]);
            }
            let o = c.output().unwrap();
            assert!(
                o.status.success(),
                "{call}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        };
        api("vm.pause", None);
        api(
            "vm.snapshot",
            Some(format!(
                r#"{{"destination_url":"file://{}"}}"#,
                dest.display()
            )),
        );
        api("vm.resume", None);
        let mem = dest.join("memory-ranges");
        assert!(mem.exists(), "no memory-ranges in {}", dest.display());
        mem
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
        // A daemon that refused us (e.g. the peer-credential test) is stopped by signal.
        let needle = format!("XDG_RUNTIME_DIR={}", self.root.join("run").display());
        let daemons = || {
            std::fs::read_dir("/proc")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .filter(|pid| {
                    // A rebuild during the run leaves the exe as "pocketd (deleted)".
                    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
                    let env = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
                    exe.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("pocketd"))
                        && env.split(|b| *b == 0).any(|v| v == needle.as_bytes())
                })
                .collect::<Vec<_>>()
        };
        for pid in daemons() {
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let left = daemons();
            if left.is_empty() {
                break;
            }
            if std::time::Instant::now() > deadline {
                for pid in left {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if std::thread::panicking() {
            eprintln!("--- pocketd.log\n{}", self.log());
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
