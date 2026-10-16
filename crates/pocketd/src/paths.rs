//! On-disk layout (ARCHITECTURE.md §8).

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
    pub runtime: PathBuf,
    /// Kernel, system image, VMM and bundled presets (`POCKET_ASSETS_DIR`, else `data`).
    pub assets: PathBuf,
}

fn xdg(var: &str, home_rel: &str) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| "/".into())).join(home_rel)
        })
}

/// The data dir when assets were installed there, else next to the binary
/// (`<prefix>/bin/pocketd` → `<prefix>/share/pocket`, packages), else the data dir.
fn default_assets(data: &std::path::Path) -> PathBuf {
    let has = |d: &std::path::Path| d.join("kernel/vmlinux").exists();
    if has(data) {
        return data.to_path_buf();
    }
    let beside = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent()?.parent().map(|p| p.join("share/pocket")));
    beside
        .into_iter()
        .chain([PathBuf::from("/usr/share/pocket")])
        .find(|d| has(d))
        .unwrap_or_else(|| data.to_path_buf())
}

pub fn runtime_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d).join("pocket"),
        None => std::env::temp_dir().join(format!("pocket-{}", unsafe { libc::getuid() })),
    }
}

impl Paths {
    pub fn from_env() -> Paths {
        let data = xdg("XDG_DATA_HOME", ".local/share").join("pocket");
        let assets = std::env::var_os("POCKET_ASSETS_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| default_assets(&data));
        Paths {
            state: xdg("XDG_STATE_HOME", ".local/state").join("pocket"),
            cache: xdg("XDG_CACHE_HOME", ".cache").join("pocket"),
            runtime: runtime_dir(),
            assets,
            data,
        }
    }

    pub fn socket(&self) -> PathBuf {
        self.runtime.join("pocketd.sock")
    }

    pub fn db(&self) -> PathBuf {
        self.data.join("state.db")
    }

    pub fn pocket_dir(&self, id: &str) -> PathBuf {
        self.data.join("pockets").join(id)
    }

    /// Short on purpose: UDS paths are limited to 108 bytes.
    pub fn pocket_runtime(&self, id: &str) -> PathBuf {
        self.runtime.join("p").join(&id[..12.min(id.len())])
    }

    pub fn kernel(&self) -> PathBuf {
        self.assets.join("kernel/vmlinux")
    }

    pub fn system_image(&self) -> PathBuf {
        self.assets.join("system.erofs")
    }

    pub fn vmm(&self) -> PathBuf {
        pocket_vmm::default_binary(&self.assets)
    }

    pub fn images(&self) -> PathBuf {
        self.data.join("images")
    }

    pub fn templates(&self) -> PathBuf {
        self.data.join("templates")
    }

    pub fn blobs(&self) -> PathBuf {
        self.cache.join("blobs")
    }

    /// Bundled tool if present, else from `PATH`.
    pub fn tool(&self, name: &str) -> PathBuf {
        let bundled = self.assets.join("bin").join(name);
        if bundled.exists() {
            bundled
        } else {
            PathBuf::from(name)
        }
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        for d in [&self.data, &self.state, &self.cache, &self.runtime] {
            std::fs::create_dir_all(d)?;
        }
        for d in [&self.data, &self.runtime] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}
