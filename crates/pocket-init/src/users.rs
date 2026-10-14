//! Guest accounts from `/etc/passwd` and `/etc/group`, and first-boot home setup.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use crate::{log, sys};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub groups: Vec<u32>,
}

fn parse_passwd(text: &str) -> Vec<User> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(User {
                name: f[0].into(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: f[5].into(),
                shell: f[6].into(),
                groups: vec![],
            })
        })
        .collect()
}

fn supplementary(group_text: &str, name: &str) -> Vec<u32> {
    group_text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() >= 4 && f[3].split(',').any(|m| m == name) {
                f[2].parse().ok()
            } else {
                None
            }
        })
        .collect()
}

pub fn lookup(name: &str) -> Option<User> {
    let mut u = parse_passwd(&fs::read_to_string("/etc/passwd").ok()?)
        .into_iter()
        .find(|u| u.name == name)?;
    u.groups = supplementary(&fs::read_to_string("/etc/group").unwrap_or_default(), name);
    Some(u)
}

fn regular_users() -> Vec<User> {
    parse_passwd(&fs::read_to_string("/etc/passwd").unwrap_or_default())
        .into_iter()
        .filter(|u| (1000..60000).contains(&u.uid) && u.home.starts_with("/home/"))
        .collect()
}

fn copy_tree(src: &Path, dst: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    sys::lchown(dst, uid, gid)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let (s, d) = (e.path(), dst.join(e.file_name()));
        let ft = e.file_type()?;
        if ft.is_dir() {
            copy_tree(&s, &d, uid, gid)?;
        } else if ft.is_symlink() {
            symlink(fs::read_link(&s)?, &d)?;
        } else {
            fs::copy(&s, &d)?;
        }
        sys::lchown(&d, uid, gid)?;
    }
    Ok(())
}

/// Home directories live on the pocket disk, so the image's are hidden: create them from
/// `/etc/skel` on first boot. An empty root-owned `/work` goes to the first regular user.
pub fn first_boot_setup() {
    let users = regular_users();
    for u in &users {
        let home = Path::new(&u.home);
        if home.exists() {
            continue;
        }
        match copy_tree(Path::new("/etc/skel"), home, u.uid, u.gid) {
            Ok(()) => {
                let _ = fs::set_permissions(home, fs::Permissions::from_mode(0o750));
            }
            Err(e) => log!("home for {}: {e}", u.name),
        }
    }
    if let Some(u) = users.first()
        && let Ok(m) = fs::metadata("/work")
        && m.uid() == 0
        && fs::read_dir("/work").is_ok_and(|mut d| d.next().is_none())
        && let Err(e) = sys::lchown(Path::new("/work"), u.uid, u.gid)
    {
        log!("chown /work: {e}");
    }
    // Login shells reset PATH, so expose the system helpers through /usr/local/bin.
    let helper = "/run/pocket/system/bin/pocket-guest";
    if Path::new(helper).exists() && Path::new("/usr/local/bin").is_dir() {
        for name in ["pocket-guest", "git-remote-pocket"] {
            let link = Path::new("/usr/local/bin").join(name);
            if fs::symlink_metadata(&link).is_err() {
                let _ = symlink(helper, &link);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_and_groups() {
        let p = "root:x:0:0:root:/root:/bin/bash\nbad line\ndev:x:1000:1000::/home/dev:/bin/bash\n";
        let users = parse_passwd(p);
        assert_eq!(users.len(), 2);
        assert_eq!(
            (
                users[1].uid,
                users[1].home.as_str(),
                users[1].shell.as_str()
            ),
            (1000, "/home/dev", "/bin/bash")
        );
        let g = "sudo:x:27:dev,other\nadm:x:4:\ndocker:x:999:dev\nweird\n";
        assert_eq!(supplementary(g, "dev"), [27, 999]);
        assert!(supplementary(g, "nobody").is_empty());
    }
}
