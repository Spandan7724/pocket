//! Persistent state (CONTRACTS.md §4): SQLite with ordered migrations tracked in
//! `PRAGMA user_version`.

use std::path::{Path, PathBuf};

use pocket_proto::rpc::{NetEntry, PocketInfo, PocketState, Verdict};
use rusqlite::{Connection, OptionalExtension, Row, params};

/// Rows kept per pocket in `net_log`; older rows are dropped on insert.
pub const NET_LOG_CAP: i64 = 10_000;

const MIGRATIONS: &[&str] = &[
    // 1: initial schema
    "CREATE TABLE pockets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL,
        state_reason TEXT,
        preset TEXT NOT NULL,
        image_digest TEXT NOT NULL,
        template_key TEXT,
        repo_path TEXT,
        base_ref TEXT,
        branch TEXT,
        vcpus INTEGER NOT NULL,
        memory_mib INTEGER NOT NULL,
        disk_bytes INTEGER NOT NULL,
        net_profile TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_active_at INTEGER NOT NULL,
        vsock_cid INTEGER NOT NULL,
        vm_json TEXT,
        meta_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE sessions (
        pocket_id TEXT NOT NULL REFERENCES pockets(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        argv_json TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_output_at INTEGER,
        exit_status TEXT,
        PRIMARY KEY (pocket_id, name)
    );
    CREATE TABLE policies (
        pocket_id TEXT NOT NULL REFERENCES pockets(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        pattern TEXT NOT NULL,
        action TEXT NOT NULL,
        source TEXT NOT NULL
    );
    CREATE TABLE net_log (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        pocket_id TEXT NOT NULL,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        host TEXT NOT NULL,
        ip TEXT,
        port INTEGER NOT NULL,
        method TEXT,
        path TEXT,
        status INTEGER,
        bytes_up INTEGER NOT NULL,
        bytes_down INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        reason TEXT NOT NULL,
        injected INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX net_log_pocket ON net_log(pocket_id, seq);
    CREATE TABLE secrets (
        name TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        bindings_json TEXT NOT NULL,
        storage TEXT NOT NULL
    );
    CREATE TABLE templates (
        key TEXT PRIMARY KEY,
        image_digest TEXT NOT NULL,
        built_at INTEGER NOT NULL,
        host_fingerprint TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        last_used_at INTEGER NOT NULL
    );
    CREATE TABLE images (
        name TEXT PRIMARY KEY,
        digest TEXT NOT NULL,
        path TEXT NOT NULL,
        source TEXT NOT NULL,
        built_at INTEGER NOT NULL,
        size_bytes INTEGER NOT NULL
    );",
];

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("state database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error(
        "state database {path} has schema version {found}, newer than this pocket ({known}); upgrade pocket"
    )]
    TooNew {
        path: PathBuf,
        found: i64,
        known: i64,
    },
    #[error("corrupt record: {0}")]
    Corrupt(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// A pocket row: the public info plus daemon-private fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocketRecord {
    pub info: PocketInfo,
    pub vsock_cid: u32,
    /// Serialized VMM handle while a VM runs.
    pub vm_json: Option<String>,
    pub meta_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRecord {
    pub name: String,
    pub digest: String,
    pub path: PathBuf,
    pub source: String,
    pub built_at: u64,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    pub kind: String,
    pub pattern: String,
    pub action: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    pub name: String,
    pub provider: String,
    pub bindings_json: String,
    pub storage: String,
}

pub struct Store {
    conn: Connection,
}

fn state_to_db(s: &PocketState) -> (&'static str, Option<&str>) {
    match s {
        PocketState::Creating => ("creating", None),
        PocketState::Running => ("running", None),
        PocketState::Paused => ("paused", None),
        PocketState::Hibernated => ("hibernated", None),
        PocketState::Stopped => ("stopped", None),
        PocketState::Broken { reason } => ("broken", Some(reason)),
    }
}

fn state_from_db(s: &str, reason: Option<String>) -> Result<PocketState> {
    Ok(match s {
        "creating" => PocketState::Creating,
        "running" => PocketState::Running,
        "paused" => PocketState::Paused,
        "hibernated" => PocketState::Hibernated,
        "stopped" => PocketState::Stopped,
        "broken" => PocketState::Broken {
            reason: reason.unwrap_or_default(),
        },
        other => return Err(StoreError::Corrupt(format!("pocket state {other:?}"))),
    })
}

const POCKET_COLS: &str = "id, name, state, state_reason, preset, image_digest, repo_path, base_ref, \
    branch, vcpus, memory_mib, disk_bytes, net_profile, created_at, last_active_at, vsock_cid, \
    vm_json, meta_json";

fn pocket_row(r: &Row) -> rusqlite::Result<(PocketRecord, String, Option<String>)> {
    let state: String = r.get(2)?;
    let reason: Option<String> = r.get(3)?;
    let rec = PocketRecord {
        info: PocketInfo {
            id: r.get(0)?,
            name: r.get(1)?,
            state: PocketState::Creating,
            preset: r.get(4)?,
            image_digest: r.get(5)?,
            repo_path: r.get::<_, Option<String>>(6)?.map(PathBuf::from),
            base_ref: r.get(7)?,
            branch: r.get(8)?,
            vcpus: r.get(9)?,
            memory_mib: r.get(10)?,
            disk_bytes: r.get::<_, i64>(11)? as u64,
            disk_used_bytes: 0,
            net_profile: r.get(12)?,
            created_at: r.get::<_, i64>(13)? as u64,
            last_active_at: r.get::<_, i64>(14)? as u64,
        },
        vsock_cid: r.get(15)?,
        vm_json: r.get(16)?,
        meta_json: r.get(17)?,
    };
    Ok((rec, state, reason))
}

fn finish(row: (PocketRecord, String, Option<String>)) -> Result<PocketRecord> {
    let (mut rec, state, reason) = row;
    rec.info.state = state_from_db(&state, reason)?;
    Ok(rec)
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut s = Store { conn };
        s.migrate(path)?;
        Ok(s)
    }

    pub fn open_in_memory() -> Result<Store> {
        let mut s = Store {
            conn: Connection::open_in_memory()?,
        };
        s.conn.pragma_update(None, "foreign_keys", "ON")?;
        s.migrate(Path::new(":memory:"))?;
        Ok(s)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?)
    }

    fn migrate(&mut self, path: &Path) -> Result<()> {
        let have = self.schema_version()?;
        let known = MIGRATIONS.len() as i64;
        if have > known {
            return Err(StoreError::TooNew {
                path: path.into(),
                found: have,
                known,
            });
        }
        for (i, m) in MIGRATIONS.iter().enumerate().skip(have as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(m)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(())
    }

    pub fn insert_pocket(&self, r: &PocketRecord) -> Result<()> {
        let i = &r.info;
        let (state, reason) = state_to_db(&i.state);
        self.conn.execute(
            &format!(
                "INSERT INTO pockets ({POCKET_COLS}) VALUES \
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)"
            ),
            params![
                i.id,
                i.name,
                state,
                reason,
                i.preset,
                i.image_digest,
                i.repo_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
                i.base_ref,
                i.branch,
                i.vcpus,
                i.memory_mib,
                i.disk_bytes as i64,
                i.net_profile,
                i.created_at as i64,
                i.last_active_at as i64,
                r.vsock_cid,
                r.vm_json,
                r.meta_json,
            ],
        )?;
        Ok(())
    }

    pub fn pockets(&self) -> Result<Vec<PocketRecord>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {POCKET_COLS} FROM pockets ORDER BY created_at, name"
        ))?;
        let rows = st.query_map([], pocket_row)?;
        rows.map(|r| finish(r?)).collect()
    }

    pub fn pocket(&self, name: &str) -> Result<Option<PocketRecord>> {
        self.conn
            .query_row(
                &format!("SELECT {POCKET_COLS} FROM pockets WHERE name = ?1"),
                [name],
                pocket_row,
            )
            .optional()?
            .map(finish)
            .transpose()
    }

    pub fn set_state(&self, id: &str, state: &PocketState) -> Result<()> {
        let (s, reason) = state_to_db(state);
        self.conn.execute(
            "UPDATE pockets SET state = ?2, state_reason = ?3 WHERE id = ?1",
            params![id, s, reason],
        )?;
        Ok(())
    }

    pub fn set_vm(&self, id: &str, vm_json: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE pockets SET vm_json = ?2 WHERE id = ?1",
            params![id, vm_json],
        )?;
        Ok(())
    }

    pub fn set_workspace(
        &self,
        id: &str,
        base_ref: Option<&str>,
        branch: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE pockets SET base_ref = ?2, branch = ?3 WHERE id = ?1",
            params![id, base_ref, branch],
        )?;
        Ok(())
    }

    pub fn set_meta(&self, id: &str, meta_json: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE pockets SET meta_json = ?2 WHERE id = ?1",
            params![id, meta_json],
        )?;
        Ok(())
    }

    pub fn touch(&self, id: &str, now: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE pockets SET last_active_at = ?2 WHERE id = ?1",
            params![id, now as i64],
        )?;
        Ok(())
    }

    pub fn delete_pocket(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM net_log WHERE pocket_id = ?1", [id])?;
        self.conn
            .execute("DELETE FROM pockets WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Lowest vsock CID ≥ 3 not used by any pocket.
    pub fn free_cid(&self) -> Result<u32> {
        let mut st = self.conn.prepare("SELECT vsock_cid FROM pockets")?;
        let used: Vec<u32> = st
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok((3..).find(|c| !used.contains(c)).unwrap())
    }

    pub fn set_policies(&self, pocket_id: &str, rules: &[PolicyRule]) -> Result<()> {
        self.conn
            .execute("DELETE FROM policies WHERE pocket_id = ?1", [pocket_id])?;
        for r in rules {
            self.conn.execute(
                "INSERT INTO policies (pocket_id, kind, pattern, action, source) VALUES (?1,?2,?3,?4,?5)",
                params![pocket_id, r.kind, r.pattern, r.action, r.source],
            )?;
        }
        Ok(())
    }

    pub fn policies(&self, pocket_id: &str) -> Result<Vec<PolicyRule>> {
        let mut st = self.conn.prepare(
            "SELECT kind, pattern, action, source FROM policies WHERE pocket_id = ?1 ORDER BY rowid",
        )?;
        let rows = st.query_map([pocket_id], |r| {
            Ok(PolicyRule {
                kind: r.get(0)?,
                pattern: r.get(1)?,
                action: r.get(2)?,
                source: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn log_net(&self, pocket_id: &str, e: &NetEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO net_log (pocket_id, ts, kind, host, ip, port, method, path, status, \
             bytes_up, bytes_down, verdict, reason, injected) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                pocket_id,
                e.ts_ms as i64,
                e.kind,
                e.host,
                e.ip,
                e.port,
                e.method,
                e.path,
                e.status,
                e.bytes_up as i64,
                e.bytes_down as i64,
                match e.verdict {
                    Verdict::Allowed => "allowed",
                    Verdict::Denied => "denied",
                },
                e.reason,
                e.injected,
            ],
        )?;
        self.conn.execute(
            "DELETE FROM net_log WHERE pocket_id = ?1 AND seq <= \
             (SELECT seq FROM net_log WHERE pocket_id = ?1 ORDER BY seq DESC LIMIT 1 OFFSET ?2)",
            params![pocket_id, NET_LOG_CAP],
        )?;
        Ok(())
    }

    /// Most recent `limit` entries, oldest first.
    pub fn net_log(&self, pocket_id: &str, pocket_name: &str, limit: u32) -> Result<Vec<NetEntry>> {
        let mut st = self.conn.prepare(
            "SELECT ts, kind, host, ip, port, method, path, status, bytes_up, bytes_down, verdict, reason, injected \
             FROM net_log WHERE pocket_id = ?1 ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![pocket_id, limit], |r| {
            let verdict: String = r.get(10)?;
            Ok(NetEntry {
                pocket: pocket_name.into(),
                ts_ms: r.get::<_, i64>(0)? as u64,
                kind: r.get(1)?,
                host: r.get(2)?,
                ip: r.get(3)?,
                port: r.get(4)?,
                method: r.get(5)?,
                path: r.get(6)?,
                status: r.get(7)?,
                bytes_up: r.get::<_, i64>(8)? as u64,
                bytes_down: r.get::<_, i64>(9)? as u64,
                verdict: if verdict == "allowed" {
                    Verdict::Allowed
                } else {
                    Verdict::Denied
                },
                reason: r.get(11)?,
                injected: r.get(12)?,
            })
        })?;
        let mut v: Vec<NetEntry> = rows.collect::<rusqlite::Result<_>>()?;
        v.reverse();
        Ok(v)
    }

    /// Secret metadata only; values live in the secret store (`pocketd::secrets`).
    pub fn put_secret(&self, r: &SecretRecord) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO secrets (name, provider, bindings_json, storage) VALUES (?1,?2,?3,?4)",
            params![r.name, r.provider, r.bindings_json, r.storage],
        )?;
        Ok(())
    }

    pub fn secrets(&self) -> Result<Vec<SecretRecord>> {
        let mut st = self
            .conn
            .prepare("SELECT name, provider, bindings_json, storage FROM secrets ORDER BY name")?;
        let rows = st.query_map([], |r| {
            Ok(SecretRecord {
                name: r.get(0)?,
                provider: r.get(1)?,
                bindings_json: r.get(2)?,
                storage: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn delete_secret(&self, name: &str) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM secrets WHERE name = ?1", [name])?
            > 0)
    }

    pub fn put_image(&self, i: &ImageRecord) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO images (name, digest, path, source, built_at, size_bytes) \
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                i.name,
                i.digest,
                i.path.to_string_lossy(),
                i.source,
                i.built_at as i64,
                i.size_bytes as i64
            ],
        )?;
        Ok(())
    }

    pub fn image(&self, name: &str) -> Result<Option<ImageRecord>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, digest, path, source, built_at, size_bytes FROM images WHERE name = ?1",
                [name],
                |r| {
                    Ok(ImageRecord {
                        name: r.get(0)?,
                        digest: r.get(1)?,
                        path: PathBuf::from(r.get::<_, String>(2)?),
                        source: r.get(3)?,
                        built_at: r.get::<_, i64>(4)? as u64,
                        size_bytes: r.get::<_, i64>(5)? as u64,
                    })
                },
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, cid: u32) -> PocketRecord {
        PocketRecord {
            info: PocketInfo {
                id: format!("id-{name}"),
                name: name.into(),
                state: PocketState::Creating,
                preset: "base".into(),
                image_digest: "sha256:aa".into(),
                repo_path: Some("/r".into()),
                base_ref: None,
                branch: None,
                vcpus: 2,
                memory_mib: 1024,
                disk_bytes: 1 << 30,
                disk_used_bytes: 0,
                net_profile: "dev".into(),
                created_at: 1,
                last_active_at: 1,
            },
            vsock_cid: cid,
            vm_json: None,
            meta_json: "{}".into(),
        }
    }

    fn entry(host: &str) -> NetEntry {
        NetEntry {
            pocket: "a".into(),
            ts_ms: 5,
            kind: "connect".into(),
            host: host.into(),
            ip: Some("1.2.3.4".into()),
            port: 443,
            method: None,
            path: None,
            status: None,
            bytes_up: 10,
            bytes_down: 20,
            verdict: Verdict::Denied,
            reason: "not in allowlist".into(),
            injected: false,
        }
    }

    #[test]
    fn state_survives_reopen_and_migrations_are_idempotent() {
        let dir = std::env::temp_dir().join(format!("pocket-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("state.db");
        {
            let s = Store::open(&db).unwrap();
            assert_eq!(s.schema_version().unwrap(), MIGRATIONS.len() as i64);
            s.insert_pocket(&rec("a", s.free_cid().unwrap())).unwrap();
            s.set_state(
                "id-a",
                &PocketState::Broken {
                    reason: "VMM died".into(),
                },
            )
            .unwrap();
            s.set_vm("id-a", Some("{\"pid\":1}")).unwrap();
            s.set_workspace("id-a", Some("abc"), Some("pocket/a"))
                .unwrap();
        }
        let s = Store::open(&db).unwrap();
        let p = s.pocket("a").unwrap().unwrap();
        assert_eq!(
            p.info.state,
            PocketState::Broken {
                reason: "VMM died".into()
            }
        );
        assert_eq!(p.vm_json.as_deref(), Some("{\"pid\":1}"));
        assert_eq!(p.info.branch.as_deref(), Some("pocket/a"));
        assert_eq!(s.free_cid().unwrap(), 4);
        assert!(s.insert_pocket(&rec("a", 9)).is_err(), "names are unique");
        s.delete_pocket("id-a").unwrap();
        assert!(s.pockets().unwrap().is_empty());
        drop(s);
        // A database from a newer pocket is refused, not damaged.
        let c = Connection::open(&db).unwrap();
        c.pragma_update(None, "user_version", 99).unwrap();
        drop(c);
        assert!(matches!(
            Store::open(&db),
            Err(StoreError::TooNew { found: 99, .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn net_log_is_a_ring() {
        let s = Store::open_in_memory().unwrap();
        s.insert_pocket(&rec("a", 3)).unwrap();
        for i in 0..(NET_LOG_CAP + 5) {
            s.log_net("id-a", &entry(&format!("h{i}.com"))).unwrap();
        }
        let all = s.net_log("id-a", "a", u32::MAX).unwrap();
        assert_eq!(all.len() as i64, NET_LOG_CAP);
        assert_eq!(all[0].host, "h5.com");
        let last = s.net_log("id-a", "a", 2).unwrap();
        assert_eq!(
            last.iter().map(|e| e.host.as_str()).collect::<Vec<_>>(),
            [
                format!("h{}.com", NET_LOG_CAP + 3),
                format!("h{}.com", NET_LOG_CAP + 4)
            ]
        );
        assert_eq!(last[0].verdict, Verdict::Denied);
    }

    #[test]
    fn images_and_policies() {
        let s = Store::open_in_memory().unwrap();
        s.insert_pocket(&rec("a", 3)).unwrap();
        let img = ImageRecord {
            name: "base".into(),
            digest: "sha256:1".into(),
            path: "/i/base.erofs".into(),
            source: "preset".into(),
            built_at: 3,
            size_bytes: 9,
        };
        s.put_image(&img).unwrap();
        assert_eq!(s.image("base").unwrap(), Some(img));
        let rules = vec![PolicyRule {
            kind: "domain".into(),
            pattern: "*.github.com".into(),
            action: "allow".into(),
            source: "cli".into(),
        }];
        s.set_policies("id-a", &rules).unwrap();
        assert_eq!(s.policies("id-a").unwrap(), rules);
    }
}
