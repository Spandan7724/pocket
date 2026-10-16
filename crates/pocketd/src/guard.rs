//! Push guardrails (SECURITY.md §Git, D22): smart-HTTP `git-receive-pack` requests to the
//! pocket's git hosts are parsed before anything reaches the remote. A guest may push only to
//! allowed ref patterns (default `refs/heads/pocket/*`) and to branches it created itself;
//! protected refs (`main`, `master`, `release/*`, the default branch) can never be updated,
//! force-pushed or deleted from a pocket.

use std::sync::{Arc, Mutex};

use pocket_net::mitm::{LocalResponse, ReqHead};

const ZERO: &str = "0000000000000000000000000000000000000000";
const MAX_COMMANDS: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct PushGuard {
    pub hosts: Vec<String>,
    /// Branch patterns (`pocket/*`, `feature`); `*` matches within and across `/`.
    pub allow: Vec<String>,
    pub protected: Vec<String>,
    /// Branches the guest created through the proxy (shared across clones of the guard).
    pub created: Arc<Mutex<Vec<String>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    pub old: String,
    pub new: String,
    pub refname: String,
}

pub fn glob(pat: &str, s: &str) -> bool {
    match pat.split_once('*') {
        None => pat == s,
        Some((pre, rest)) => {
            s.starts_with(pre) && (0..=s.len() - pre.len()).any(|i| glob(rest, &s[pre.len() + i..]))
        }
    }
}

/// Ref-update commands at the start of a receive-pack request body; `None` if the command
/// list is malformed or not complete within `body`.
pub fn parse_commands(body: &[u8]) -> Option<(Vec<Command>, Vec<String>)> {
    let mut cmds = vec![];
    let mut caps = vec![];
    let mut i = 0;
    loop {
        let len = usize::from_str_radix(std::str::from_utf8(body.get(i..i + 4)?).ok()?, 16).ok()?;
        if len == 0 {
            return Some((cmds, caps));
        }
        if len < 4 {
            return None;
        }
        let line = body.get(i + 4..i + len)?;
        i += len;
        let (text, c) = match line.iter().position(|b| *b == 0) {
            Some(z) => (&line[..z], Some(&line[z + 1..])),
            None => (line, None),
        };
        if let Some(c) = c {
            caps = String::from_utf8_lossy(c)
                .split_whitespace()
                .map(String::from)
                .collect();
        }
        let text = std::str::from_utf8(text).ok()?.trim_end_matches('\n');
        if text.starts_with("shallow ") || text.starts_with("push-cert") {
            continue;
        }
        let mut p = text.split(' ');
        let (Some(old), Some(new), Some(r), None) = (p.next(), p.next(), p.next(), p.next()) else {
            return None;
        };
        let hex =
            |s: &str| (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
        if !hex(old) || !hex(new) || !r.starts_with("refs/") || r.contains("..") {
            return None;
        }
        cmds.push(Command {
            old: old.into(),
            new: new.into(),
            refname: r.into(),
        });
    }
}

fn pkt(data: &[u8]) -> Vec<u8> {
    let mut v = format!("{:04x}", data.len() + 4).into_bytes();
    v.extend_from_slice(data);
    v
}

/// A receive-pack result rejecting every command, in the framing the client asked for, so
/// git prints `! [remote rejected] main (…)` instead of a bare HTTP error.
fn rejection(cmds: &[Command], caps: &[String], why: &[(String, String)]) -> Vec<u8> {
    let mut report = pkt(b"unpack ok\n");
    for c in cmds {
        let reason = why
            .iter()
            .find(|(r, _)| r == &c.refname)
            .map(|(_, w)| w.as_str())
            .unwrap_or("rejected with other refs by pocket");
        report.extend(pkt(format!("ng {} {reason}\n", c.refname).as_bytes()));
    }
    report.extend_from_slice(b"0000");
    let band = caps
        .iter()
        .any(|c| c == "side-band-64k" || c == "side-band");
    if !band {
        return report;
    }
    let mut out = vec![];
    for (r, w) in why {
        let mut m = vec![2u8];
        m.extend_from_slice(format!("pocket: push to {r} blocked: {w}\n").as_bytes());
        out.extend(pkt(&m));
    }
    for chunk in report.chunks(65_000) {
        let mut m = vec![1u8];
        m.extend_from_slice(chunk);
        out.extend(pkt(&m));
    }
    out.extend_from_slice(b"0000");
    out
}

pub const DEFAULT_PROTECTED: &[&str] = &["main", "master", "release/*", "trunk", "develop"];
pub const DEFAULT_ALLOW: &[&str] = &["pocket/*"];

/// Guard for a pocket: its origin's host plus GitHub when a GitHub credential is injected.
pub fn for_pocket(
    meta: &crate::daemon::Meta,
    hooks: &crate::inject::PocketHooks,
) -> Option<PushGuard> {
    let mut hosts: Vec<String> = meta.origin_host.iter().cloned().collect();
    let github = hooks
        .items
        .read()
        .unwrap()
        .iter()
        .any(|i| i.info.provider == "github");
    if github && !hosts.iter().any(|h| h == "github.com") {
        hosts.push("github.com".into());
    }
    if hosts.is_empty() {
        return None;
    }
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut protected = if meta.git_protected.is_empty() {
        s(DEFAULT_PROTECTED)
    } else {
        meta.git_protected.clone()
    };
    if let Some(b) = &meta.base_branch
        && !protected.contains(b)
    {
        protected.push(b.clone());
    }
    Some(PushGuard {
        hosts,
        allow: if meta.git_allow_push.is_empty() {
            s(DEFAULT_ALLOW)
        } else {
            meta.git_allow_push.clone()
        },
        protected,
        created: Default::default(),
    })
}

/// The decoded body prefix (receive-pack requests may be gzip-compressed).
fn decoded(req: &ReqHead, body: &[u8]) -> Vec<u8> {
    if !req
        .header("content-encoding")
        .is_some_and(|e| e.eq_ignore_ascii_case("gzip"))
    {
        return body.to_vec();
    }
    let mut out = vec![];
    let mut d = flate2::read::GzDecoder::new(body);
    let mut buf = [0u8; 8192];
    while let Ok(n) = std::io::Read::read(&mut d, &mut buf) {
        if n == 0 || out.len() > MAX_COMMANDS {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

impl PushGuard {
    pub fn covers(&self, host: &str) -> bool {
        self.hosts
            .iter()
            .any(|h| crate::inject::host_matches(h, host))
    }

    fn is_push(host: &str, req: &ReqHead, hosts: &[String]) -> bool {
        req.method == "POST"
            && req
                .path
                .split('?')
                .next()
                .is_some_and(|p| p.ends_with("/git-receive-pack"))
            && hosts.iter().any(|h| crate::inject::host_matches(h, host))
    }

    pub fn body_needed(&self, host: &str, req: &ReqHead) -> usize {
        if Self::is_push(host, req, &self.hosts) {
            MAX_COMMANDS
        } else {
            0
        }
    }

    fn verdict(&self, c: &Command) -> Result<(), String> {
        let Some(branch) = c.refname.strip_prefix("refs/heads/") else {
            return Err("only branches can be pushed from a pocket (no tags or other refs)".into());
        };
        if self.protected.iter().any(|p| glob(p, branch)) {
            return Err(if c.new == ZERO {
                "deleting a protected branch".into()
            } else {
                "protected branch; push to a pocket/* branch and open a PR".into()
            });
        }
        if self.allow.iter().any(|p| glob(p, branch)) {
            return Ok(());
        }
        let created = self.created.lock().unwrap();
        if created.iter().any(|b| b == branch) {
            return Ok(());
        }
        if c.old == ZERO && c.new != ZERO {
            return Ok(());
        }
        Err("branch not created in this pocket and not in git.allow_push".into())
    }

    /// `None` = forward; `Some` = answer locally (rejected push).
    pub fn check(
        &self,
        host: &str,
        req: &ReqHead,
        body: &[u8],
        complete: bool,
    ) -> Option<LocalResponse> {
        if !Self::is_push(host, req, &self.hosts) {
            return None;
        }
        let reject = |reason: String, body: Vec<u8>, ct: &str| LocalResponse {
            status: if ct.starts_with("application/x-git") {
                200
            } else {
                403
            },
            content_type: ct.into(),
            extra_headers: vec![("Cache-Control".into(), "no-cache".into())],
            body,
            reason,
            denied: true,
        };
        let body = decoded(req, body);
        let Some((cmds, caps)) = parse_commands(&body) else {
            let why = if complete || body.len() < MAX_COMMANDS {
                "malformed push request"
            } else {
                "push command list too large"
            };
            return Some(reject(
                format!("push blocked: {why}"),
                format!("blocked by pocket: {why}\n").into_bytes(),
                "text/plain",
            ));
        };
        let why: Vec<(String, String)> = cmds
            .iter()
            .filter_map(|c| self.verdict(c).err().map(|w| (c.refname.clone(), w)))
            .collect();
        if why.is_empty() {
            let mut created = self.created.lock().unwrap();
            for c in &cmds {
                if c.old == ZERO
                    && let Some(b) = c.refname.strip_prefix("refs/heads/")
                    && !created.iter().any(|x| x == b)
                {
                    created.push(b.to_string());
                }
            }
            return None;
        }
        let summary = why
            .iter()
            .map(|(r, w)| format!("{r}: {w}"))
            .collect::<Vec<_>>()
            .join("; ");
        Some(reject(
            format!("push blocked: {summary}"),
            rejection(&cmds, &caps, &why),
            "application/x-git-receive-pack-result",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(cmds: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut b = vec![];
        for (i, (o, n, r)) in cmds.iter().enumerate() {
            let line = if i == 0 {
                format!("{o} {n} {r}\0report-status side-band-64k\n")
            } else {
                format!("{o} {n} {r}\n")
            };
            b.extend(pkt(line.as_bytes()));
        }
        b.extend_from_slice(b"0000PACK....");
        b
    }

    fn guard() -> PushGuard {
        PushGuard {
            hosts: vec!["github.com".into()],
            allow: vec!["pocket/*".into()],
            protected: vec!["main".into(), "master".into(), "release/*".into()],
            created: Default::default(),
        }
    }

    fn req() -> ReqHead {
        ReqHead {
            method: "POST".into(),
            path: "/o/r.git/git-receive-pack".into(),
            headers: vec![],
        }
    }

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";

    #[test]
    fn protected_refs_blocked_allowed_pass() {
        let g = guard();
        let r = req();
        assert!(
            g.check(
                "github.com",
                &r,
                &body(&[(A, B, "refs/heads/pocket/x")]),
                true
            )
            .is_none()
        );
        let blocked = g
            .check("github.com", &r, &body(&[(A, B, "refs/heads/main")]), true)
            .unwrap();
        assert!(blocked.denied && blocked.reason.contains("protected"));
        assert!(String::from_utf8_lossy(&blocked.body).contains("ng refs/heads/main"));
        let del = g
            .check(
                "github.com",
                &r,
                &body(&[(A, ZERO, "refs/heads/release/1")]),
                true,
            )
            .unwrap();
        assert!(
            del.reason.contains("deleting a protected branch"),
            "{}",
            del.reason
        );
        assert!(
            g.check("github.com", &r, &body(&[(A, B, "refs/tags/v1")]), true)
                .is_some()
        );
        // Mixed push: everything is rejected.
        assert!(
            g.check(
                "github.com",
                &r,
                &body(&[(A, B, "refs/heads/pocket/x"), (A, B, "refs/heads/main")]),
                true
            )
            .is_some()
        );
        // A new branch may be created, then updated; an existing foreign one may not.
        assert!(
            g.check(
                "github.com",
                &r,
                &body(&[(ZERO, B, "refs/heads/feat")]),
                true
            )
            .is_none()
        );
        assert!(
            g.check("github.com", &r, &body(&[(B, A, "refs/heads/feat")]), true)
                .is_none()
        );
        assert!(
            g.check("github.com", &r, &body(&[(A, B, "refs/heads/other")]), true)
                .is_some()
        );
        assert!(
            g.check("gitlab.com", &r, &body(&[(A, B, "refs/heads/main")]), true)
                .is_none()
        );
        assert!(g.check("github.com", &r, b"garbage", true).is_some());
    }

    #[test]
    fn globs() {
        assert!(glob("pocket/*", "pocket/a/b"));
        assert!(glob("release/*", "release/1.0"));
        assert!(!glob("release/*", "releases"));
        assert!(glob("main", "main") && !glob("main", "main2"));
    }
}
