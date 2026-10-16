//! Per-pocket interception hooks: credential injection (placeholders → real values, only for
//! a secret's bound hosts), host-side ChatGPT token refresh (Q3, D21) and, later, push
//! guardrails. The guest never sees a real value unless the user opted in to copying it.

use std::sync::{Arc, RwLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use pocket_net::mitm::{Action, HookFut, LocalResponse, MitmHooks, ReqHead};
use pocket_net::policy::normalize_host;
use pocket_proto::rpc::{ErrorCode, SecretInfo};
use serde::{Deserialize, Serialize};

use crate::daemon::{Daemon, R, err, random_bytes};

/// Codex's OAuth client id and token endpoint (codex-rs `login/src/auth/manager.rs`).
pub const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const CODEX_TOKEN_HOST: &str = "auth.openai.com";
pub const CODEX_TOKEN_PATH: &str = "/oauth/token";
/// Refresh the real access token on the host when it expires within this window.
const REFRESH_WINDOW_S: u64 = 15 * 60;

/// What a pocket remembers about each injected secret (pocket meta; no real values).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InjectedSecret {
    pub name: String,
    pub placeholder: String,
    #[serde(default)]
    pub copy_in: bool,
    /// ChatGPT logins: placeholder access and id tokens currently held by the guest.
    #[serde(default)]
    pub access_placeholder: Option<String>,
    #[serde(default)]
    pub id_placeholder: Option<String>,
}

/// A Codex `auth.json` from a ChatGPT login.
#[derive(Debug, Clone)]
pub struct ChatGpt {
    pub raw: serde_json::Value,
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: String,
    pub account_id: Option<String>,
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 3339 UTC timestamp (Codex's `last_refresh`).
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let t = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        t / 3600,
        (t / 60) % 60,
        t % 60
    )
}

pub fn jwt_claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?).ok()
}

pub fn jwt_exp(token: &str) -> Option<u64> {
    jwt_claims(token)?.get("exp")?.as_u64()
}

/// Same header and claims (clients read expiry and account from them), random signature:
/// it identifies the real token to the proxy and is worthless anywhere else.
pub fn placeholder_jwt(real: &str) -> String {
    let mut parts = real.splitn(3, '.');
    let (h, p) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let sig_len = parts.next().map(str::len).unwrap_or(43).max(43);
    let sig: String = URL_SAFE_NO_PAD
        .encode(random_bytes(sig_len))
        .chars()
        .take(sig_len)
        .collect();
    format!("{h}.{p}.{sig}")
}

impl ChatGpt {
    pub fn parse(json: &str) -> R<ChatGpt> {
        let bad = |why: &str| {
            err(
                ErrorCode::BadRequest,
                format!("not a Codex ChatGPT login: {why}"),
            )
            .hint("run `codex login` on the host first, then `pocket login openai --from-codex`")
        };
        let raw: serde_json::Value = serde_json::from_str(json).map_err(|_| bad("invalid JSON"))?;
        let t = raw.get("tokens").ok_or_else(|| bad("no tokens"))?;
        let s = |k: &str| {
            t.get(k)
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty() && !v.contains(char::is_whitespace))
                .map(String::from)
                .ok_or_else(|| bad(&format!("no {k}")))
        };
        Ok(ChatGpt {
            id_token: s("id_token")?,
            access_token: s("access_token")?,
            refresh_token: s("refresh_token")?,
            account_id: t
                .get("account_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            raw,
        })
    }

    pub fn to_json(&self) -> String {
        let mut raw = self.raw.clone();
        raw["tokens"]["id_token"] = self.id_token.clone().into();
        raw["tokens"]["access_token"] = self.access_token.clone().into();
        raw["tokens"]["refresh_token"] = self.refresh_token.clone().into();
        raw["last_refresh"] = rfc3339(now_s()).into();
        serde_json::to_string_pretty(&raw).unwrap()
    }

    /// The guest's `auth.json`: placeholders for every token, the real account id.
    pub fn guest_auth_json(&self, s: &InjectedSecret) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": s.id_placeholder,
                "access_token": s.access_placeholder,
                "refresh_token": s.placeholder,
                "account_id": self.account_id,
            },
            "last_refresh": rfc3339(now_s()),
        }))
        .unwrap()
    }
}

/// Upstream access for host-side requests (same resolver/connector as the pocket proxy).
pub struct Net {
    pub resolver: Arc<dyn pocket_net::proxy::Resolver>,
    pub connector: Arc<dyn pocket_net::proxy::Connector>,
    pub tls: Arc<rustls::ClientConfig>,
}

pub struct Item {
    pub info: SecretInfo,
    pub real: String,
    pub meta: InjectedSecret,
    pub chat: Option<ChatGpt>,
    /// Access-token placeholders the guest may still hold from before a refresh.
    pub old_access: Vec<String>,
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(d) => {
            host.len() > d.len() + 1
                && host.ends_with(d)
                && host.as_bytes()[host.len() - d.len() - 1] == b'.'
        }
        None => normalize_host(pattern) == host,
    }
}

pub struct PocketHooks {
    pub pocket_id: String,
    pub items: RwLock<Vec<Item>>,
    pub net: Net,
    pub daemon: Weak<Daemon>,
    /// Push guardrails (M7) for these hosts.
    pub guard: RwLock<Option<crate::guard::PushGuard>>,
    refresh: tokio::sync::Mutex<()>,
}

impl PocketHooks {
    pub fn new(pocket_id: String, items: Vec<Item>, net: Net, daemon: Weak<Daemon>) -> PocketHooks {
        PocketHooks {
            pocket_id,
            items: RwLock::new(items),
            net,
            daemon,
            guard: RwLock::new(None),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    fn bound(&self, host: &str) -> bool {
        self.items
            .read()
            .unwrap()
            .iter()
            .any(|i| !i.meta.copy_in && i.info.hosts.iter().any(|h| host_matches(h, host)))
    }

    fn is_refresh(host: &str, req: &ReqHead) -> bool {
        host == CODEX_TOKEN_HOST
            && req.method == "POST"
            && req.path.split('?').next() == Some(CODEX_TOKEN_PATH)
    }

    /// Answers the guest's refresh request with fresh placeholders, refreshing the real
    /// tokens on the host first when they are close to expiry.
    async fn chatgpt_refresh(&self, idx: usize) -> LocalResponse {
        let _g = self.refresh.lock().await;
        let (chat, name) = {
            let items = self.items.read().unwrap();
            (
                items[idx].chat.clone().unwrap(),
                items[idx].info.name.clone(),
            )
        };
        let mut chat = chat;
        let fresh = jwt_exp(&chat.access_token).is_some_and(|e| e > now_s() + REFRESH_WINDOW_S);
        if !fresh {
            match self.refresh_upstream(&chat).await {
                Ok(new) => {
                    if let Some(d) = self.daemon.upgrade() {
                        d.chatgpt_refreshed(&name, &chat, &new);
                    }
                    chat = new;
                }
                Err(e) => {
                    tracing::warn!("{name}: host-side token refresh failed: {e}");
                    return LocalResponse {
                        status: 401,
                        content_type: "application/json".into(),
                        extra_headers: vec![],
                        body: serde_json::to_vec(&serde_json::json!({
                            "error": "refresh_failed",
                            "error_description": "pocket could not refresh the ChatGPT login on the host; run `codex login` on the host and `pocket login openai --from-codex`",
                        }))
                        .unwrap(),
                        reason: format!("host-side refresh failed: {e}"),
                        denied: true,
                    };
                }
            }
        }
        let (body, meta) = {
            let mut items = self.items.write().unwrap();
            let it = &mut items[idx];
            if let Some(old) = it.meta.access_placeholder.take() {
                it.old_access.push(old);
                if it.old_access.len() > 4 {
                    it.old_access.remove(0);
                }
            }
            it.meta.access_placeholder = Some(placeholder_jwt(&chat.access_token));
            it.meta.id_placeholder = Some(placeholder_jwt(&chat.id_token));
            it.chat = Some(chat);
            (
                serde_json::json!({
                    "id_token": it.meta.id_placeholder,
                    "access_token": it.meta.access_placeholder,
                    "refresh_token": it.meta.placeholder,
                    "token_type": "Bearer",
                }),
                it.meta.clone(),
            )
        };
        if let Some(d) = self.daemon.upgrade() {
            d.update_injected(&self.pocket_id, &meta);
        }
        LocalResponse {
            status: 200,
            content_type: "application/json".into(),
            extra_headers: vec![("Cache-Control".into(), "no-store".into())],
            body: serde_json::to_vec(&body).unwrap(),
            reason: "token refresh answered by pocket (host-side)".into(),
            denied: false,
        }
    }

    async fn refresh_upstream(&self, chat: &ChatGpt) -> std::io::Result<ChatGpt> {
        let body = serde_json::to_vec(&serde_json::json!({
            "client_id": CODEX_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": chat.refresh_token,
            "scope": "openid profile email",
        }))
        .unwrap();
        let r = pocket_net::client::request(
            &*self.net.resolver,
            &*self.net.connector,
            self.net.tls.clone(),
            CODEX_TOKEN_HOST,
            "POST",
            CODEX_TOKEN_PATH,
            &[
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ],
            &body,
        )
        .await?;
        if r.status != 200 {
            return Err(std::io::Error::other(format!(
                "token endpoint answered {}",
                r.status
            )));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).map_err(std::io::Error::other)?;
        let mut new = chat.clone();
        let take = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        };
        new.access_token = take("access_token")
            .ok_or_else(|| std::io::Error::other("no access_token in reply"))?;
        if let Some(t) = take("id_token") {
            new.id_token = t;
        }
        if let Some(t) = take("refresh_token") {
            new.refresh_token = t;
        }
        Ok(new)
    }
}

/// Replaces `ph` with `real` in a header value, including inside `Basic` credentials.
fn substitute(value: &str, ph: &str, real: &str) -> Option<String> {
    if value.contains(ph) {
        return Some(value.replace(ph, real));
    }
    let (scheme, cred) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(STANDARD.decode(cred.trim()).ok()?).ok()?;
    decoded
        .contains(ph)
        .then(|| format!("{scheme} {}", STANDARD.encode(decoded.replace(ph, real))))
}

impl MitmHooks for PocketHooks {
    fn intercepts(&self, host: &str, port: u16) -> bool {
        port == 443
            && (self.bound(host)
                || self
                    .guard
                    .read()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|g| g.covers(host)))
    }

    fn body_needed(&self, host: &str, req: &ReqHead) -> usize {
        if Self::is_refresh(host, req) && self.bound(host) {
            return 64 * 1024;
        }
        self.guard
            .read()
            .unwrap()
            .as_ref()
            .map_or(0, |g| g.body_needed(host, req))
    }

    fn request<'a>(
        &'a self,
        host: &'a str,
        req: &'a mut ReqHead,
        body: &'a [u8],
        complete: bool,
    ) -> HookFut<'a> {
        Box::pin(async move {
            let guard = self.guard.read().unwrap().clone();
            if let Some(g) = guard
                && let Some(resp) = g.check(host, req, body, complete)
            {
                return Action::Respond(resp);
            }
            if Self::is_refresh(host, req) {
                let text = String::from_utf8_lossy(body);
                let idx = self.items.read().unwrap().iter().position(|i| {
                    i.chat.is_some() && !i.meta.copy_in && text.contains(&i.meta.placeholder)
                });
                if let Some(idx) = idx {
                    return Action::Respond(self.chatgpt_refresh(idx).await);
                }
            }
            let items = self.items.read().unwrap();
            let mut injected = false;
            for it in items.iter() {
                if it.meta.copy_in || !it.info.hosts.iter().any(|h| host_matches(h, host)) {
                    continue;
                }
                let mut pairs: Vec<(&str, &str)> = vec![];
                match &it.chat {
                    Some(c) => {
                        for ph in it
                            .meta
                            .access_placeholder
                            .iter()
                            .chain(it.old_access.iter())
                        {
                            pairs.push((ph, &c.access_token));
                        }
                    }
                    None => pairs.push((&it.meta.placeholder, &it.real)),
                }
                let mut hit = false;
                for (_, v) in req.headers.iter_mut() {
                    for (ph, real) in &pairs {
                        if let Some(nv) = substitute(v, ph, real) {
                            *v = nv;
                            hit = true;
                        }
                    }
                }
                if !hit
                    && let Some(tpl) = &it.info.header
                    && let Some((name, fmt)) = tpl.split_once(':')
                    && req.header(name.trim()).is_none()
                {
                    req.set_header(name.trim(), fmt.trim().replace("{}", &it.real));
                    hit = true;
                }
                injected |= hit;
            }
            Action::Forward { injected }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_and_matching() {
        assert_eq!(
            substitute("Bearer PH", "PH", "REAL").as_deref(),
            Some("Bearer REAL")
        );
        let basic = format!("Basic {}", STANDARD.encode("x-access-token:PH"));
        let out = substitute(&basic, "PH", "REAL").unwrap();
        assert_eq!(
            STANDARD
                .decode(out.strip_prefix("Basic ").unwrap())
                .unwrap(),
            b"x-access-token:REAL"
        );
        assert_eq!(substitute("Bearer other", "PH", "REAL"), None);
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(!host_matches("*.github.com", "github.com"));
        assert!(!host_matches("*.github.com", "evilgithub.com"));
        assert!(host_matches("api.anthropic.com", "api.anthropic.com"));
    }

    #[test]
    fn jwt_placeholders_keep_claims() {
        let claims = URL_SAFE_NO_PAD.encode(br#"{"exp":1900000000,"email":"a@b"}"#);
        let real = format!("eyJhbGciOiJSUzI1NiJ9.{claims}.realsignature0123456789");
        let ph = placeholder_jwt(&real);
        assert_ne!(ph, real);
        assert_eq!(jwt_exp(&ph), Some(1_900_000_000));
        assert!(!ph.ends_with("realsignature0123456789"));
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_760_000_000), "2025-10-09T08:53:20Z");
    }
}
