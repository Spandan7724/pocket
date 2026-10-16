//! Egress policy: per-pocket allow/deny rules over host names, wildcards and CIDRs, plus
//! address ranges that are denied whatever the rules say (SECURITY.md §Network).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `example.com`
    Exact(String),
    /// `*.example.com`: subdomains only, not the apex.
    Subdomains(String),
    /// `*`
    Any,
    /// `10.1.2.0/24` or a single address; matches IP-literal destinations only.
    Cidr(IpAddr, u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub pattern: Pattern,
    /// `None` = the policy's default ports.
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid rule {rule:?}: {why}")]
pub struct RuleError {
    pub rule: String,
    pub why: &'static str,
}

/// Lowercase, no trailing dot, brackets stripped from IPv6 literals.
pub fn normalize_host(h: &str) -> String {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    match h.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        Some(inner) => inner.to_string(),
        None => h,
    }
}

fn valid_label_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

impl Rule {
    /// `host`, `*.host`, `*`, `cidr`, each optionally `:port` (IPv6 CIDRs in brackets).
    pub fn parse(s: &str) -> Result<Rule, RuleError> {
        let bad = |why| RuleError {
            rule: s.into(),
            why,
        };
        let s = s.trim();
        let (body, port) = if let Some(rest) = s.strip_prefix('[') {
            let (inner, after) = rest.split_once(']').ok_or_else(|| bad("unclosed ["))?;
            let port = match after.strip_prefix(':') {
                Some(p) => Some(p.parse::<u16>().map_err(|_| bad("bad port"))?),
                None if after.is_empty() => None,
                None => return Err(bad("junk after ]")),
            };
            (inner.to_string(), port)
        } else {
            match s.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (
                    h.to_string(),
                    Some(p.parse::<u16>().map_err(|_| bad("bad port"))?),
                ),
                _ => (s.to_string(), None),
            }
        };
        if port == Some(0) {
            return Err(bad("port 0"));
        }
        let body = body.to_ascii_lowercase();
        let pattern = if body == "*" {
            Pattern::Any
        } else if let Some((ip, len)) = body.split_once('/') {
            let ip: IpAddr = ip.parse().map_err(|_| bad("bad CIDR address"))?;
            let len: u8 = len.parse().map_err(|_| bad("bad CIDR prefix"))?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if len > max {
                return Err(bad("CIDR prefix too long"));
            }
            Pattern::Cidr(ip, len)
        } else if let Ok(ip) = body.parse::<IpAddr>() {
            Pattern::Cidr(ip, if ip.is_ipv4() { 32 } else { 128 })
        } else if let Some(d) = body.strip_prefix("*.") {
            if !valid_label_host(d) {
                return Err(bad("bad domain"));
            }
            Pattern::Subdomains(normalize_host(d))
        } else {
            if body.contains('*') {
                return Err(bad("only a leading `*.` wildcard is supported"));
            }
            if !valid_label_host(&body) {
                return Err(bad("bad host name"));
            }
            Pattern::Exact(normalize_host(&body))
        };
        Ok(Rule { pattern, port })
    }

    /// Whether this rule names `host:port` (ports: an explicit one, else 80/443).
    pub fn allows(&self, host: &str, port: u16) -> bool {
        self.matches_host(host) && self.port.map_or([80, 443].contains(&port), |p| p == port)
    }

    fn matches_host(&self, host: &str) -> bool {
        match (&self.pattern, host.parse::<IpAddr>()) {
            (Pattern::Any, _) => true,
            (Pattern::Cidr(net, len), Ok(ip)) => in_cidr(ip, *net, *len),
            (Pattern::Cidr(..), Err(_)) => false,
            (_, Ok(_)) => false,
            (Pattern::Exact(h), Err(_)) => h == host,
            (Pattern::Subdomains(d), Err(_)) => {
                host.len() > d.len() + 1
                    && host.ends_with(d.as_str())
                    && host.as_bytes()[host.len() - d.len() - 1] == b'.'
            }
        }
    }
}

fn in_cidr(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

fn v4_in(ip: Ipv4Addr, base: [u8; 4], len: u8) -> bool {
    in_cidr(IpAddr::V4(ip), IpAddr::V4(Ipv4Addr::from(base)), len)
}

/// Why `ip` may never be reached from a pocket, if so. Applied to every resolved address,
/// independent of the rules (an allowlisted name resolving here is still denied).
pub fn forbidden_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return forbidden_v4(v4).or(Some("IPv4-mapped address"));
            }
            let seg = v6.segments();
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) embed IPv4 addresses.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
                let v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    seg[6] as u8,
                    (seg[7] >> 8) as u8,
                    seg[7] as u8,
                );
                return forbidden_v4(v4);
            }
            if seg[0] == 0x2002 {
                let v4 = Ipv4Addr::new(
                    (seg[1] >> 8) as u8,
                    seg[1] as u8,
                    (seg[2] >> 8) as u8,
                    seg[2] as u8,
                );
                if let Some(r) = forbidden_v4(v4) {
                    return Some(r);
                }
            }
            forbidden_v6(v6)
        }
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_private() {
        Some("private network (RFC 1918)")
    } else if ip.is_link_local() {
        Some("link-local / cloud metadata")
    } else if v4_in(ip, [100, 64, 0, 0], 10) {
        Some("carrier-grade NAT / metadata (RFC 6598)")
    } else if ip.is_unspecified() || v4_in(ip, [0, 0, 0, 0], 8) {
        Some("unspecified / this network")
    } else if ip.is_multicast() || ip.is_broadcast() || v4_in(ip, [240, 0, 0, 0], 4) {
        Some("multicast / broadcast / reserved")
    } else if v4_in(ip, [192, 0, 0, 0], 24)
        || v4_in(ip, [192, 0, 2, 0], 24)
        || v4_in(ip, [198, 18, 0, 0], 15)
        || v4_in(ip, [198, 51, 100, 0], 24)
        || v4_in(ip, [203, 0, 113, 0], 24)
    {
        Some("special-purpose range")
    } else {
        None
    }
}

fn forbidden_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if first & 0xfe00 == 0xfc00 {
        Some("unique local (fc00::/7, includes fd00:ec2::254 metadata)")
    } else if first & 0xffc0 == 0xfe80 {
        Some("link-local")
    } else if first & 0xff00 == 0xff00 {
        Some("multicast")
    } else if ip.segments()[..6] == [0, 0, 0, 0, 0, 0] {
        Some("IPv4-compatible address")
    } else if first == 0x2001 && ip.segments()[1] == 0x0db8 {
        Some("documentation range")
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub profile: String,
    pub allow: Vec<Rule>,
    pub deny: Vec<Rule>,
    pub default_ports: Vec<u16>,
}

pub const PROFILES: &[&str] = &["dev", "strict", "offline"];

/// Destinations the agents in the `base` image need: their own services and the model
/// providers they can be pointed at. Sources: Claude Code
/// https://code.claude.com/docs/en/network-config (its optional Datadog telemetry is left
/// out), GitHub Copilot's allowlist reference, Cursor's network configuration page, and the
/// Gemini CLI source.
const AGENT_APIS: &[&str] = &[
    // Anthropic / Claude Code
    "api.anthropic.com",
    "claude.ai",
    "claude.com",
    "platform.claude.com",
    "mcp-proxy.anthropic.com",
    "downloads.claude.ai",
    "code.claude.com",
    "raw.githubusercontent.com",
    // OpenAI / Codex
    "api.openai.com",
    "auth.openai.com",
    "chatgpt.com",
    // Google / Gemini CLI
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "accounts.google.com",
    "codeassist.google.com",
    // GitHub Copilot CLI
    "api.github.com",
    "*.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "default.exp-tas.com",
    // Cursor CLI
    "cursor.com",
    "downloads.cursor.com",
    "*.cursor.sh",
    "*.cursor-cdn.com",
    "*.cursorapi.com",
    // Amp, OpenCode, Kilo
    "ampcode.com",
    "*.ampcode.com",
    "opencode.ai",
    "*.opencode.ai",
    "models.dev",
    "kilo.ai",
    "*.kilo.ai",
    "kilocode.ai",
    "*.kilocode.ai",
    // Model providers used by Pi, mu, Aider, Goose, Crush, Qwen Code
    "openrouter.ai",
    "api.x.ai",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.moonshot.ai",
    "*.kimi.com",
    "api.z.ai",
    "chat.qwen.ai",
    "dashscope.aliyuncs.com",
    "dashscope-intl.aliyuncs.com",
];

const DEV_EXTRA: &[&str] = &[
    "github.com",
    "*.github.com",
    "*.githubusercontent.com",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "repo.yarnpkg.com",
    "nodejs.org",
    "bun.sh",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    "static.rust-lang.org",
    "proxy.golang.org",
    "sum.golang.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "services.gradle.org",
    "downloads.gradle.org",
    "plugins.gradle.org",
    "plugins-artifacts.gradle.org",
    "rubygems.org",
    "index.rubygems.org",
    "packagist.org",
    "repo.packagist.org",
    "getcomposer.org",
    "api.nuget.org",
    "globalcdn.nuget.org",
    "deb.debian.org",
    "security.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "*.docker.io",
    "ghcr.io",
];

impl Policy {
    pub fn profile(name: &str) -> Option<Policy> {
        let allow: Vec<&str> = match name {
            "dev" => AGENT_APIS.iter().chain(DEV_EXTRA).copied().collect(),
            "strict" => AGENT_APIS.to_vec(),
            "offline" => vec![],
            _ => return None,
        };
        Some(Policy {
            profile: name.into(),
            allow: allow
                .into_iter()
                .map(|r| Rule::parse(r).expect("built-in rule"))
                .collect(),
            deny: vec![],
            default_ports: vec![80, 443],
        })
    }

    /// Name-level decision (before resolution). `Err` carries the reason.
    pub fn decide(&self, host: &str, port: u16) -> Result<(), String> {
        let host = normalize_host(host);
        let port_ok = |r: &Rule| match r.port {
            Some(p) => p == port,
            None => self.default_ports.contains(&port),
        };
        if let Some(r) = self
            .deny
            .iter()
            .find(|r| r.matches_host(&host) && (r.port.is_none() || r.port == Some(port)))
        {
            return Err(format!("denied by rule {:?}", r.pattern));
        }
        if let Ok(ip) = host.parse::<IpAddr>()
            && let Some(why) = forbidden_ip(ip)
        {
            return Err(format!("{ip} is {why} (always denied)"));
        }
        let matching: Vec<&Rule> = self
            .allow
            .iter()
            .filter(|r| r.matches_host(&host))
            .collect();
        if matching.is_empty() {
            return Err(format!("{host} is not allowed by profile {}", self.profile));
        }
        if !matching.iter().any(|r| port_ok(r)) {
            return Err(format!("port {port} is not allowed for {host}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(rules: &[&str]) -> Policy {
        Policy {
            profile: "test".into(),
            allow: rules.iter().map(|r| Rule::parse(r).unwrap()).collect(),
            deny: vec![],
            default_ports: vec![80, 443],
        }
    }

    #[test]
    fn rule_parsing() {
        assert_eq!(Rule::parse("*").unwrap().pattern, Pattern::Any);
        assert_eq!(
            Rule::parse("Example.COM:8443").unwrap(),
            Rule {
                pattern: Pattern::Exact("example.com".into()),
                port: Some(8443)
            }
        );
        assert_eq!(
            Rule::parse("[2001:db8::/32]:443").unwrap().pattern,
            Pattern::Cidr("2001:db8::".parse().unwrap(), 32)
        );
        for bad in [
            "a*.com",
            "*.",
            "x:0",
            "1.2.3.4/33",
            "a b",
            "[::1",
            "x:99999",
        ] {
            assert!(Rule::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn matching_and_ports() {
        let pol = p(&["github.com", "*.githubusercontent.com", "api.x.com:8443"]);
        assert!(pol.decide("github.com", 443).is_ok());
        assert!(pol.decide("GitHub.com.", 80).is_ok());
        assert!(
            pol.decide("api.github.com", 443).is_err(),
            "exact does not cover subdomains"
        );
        assert!(pol.decide("raw.githubusercontent.com", 443).is_ok());
        assert!(
            pol.decide("githubusercontent.com", 443).is_err(),
            "*. excludes the apex"
        );
        assert!(pol.decide("evilgithubusercontent.com", 443).is_err());
        assert!(pol.decide("github.com", 22).is_err());
        assert!(pol.decide("api.x.com", 8443).is_ok());
        assert!(pol.decide("api.x.com", 443).is_err());
    }

    #[test]
    fn private_ranges_denied_even_with_wildcards() {
        let pol = p(&["*", "0.0.0.0/0", "[::/0]"]);
        for ip in [
            "127.0.0.1",
            "127.5.5.5",
            "10.0.0.1",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::",
            "::127.0.0.1",
        ] {
            let host = if ip.contains(':') {
                format!("[{ip}]")
            } else {
                ip.to_string()
            };
            let r = pol.decide(&host, 443);
            assert!(r.is_err(), "{ip} allowed");
            assert!(forbidden_ip(ip.parse().unwrap()).is_some(), "{ip}");
        }
        assert!(pol.decide("1.1.1.1", 443).is_ok());
        assert!(pol.decide("[2606:4700:4700::1111]", 443).is_ok());
        assert!(forbidden_ip("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn profiles() {
        let dev = Policy::profile("dev").unwrap();
        assert!(dev.decide("registry.npmjs.org", 443).is_ok());
        assert!(dev.decide("api.anthropic.com", 443).is_ok());
        assert!(dev.decide("example.com", 443).is_err());
        for host in [
            "api.anthropic.com",
            "claude.ai",
            "claude.com",
            "platform.claude.com",
            "mcp-proxy.anthropic.com",
            "downloads.claude.ai",
        ] {
            assert!(
                dev.decide(host, 443).is_ok(),
                "{host} (Claude Code login and API)"
            );
        }
        assert!(
            dev.decide("http-intake.logs.us5.datadoghq.com", 443)
                .is_err()
        );
        let strict = Policy::profile("strict").unwrap();
        assert!(strict.decide("api.anthropic.com", 443).is_ok());
        assert!(strict.decide("platform.claude.com", 443).is_ok());
        assert!(strict.decide("registry.npmjs.org", 443).is_err());
        let off = Policy::profile("offline").unwrap();
        assert!(off.decide("api.anthropic.com", 443).is_err());
        assert!(Policy::profile("nope").is_none());
    }

    #[test]
    fn deny_rules_win() {
        let mut pol = p(&["*.example.com"]);
        pol.deny.push(Rule::parse("bad.example.com").unwrap());
        assert!(pol.decide("good.example.com", 443).is_ok());
        assert!(pol.decide("bad.example.com", 443).is_err());
    }
}
