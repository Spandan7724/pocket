//! Attach-side host integrations: inline notices from daemon events, the OSC 52 clipboard
//! policy, and image paste from the host clipboard or a pasted image path.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::Sender;

use pocket_proto::rpc::{ApprovalWhat, Event, Topic};

use crate::client::Client;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clip {
    Allow,
    Deny,
    Ask,
}

/// A `[ui]` string setting from `~/.config/pocket/config.toml`.
pub fn ui_setting(key: &str) -> Option<String> {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    let text = std::fs::read_to_string(dir.join("pocket/config.toml")).ok()?;
    let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
    doc.get("ui")?.get(key)?.as_str().map(String::from)
}

/// `[ui] clipboard_osc52` (default allow).
pub fn clipboard_policy() -> Clip {
    match ui_setting("clipboard_osc52").as_deref() {
        Some("deny") => Clip::Deny,
        Some("ask") => Clip::Ask,
        _ => Clip::Allow,
    }
}

const MAX_OSC52: usize = 4 << 20;

/// Streaming filter for OSC 52 (clipboard) sequences in guest output. Writes pass, are
/// dropped, or are held for the user per policy; reads (`?`) are always dropped.
pub struct Osc52 {
    policy: Clip,
    buf: Vec<u8>,
    state: u8,
}

pub enum Held {
    /// A clipboard write waiting for the user's yes (the full sequence).
    Ask(Vec<u8>),
    Blocked(usize),
}

impl Osc52 {
    pub fn new(policy: Clip) -> Osc52 {
        Osc52 {
            policy,
            buf: vec![],
            state: 0,
        }
    }

    /// Bytes to show, plus any write held back.
    pub fn feed(&mut self, data: &[u8]) -> (Vec<u8>, Vec<Held>) {
        let mut out = Vec::with_capacity(data.len());
        let mut held = vec![];
        for &b in data {
            match self.state {
                0 => {
                    if b == 0x1b {
                        self.buf.clear();
                        self.buf.push(b);
                        self.state = 1;
                    } else {
                        out.push(b);
                    }
                }
                // Prefix match of ESC ] 5 2 ;
                1..=4 => {
                    self.buf.push(b);
                    let want = b"\x1b]52;"[self.state as usize];
                    if b == want {
                        self.state += 1;
                    } else {
                        out.append(&mut self.buf);
                        self.state = 0;
                    }
                }
                _ => {
                    self.buf.push(b);
                    let end = b == 0x07 || self.buf.ends_with(b"\x1b\\");
                    if self.buf.len() > MAX_OSC52 && !end {
                        held.push(Held::Blocked(self.buf.len()));
                        self.buf.clear();
                        self.state = 0;
                        continue;
                    }
                    if end {
                        let seq = std::mem::take(&mut self.buf);
                        self.state = 0;
                        let body = &seq[5..];
                        let payload = body.splitn(2, |c| *c == b';').nth(1).unwrap_or(&[]);
                        let read = payload.starts_with(b"?");
                        match (read, self.policy) {
                            (true, _) => {}
                            (false, Clip::Allow) => out.extend_from_slice(&seq),
                            (false, Clip::Deny) => held.push(Held::Blocked(seq.len())),
                            (false, Clip::Ask) => held.push(Held::Ask(seq)),
                        }
                    }
                }
            }
        }
        (out, held)
    }
}

/// PNG bytes from the host clipboard, if it holds an image (Wayland or X11).
pub fn clipboard_image() -> Option<Vec<u8>> {
    let run = |cmd: &str, args: &[&str]| -> Option<Vec<u8>> {
        let o = Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        o.status.success().then_some(o.stdout)
    };
    if let Ok(cmd) = std::env::var("POCKET_CLIPBOARD_IMAGE_CMD") {
        return run("/bin/sh", &["-c", &cmd]).filter(|d| d.starts_with(b"\x89PNG"));
    }
    let types_has_png = |t: Vec<u8>| {
        String::from_utf8_lossy(&t)
            .lines()
            .any(|l| l.trim() == "image/png")
    };
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        if run("wl-paste", &["--list-types"]).is_some_and(types_has_png) {
            return run("wl-paste", &["--no-newline", "--type", "image/png"]);
        }
    } else if std::env::var_os("DISPLAY").is_some()
        && run("xclip", &["-selection", "clipboard", "-t", "TARGETS", "-o"])
            .is_some_and(types_has_png)
    {
        return run(
            "xclip",
            &["-selection", "clipboard", "-t", "image/png", "-o"],
        );
    }
    None
}

/// An image file the user pasted (a dropped file is pasted as its path).
pub fn pasted_image_path(text: &[u8]) -> Option<Vec<u8>> {
    let t = std::str::from_utf8(text).ok()?.trim();
    let t = t.trim_matches(|c| c == '\'' || c == '"');
    let t = t.strip_prefix("file://").unwrap_or(t);
    if !t.starts_with('/') || t.contains('\n') {
        return None;
    }
    let lower = t.to_ascii_lowercase();
    if ![".png", ".jpg", ".jpeg", ".gif", ".webp"]
        .iter()
        .any(|e| lower.ends_with(e))
    {
        return None;
    }
    let mut f = std::fs::File::open(t).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > 32 << 20 {
        return None;
    }
    let mut data = vec![];
    f.read_to_end(&mut data).ok()?;
    Some(data)
}

fn describe(ev: &Event, pocket: &str) -> Option<String> {
    match ev {
        Event::Port {
            pocket: p,
            port,
            open: true,
        } if p == pocket => Some(format!(
            "port {} forwarded to 127.0.0.1:{} · pocket open {pocket} {}",
            port.guest, port.host, port.guest
        )),
        Event::Approval(a) if a.pocket == pocket => Some(match &a.what {
            ApprovalWhat::Network { host, .. } => format!("blocked {host} — Ctrl-] a to review"),
            ApprovalWhat::SshSign { comment, key } => format!(
                "ssh signature requested ({}) — Ctrl-] a to review",
                if comment.is_empty() { key } else { comment }
            ),
            ApprovalWhat::File { path } => {
                format!("the pocket asks for {path} — Ctrl-] a to review")
            }
        }),
        Event::Notice {
            pocket: p,
            kind,
            title,
            body,
            ..
        } if p == pocket && kind != "bell" => Some(if kind == "url" {
            format!("opened {body} in your browser")
        } else if body.is_empty() {
            title.clone()
        } else {
            format!("{title}: {body}")
        }),
        _ => None,
    }
}

/// Forwards this pocket's notices to `tx` (and a byte to `wake`) until the daemon goes away.
pub fn subscribe(pocket: String, tx: Sender<String>, wake: i32) {
    std::thread::spawn(move || {
        let Ok(mut c) = Client::connect() else { return };
        if c.subscribe(vec![Topic::Notices]).is_err() {
            return;
        }
        while let Ok(ev) = c.next_event() {
            if let Some(text) = describe(&ev, &pocket) {
                if tx.send(text).is_err() {
                    return;
                }
                // SAFETY: write(2) on our own pipe.
                unsafe { libc::write(wake, [1u8].as_ptr().cast(), 1) };
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_policies() {
        let seq = b"\x1b]52;c;aGVsbG8=\x07";
        let mut a = Osc52::new(Clip::Allow);
        let (out, held) = a.feed(&[b"x".as_slice(), seq, b"y"].concat());
        assert_eq!(out, [b"x".as_slice(), seq, b"y"].concat());
        assert!(held.is_empty());
        let mut d = Osc52::new(Clip::Deny);
        let (out, held) = d.feed(&[b"x".as_slice(), seq, b"y"].concat());
        assert_eq!(out, b"xy");
        assert!(matches!(held[0], Held::Blocked(_)));
        // Reads are never forwarded, even when writes are allowed; split chunks work.
        let mut a = Osc52::new(Clip::Allow);
        let (o1, _) = a.feed(b"a\x1b]5");
        let (o2, _) = a.feed(b"2;c;?\x1b\\b");
        assert_eq!([o1, o2].concat(), b"ab");
        let mut k = Osc52::new(Clip::Ask);
        let (out, held) = k.feed(seq);
        assert!(out.is_empty() && matches!(&held[0], Held::Ask(s) if s == seq));
        // Other escapes pass untouched.
        let mut a = Osc52::new(Clip::Deny);
        let (out, _) = a.feed(b"\x1b]0;title\x07\x1b[31mred");
        assert_eq!(out, b"\x1b]0;title\x07\x1b[31mred");
    }
}
