//! Notifications from session output (M8): a bare BEL, OSC 9 (`ESC ] 9 ; text`) and OSC 777
//! (`ESC ] 777 ; notify ; title ; body`) become host notifications. The scanner keeps state
//! across output chunks and never alters the bytes passed to clients.

use std::time::{Duration, Instant};

const MAX_OSC: usize = 2048;
const MIN_GAP: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
pub enum Found {
    Bell,
    Notify { title: String, body: String },
}

#[derive(Default)]
pub struct Scanner {
    state: St,
    osc: Vec<u8>,
    last: Option<Instant>,
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
enum St {
    #[default]
    Text,
    Esc,
    Osc,
    OscEsc,
    /// Other escape strings (DCS, APC, PM, SOS): skipped to their terminator.
    Str,
    StrEsc,
}

fn clean(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .filter(|c| !c.is_control())
        .take(1024)
        .collect()
}

fn parse_osc(osc: &[u8]) -> Option<Found> {
    let text = std::str::from_utf8(osc).ok()?;
    if let Some(rest) = text.strip_prefix("9;") {
        // `9;4;…` is a progress report (ConEmu/Windows Terminal), not a notification.
        if rest.starts_with("4;") {
            return None;
        }
        return Some(Found::Notify {
            title: String::new(),
            body: clean(rest.as_bytes()),
        });
    }
    let rest = text.strip_prefix("777;notify;")?;
    let (title, body) = rest.split_once(';').unwrap_or((rest, ""));
    Some(Found::Notify {
        title: clean(title.as_bytes()),
        body: clean(body.as_bytes()),
    })
}

impl Scanner {
    /// Notifications found in `data` (rate-limited to one a second).
    pub fn feed(&mut self, data: &[u8]) -> Vec<Found> {
        let mut out = vec![];
        for &b in data {
            match (self.state, b) {
                (St::Text, 0x1b) => self.state = St::Esc,
                (St::Text, 0x07) => out.push(Found::Bell),
                (St::Text, _) => {}
                (St::Esc, b']') => {
                    self.state = St::Osc;
                    self.osc.clear();
                }
                (St::Esc, b'P' | b'_' | b'^' | b'X') => self.state = St::Str,
                (St::Esc, 0x1b) => {}
                (St::Esc, _) => self.state = St::Text,
                (St::Osc, 0x07) => {
                    out.extend(parse_osc(&self.osc));
                    self.state = St::Text;
                }
                (St::Osc, 0x1b) => self.state = St::OscEsc,
                (St::Osc, _) => {
                    if self.osc.len() < MAX_OSC {
                        self.osc.push(b);
                    }
                }
                (St::OscEsc, b'\\') => {
                    out.extend(parse_osc(&self.osc));
                    self.state = St::Text;
                }
                (St::OscEsc, _) => self.state = St::Text,
                (St::Str, 0x1b) => self.state = St::StrEsc,
                (St::Str, 0x07) => self.state = St::Text,
                (St::Str, _) => {}
                (St::StrEsc, b'\\') => self.state = St::Text,
                (St::StrEsc, _) => self.state = St::Str,
            }
        }
        if out.is_empty() {
            return out;
        }
        let now = Instant::now();
        if self.last.is_some_and(|t| now.duration_since(t) < MIN_GAP) {
            return vec![];
        }
        self.last = Some(now);
        // A notification wins over the bell that often accompanies it.
        let notify = out.iter().position(|f| matches!(f, Found::Notify { .. }));
        vec![match notify {
            Some(i) => out.swap_remove(i),
            None => Found::Bell,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bells_and_osc_notifications() {
        let mut s = Scanner::default();
        assert_eq!(s.feed(b"\x1b]0;title\x07plain"), vec![]);
        assert_eq!(s.feed(b"done\x07"), vec![Found::Bell]);
        let mut s = Scanner::default();
        assert_eq!(
            s.feed(b"\x1b]777;notify;Claude;Waiting for input\x1b\\"),
            vec![Found::Notify {
                title: "Claude".into(),
                body: "Waiting for input".into()
            }]
        );
        let mut s = Scanner::default();
        assert_eq!(s.feed(b"\x1b]9;4;1;50\x07"), vec![]);
        // Split across chunks.
        assert_eq!(s.feed(b"\x1b]9;Build "), vec![]);
        assert_eq!(
            s.feed(b"finished\x07"),
            vec![Found::Notify {
                title: String::new(),
                body: "Build finished".into()
            }]
        );
        // Rate limit.
        assert_eq!(s.feed(b"\x07"), vec![]);
        // BEL inside DCS is not a bell.
        let mut s = Scanner::default();
        assert_eq!(s.feed(b"\x1bPq#0\x07"), vec![]);
    }
}

/// The last line of a session's output with escape sequences removed, for the host's
/// "waiting at a prompt" check. A carriage return starts the line over (redraws).
#[derive(Default)]
pub struct Tail {
    cur: Vec<u8>,
    last: Vec<u8>,
    esc: u8,
    /// A carriage return: the next printable byte starts the line over.
    cr: bool,
}

impl Tail {
    pub fn feed(&mut self, data: &[u8]) {
        const LIMIT: usize = pocket_proto::guest::MAX_TAIL;
        for &b in data {
            match self.esc {
                // ESC seen: `[` = CSI, `]` = OSC, else a two-byte sequence.
                1 => {
                    self.esc = match b {
                        b'[' => 2,
                        b']' | b'P' | b'_' | b'^' | b'X' => 3,
                        _ => 0,
                    }
                }
                2 => {
                    if (0x40..=0x7e).contains(&b) {
                        self.esc = 0;
                    }
                }
                3 => match b {
                    0x07 => self.esc = 0,
                    0x1b => self.esc = 4,
                    _ => {}
                },
                4 => self.esc = if b == b'\\' { 0 } else { 3 },
                _ => match b {
                    0x1b => self.esc = 1,
                    b'\n' => {
                        if self.cur.iter().any(|c| !c.is_ascii_whitespace()) {
                            self.last = std::mem::take(&mut self.cur);
                        }
                        self.cur.clear();
                        self.cr = false;
                    }
                    b'\r' => self.cr = true,
                    0x08 => {
                        self.cur.pop();
                    }
                    b if b < 0x20 || b == 0x7f => {}
                    b => {
                        if std::mem::take(&mut self.cr) {
                            self.cur.clear();
                        }
                        if self.cur.len() < LIMIT {
                            self.cur.push(b);
                        }
                    }
                },
            }
        }
    }

    pub fn text(&self) -> String {
        let src = if self.cur.iter().any(|c| !c.is_ascii_whitespace()) {
            &self.cur
        } else {
            &self.last
        };
        let mut s: String = String::from_utf8_lossy(src)
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        while s.len() > pocket_proto::guest::MAX_TAIL {
            s.pop();
        }
        s
    }
}

#[cfg(test)]
mod tail_tests {
    use super::Tail;

    #[test]
    fn strips_escapes_and_keeps_the_last_line() {
        let mut t = Tail::default();
        t.feed(b"building...\r\n\x1b[1;32mdone\x1b[0m\r\n\x1b]0;title\x07Allow? [y/n] ");
        assert_eq!(t.text(), "Allow? [y/n] ");
        t.feed(b"\r\n");
        assert_eq!(t.text(), "Allow? [y/n] ");
        t.feed(b"progress 10%\rprogress 20%");
        assert_eq!(t.text(), "progress 20%");
    }
}
