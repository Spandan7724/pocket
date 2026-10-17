//! Colours and glyphs (STYLES.md). State is always shown by a glyph and a word; colour only
//! reinforces it, so `NO_COLOR` and colour-blind users lose nothing.

use pocket_proto::rpc::{PocketState, SessionState};
use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Dark,
    Light,
    /// `NO_COLOR`: modifiers only.
    Mono,
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub mode: Mode,
}

impl Theme {
    /// `POCKET_THEME=dark|light|mono` or `[ui] theme`, then `NO_COLOR`, then the terminal's
    /// `COLORFGBG` (a light background has a high second field), else dark.
    pub fn detect(configured: Option<&str>) -> Theme {
        let env = std::env::var("POCKET_THEME").ok();
        let pick = env.as_deref().or(configured).unwrap_or("auto");
        let mode = match pick {
            "dark" => Mode::Dark,
            "light" => Mode::Light,
            "mono" | "none" => Mode::Mono,
            _ if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) => Mode::Mono,
            _ => match std::env::var("COLORFGBG")
                .ok()
                .and_then(|v| v.rsplit(';').next()?.parse::<u8>().ok())
            {
                Some(bg) if bg == 7 || bg >= 9 => Mode::Light,
                _ => Mode::Dark,
            },
        };
        Theme { mode }
    }

    pub fn new(mode: Mode) -> Theme {
        Theme { mode }
    }

    fn fg(&self, c: Color) -> Style {
        match self.mode {
            Mode::Mono => Style::default(),
            _ => Style::default().fg(c),
        }
    }

    /// Accent for active controls, the selection and key labels.
    pub fn accent(&self) -> Style {
        self.fg(match self.mode {
            Mode::Light => Color::Magenta,
            _ => Color::Cyan,
        })
    }

    pub fn title(&self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }

    pub fn dim(&self) -> Style {
        Style::default().add_modifier(Modifier::DIM)
    }

    pub fn ok(&self) -> Style {
        self.fg(Color::Green)
    }

    pub fn bad(&self) -> Style {
        self.fg(Color::Red)
    }

    /// Needs the user (waiting for input, approvals, warnings).
    pub fn attention(&self) -> Style {
        self.fg(Color::Magenta).add_modifier(Modifier::BOLD)
    }

    pub fn selected(&self) -> Style {
        match self.mode {
            Mode::Mono => Style::default().add_modifier(Modifier::REVERSED),
            Mode::Dark => Style::default().bg(Color::Indexed(237)),
            Mode::Light => Style::default().bg(Color::Indexed(254)),
        }
    }

    pub fn border(&self, focused: bool) -> Style {
        if focused { self.accent() } else { self.dim() }
    }

    pub fn key(&self) -> Style {
        self.accent().add_modifier(Modifier::BOLD)
    }

    pub fn added(&self) -> Style {
        self.fg(Color::Green)
    }

    pub fn removed(&self) -> Style {
        self.fg(Color::Red)
    }

    pub fn hunk(&self) -> Style {
        self.accent()
    }
}

pub fn pocket_glyph(s: &PocketState) -> &'static str {
    match s {
        PocketState::Running => "●",
        PocketState::Creating => "◔",
        PocketState::Paused => "‖",
        PocketState::Hibernated => "◌",
        PocketState::Stopped => "■",
        PocketState::Broken { .. } => "⚠",
    }
}

pub fn pocket_style(t: &Theme, s: &PocketState) -> Style {
    match s {
        PocketState::Running => t.ok(),
        PocketState::Broken { .. } => t.bad(),
        PocketState::Creating => t.accent(),
        _ => t.dim(),
    }
}

pub fn session_glyph(s: SessionState, code: Option<i32>) -> &'static str {
    match s {
        SessionState::Working => "●",
        SessionState::Waiting => "○",
        SessionState::Idle => "·",
        SessionState::Exited if code == Some(0) => "✓",
        SessionState::Exited => "✗",
    }
}

pub fn session_label(s: SessionState) -> &'static str {
    match s {
        SessionState::Working => "working",
        SessionState::Waiting => "input needed",
        SessionState::Idle => "idle",
        SessionState::Exited => "exited",
    }
}

pub fn session_style(t: &Theme, s: SessionState, code: Option<i32>) -> Style {
    match s {
        SessionState::Working => t.ok(),
        SessionState::Waiting => t.attention(),
        SessionState::Exited if code == Some(0) => t.dim(),
        SessionState::Exited => t.bad(),
        SessionState::Idle => t.dim(),
    }
}
