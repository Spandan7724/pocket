//! Dashboard state and input handling. Pure: no I/O. Everything that talks to the daemon
//! goes out as a [`Cmd`] to the worker and comes back as an [`Update`], so a slow or dead
//! daemon can never stall a frame.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pocket_proto::guest::SessionInfo;
use pocket_proto::rpc::{
    ApprovalInfo, Decision, NetEntry, PocketInfo, PocketState, PortInfo, SessionState,
    session_state,
};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent};

use crate::theme::Theme;

pub type Screen = Arc<Mutex<vt100::Parser>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Pause,
    Resume,
    Hibernate,
    Stop,
    Start,
    Remove,
    Apply,
    Pr,
    NewSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NewSpec {
    pub name: Option<String>,
    /// `None` = scratch pocket.
    pub repo: Option<String>,
    pub preset: String,
    pub cpus: Option<u8>,
    pub memory: Option<String>,
    pub net: String,
    /// Default session command (`None` = shell).
    pub agent: Option<String>,
}

/// Requests to the worker. Sending never blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    Refresh,
    LoadDiff(String),
    LoadNet(String),
    LoadPorts(String),
    /// Diff stat for a removal confirmation.
    LoadStat(String),
    /// The sessions to stream into panes (anything else is closed).
    Previews(Vec<(String, String)>),
    Input(String, String, Vec<u8>),
    Pocket(String, Action),
    New(NewSpec),
    Approve(u64, Decision),
    OpenPort(u16),
    /// Remember the wizard's last values.
    SavePrefs(NewSpec),
}

pub enum Update {
    Connected(bool),
    Pockets(Vec<PocketInfo>),
    Sessions(String, Vec<SessionInfo>),
    Diff(String, Result<String, String>),
    Stat(String, Result<String, String>),
    Net(String, Result<Vec<NetEntry>, String>),
    Ports(String, Result<Vec<PortInfo>, String>),
    Approvals(Vec<ApprovalInfo>),
    /// A live request seen on the event stream (header rate).
    Request(NetEntry),
    Preview(String, String, Screen),
    PreviewClosed(String, String),
    /// A preview screen changed.
    Redraw,
    Status(String),
    Error(String),
    Prefs(NewSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Quit,
    Attach {
        pocket: String,
        session: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Session,
    Diff,
    Network,
    Ports,
    Info,
}

pub const TABS: [Tab; 5] = [Tab::Session, Tab::Diff, Tab::Network, Tab::Ports, Tab::Info];

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Tab::Session => "Session",
            Tab::Diff => "Diff",
            Tab::Network => "Network",
            Tab::Ports => "Ports",
            Tab::Info => "Info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Tree,
    Grid,
}

pub enum Loaded<T> {
    Loading,
    Ready(T),
    Failed(String),
}

#[derive(Default)]
pub struct Details {
    pub diff: Option<Loaded<String>>,
    pub net: Option<Loaded<Vec<NetEntry>>>,
    pub ports: Option<Loaded<Vec<PortInfo>>>,
}

pub struct SessionRow {
    pub info: SessionInfo,
    pub state: SessionState,
}

pub struct PocketRow {
    pub info: PocketInfo,
    pub sessions: Vec<SessionRow>,
    pub expanded: bool,
}

impl PocketRow {
    pub fn waiting(&self) -> usize {
        self.sessions
            .iter()
            .filter(|s| s.state == SessionState::Waiting)
            .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    Pocket(usize),
    Session(usize, usize),
}

pub struct Field {
    pub label: &'static str,
    pub value: String,
    /// Cycled with ←/→ when set; free text otherwise.
    pub choices: Vec<&'static str>,
    pub hint: &'static str,
}

pub struct Wizard {
    pub fields: Vec<Field>,
    pub focus: usize,
}

pub struct PaletteItem {
    pub label: &'static str,
    pub key: &'static str,
    pub run: fn(&mut App) -> Vec<Cmd>,
}

pub enum Overlay {
    Help,
    Palette {
        query: String,
        sel: usize,
    },
    Wizard(Wizard),
    Confirm {
        title: String,
        lines: Vec<String>,
        /// Pocket whose diff stat fills in the "what is lost" line.
        stat_for: Option<String>,
        cmd: Cmd,
    },
}

pub struct App {
    pub pockets: Vec<PocketRow>,
    pub sel: usize,
    pub tree_offset: usize,
    pub tab: Tab,
    pub view: View,
    pub overlay: Option<Overlay>,
    pub filter: String,
    pub filtering: bool,
    pub theme: Theme,
    pub status: Option<(String, Instant, bool)>,
    pub details: HashMap<String, Details>,
    pub approvals: Vec<ApprovalInfo>,
    pub screens: HashMap<(String, String), Screen>,
    /// Keys go to the previewed session (Ctrl-] leaves).
    pub interact: bool,
    pub grid_focus: usize,
    pub zoom: bool,
    pub detail_scroll: u16,
    pub requests: VecDeque<u64>,
    pub connected: bool,
    pub loaded: bool,
    pub prefs: NewSpec,
    pub stat: HashMap<String, Loaded<String>>,
    /// Host RAM, for the header.
    pub host_mem: u64,
    /// Last frame's render time.
    pub frame_us: u64,
    /// Tree rows' screen area from the last frame (mouse hits).
    pub tree_area: ratatui::layout::Rect,
    pub now_ms: u64,
    pub cwd_repo: Option<String>,
    last_previews: Vec<(String, String)>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl App {
    pub fn new(theme: Theme) -> App {
        App {
            pockets: vec![],
            sel: 0,
            tree_offset: 0,
            tab: Tab::Session,
            view: View::Tree,
            overlay: None,
            filter: String::new(),
            filtering: false,
            theme,
            status: None,
            details: HashMap::new(),
            approvals: vec![],
            screens: HashMap::new(),
            interact: false,
            grid_focus: 0,
            zoom: false,
            detail_scroll: 0,
            requests: VecDeque::new(),
            connected: true,
            loaded: false,
            prefs: NewSpec {
                preset: "base".into(),
                net: "dev".into(),
                ..Default::default()
            },
            stat: HashMap::new(),
            host_mem: 0,
            frame_us: 0,
            tree_area: Default::default(),
            now_ms: now_ms(),
            cwd_repo: None,
            last_previews: vec![],
        }
    }

    // ---- rows and selection ------------------------------------------------------------

    fn matches(&self, p: &PocketRow) -> bool {
        self.filter.is_empty()
            || p.info.name.contains(&self.filter)
            || p.sessions
                .iter()
                .any(|s| s.info.name.contains(&self.filter))
    }

    pub fn rows(&self) -> Vec<Row> {
        let mut out = vec![];
        for (i, p) in self.pockets.iter().enumerate() {
            if !self.matches(p) {
                continue;
            }
            out.push(Row::Pocket(i));
            if p.expanded {
                for j in 0..p.sessions.len() {
                    out.push(Row::Session(i, j));
                }
            }
        }
        out
    }

    pub fn current(&self) -> Option<Row> {
        let rows = self.rows();
        rows.get(self.sel.min(rows.len().saturating_sub(1)))
            .copied()
    }

    pub fn current_pocket(&self) -> Option<&PocketRow> {
        match self.current()? {
            Row::Pocket(i) | Row::Session(i, _) => self.pockets.get(i),
        }
    }

    /// The session the detail pane shows: the selected one, else the pocket's busiest.
    pub fn current_session(&self) -> Option<(&PocketRow, &SessionRow)> {
        match self.current()? {
            Row::Session(i, j) => {
                let p = self.pockets.get(i)?;
                Some((p, p.sessions.get(j)?))
            }
            Row::Pocket(i) => {
                let p = self.pockets.get(i)?;
                let s = p
                    .sessions
                    .iter()
                    .filter(|s| s.state != SessionState::Exited)
                    .max_by_key(|s| {
                        (
                            s.state == SessionState::Waiting,
                            s.state == SessionState::Working,
                            s.info.last_output_unix_ms,
                        )
                    })?;
                Some((p, s))
            }
        }
    }

    /// Sessions in the grid: live sessions of running pockets, those needing input first.
    pub fn grid(&self) -> Vec<(usize, usize)> {
        let mut v: Vec<(usize, usize)> = vec![];
        for (i, p) in self.pockets.iter().enumerate() {
            if p.info.state != PocketState::Running || !self.matches(p) {
                continue;
            }
            for (j, s) in p.sessions.iter().enumerate() {
                if s.state != SessionState::Exited {
                    v.push((i, j));
                }
            }
        }
        v.sort_by_key(|&(i, j)| {
            let s = &self.pockets[i].sessions[j];
            (
                s.state != SessionState::Waiting,
                s.state != SessionState::Working,
                std::cmp::Reverse(s.info.last_output_unix_ms),
            )
        });
        v.truncate(9);
        v
    }

    fn select_by(&mut self, delta: isize) {
        let n = self.rows().len();
        if n == 0 {
            self.sel = 0;
            return;
        }
        self.sel = (self.sel as isize + delta).clamp(0, n as isize - 1) as usize;
        self.detail_scroll = 0;
    }

    pub fn set_status(&mut self, msg: impl Into<String>, error: bool) {
        self.status = Some((msg.into(), Instant::now(), error));
    }

    pub fn status_line(&self) -> Option<(&str, bool)> {
        self.status
            .as_ref()
            .filter(|(_, t, e)| t.elapsed() < Duration::from_secs(if *e { 8 } else { 4 }))
            .map(|(m, _, e)| (m.as_str(), *e))
    }

    pub fn requests_per_min(&self) -> usize {
        let cut = self.now_ms.saturating_sub(60_000);
        self.requests.iter().filter(|&&t| t >= cut).count()
    }

    // ---- updates from the worker -----------------------------------------------------

    pub fn apply(&mut self, u: Update) -> Vec<Cmd> {
        self.now_ms = now_ms();
        let mut out = vec![];
        match u {
            Update::Connected(c) => {
                self.connected = c;
                if !c {
                    self.set_status("pocketd is not reachable — retrying", true);
                }
            }
            Update::Pockets(list) => {
                let keep_name = self.current_pocket().map(|p| p.info.name.clone());
                let keep_session = match self.current() {
                    Some(Row::Session(i, j)) => self
                        .pockets
                        .get(i)
                        .and_then(|p| p.sessions.get(j))
                        .map(|s| s.info.name.clone()),
                    _ => None,
                };
                let mut old: HashMap<String, PocketRow> = self
                    .pockets
                    .drain(..)
                    .map(|p| (p.info.name.clone(), p))
                    .collect();
                self.pockets = list
                    .into_iter()
                    .map(|info| match old.remove(&info.name) {
                        Some(mut p) => {
                            p.info = info;
                            p
                        }
                        None => PocketRow {
                            expanded: true,
                            info,
                            sessions: vec![],
                        },
                    })
                    .collect();
                self.pockets.sort_by(|a, b| a.info.name.cmp(&b.info.name));
                self.loaded = true;
                self.reselect(keep_name.as_deref(), keep_session.as_deref());
                out.extend(self.wanted_previews());
            }
            Update::Sessions(pocket, list) => {
                let now = self.now_ms;
                if let Some(p) = self.pockets.iter_mut().find(|p| p.info.name == pocket) {
                    p.sessions = list
                        .into_iter()
                        .map(|info| SessionRow {
                            state: session_state(&info, now),
                            info,
                        })
                        .collect();
                }
                out.extend(self.wanted_previews());
            }
            Update::Diff(p, r) => {
                self.details.entry(p).or_default().diff = Some(loaded(r));
            }
            Update::Stat(p, r) => {
                self.stat.insert(p, loaded(r));
            }
            Update::Net(p, r) => {
                self.details.entry(p).or_default().net = Some(loaded(r));
            }
            Update::Ports(p, r) => {
                self.details.entry(p).or_default().ports = Some(loaded(r));
            }
            Update::Approvals(a) => self.approvals = a,
            Update::Request(e) => {
                self.requests.push_back(e.ts_ms);
                while self.requests.len() > 10_000 {
                    self.requests.pop_front();
                }
                if let Some(Loaded::Ready(v)) =
                    self.details.get_mut(&e.pocket).and_then(|d| d.net.as_mut())
                {
                    v.push(e);
                }
            }
            Update::Preview(p, s, screen) => {
                self.screens.insert((p, s), screen);
            }
            Update::PreviewClosed(p, s) => {
                self.screens.remove(&(p.clone(), s.clone()));
                if self.interact
                    && self
                        .current_session()
                        .is_some_and(|(cp, cs)| cp.info.name == p && cs.info.name == s)
                {
                    self.interact = false;
                }
            }
            Update::Redraw => {}
            Update::Status(m) => self.set_status(m, false),
            Update::Error(m) => self.set_status(m, true),
            Update::Prefs(p) => self.prefs = p,
        }
        out
    }

    fn reselect(&mut self, pocket: Option<&str>, session: Option<&str>) {
        let rows = self.rows();
        if let Some(name) = pocket {
            let at = rows.iter().position(|r| match *r {
                Row::Session(i, j) => {
                    self.pockets[i].info.name == name
                        && session.is_some_and(|s| self.pockets[i].sessions[j].info.name == s)
                }
                Row::Pocket(i) => session.is_none() && self.pockets[i].info.name == name,
            });
            let at = at.or_else(|| {
                rows.iter()
                    .position(|r| matches!(*r, Row::Pocket(i) if self.pockets[i].info.name == name))
            });
            if let Some(at) = at {
                self.sel = at;
                return;
            }
        }
        self.sel = self.sel.min(rows.len().saturating_sub(1));
    }

    /// Previews follow what is on screen: the detail pane's session, or the grid.
    pub fn wanted_previews(&mut self) -> Vec<Cmd> {
        let want: Vec<(String, String)> = match self.view {
            View::Grid => self
                .grid()
                .into_iter()
                .map(|(i, j)| {
                    let p = &self.pockets[i];
                    (p.info.name.clone(), p.sessions[j].info.name.clone())
                })
                .collect(),
            View::Tree if self.tab == Tab::Session => self
                .current_session()
                .filter(|(p, s)| {
                    p.info.state == PocketState::Running && s.state != SessionState::Exited
                })
                .map(|(p, s)| vec![(p.info.name.clone(), s.info.name.clone())])
                .unwrap_or_default(),
            View::Tree => vec![],
        };
        if want == self.last_previews {
            return vec![];
        }
        self.last_previews = want.clone();
        vec![Cmd::Previews(want)]
    }

    /// Loads what the visible tab needs.
    fn load_tab(&mut self) -> Vec<Cmd> {
        let Some(p) = self.current_pocket().map(|p| p.info.name.clone()) else {
            return vec![];
        };
        let d = self.details.entry(p.clone()).or_default();
        match self.tab {
            Tab::Diff if d.diff.is_none() => {
                d.diff = Some(Loaded::Loading);
                vec![Cmd::LoadDiff(p)]
            }
            Tab::Network if d.net.is_none() => {
                d.net = Some(Loaded::Loading);
                vec![Cmd::LoadNet(p)]
            }
            Tab::Ports if d.ports.is_none() => {
                d.ports = Some(Loaded::Loading);
                vec![Cmd::LoadPorts(p)]
            }
            _ => vec![],
        }
    }

    fn after_move(&mut self) -> Vec<Cmd> {
        let mut out = self.wanted_previews();
        out.extend(self.load_tab());
        out
    }

    // ---- input -----------------------------------------------------------------------

    pub fn mouse(&mut self, m: MouseEvent) -> Vec<Cmd> {
        use ratatui::crossterm::event::{MouseButton, MouseEventKind};
        match m.kind {
            MouseEventKind::ScrollDown => {
                self.select_by(1);
                self.after_move()
            }
            MouseEventKind::ScrollUp => {
                self.select_by(-1);
                self.after_move()
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let a = self.tree_area;
                if self.overlay.is_none()
                    && m.column >= a.x
                    && m.column < a.x + a.width
                    && m.row >= a.y
                    && m.row < a.y + a.height
                {
                    let at = self.tree_offset + (m.row - a.y) as usize;
                    if at < self.rows().len() {
                        self.sel = at;
                        return self.after_move();
                    }
                }
                vec![]
            }
            _ => vec![],
        }
    }

    pub fn paste(&mut self, text: &str) -> Vec<Cmd> {
        if self.interact
            && let Some((p, s)) = self.current_session()
        {
            let mut b = b"\x1b[200~".to_vec();
            b.extend(text.as_bytes());
            b.extend(b"\x1b[201~");
            return vec![Cmd::Input(p.info.name.clone(), s.info.name.clone(), b)];
        }
        if let Some(Overlay::Wizard(w)) = &mut self.overlay {
            let f = &mut w.fields[w.focus];
            if f.choices.is_empty() {
                f.value.push_str(text.trim());
            }
        } else if let Some(Overlay::Palette { query, .. }) = &mut self.overlay {
            query.push_str(text.trim());
        } else if self.filtering {
            self.filter.push_str(text.trim());
        }
        vec![]
    }

    /// Returns the commands to send and, when the dashboard should exit, why.
    pub fn key(&mut self, k: KeyEvent) -> (Vec<Cmd>, Option<Outcome>) {
        self.now_ms = now_ms();
        if k.kind == KeyEventKind::Release {
            return (vec![], None);
        }
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if self.interact {
            if ctrl && k.code == KeyCode::Char(']') {
                self.interact = false;
                self.set_status("left the session; keys control the dashboard again", false);
                return (vec![], None);
            }
            if let Some((p, s)) = self.current_session() {
                let bytes = key_bytes(k);
                if !bytes.is_empty() {
                    return (
                        vec![Cmd::Input(p.info.name.clone(), s.info.name.clone(), bytes)],
                        None,
                    );
                }
            }
            return (vec![], None);
        }
        if let Some(o) = self.overlay.take() {
            return self.overlay_key(o, k);
        }
        if self.filtering {
            match k.code {
                KeyCode::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.sel = 0;
            return (self.after_move(), None);
        }
        if ctrl && k.code == KeyCode::Char('p') {
            self.overlay = Some(Overlay::Palette {
                query: String::new(),
                sel: 0,
            });
            return (vec![], None);
        }
        if ctrl && k.code == KeyCode::Char('c') {
            return (vec![], Some(Outcome::Quit));
        }
        let cmds = match k.code {
            KeyCode::Char('q') => return (vec![], Some(Outcome::Quit)),
            KeyCode::Down | KeyCode::Char('j') => {
                if self.view == View::Grid {
                    self.grid_focus =
                        (self.grid_focus + 1).min(self.grid().len().saturating_sub(1));
                    vec![]
                } else {
                    self.select_by(1);
                    self.after_move()
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.view == View::Grid {
                    self.grid_focus = self.grid_focus.saturating_sub(1);
                    vec![]
                } else {
                    self.select_by(-1);
                    self.after_move()
                }
            }
            KeyCode::Home => {
                self.sel = 0;
                self.after_move()
            }
            KeyCode::End => {
                self.sel = self.rows().len().saturating_sub(1);
                self.after_move()
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(Row::Pocket(i) | Row::Session(i, _)) = self.current() {
                    self.pockets[i].expanded = false;
                    let at = self.rows().iter().position(|r| *r == Row::Pocket(i));
                    self.sel = at.unwrap_or(0);
                }
                self.after_move()
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(Row::Pocket(i)) = self.current() {
                    self.pockets[i].expanded = true;
                }
                vec![]
            }
            KeyCode::Enter => return (vec![], self.attach_target()),
            KeyCode::Tab | KeyCode::BackTab => {
                let i = TABS.iter().position(|t| *t == self.tab).unwrap_or(0);
                let n = if k.code == KeyCode::Tab {
                    i + 1
                } else {
                    i + TABS.len() - 1
                };
                self.tab = TABS[n % TABS.len()];
                self.detail_scroll = 0;
                self.after_move()
            }
            KeyCode::Char(c @ '1'..='5') => {
                self.tab = TABS[(c as u8 - b'1') as usize];
                self.detail_scroll = 0;
                self.after_move()
            }
            KeyCode::Char('d') => self.goto_tab(Tab::Diff),
            KeyCode::Char('N') => self.goto_tab(Tab::Network),
            KeyCode::Char('P') if self.tab != Tab::Diff => self.goto_tab(Tab::Ports),
            KeyCode::Char('I') => self.goto_tab(Tab::Info),
            KeyCode::Char('g') => {
                self.view = if self.view == View::Grid {
                    View::Tree
                } else {
                    View::Grid
                };
                self.grid_focus = 0;
                self.zoom = false;
                self.wanted_previews()
            }
            KeyCode::Char('z') if self.view == View::Grid => {
                self.zoom = !self.zoom;
                vec![]
            }
            KeyCode::Char('i') => {
                if self.tab == Tab::Session
                    && self.view == View::Tree
                    && let Some((p, s)) = self.current_session()
                {
                    let key = (p.info.name.clone(), s.info.name.clone());
                    if self.screens.contains_key(&key) {
                        self.interact = true;
                        self.set_status("typing into the session — Ctrl-] to leave", false);
                    } else {
                        self.set_status("no live view of this session yet", true);
                    }
                }
                vec![]
            }
            KeyCode::Char('n') => {
                self.overlay = Some(Overlay::Wizard(self.wizard()));
                vec![]
            }
            KeyCode::Char('t') => self.on_pocket(Action::NewSession),
            KeyCode::Char('p') => {
                let resume = self.current_pocket().is_some_and(|p| {
                    matches!(p.info.state, PocketState::Paused | PocketState::Hibernated)
                });
                self.on_pocket(if resume {
                    Action::Resume
                } else {
                    Action::Pause
                })
            }
            KeyCode::Char('H') => self.on_pocket(Action::Hibernate),
            KeyCode::Char('s') => {
                let start = self.current_pocket().is_some_and(|p| {
                    matches!(
                        p.info.state,
                        PocketState::Stopped | PocketState::Broken { .. }
                    )
                });
                if start {
                    self.on_pocket(Action::Start)
                } else {
                    self.confirm_pocket(Action::Stop)
                }
            }
            KeyCode::Char('x') => self.confirm_pocket(Action::Remove),
            KeyCode::Char('a') if self.tab == Tab::Diff => self.confirm_pocket(Action::Apply),
            KeyCode::Char('P') if self.tab == Tab::Diff => self.confirm_pocket(Action::Pr),
            KeyCode::Char('r') => {
                if let Some(p) = self.current_pocket().map(|p| p.info.name.clone()) {
                    self.details.remove(&p);
                }
                let mut v = vec![Cmd::Refresh];
                v.extend(self.load_tab());
                v
            }
            KeyCode::Char('o') if self.tab == Tab::Network => self.approve(Decision::Once),
            KeyCode::Char('A') if self.tab == Tab::Network => self.approve(Decision::Pocket),
            KeyCode::Char('D') if self.tab == Tab::Network => self.approve(Decision::Deny),
            KeyCode::Char('o') if self.tab == Tab::Ports => {
                let port = self.current_pocket().and_then(|p| {
                    match self.details.get(&p.info.name)?.ports.as_ref()? {
                        Loaded::Ready(v) => v.first().map(|f| f.host),
                        _ => None,
                    }
                });
                match port {
                    Some(h) => vec![Cmd::OpenPort(h)],
                    None => {
                        self.set_status("no forwarded port to open", true);
                        vec![]
                    }
                }
            }
            KeyCode::PageDown | KeyCode::Char('J') => {
                self.detail_scroll = self.detail_scroll.saturating_add(10);
                vec![]
            }
            KeyCode::PageUp | KeyCode::Char('K') => {
                self.detail_scroll = self.detail_scroll.saturating_sub(10);
                vec![]
            }
            KeyCode::Char('/') => {
                self.filtering = true;
                vec![]
            }
            KeyCode::Char(':') => {
                self.overlay = Some(Overlay::Palette {
                    query: String::new(),
                    sel: 0,
                });
                vec![]
            }
            KeyCode::Char('?') => {
                self.overlay = Some(Overlay::Help);
                vec![]
            }
            KeyCode::Char('T') => {
                self.cycle_theme();
                vec![]
            }
            KeyCode::Esc => {
                self.filter.clear();
                vec![]
            }
            _ => vec![],
        };
        (cmds, None)
    }

    pub fn cycle_theme(&mut self) {
        use crate::theme::Mode;
        self.theme.mode = match self.theme.mode {
            Mode::Dark => Mode::Light,
            Mode::Light => Mode::Mono,
            Mode::Mono => Mode::Dark,
        };
        let name = format!("{:?}", self.theme.mode).to_lowercase();
        self.set_status(format!("theme: {name}"), false);
    }

    fn goto_tab(&mut self, t: Tab) -> Vec<Cmd> {
        self.tab = t;
        self.view = View::Tree;
        self.detail_scroll = 0;
        self.after_move()
    }

    pub fn attach_target(&mut self) -> Option<Outcome> {
        if self.view == View::Grid {
            let g = self.grid();
            let (i, j) = *g.get(self.grid_focus)?;
            let p = &self.pockets[i];
            return Some(Outcome::Attach {
                pocket: p.info.name.clone(),
                session: Some(p.sessions[j].info.name.clone()),
            });
        }
        let out = match self.current()? {
            Row::Session(i, j) => {
                let p = &self.pockets[i];
                Outcome::Attach {
                    pocket: p.info.name.clone(),
                    session: Some(p.sessions[j].info.name.clone()),
                }
            }
            Row::Pocket(i) => Outcome::Attach {
                pocket: self.pockets[i].info.name.clone(),
                session: None,
            },
        };
        let state = &self.current_pocket()?.info.state;
        if matches!(
            state,
            PocketState::Stopped | PocketState::Broken { .. } | PocketState::Creating
        ) {
            self.set_status(
                format!("the pocket is {} — press s to start it", state.label()),
                true,
            );
            return None;
        }
        Some(out)
    }

    fn approve(&mut self, d: Decision) -> Vec<Cmd> {
        let Some(name) = self.current_pocket().map(|p| p.info.name.clone()) else {
            return vec![];
        };
        match self.approvals.iter().find(|a| a.pocket == name) {
            Some(a) => {
                let id = a.id;
                self.approvals.retain(|x| x.id != id);
                vec![Cmd::Approve(id, d), Cmd::Refresh]
            }
            None => {
                self.set_status("no pending request for this pocket", true);
                vec![]
            }
        }
    }

    fn on_pocket(&mut self, a: Action) -> Vec<Cmd> {
        match self.current_pocket() {
            Some(p) => {
                let name = p.info.name.clone();
                self.set_status(format!("{} {name}…", verb(&a)), false);
                vec![Cmd::Pocket(name, a)]
            }
            None => {
                self.set_status("no pocket selected — press n to create one", true);
                vec![]
            }
        }
    }

    /// Destructive actions confirm and say what is lost.
    fn confirm_pocket(&mut self, a: Action) -> Vec<Cmd> {
        let Some(p) = self.current_pocket() else {
            return vec![];
        };
        let name = p.info.name.clone();
        let sessions = p
            .sessions
            .iter()
            .filter(|s| s.state != SessionState::Exited)
            .count();
        let (title, mut lines, stat) = match a {
            Action::Remove => (
                format!("Remove {name}?"),
                vec![
                    format!("Deletes the VM, its disk and {sessions} running session(s)."),
                    "Work not applied with `a` (diff tab) or pushed with P is lost.".into(),
                ],
                p.info.repo_path.is_some(),
            ),
            Action::Stop => (
                format!("Stop {name}?"),
                vec![format!(
                    "Shuts the VM down; {sessions} running session(s) end. The disk is kept."
                )],
                false,
            ),
            Action::Apply => (
                format!("Apply {name}'s work?"),
                vec!["Squashes the pocket branch onto your current host branch.".into()],
                true,
            ),
            Action::Pr => (
                format!("Open a pull request for {name}?"),
                vec!["Pushes the pocket branch from this machine and opens a PR.".into()],
                true,
            ),
            _ => return self.on_pocket(a),
        };
        if p.info.repo_path.is_none() && matches!(a, Action::Apply | Action::Pr) {
            self.set_status(format!("{name} has no repository"), true);
            return vec![];
        }
        lines.push(String::new());
        lines.push("y / ⏎ confirm · n / Esc cancel".into());
        let mut out = vec![];
        if stat {
            self.stat.insert(name.clone(), Loaded::Loading);
            out.push(Cmd::LoadStat(name.clone()));
        }
        self.overlay = Some(Overlay::Confirm {
            title,
            lines,
            stat_for: stat.then(|| name.clone()),
            cmd: Cmd::Pocket(name, a),
        });
        out
    }

    fn wizard(&self) -> Wizard {
        let p = &self.prefs;
        let repo = self.cwd_repo.clone().unwrap_or_default();
        Wizard {
            focus: 0,
            fields: vec![
                Field {
                    label: "Name",
                    value: String::new(),
                    choices: vec![],
                    hint: "empty = picked for you",
                },
                Field {
                    label: "Repository",
                    value: repo,
                    choices: vec![],
                    hint: "path to clone in; empty = scratch pocket",
                },
                Field {
                    label: "Preset",
                    value: p.preset.clone(),
                    choices: vec![],
                    hint: "image preset",
                },
                Field {
                    label: "CPUs",
                    value: p.cpus.map(|c| c.to_string()).unwrap_or_else(|| "2".into()),
                    choices: vec!["1", "2", "4", "8"],
                    hint: "← → to change",
                },
                Field {
                    label: "Memory",
                    value: p.memory.clone().unwrap_or_else(|| "2G".into()),
                    choices: vec!["1G", "2G", "4G", "8G", "16G"],
                    hint: "a ceiling; untouched memory costs nothing",
                },
                Field {
                    label: "Network",
                    value: p.net.clone(),
                    choices: vec!["dev", "strict", "offline", "full"],
                    hint: "full = unfiltered NIC (not policed)",
                },
                Field {
                    label: "Start",
                    value: p.agent.clone().unwrap_or_else(|| "shell".into()),
                    choices: vec!["shell", "claude", "codex", "gemini", "opencode"],
                    hint: "first session",
                },
            ],
        }
    }

    fn spec(w: &Wizard) -> NewSpec {
        let v = |i: usize| w.fields[i].value.trim().to_string();
        let some = |s: String| (!s.is_empty()).then_some(s);
        NewSpec {
            name: some(v(0)),
            repo: some(v(1)),
            preset: some(v(2)).unwrap_or_else(|| "base".into()),
            cpus: v(3).parse().ok(),
            memory: some(v(4)),
            net: some(v(5)).unwrap_or_else(|| "dev".into()),
            agent: some(v(6)).filter(|a| a != "shell"),
        }
    }

    pub fn palette_items() -> Vec<PaletteItem> {
        fn k(code: KeyCode) -> KeyEvent {
            KeyEvent::new(code, KeyModifiers::NONE)
        }
        fn press(a: &mut App, code: KeyCode) -> Vec<Cmd> {
            a.key(k(code)).0
        }
        vec![
            PaletteItem {
                label: "New pocket",
                key: "n",
                run: |a| press(a, KeyCode::Char('n')),
            },
            PaletteItem {
                label: "New shell session",
                key: "t",
                run: |a| press(a, KeyCode::Char('t')),
            },
            PaletteItem {
                label: "Pause / resume",
                key: "p",
                run: |a| press(a, KeyCode::Char('p')),
            },
            PaletteItem {
                label: "Hibernate",
                key: "H",
                run: |a| press(a, KeyCode::Char('H')),
            },
            PaletteItem {
                label: "Stop / start",
                key: "s",
                run: |a| press(a, KeyCode::Char('s')),
            },
            PaletteItem {
                label: "Remove pocket",
                key: "x",
                run: |a| press(a, KeyCode::Char('x')),
            },
            PaletteItem {
                label: "Show diff",
                key: "d",
                run: |a| press(a, KeyCode::Char('d')),
            },
            PaletteItem {
                label: "Apply changes",
                key: "a",
                run: |a| {
                    a.tab = Tab::Diff;
                    a.confirm_pocket(Action::Apply)
                },
            },
            PaletteItem {
                label: "Open pull request",
                key: "P",
                run: |a| {
                    a.tab = Tab::Diff;
                    a.confirm_pocket(Action::Pr)
                },
            },
            PaletteItem {
                label: "Network log",
                key: "N",
                run: |a| press(a, KeyCode::Char('N')),
            },
            PaletteItem {
                label: "Ports",
                key: "P",
                run: |a| a.goto_tab(Tab::Ports),
            },
            PaletteItem {
                label: "Info",
                key: "I",
                run: |a| press(a, KeyCode::Char('I')),
            },
            PaletteItem {
                label: "Grid view",
                key: "g",
                run: |a| press(a, KeyCode::Char('g')),
            },
            PaletteItem {
                label: "Filter",
                key: "/",
                run: |a| press(a, KeyCode::Char('/')),
            },
            PaletteItem {
                label: "Refresh",
                key: "r",
                run: |a| press(a, KeyCode::Char('r')),
            },
            PaletteItem {
                label: "Cycle theme (dark/light/no colour)",
                key: "T",
                run: |a| {
                    a.cycle_theme();
                    vec![]
                },
            },
            PaletteItem {
                label: "Help",
                key: "?",
                run: |a| {
                    a.overlay = Some(Overlay::Help);
                    vec![]
                },
            },
        ]
    }

    /// Subsequence match, case-insensitive; earlier and tighter matches rank first.
    pub fn palette_matches(query: &str) -> Vec<PaletteItem> {
        let q: Vec<char> = query
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut scored: Vec<(usize, PaletteItem)> = App::palette_items()
            .into_iter()
            .filter_map(|it| {
                let l: Vec<char> = it.label.to_lowercase().chars().collect();
                let mut pos = 0;
                let mut first = None;
                for &c in &q {
                    let at = l[pos..].iter().position(|&x| x == c)? + pos;
                    first.get_or_insert(at);
                    pos = at + 1;
                }
                Some((pos - first.unwrap_or(0) + first.unwrap_or(0), it))
            })
            .collect();
        scored.sort_by_key(|(s, _)| *s);
        scored.into_iter().map(|(_, it)| it).collect()
    }

    fn overlay_key(&mut self, o: Overlay, k: KeyEvent) -> (Vec<Cmd>, Option<Outcome>) {
        match o {
            Overlay::Help => {
                if !matches!(
                    k.code,
                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter
                ) {
                    self.overlay = Some(Overlay::Help);
                }
                (vec![], None)
            }
            Overlay::Confirm {
                title,
                lines,
                stat_for,
                cmd,
            } => match k.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    if let Cmd::Pocket(n, a) = &cmd {
                        self.set_status(format!("{} {n}…", verb(a)), false);
                    }
                    (vec![cmd], None)
                }
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {
                    self.set_status("cancelled", false);
                    (vec![], None)
                }
                _ => {
                    self.overlay = Some(Overlay::Confirm {
                        title,
                        lines,
                        stat_for,
                        cmd,
                    });
                    (vec![], None)
                }
            },
            Overlay::Palette { mut query, mut sel } => {
                let n = App::palette_matches(&query).len();
                match k.code {
                    KeyCode::Esc => return (vec![], None),
                    KeyCode::Enter => {
                        let items = App::palette_matches(&query);
                        return match items.get(sel) {
                            Some(it) => ((it.run)(self), None),
                            None => (vec![], None),
                        };
                    }
                    KeyCode::Down => sel = (sel + 1).min(n.saturating_sub(1)),
                    KeyCode::Up => sel = sel.saturating_sub(1),
                    KeyCode::Backspace => {
                        query.pop();
                        sel = 0;
                    }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                        query.push(c);
                        sel = 0;
                    }
                    _ => {}
                }
                self.overlay = Some(Overlay::Palette { query, sel });
                (vec![], None)
            }
            Overlay::Wizard(mut w) => {
                match k.code {
                    KeyCode::Esc => return (vec![], None),
                    KeyCode::Enter => {
                        let spec = App::spec(&w);
                        self.prefs = NewSpec {
                            name: None,
                            repo: None,
                            ..spec.clone()
                        };
                        self.set_status(
                            format!(
                                "creating {}…",
                                spec.name.clone().unwrap_or_else(|| "a pocket".into())
                            ),
                            false,
                        );
                        return (
                            vec![Cmd::SavePrefs(self.prefs.clone()), Cmd::New(spec)],
                            None,
                        );
                    }
                    KeyCode::Down | KeyCode::Tab => w.focus = (w.focus + 1) % w.fields.len(),
                    KeyCode::Up | KeyCode::BackTab => {
                        w.focus = (w.focus + w.fields.len() - 1) % w.fields.len()
                    }
                    KeyCode::Left | KeyCode::Right => {
                        let f = &mut w.fields[w.focus];
                        if !f.choices.is_empty() {
                            let i = f.choices.iter().position(|c| *c == f.value).unwrap_or(0);
                            let n = f.choices.len();
                            let j = if k.code == KeyCode::Right {
                                i + 1
                            } else {
                                i + n - 1
                            };
                            f.value = f.choices[j % n].to_string();
                        }
                    }
                    KeyCode::Backspace => {
                        let f = &mut w.fields[w.focus];
                        if f.choices.is_empty() {
                            f.value.pop();
                        }
                    }
                    KeyCode::Char(c) => {
                        let f = &mut w.fields[w.focus];
                        if f.choices.is_empty() {
                            f.value.push(c);
                        }
                    }
                    _ => {}
                }
                self.overlay = Some(Overlay::Wizard(w));
                (vec![], None)
            }
        }
    }
}

fn loaded<T>(r: Result<T, String>) -> Loaded<T> {
    match r {
        Ok(v) => Loaded::Ready(v),
        Err(e) => Loaded::Failed(e),
    }
}

pub fn verb(a: &Action) -> &'static str {
    match a {
        Action::Pause => "pausing",
        Action::Resume => "resuming",
        Action::Hibernate => "hibernating",
        Action::Stop => "stopping",
        Action::Start => "starting",
        Action::Remove => "removing",
        Action::Apply => "applying",
        Action::Pr => "opening a pull request for",
        Action::NewSession => "opening a shell in",
    }
}

/// Bytes a terminal would send for `k` (interact mode).
pub fn key_bytes(k: KeyEvent) -> Vec<u8> {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let alt = k.modifiers.contains(KeyModifiers::ALT);
    let mut out = match k.code {
        KeyCode::Char(c) if ctrl && c.is_ascii_alphabetic() => {
            vec![(c.to_ascii_lowercase() as u8) & 0x1f]
        }
        KeyCode::Char(c) => c.to_string().into_bytes(),
        KeyCode::Enter => b"\r".to_vec(),
        KeyCode::Tab => b"\t".to_vec(),
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        _ => vec![],
    };
    if alt && !out.is_empty() {
        out.insert(0, 0x1b);
    }
    out
}
