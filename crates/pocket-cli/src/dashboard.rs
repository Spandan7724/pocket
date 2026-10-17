//! `pocket` without arguments: the dashboard. The UI thread only draws; a worker thread owns
//! the daemon connection, slow actions get their own threads, and each previewed session is
//! a direct attach stream at the session's own size that never sends input unless the user
//! types into it.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pocket_proto::frame::{recv, send};
use pocket_proto::guest::{AttachIn, AttachOut, PtySize, SessionInfo, StreamOpen};
use pocket_proto::rpc::{
    ApplyMode, Event, NewPocket, PocketInfo, PocketState, Request, Response, Topic,
};
use pocket_tui::app::{Action, Cmd, NewSpec, Outcome, Screen, Update};
use pocket_tui::{App, Source};

use crate::client::Client;
use crate::error::{CliError, Result};

pub struct Worker {
    tx: Sender<Cmd>,
    rx: Receiver<Update>,
}

impl Source for Worker {
    fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }
    fn try_recv(&self) -> Option<Update> {
        self.rx.try_recv().ok()
    }
}

struct Preview {
    stop: Arc<AtomicBool>,
    input: UnixStream,
    size: PtySize,
    screen: Screen,
}

impl Drop for Preview {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.input.shutdown(std::net::Shutdown::Both);
    }
}

fn prefs_path() -> std::path::PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                .join(".local/state")
        })
        .join("pocket/dashboard.json")
}

fn load_prefs() -> Option<NewSpec> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(prefs_path()).ok()?).ok()?;
    Some(NewSpec {
        name: None,
        repo: None,
        preset: v["preset"].as_str()?.to_string(),
        cpus: v["cpus"].as_u64().map(|c| c as u8),
        memory: v["memory"].as_str().map(String::from),
        net: v["net"].as_str().unwrap_or("dev").to_string(),
        agent: v["agent"].as_str().map(String::from),
    })
}

fn save_prefs(p: &NewSpec) {
    let v = serde_json::json!({
        "preset": p.preset, "cpus": p.cpus, "memory": p.memory, "net": p.net, "agent": p.agent,
    });
    let path = prefs_path();
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(path, v.to_string());
}

impl Worker {
    pub fn start() -> Worker {
        let (tx, cmd_rx) = channel();
        let (up, rx) = channel();
        if let Some(p) = load_prefs() {
            let _ = up.send(Update::Prefs(p));
        }
        let (up2, tx2) = (up.clone(), tx.clone());
        std::thread::spawn(move || events(up2, tx2));
        std::thread::spawn(move || requests(cmd_rx, up));
        Worker { tx, rx }
    }
}

/// Live events: a state change or a new request triggers a refresh, network entries feed
/// the header rate and the Network tab.
fn events(up: Sender<Update>, cmds: Sender<Cmd>) {
    loop {
        let sub = Client::connect_existing().and_then(|mut c| {
            c.subscribe(vec![Topic::Pockets, Topic::Net, Topic::Notices])
                .ok()
                .map(|_| c)
        });
        let Some(mut c) = sub else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        while let Ok(e) = c.next_event() {
            let ok = match e {
                Event::Net(n) => up.send(Update::Request(n)).is_ok(),
                Event::Notice {
                    pocket,
                    title,
                    body,
                    kind,
                    ..
                } => {
                    let msg = if kind == "url" {
                        format!("{pocket}: opened {body}")
                    } else {
                        format!("{title}: {body}")
                    };
                    up.send(Update::Status(msg)).is_ok() && cmds.send(Cmd::Refresh).is_ok()
                }
                _ => cmds.send(Cmd::Refresh).is_ok(),
            };
            if !ok {
                return;
            }
        }
    }
}

struct State {
    up: Sender<Update>,
    client: Option<Client>,
    pockets: Vec<PocketInfo>,
    sessions: HashMap<String, Vec<SessionInfo>>,
    previews: HashMap<(String, String), Preview>,
    redraw: Arc<AtomicU64>,
}

impl State {
    fn client(&mut self) -> Option<&mut Client> {
        if self.client.is_none() {
            match Client::connect() {
                Ok(c) => {
                    self.client = Some(c);
                    let _ = self.up.send(Update::Connected(true));
                }
                Err(_) => {
                    let _ = self.up.send(Update::Connected(false));
                    return None;
                }
            }
        }
        self.client.as_mut()
    }

    fn request(&mut self, req: Request) -> std::result::Result<Response, String> {
        let Some(c) = self.client() else {
            return Err("pocketd is not reachable".into());
        };
        match c.request(req) {
            Ok(r) => Ok(r),
            Err(e) => {
                if e.exit == 11 {
                    self.client = None;
                }
                Err(e.message)
            }
        }
    }

    fn refresh(&mut self) {
        let Ok(Response::Pockets(list)) = self.request(Request::List) else {
            return;
        };
        self.pockets = list.clone();
        let _ = self.up.send(Update::Pockets(list.clone()));
        for p in list.iter().filter(|p| p.state == PocketState::Running) {
            if let Ok(Response::Sessions(s)) = self.request(Request::SessionList {
                pocket: p.name.clone(),
                peek: true,
            }) {
                self.sessions.insert(p.name.clone(), s.clone());
                let _ = self.up.send(Update::Sessions(p.name.clone(), s));
            }
        }
        for p in list.iter().filter(|p| p.state != PocketState::Running) {
            if self.sessions.remove(&p.name).is_some() {
                let _ = self.up.send(Update::Sessions(p.name.clone(), vec![]));
            }
        }
        if let Ok(Response::Approvals(a)) = self.request(Request::Approvals { pocket: None }) {
            let _ = self.up.send(Update::Approvals(a));
        }
        // Sessions resized by an attached client: follow their size, never set it.
        for ((p, s), pv) in self.previews.iter_mut() {
            if let Some(info) = self
                .sessions
                .get(p)
                .and_then(|l| l.iter().find(|x| &x.name == s))
                && info.size != pv.size
            {
                pv.size = info.size;
                pv.screen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .screen_mut()
                    .set_size(info.size.rows, info.size.cols);
            }
        }
    }

    fn previews(&mut self, want: Vec<(String, String)>) {
        self.previews.retain(|k, _| want.contains(k));
        for (p, s) in want {
            if self.previews.contains_key(&(p.clone(), s.clone())) {
                continue;
            }
            // Only running pockets: attaching would wake a paused one.
            if !self
                .pockets
                .iter()
                .any(|x| x.name == p && x.state == PocketState::Running)
            {
                continue;
            }
            let Some(size) = self
                .sessions
                .get(&p)
                .and_then(|l| l.iter().find(|x| x.name == s))
                .map(|x| x.size)
            else {
                continue;
            };
            match self.open_preview(&p, &s, size) {
                Ok(pv) => {
                    let _ = self
                        .up
                        .send(Update::Preview(p.clone(), s.clone(), pv.screen.clone()));
                    self.previews.insert((p, s), pv);
                }
                Err(e) => {
                    let _ = self.up.send(Update::Error(format!("preview {p}:{s}: {e}")));
                }
            }
        }
    }

    fn open_preview(
        &mut self,
        pocket: &str,
        session: &str,
        size: PtySize,
    ) -> std::result::Result<Preview, String> {
        let Response::Attach {
            session,
            vsock_uds,
            token,
        } = self.request(Request::AttachAuthorize {
            pocket: pocket.into(),
            session: Some(session.into()),
        })?
        else {
            return Err("unexpected reply".into());
        };
        let stream = crate::vsock::open(
            &vsock_uds,
            &StreamOpen::Attach {
                session: session.clone(),
                // The session's current size: a preview must not resize it.
                size,
                replay_scrollback: true,
                token,
            },
        )
        .map_err(|e| e.message)?;
        let screen: Screen = Arc::new(Mutex::new(vt100::Parser::new(size.rows, size.cols, 0)));
        let stop = Arc::new(AtomicBool::new(false));
        let mut rd = stream.try_clone().map_err(|e| e.to_string())?;
        let (scr, st, up, redraw) = (
            screen.clone(),
            stop.clone(),
            self.up.clone(),
            self.redraw.clone(),
        );
        let (p, s) = (pocket.to_string(), session.clone());
        std::thread::spawn(move || {
            while let Ok(Some(AttachOut::Data(d))) = recv::<_, AttachOut>(&mut rd) {
                scr.lock().unwrap_or_else(|e| e.into_inner()).process(&d);
                // At most one redraw request per frame, however fast output arrives.
                let now = crate::now_ms();
                if now.saturating_sub(redraw.load(Ordering::SeqCst)) >= 16 {
                    redraw.store(now, Ordering::SeqCst);
                    let _ = up.send(Update::Redraw);
                }
                if st.load(Ordering::SeqCst) {
                    return;
                }
            }
            let _ = up.send(Update::PreviewClosed(p, s));
        });
        Ok(Preview {
            stop,
            input: stream,
            size,
            screen,
        })
    }

    fn input(&mut self, pocket: String, session: String, bytes: Vec<u8>) {
        if let Some(pv) = self.previews.get_mut(&(pocket, session)) {
            let _ = send(&mut pv.input, &AttachIn::Data(bytes));
        }
    }
}

/// Runs a slow action on its own connection so refreshes keep going.
fn background(
    up: &Sender<Update>,
    kick: Sender<()>,
    f: impl FnOnce(&mut Client) -> Result<String> + Send + 'static,
) {
    let up = up.clone();
    std::thread::spawn(move || {
        let r = Client::connect().and_then(|mut c| f(&mut c));
        let _ = up.send(match r {
            Ok(m) => Update::Status(m),
            Err(e) => Update::Error(match e.hint {
                Some(h) => format!("{} — {h}", e.message),
                None => e.message,
            }),
        });
        let _ = kick.send(());
    });
}

fn requests(cmds: Receiver<Cmd>, up: Sender<Update>) {
    let mut st = State {
        up: up.clone(),
        client: None,
        pockets: vec![],
        sessions: HashMap::new(),
        previews: HashMap::new(),
        redraw: Arc::new(AtomicU64::new(0)),
    };
    let (kick_tx, kick_rx) = channel::<()>();
    let mut last = Instant::now() - Duration::from_secs(10);
    loop {
        let cmd = match cmds.recv_timeout(Duration::from_millis(250)) {
            Ok(c) => Some(c),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let kicked = kick_rx.try_recv().is_ok();
        let due = last.elapsed() >= Duration::from_secs(1);
        match cmd {
            None if due || kicked => {}
            None => continue,
            Some(Cmd::Refresh) => {}
            Some(c) => {
                handle(&mut st, c, &kick_tx);
                if !kicked {
                    continue;
                }
            }
        }
        // Coalesce a burst of refresh requests.
        while let Ok(c) = cmds.try_recv() {
            if c != Cmd::Refresh {
                handle(&mut st, c, &kick_tx);
            }
        }
        st.refresh();
        last = Instant::now();
    }
}

fn handle(st: &mut State, c: Cmd, kick: &Sender<()>) {
    let up = st.up.clone();
    match c {
        Cmd::Refresh => st.refresh(),
        Cmd::Previews(want) => st.previews(want),
        Cmd::Input(p, s, b) => st.input(p, s, b),
        Cmd::LoadNet(p) => {
            let r = match st.request(Request::NetLog {
                pocket: p.clone(),
                limit: 200,
            }) {
                Ok(Response::NetLog(v)) => Ok(v),
                Ok(_) => Err("unexpected reply".into()),
                Err(e) => Err(e),
            };
            let _ = up.send(Update::Net(p, r));
        }
        Cmd::LoadPorts(p) => {
            let running = st
                .pockets
                .iter()
                .any(|x| x.name == p && x.state == PocketState::Running);
            let r = if running {
                match st.request(Request::Ports { pocket: p.clone() }) {
                    Ok(Response::Ports(v)) => Ok(v),
                    Ok(_) => Err("unexpected reply".into()),
                    Err(e) => Err(e),
                }
            } else {
                Err("the pocket is not running (p resumes it)".into())
            };
            let _ = up.send(Update::Ports(p, r));
        }
        Cmd::LoadDiff(p) | Cmd::LoadStat(p) if !st.pockets.iter().any(|x| x.name == p) => {
            let _ = up.send(Update::Diff(p, Err("no such pocket".into())));
        }
        Cmd::LoadDiff(p) => {
            let up = up.clone();
            std::thread::spawn(move || {
                let r = Client::connect()
                    .and_then(|mut c| {
                        c.request(Request::Diff {
                            pocket: p.clone(),
                            uncommitted: true,
                            stat: false,
                            color: false,
                        })
                    })
                    .map_err(|e| e.message)
                    .and_then(|r| match r {
                        Response::Text { text, .. } => Ok(text),
                        _ => Err("unexpected reply".into()),
                    });
                let _ = up.send(Update::Diff(p, r));
            });
        }
        Cmd::LoadStat(p) => {
            let up = up.clone();
            std::thread::spawn(move || {
                let r = Client::connect()
                    .and_then(|mut c| {
                        c.request(Request::Diff {
                            pocket: p.clone(),
                            uncommitted: true,
                            stat: true,
                            color: false,
                        })
                    })
                    .map_err(|e| e.message)
                    .and_then(|r| match r {
                        Response::Text { text, .. } => Ok(text),
                        _ => Err("unexpected reply".into()),
                    });
                let _ = up.send(Update::Stat(p, r));
            });
        }
        Cmd::Approve(id, decision) => {
            if let Err(e) = st.request(Request::Approve { id, decision }) {
                let _ = up.send(Update::Error(e));
            }
        }
        Cmd::OpenPort(h) => {
            let url = format!("http://127.0.0.1:{h}/");
            let _ = up.send(match crate::open_browser(&url) {
                Ok(()) => Update::Status(format!("opened {url}")),
                Err(e) => Update::Error(e.message),
            });
        }
        Cmd::SavePrefs(p) => save_prefs(&p),
        Cmd::New(spec) => {
            let kick = kick.clone();
            let up2 = up.clone();
            background(&up, kick, move |c| {
                let req = new_request(spec)?;
                let name = req.name.clone();
                let r = c.request_with(Request::NewPocket(req), |stage| {
                    let _ = up2.send(Update::Status(format!(
                        "{}: {stage}",
                        name.clone().unwrap_or_else(|| "new pocket".into())
                    )));
                })?;
                Ok(match r {
                    Response::Pocket(p) => format!("created {} — ⏎ attaches", p.name),
                    _ => "created".into(),
                })
            });
        }
        Cmd::Pocket(name, a) => {
            let kick = kick.clone();
            background(&up, kick, move |c| {
                let pocket = name.clone();
                let (req, done) = match a {
                    Action::Pause => (Request::Pause { pocket }, "paused"),
                    Action::Resume => (Request::Resume { pocket }, "resumed"),
                    Action::Hibernate => (Request::Hibernate { pocket }, "hibernated"),
                    Action::Stop => (Request::Stop { pocket }, "stopped"),
                    Action::Start => (Request::Start { pocket }, "started"),
                    Action::Remove => (Request::Remove { pocket }, "removed"),
                    Action::NewSession => (
                        Request::SessionCreate {
                            pocket,
                            name: None,
                            argv: None,
                            rows: 24,
                            cols: 80,
                            term: std::env::var("TERM").ok(),
                            terminfo: std::env::var("TERM")
                                .ok()
                                .and_then(|t| pocket_proto::rpc::find_terminfo(&t)),
                        },
                        "opened a shell in",
                    ),
                    Action::Apply => (
                        Request::Apply {
                            pocket,
                            mode: ApplyMode::Squash,
                            onto: None,
                            uncommitted: true,
                            message: None,
                        },
                        "applied",
                    ),
                    Action::Pr => (
                        Request::Pr {
                            pocket,
                            title: None,
                            body: None,
                            draft: false,
                            base: None,
                        },
                        "opened a pull request for",
                    ),
                };
                let r = c.request(req)?;
                Ok(match r {
                    Response::Text { url: Some(u), .. } => format!("{done} {name}: {u}"),
                    Response::Text { text, .. } if !text.trim().is_empty() => {
                        format!(
                            "{done} {name}: {}",
                            text.trim().lines().last().unwrap_or("")
                        )
                    }
                    _ => format!("{done} {name}"),
                })
            });
        }
    }
}

fn new_request(spec: NewSpec) -> Result<NewPocket> {
    let repo = match spec.repo.as_deref() {
        Some(r) => {
            let p = std::path::PathBuf::from(r);
            Some(
                p.canonicalize()
                    .map_err(|e| CliError::io(&format!("repository {r}"), e))?,
            )
        }
        None => None,
    };
    let memory_mib = spec
        .memory
        .as_deref()
        .map(crate::parse_size_mib)
        .transpose()?
        .map(|m| m as u32);
    let command = spec.agent.map(|a| vec![a]);
    let mut req = crate::default_new(spec.name, Some(spec.preset), repo);
    req.cpus = spec.cpus;
    req.memory_mib = memory_mib;
    req.net_profile = Some(spec.net);
    req.command = command;
    if let Some(r) = req.repo.clone()
        && let Some((_, p)) = crate::project::load(&r)?
    {
        crate::project::apply(&p, &r, &mut req, false)?;
    }
    Ok(req)
}

fn host_mem() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        })
        .map(|k| k << 10)
        .unwrap_or(0)
}

pub fn run() -> Result<u8> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(CliError::usage("the dashboard needs a terminal")
            .hint("use `pocket ls`, `pocket sessions P` or `--json` in scripts"));
    }
    // Starts the daemon if needed, so the first frame has data soon.
    Client::connect()?;
    let worker = Worker::start();
    let mut app = App::new(pocket_tui::theme::Theme::detect(
        crate::notice::ui_setting("theme").as_deref(),
    ));
    app.host_mem = host_mem();
    app.cwd_repo = std::env::current_dir()
        .ok()
        .and_then(|d| crate::repo_root(&d))
        .map(|p| p.display().to_string());
    loop {
        let outcome = pocket_tui::run(&mut app, &worker)
            .map_err(|e| CliError::io("dashboard terminal", e))?;
        match outcome {
            Outcome::Quit => return Ok(0),
            Outcome::Attach { pocket, session } => {
                // The dashboard has left the screen; the attach owns the terminal now.
                let mut c = Client::connect()?;
                if let Err(e) = crate::attach::attach(&mut c, &pocket, session) {
                    app.set_status(format!("attach {pocket}: {}", e.message), true);
                }
            }
        }
    }
}
