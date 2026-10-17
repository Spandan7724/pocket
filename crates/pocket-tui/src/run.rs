//! The terminal loop. It only draws and reads input; the [`Source`] does all daemon work on
//! its own threads, so the loop never waits on pocketd.

use std::io;
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

use crate::app::{App, Cmd, Outcome, Update};

pub trait Source {
    /// Queues work for the worker; never blocks.
    fn send(&self, cmd: Cmd);
    fn try_recv(&self) -> Option<Update>;
}

/// Puts the terminal back however `run` ends (return, error or panic), before anything
/// else — an attach — writes to it.
struct Guard;

impl Guard {
    fn enter() -> io::Result<Guard> {
        enable_raw_mode()?;
        let g = Guard;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            ratatui::crossterm::terminal::Clear(ratatui::crossterm::terminal::ClearType::All),
            EnableMouseCapture,
            EnableBracketedPaste
        )?;
        Ok(g)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen,
            ratatui::crossterm::cursor::Show
        );
        let _ = disable_raw_mode();
    }
}

/// One loop iteration without a terminal: apply what the worker sent. Used by `run` and by
/// tests that check the loop keeps going while the worker is stuck.
pub fn pump(app: &mut App, src: &dyn Source) -> bool {
    let mut changed = false;
    // Bounded: a flood of updates must not starve input.
    for _ in 0..256 {
        let Some(u) = src.try_recv() else { break };
        for c in app.apply(u) {
            src.send(c);
        }
        changed = true;
    }
    changed
}

pub fn run(app: &mut App, src: &dyn Source) -> io::Result<Outcome> {
    let guard = Guard::enter()?;
    // No `Terminal::clear`: it asks the terminal for the cursor position, which some
    // terminals and multiplexers answer slowly or never.
    let mut term = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    src.send(Cmd::Refresh);
    for c in app.wanted_previews() {
        src.send(c);
    }
    let mut dirty = true;
    let mut drawn = Instant::now();
    let outcome = loop {
        dirty |= pump(app, src);
        if dirty || drawn.elapsed() > Duration::from_secs(1) {
            term.draw(|f| crate::ui::draw(f, app))?;
            drawn = Instant::now();
            dirty = false;
        }
        if !event::poll(Duration::from_millis(16))? {
            continue;
        }
        dirty = true;
        let cmds = match event::read()? {
            Event::Key(k) => {
                let (cmds, out) = app.key(k);
                for c in cmds {
                    src.send(c);
                }
                if let Some(o) = out {
                    break o;
                }
                continue;
            }
            Event::Mouse(m) => app.mouse(m),
            Event::Paste(p) => app.paste(&p),
            _ => vec![],
        };
        for c in cmds {
            src.send(c);
        }
    };
    drop(term);
    drop(guard);
    Ok(outcome)
}
