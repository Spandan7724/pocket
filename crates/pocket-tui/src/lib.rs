//! ratatui dashboard for pocket (TUI.md, normative spec in STYLES.md): a pure [`app::App`]
//! model driven by keys and worker updates, rendered by [`ui::draw`].

pub mod app;
pub mod pane;
pub mod run;
pub mod scenes;
pub mod theme;
pub mod ui;

pub use app::{App, Cmd, Outcome, Update};
pub use run::{Source, run};
