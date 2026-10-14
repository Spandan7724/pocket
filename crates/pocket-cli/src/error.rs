//! User-facing errors: what happened, why, how to fix (rendered by miette); each maps to a
//! documented exit code (CLI.md §Exit codes).

use pocket_proto::rpc::{ErrorCode, RpcError};

#[derive(Debug)]
pub struct CliError {
    pub message: String,
    pub hint: Option<String>,
    pub code: String,
    pub exit: u8,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl miette::Diagnostic for CliError {
    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        Some(Box::new(format!("pocket::{}", self.code)))
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.hint
            .as_ref()
            .map(|h| Box::new(h.clone()) as Box<dyn std::fmt::Display>)
    }
}

impl CliError {
    pub fn new(code: &str, exit: u8, message: impl Into<String>) -> CliError {
        CliError {
            message: message.into(),
            hint: None,
            code: code.into(),
            exit,
        }
    }

    pub fn hint(mut self, h: impl Into<String>) -> CliError {
        self.hint = Some(h.into());
        self
    }

    pub fn usage(message: impl Into<String>) -> CliError {
        CliError::new("usage", 2, message)
    }

    pub fn daemon(message: impl Into<String>) -> CliError {
        CliError::new("daemon_unavailable", 11, message)
    }

    pub fn io(what: &str, e: std::io::Error) -> CliError {
        CliError::new("io", 12, format!("{what}: {e}"))
    }
}

impl From<RpcError> for CliError {
    fn from(e: RpcError) -> CliError {
        let code = match e.code {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::NotFound => "not_found",
            ErrorCode::AlreadyExists => "already_exists",
            ErrorCode::VersionMismatch => "version_mismatch",
            ErrorCode::InvalidState => "invalid_state",
            ErrorCode::HostSetup => "host_setup",
            ErrorCode::Vmm => "vmm",
            ErrorCode::Guest => "guest",
            ErrorCode::Image => "image",
            ErrorCode::Workspace => "workspace",
            ErrorCode::Internal => "internal",
        };
        CliError {
            message: e.message,
            hint: e.hint,
            code: code.into(),
            exit: e.code.exit_code(),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
