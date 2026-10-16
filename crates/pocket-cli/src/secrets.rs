//! `pocket login` and `pocket secrets`: credentials go to pocketd over the 0600 socket and
//! are stored host-side; pockets get placeholders the proxy swaps for the real value.

use std::io::{Read, Write};
use std::path::PathBuf;

use clap::Subcommand;
use pocket_proto::rpc::{Request, Response, SecretAdd, SecretInfo};

use crate::client::Client;
use crate::error::{CliError, Result};
use crate::{json, term};

#[derive(Subcommand)]
pub enum SecretsCmd {
    /// List stored secrets (never their values).
    Ls,
    /// Store a secret; the value is read from the terminal (hidden) or stdin.
    Add {
        name: String,
        /// Destination host the value is injected for (`host` or `*.domain`); repeatable.
        #[arg(long = "host")]
        hosts: Vec<String>,
        /// Guest environment variable that holds the placeholder; repeatable.
        #[arg(long)]
        env: Vec<String>,
        /// Header added when the guest sends none, e.g. `X-Api-Key: {}`.
        #[arg(long)]
        header: Option<String>,
        /// anthropic, openai, github or custom (default: guessed from the value).
        #[arg(long)]
        provider: Option<String>,
    },
    /// Remove a stored secret.
    Rm {
        name: String,
        #[arg(long, short)]
        force: bool,
    },
    /// Add destinations, env vars or a header template to a secret.
    Bind {
        name: String,
        #[arg(long = "host")]
        hosts: Vec<String>,
        #[arg(long)]
        env: Vec<String>,
        #[arg(long)]
        header: Option<String>,
    },
}

/// Hidden terminal input, or all of stdin when it is not a terminal. Escape sequences and
/// control characters (line breaks included) are removed: tokens copied from a terminal
/// often carry colors and the wrap's line breaks.
pub fn read_secret(prompt: &str) -> Result<String> {
    if !term::is_tty(0) {
        let mut s = Vec::new();
        std::io::stdin()
            .read_to_end(&mut s)
            .map_err(|e| CliError::io("stdin", e))?;
        return Ok(clean(&s));
    }
    eprint!("{prompt}");
    // Bracketed paste delivers a multi-line paste whole instead of ending at its first line.
    eprint!("\x1b[?2004h");
    let _ = std::io::stderr().flush();
    // SAFETY: termios calls on fd 0, restored before returning.
    let old = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        libc::tcgetattr(0, &mut t);
        let old = t;
        t.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(0, libc::TCSANOW, &t);
        old
    };
    let r = read_hidden(&mut std::io::stdin().lock());
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
    eprint!("\x1b[?2004l");
    eprintln!();
    match r.map_err(|e| CliError::io("terminal", e))? {
        Some(s) => Ok(clean(&s)),
        None => Err(CliError::usage("cancelled")),
    }
}

/// Reads until Enter, or until a bracketed paste ends; `None` on Ctrl-C / Ctrl-D.
fn read_hidden(r: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    const START: &[u8] = b"\x1b[200~";
    const END: &[u8] = b"\x1b[201~";
    let mut buf = Vec::new();
    let mut pasting = false;
    let mut b = [0u8; 1];
    loop {
        if r.read(&mut b)? == 0 {
            return Ok(None);
        }
        buf.push(b[0]);
        if buf.ends_with(START) {
            buf.truncate(buf.len() - START.len());
            pasting = true;
        } else if buf.ends_with(END) {
            buf.truncate(buf.len() - END.len());
            return Ok(Some(buf));
        } else if !pasting {
            match b[0] {
                b'\r' | b'\n' => return Ok(Some(buf)),
                3 | 4 => return Ok(None),
                _ => {}
            }
        }
    }
}

/// Drops ANSI escape sequences and control characters, then trims.
fn clean(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            match it.next() {
                // CSI: parameters, then a final byte in @..~
                Some('[') => {
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                // OSC (e.g. hyperlinks): until BEL or ST
                Some(']') => {
                    while let Some(c) = it.next() {
                        if c == '\x07' || (c == '\x1b' && it.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                _ => {}
            }
        } else if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// Provider tokens never contain whitespace; a terminal wrap can add indentation.
fn token(s: String) -> String {
    s.split_whitespace().collect()
}

fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| "/".into()))
}

fn describe(i: &SecretInfo) -> String {
    let env = if i.env.is_empty() {
        String::new()
    } else {
        format!(" as {}", i.env.join(", "))
    };
    format!(
        "stored {} ({} {}, {}) — new pockets get a placeholder{env}; the real value is sent only to {}",
        i.name,
        i.provider,
        i.kind,
        i.storage,
        i.hosts.join(", ")
    )
}

fn add(c: &mut Client, a: SecretAdd, j: bool) -> Result<u8> {
    let Response::Secret(info) = c.request(Request::SecretAdd(a))? else {
        return Err(CliError::new("internal", 70, "unexpected reply"));
    };
    if j {
        json(&info);
    } else {
        println!("{}", describe(&info));
    }
    Ok(0)
}

pub fn login(
    c: &mut Client,
    provider: &str,
    name: Option<String>,
    from_codex: bool,
    from_gh: bool,
    j: bool,
) -> Result<u8> {
    let (name, provider, value) = match provider {
        "claude" | "anthropic" => {
            let v = token(read_secret(
                "Paste an Anthropic API key (sk-ant-api…) or a Claude subscription token from \
                 `claude setup-token` (sk-ant-oat…): ",
            )?);
            if !v.starts_with("sk-ant-") {
                return Err(CliError::usage("that does not look like an Anthropic key or token")
                    .hint("API keys start with sk-ant-api, `claude setup-token` tokens with sk-ant-oat"));
            }
            (name.unwrap_or_else(|| "claude".into()), "anthropic", v)
        }
        "openai" | "codex" => {
            let v = if from_codex {
                let p = home().join(".codex/auth.json");
                let text = std::fs::read_to_string(&p).map_err(|e| {
                    CliError::io(&p.display().to_string(), e)
                        .hint("run `codex login` on the host first")
                })?;
                let v: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| CliError::usage(format!("{} is not JSON", p.display())))?;
                match v.get("OPENAI_API_KEY").and_then(|k| k.as_str()) {
                    Some(k) if !k.is_empty() && v.get("tokens").is_none_or(|t| t.is_null()) => {
                        k.to_string()
                    }
                    _ => text,
                }
            } else {
                token(read_secret(
                    "Paste an OpenAI API key (sk-…), or rerun with --from-codex to use your Codex login: ",
                )?)
            };
            (name.unwrap_or_else(|| "openai".into()), "openai", v)
        }
        "github" | "gh" => {
            let v = if from_gh {
                let o = std::process::Command::new("gh")
                    .args(["auth", "token"])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .map_err(|e| {
                        CliError::io("run `gh auth token`", e)
                            .hint("install the GitHub CLI or paste a token")
                    })?;
                if !o.status.success() {
                    return Err(
                        CliError::usage("`gh auth token` failed").hint("run `gh auth login` first")
                    );
                }
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            } else {
                token(read_secret(
                    "Paste a GitHub token (a fine-grained token limited to the repos you work on is best): ",
                )?)
            };
            (name.unwrap_or_else(|| "github".into()), "github", v)
        }
        other => {
            return Err(CliError::usage(format!("unknown provider {other:?}"))
                .hint("use claude, openai or github; for anything else use `pocket secrets add NAME --host HOST`"));
        }
    };
    if value.is_empty() {
        return Err(CliError::usage("no credential given"));
    }
    add(
        c,
        SecretAdd {
            name,
            provider: Some(provider.into()),
            kind: None,
            value,
            hosts: vec![],
            env: vec![],
            header: None,
        },
        j,
    )
}

pub fn secrets(c: &mut Client, cmd: SecretsCmd, j: bool) -> Result<u8> {
    match cmd {
        SecretsCmd::Ls => {
            let Response::Secrets(list) = c.request(Request::SecretList)? else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&list);
            } else if list.is_empty() {
                println!(
                    "no secrets yet — add one with `pocket login claude|openai|github` or `pocket secrets add`"
                );
            } else {
                println!(
                    "{:<14} {:<10} {:<12} {:<8} {:<40} ENV",
                    "NAME", "PROVIDER", "KIND", "STORAGE", "HOSTS"
                );
                for s in list {
                    println!(
                        "{:<14} {:<10} {:<12} {:<8} {:<40} {}",
                        s.name,
                        s.provider,
                        s.kind,
                        s.storage,
                        s.hosts.join(","),
                        s.env.join(",")
                    );
                }
            }
            Ok(0)
        }
        SecretsCmd::Add {
            name,
            hosts,
            env,
            header,
            provider,
        } => {
            let value = read_secret(&format!("Value for {name}: "))?;
            add(
                c,
                SecretAdd {
                    name,
                    provider,
                    kind: None,
                    value,
                    hosts,
                    env,
                    header,
                },
                j,
            )
        }
        SecretsCmd::Rm { name, force } => {
            if !force
                && !crate::confirm(&format!(
                    "remove secret {name}? Pockets using it lose access"
                ))
            {
                return Err(CliError::usage(format!("not removing {name}"))
                    .hint("confirm interactively, or pass --force"));
            }
            c.request(Request::SecretRemove { name: name.clone() })?;
            if !j {
                println!("removed {name}");
            }
            Ok(0)
        }
        SecretsCmd::Bind {
            name,
            hosts,
            env,
            header,
        } => {
            let Response::Secret(info) = c.request(Request::SecretBind {
                name,
                hosts,
                env,
                header,
            })?
            else {
                return Err(CliError::new("internal", 70, "unexpected reply"));
            };
            if j {
                json(&info);
            } else {
                println!("{}", describe(&info));
            }
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(input: &[u8]) -> Option<String> {
        read_hidden(&mut &input[..])
            .unwrap()
            .map(|b| token(clean(&b)))
    }

    #[test]
    fn wrapped_colored_paste_becomes_one_token() {
        let paste = b"\x1b[200~\x1b[1;32msk-ant-oat01-abc\x1b[0m\r\n  def\x1b]8;;https://x\x07ghi\x1b]8;;\x1b\\\x1b[201~";
        assert_eq!(read(paste).unwrap(), "sk-ant-oat01-abcdefghi");
    }

    #[test]
    fn typed_input_ends_at_enter_and_ctrl_c_cancels() {
        assert_eq!(read(b"sk-ant-api03-x\rjunk").unwrap(), "sk-ant-api03-x");
        assert_eq!(read(b"sk-\x03"), None);
        assert_eq!(read(b""), None);
    }

    #[test]
    fn piped_values_lose_controls_but_keep_inner_spaces() {
        assert_eq!(clean(b"  Bearer abc\x1b[0m\n"), "Bearer abc");
    }
}
