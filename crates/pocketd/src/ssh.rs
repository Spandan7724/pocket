//! SSH over vsock (M11, `pocket code` / `pocket ssh`): the guest's sshd listens on its own
//! loopback only; the host reaches it through a `PortForward` stream to port 22. Settings
//! are on sshd's command line, so the image's sshd_config does not matter.

use std::sync::Arc;

use pocket_proto::rpc::{ErrorCode, Response};

use crate::daemon::{Daemon, R, err, guest_err};
use crate::guest::ExecReq;

fn valid_key(k: &str) -> bool {
    let mut it = k.split_whitespace();
    matches!(
        (it.next(), it.next()),
        (Some("ssh-ed25519"), Some(b)) if !b.is_empty()
            && b.len() < 200
            && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
    )
}

pub async fn prepare(d: &Arc<Daemon>, pocket: &str, public_key: &str) -> R<Response> {
    let key = public_key.trim();
    if !valid_key(key) || key.lines().count() != 1 || key.len() > 512 {
        return Err(err(
            ErrorCode::BadRequest,
            "expected one ssh-ed25519 public key",
        ));
    }
    let rec = d.find(pocket)?;
    let live = d.running(&rec)?;
    let user = live.user.clone().unwrap_or_else(|| "root".into());
    let script = r#"set -e
command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || { echo "no OpenSSH server (sshd) in this image" >&2; exit 3; }
mkdir -p /run/sshd /run/pocket/ssh
chmod 755 /run/pocket/ssh
printf '%s\n' "$1" > /run/pocket/ssh/authorized_keys
chmod 644 /run/pocket/ssh/authorized_keys
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
if ! pgrep -x sshd >/dev/null 2>&1; then
  SSHD=$(command -v sshd || echo /usr/sbin/sshd)
  "$SSHD" -h /etc/ssh/ssh_host_ed25519_key -o ListenAddress=127.0.0.1 -o Port=22 \
    -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o "AuthorizedKeysFile=.ssh/authorized_keys /run/pocket/ssh/authorized_keys" \
    -o PermitRootLogin=prohibit-password -o AllowTcpForwarding=yes -o PrintMotd=no \
    -o AcceptEnv="LANG LC_* COLORTERM TERM_PROGRAM"
fi
cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub"#;
    let o = live
        .guest
        .exec(
            ExecReq {
                argv: &["/bin/sh", "-c", script, "sh", key],
                env: vec![],
                cwd: "/",
                user: None,
                stdin: None,
            },
            4096,
        )
        .await
        .map_err(guest_err)?;
    if !o.ok() {
        let msg = o.stderr_text();
        return Err(err(
            ErrorCode::Guest,
            format!("start sshd in {}: {msg}", rec.info.name),
        )
        .hint(if msg.contains("no OpenSSH") {
            "use the base preset, or add `apt-get install -y openssh-server` to sandbox.setup"
        } else {
            "see `pocket exec P --root -- sshd -t`"
        }));
    }
    // The guest names its own host key; it is only pinned for this pocket's alias.
    let host_key = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if !valid_key(&host_key) {
        return Err(err(
            ErrorCode::Guest,
            "the pocket returned an invalid host key",
        ));
    }
    Ok(Response::Ssh {
        vsock_uds: live.vm.vsock_uds.clone(),
        user,
        host_key,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn keys() {
        assert!(super::valid_key(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI+/= pocket"
        ));
        assert!(!super::valid_key("ssh-rsa AAAA"));
        assert!(!super::valid_key("ssh-ed25519 AA$(reboot)"));
    }
}
