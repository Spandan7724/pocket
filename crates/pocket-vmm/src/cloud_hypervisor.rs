use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Disk {
    pub path: PathBuf,
    pub read_only: bool,
}

/// Cold boot of one VM. Disk order defines guest order: `/dev/vda`, `/dev/vdb`, ...;
/// pmem devices appear as `/dev/pmem0`, ...
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    pub binary: PathBuf,
    pub kernel: PathBuf,
    pub cmdline: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub disks: Vec<Disk>,
    pub pmem: Vec<PathBuf>,
    pub vsock_cid: u32,
    pub vsock_uds: PathBuf,
    pub api_socket: PathBuf,
    /// Guest serial console goes here (and `console=ttyS0` is added) when set.
    pub serial_log: Option<PathBuf>,
}

impl LaunchSpec {
    pub fn command(&self) -> Command {
        let mut cmdline = self.cmdline.clone();
        if self.serial_log.is_some() {
            cmdline.push_str(" console=ttyS0");
        }
        let mut c = Command::new(&self.binary);
        c.arg("--api-socket")
            .arg(&self.api_socket)
            .arg("--kernel")
            .arg(&self.kernel)
            .arg("--cmdline")
            .arg(cmdline)
            .arg("--cpus")
            .arg(format!("boot={}", self.vcpus))
            .arg("--memory")
            .arg(format!("size={}M", self.memory_mib));
        if !self.disks.is_empty() {
            c.arg("--disk");
            for d in &self.disks {
                c.arg(format!(
                    "path={},readonly={},image_type=raw",
                    d.path.display(),
                    if d.read_only { "on" } else { "off" }
                ));
            }
        }
        if !self.pmem.is_empty() {
            c.arg("--pmem");
            for p in &self.pmem {
                c.arg(format!("file={},discard_writes=on", p.display()));
            }
        }
        c.arg("--vsock").arg(format!(
            "cid={},socket={}",
            self.vsock_cid,
            self.vsock_uds.display()
        ));
        c.arg("--rng").arg("src=/dev/urandom");
        match &self.serial_log {
            Some(p) => c.arg("--serial").arg(format!("file={}", p.display())),
            None => c.arg("--serial").arg("off"),
        };
        c.arg("--console").arg("off");
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lists_devices_in_order() {
        let spec = LaunchSpec {
            binary: "/ch".into(),
            kernel: "/k".into(),
            cmdline: "quiet".into(),
            vcpus: 2,
            memory_mib: 256,
            disks: vec![
                Disk {
                    path: "/sys.erofs".into(),
                    read_only: true,
                },
                Disk {
                    path: "/disk.raw".into(),
                    read_only: false,
                },
            ],
            pmem: vec!["/base.erofs".into()],
            vsock_cid: 3,
            vsock_uds: "/v.sock".into(),
            api_socket: "/api.sock".into(),
            serial_log: None,
        };
        let args: Vec<String> = spec
            .command()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let disk = args.iter().position(|a| a == "--disk").unwrap();
        assert_eq!(args[disk + 1], "path=/sys.erofs,readonly=on,image_type=raw");
        assert_eq!(args[disk + 2], "path=/disk.raw,readonly=off,image_type=raw");
        assert!(args.contains(&"file=/base.erofs,discard_writes=on".to_string()));
        assert!(args.contains(&"cid=3,socket=/v.sock".to_string()));
        assert!(args.contains(&"quiet".to_string()));
    }
}
