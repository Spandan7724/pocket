"""M0 spike harness: boot/restore Firecracker and Cloud Hypervisor VMs and talk to spike-init."""

import http.client
import json
import os
import shutil
import socket
import subprocess
import time

SPIKE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(SPIKE, "bin")
OUT = os.path.join(SPIKE, "out")
KERNEL = os.path.join(BIN, "vmlinux")
ROOTFS = os.path.join(BIN, "spike-root.erofs")
FC = os.path.join(BIN, "firecracker")
CH = os.environ.get("POCKET_SPIKE_CH", os.path.join(BIN, "cloud-hypervisor"))

BASE_ARGS = "reboot=k panic=1 nomodule 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.dumbkbd swiotlb=noforce quiet"
ROOT_ARGS = "root=/dev/vda ro rootfstype=erofs init=/sbin/init"


class UHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def api(sock, method, url, body=None):
    c = UHTTP(sock)
    c.request(method, url, body=json.dumps(body) if body is not None else None,
              headers={"Content-Type": "application/json"} if body is not None else {})
    r = c.getresponse()
    data = r.read()
    c.close()
    if r.status >= 300:
        raise RuntimeError(f"{method} {url} -> {r.status} {data!r}")
    return data


def wait_path(p, timeout=5):
    end = time.monotonic() + timeout
    while not os.path.exists(p):
        if time.monotonic() > end:
            raise TimeoutError(p)
        time.sleep(0.0002)


def listen_ready(vsock_path):
    p = vsock_path + "_1000"
    if os.path.exists(p):
        os.unlink(p)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(p)
    s.listen(4)
    return s


def recv_line(s):
    buf = b""
    while not buf.endswith(b"\n"):
        d = s.recv(4096)
        if not d:
            raise ConnectionError("eof")
        buf += d
    return buf.decode().strip()


def vconnect(vsock_path, port=1024, timeout=5):
    """Hybrid vsock: connect to the VMM UDS and ask for a guest port."""
    end = time.monotonic() + timeout
    while True:
        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(vsock_path)
            s.sendall(f"CONNECT {port}\n".encode())
            line = recv_line(s)
            if line.startswith("OK"):
                return s
            s.close()
        except (OSError, ConnectionError):
            if s:
                s.close()
        if time.monotonic() > end:
            raise TimeoutError("vsock connect")
        time.sleep(0.0002)


def mem_stats(pid):
    rss = pss = 0
    with open(f"/proc/{pid}/smaps_rollup") as f:
        for line in f:
            if line.startswith("Rss:"):
                rss = int(line.split()[1])
            elif line.startswith("Pss:"):
                pss = int(line.split()[1])
    return rss, pss  # KiB


class VM:
    def __init__(self, backend, name, mem_mib=256, vcpus=1, disks=(), pmem=(), balloon=False,
                 console=False, cid=3):
        self.backend = backend
        self.dir = os.path.join(OUT, "vms", name)
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        self.api_sock = os.path.join(self.dir, "api.sock")
        self.vsock = os.path.join(self.dir, "vsock.sock")
        self.mem_mib, self.vcpus = mem_mib, vcpus
        self.disks, self.pmem, self.balloon = list(disks), list(pmem), balloon
        self.console, self.cid = console, cid
        self.proc = None
        self.log = open(os.path.join(self.dir, "vmm.log"), "wb")

    @property
    def pid(self):
        return self.proc.pid

    def cmdline(self):
        args = BASE_ARGS + " " + ROOT_ARGS
        if self.backend == "fc":
            args += " pci=off"
        if self.console:
            args = args.replace("8250.nr_uarts=0 ", "").replace(" quiet", "") + " console=ttyS0"
        return args

    def boot(self):
        """Spawn the VMM; returns (t_spawn, ready_line, t_ready) using monotonic clock."""
        lsock = listen_ready(self.vsock)
        if self.backend == "fc":
            cfg = {
                "boot-source": {"kernel_image_path": KERNEL, "boot_args": self.cmdline()},
                "drives": [{"drive_id": "root", "path_on_host": ROOTFS, "is_root_device": True,
                            "is_read_only": True}]
                + [{"drive_id": f"d{i}", "path_on_host": p, "is_root_device": False,
                    "is_read_only": ro} for i, (p, ro) in enumerate(self.disks)],
                "machine-config": {"vcpu_count": self.vcpus, "mem_size_mib": self.mem_mib},
                "vsock": {"guest_cid": self.cid, "uds_path": self.vsock},
            }
            if self.pmem:
                cfg["pmem"] = [{"id": f"p{i}", "path_on_host": p, "read_only": True}
                               for i, p in enumerate(self.pmem)]
            if self.balloon:
                cfg["balloon"] = {"amount_mib": 0, "deflate_on_oom": True,
                                  "stats_polling_interval_s": 0, "free_page_reporting": True}
            cfgp = os.path.join(self.dir, "config.json")
            with open(cfgp, "w") as f:
                json.dump(cfg, f)
            argv = [FC, "--api-sock", self.api_sock, "--config-file", cfgp, "--level", "Warning"]
        else:
            argv = [CH, "--api-socket", self.api_sock, "--kernel", KERNEL,
                    "--cmdline", self.cmdline(),
                    "--cpus", f"boot={self.vcpus}", "--memory", f"size={self.mem_mib}M",
                    "--disk", f"path={ROOTFS},readonly=on,image_type=raw"]
            argv += [f"path={p},readonly={'on' if ro else 'off'},image_type=raw" for p, ro in self.disks]
            argv += ["--vsock", f"cid={self.cid},socket={self.vsock}"]
            if self.pmem:
                argv += ["--pmem"] + [f"file={p},discard_writes=on" for p in self.pmem]
            if self.balloon:
                argv += ["--balloon", "size=0,free_page_reporting=on,deflate_on_oom=on"]
            argv += ["--serial", "tty" if self.console else "off", "--console", "off"]
        t0 = time.monotonic()
        self.proc = subprocess.Popen(argv, stdout=None if self.console else self.log,
                                     stderr=subprocess.STDOUT if not self.console else None,
                                     stdin=subprocess.DEVNULL)
        lsock.settimeout(10)
        conn, _ = lsock.accept()
        line = recv_line(conn)
        t1 = time.monotonic()
        conn.close()
        lsock.close()
        return t0, line, t1

    def ctl(self, cmd, timeout=60):
        s = vconnect(self.vsock, timeout=timeout)
        s.settimeout(timeout)
        s.sendall((cmd + "\n").encode())
        r = recv_line(s)
        s.close()
        return r

    def pause(self):
        if self.backend == "fc":
            api(self.api_sock, "PATCH", "/vm", {"state": "Paused"})
        else:
            api(self.api_sock, "PUT", "/api/v1/vm.pause")

    def snapshot(self, sdir):
        shutil.rmtree(sdir, ignore_errors=True)
        os.makedirs(sdir)
        self.pause()
        if self.backend == "fc":
            api(self.api_sock, "PUT", "/snapshot/create",
                {"snapshot_type": "Full", "snapshot_path": os.path.join(sdir, "vmstate"),
                 "mem_file_path": os.path.join(sdir, "mem")})
        else:
            api(self.api_sock, "PUT", "/api/v1/vm.snapshot", {"destination_url": f"file://{sdir}"})

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def restore(backend, name, sdir, disk_map=None, mode=None):
    """Restore a clone from sdir. Returns (vm, t_spawn, t_api_done, t_ready).

    disk_map: {original_path: new_path} to rebind per-clone disks.
    """
    vm = VM(backend, name)
    disk_map = disk_map or {}
    if backend == "fc":
        t0 = time.monotonic()
        vm.proc = subprocess.Popen([FC, "--api-sock", vm.api_sock, "--level", "Warning"],
                                   stdout=vm.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        wait_path(vm.api_sock)
        api(vm.api_sock, "PUT", "/snapshot/load",
            {"snapshot_path": os.path.join(sdir, "vmstate"),
             "mem_backend": {"backend_type": "File", "backend_path": os.path.join(sdir, "mem")},
             "vsock_override": {"uds_path": vm.vsock},
             "resume_vm": not disk_map})
        for i, (_, new) in enumerate(disk_map.items()):
            api(vm.api_sock, "PATCH", f"/drives/d{i}", {"drive_id": f"d{i}", "path_on_host": new})
        if disk_map:
            api(vm.api_sock, "PATCH", "/vm", {"state": "Resumed"})
        t1 = time.monotonic()
    else:
        cdir = os.path.join(vm.dir, "snap")
        os.makedirs(cdir)
        with open(os.path.join(sdir, "config.json")) as f:
            cfg = json.load(f)
        cfg["vsock"]["socket"] = vm.vsock
        for d in cfg.get("disks") or []:
            if d["path"] in disk_map:
                d["path"] = disk_map[d["path"]]
        with open(os.path.join(cdir, "config.json"), "w") as f:
            json.dump(cfg, f)
        shutil.copy(os.path.join(sdir, "state.json"), cdir)
        os.symlink(os.path.join(sdir, "memory-ranges"), os.path.join(cdir, "memory-ranges"))
        rmode = {"cow": "copyonwrite", "copy": "copy"}[mode or os.environ.get("CH_MODES", "copy").split(",")[0]]
        t0 = time.monotonic()
        vm.proc = subprocess.Popen(
            [CH, "--api-socket", vm.api_sock,
             "--restore", f"source_url=file://{cdir},memory_restore_mode={rmode},resume=true"],
            stdout=vm.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        t1 = None
    s = vconnect(vm.vsock, timeout=10)
    s.sendall(b"PING\n")
    recv_line(s)
    t2 = time.monotonic()
    s.close()
    return vm, t0, t1, t2


def pct(xs, p):
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)
