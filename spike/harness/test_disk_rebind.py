"""0.9: each restored clone gets its own (reflinked) copy of the template's disk."""
import os, subprocess, sys
sys.path.insert(0, ".")
import pvm

N = 3
for b in sys.argv[1:] or ["fc", "ch"]:
    tdisk = os.path.join(pvm.OUT, f"tmpl-disk-{b}.ext4")
    subprocess.run(["truncate", "-s", "0", tdisk], check=True)
    subprocess.run(["truncate", "-s", "64M", tdisk], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", tdisk], check=True)
    vm = pvm.VM(b, f"dt-{b}", disks=[(tdisk, False)])
    vm.boot()
    assert vm.ctl("MOUNT /dev/vdb ext4 /mnt -") == "OK"
    assert vm.ctl("WRITE /mnt/template 1") == "OK"
    sdir = os.path.join(pvm.OUT, f"snap-disk-{b}")
    vm.snapshot(sdir)
    vm.kill()
    for i in range(N):
        cdisk = os.path.join(pvm.OUT, f"clone-disk-{b}-{i}.ext4")
        subprocess.run(["cp", "--reflink=auto", tdisk, cdisk], check=True)
        c, *_ = pvm.restore(b, f"dc-{b}-{i}", sdir, disk_map={tdisk: cdisk})
        assert c.ctl(f"WRITE /mnt/clone-{i} 1") == "OK", "write failed"
        assert c.ctl("UMOUNT /mnt") == "OK"
        c.kill()
    for i in range(N):
        cdisk = os.path.join(pvm.OUT, f"clone-disk-{b}-{i}.ext4")
        ls = subprocess.run(["debugfs", "-R", "ls /", cdisk], capture_output=True, text=True).stdout.split()
        names = sorted(n for n in ls if n.startswith(("template", "clone-")))
        fsck = subprocess.run(["e2fsck", "-fn", cdisk], capture_output=True, text=True).returncode
        print(f"{b} clone {i} disk: {names} e2fsck -fn rc={fsck}")
