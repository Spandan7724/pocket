"""0.10: 10 VMs read the same 256 MiB erofs; pmem+DAX vs virtio-blk. Reports total PSS."""
import os, subprocess, sys
sys.path.insert(0, ".")
import pvm

N = 10
img = os.path.join(pvm.OUT, "data.erofs")
if not os.path.exists(img):
    src = os.path.join(pvm.OUT, "data-src")
    os.makedirs(src, exist_ok=True)
    for i in range(64):
        with open(os.path.join(src, f"f{i}"), "wb") as f:
            f.write(os.urandom(4 << 20))
    subprocess.run(["mkfs.erofs", img, src], check=True, capture_output=True)
    size = os.stat(img).st_size
    os.truncate(img, (size + (2 << 20) - 1) // (2 << 20) * (2 << 20))

for b in sys.argv[1:] or ["fc", "ch"]:
    for kind in os.environ.get("KINDS", "pmem-dax,blk").split(","):
        vms = []
        for i in range(N):
            if kind == "pmem-dax":
                vm = pvm.VM(b, f"dax-{b}-{i}", mem_mib=512, pmem=[img], cid=3 + i)
            else:
                vm = pvm.VM(b, f"blk-{b}-{i}", mem_mib=512, disks=[(img, True)], cid=3 + i)
            vm.boot()
            vms.append(vm)
        before = sum(pvm.mem_stats(v.pid)[1] for v in vms) / 1024
        dev, opts = ("/dev/pmem0", "dax=always") if kind == "pmem-dax" else ("/dev/vdb", "ro")
        mounts = {v.ctl(f"MOUNT {dev} erofs /mnt {opts}") for v in vms}
        reads = {v.ctl("READALL /mnt") for v in vms}
        stats = [pvm.mem_stats(v.pid) for v in vms]
        rss = sum(s[0] for s in stats) / 1024
        pss = sum(s[1] for s in stats) / 1024
        for v in vms:
            v.kill()
        print(f"{b} {kind}: mount={mounts} bytes_read/VM={reads} total PSS before={before:.0f} MiB "
              f"after={pss:.0f} MiB (delta {pss-before:.0f} MiB for {N} VMs), total RSS={rss:.0f} MiB")
