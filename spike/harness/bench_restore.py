"""0.7: snapshot once, restore N times -> ready; RSS/PSS right after restore."""
import json, os, sys
sys.path.insert(0, ".")
import pvm

N = int(sys.argv[1]) if len(sys.argv) > 1 else 50
MEM = int(sys.argv[2]) if len(sys.argv) > 2 else 512
res = {}
MODES = {"fc": ["cow"], "ch": os.environ.get("CH_MODES", "copy").split(",")}
for b, modes in MODES.items():
    vm = pvm.VM(b, f"tmpl-{b}", mem_mib=MEM)
    vm.boot()
    # hold 64 MiB touched in a guest process across the snapshot so memory content is non-trivial
    s = pvm.vconnect(vm.vsock); s.sendall(b"ALLOC 64\n"); pvm.recv_line(s)
    orig_rss, _ = pvm.mem_stats(vm.pid)
    sdir = os.path.join(pvm.OUT, f"snap-{b}")
    vm.snapshot(sdir)
    s.close()
    vm.kill()
    sizes = {f: (os.stat(os.path.join(sdir, f)).st_size, os.stat(os.path.join(sdir, f)).st_blocks * 512)
             for f in os.listdir(sdir)}
    for mode in modes:
        r = {"total_ms": [], "api_ms": [], "rss_kib": [], "pss_kib": [], "orig_rss_kib": orig_rss,
             "snapshot_files": sizes}
        for i in range(N):
            c, t0, t1, t2 = pvm.restore(b, f"r-{b}", sdir, mode=mode)
            rss, pss = pvm.mem_stats(c.pid)
            c.kill()
            r["total_ms"].append((t2 - t0) * 1e3)
            if t1:
                r["api_ms"].append((t1 - t0) * 1e3)
            r["rss_kib"].append(rss); r["pss_kib"].append(pss)
        res[f"{b}-{mode}"] = r
        print(f"{b}-{mode}: spawn->ready p50={pvm.pct(r['total_ms'],50):.1f} p95={pvm.pct(r['total_ms'],95):.1f} ms"
              + (f"; spawn->load-done p50={pvm.pct(r['api_ms'],50):.1f}" if r["api_ms"] else "")
              + f"; RSS after restore p50={pvm.pct(r['rss_kib'],50)/1024:.1f} MiB (orig VM {orig_rss/1024:.1f} MiB)"
              + f"; snapshot files {sizes}")
json.dump(res, open(pvm.OUT + f"/restore-{MEM}{os.environ.get('TAG', '')}.json", "w"))
