"""0.6: cold boot -> READY, FC vs CH, N runs each (interleaved)."""
import json, os, sys, time
sys.path.insert(0, ".")
import pvm

N = int(sys.argv[1]) if len(sys.argv) > 1 else 60
res = {"fc": {"host_ms": [], "guest_ms": []}, "ch": {"host_ms": [], "guest_ms": []}}
for i in range(N):
    for b in ("fc", "ch"):
        vm = pvm.VM(b, f"boot-{b}")
        t0, line, t1 = vm.boot()
        vm.kill()
        res[b]["host_ms"].append((t1 - t0) * 1e3)
        res[b]["guest_ms"].append(int(line.split()[1]) / 1e6)
for b, r in res.items():
    for k, xs in r.items():
        print(f"{b} {k}: n={len(xs)} p50={pvm.pct(xs,50):.1f} p95={pvm.pct(xs,95):.1f} min={min(xs):.1f} max={max(xs):.1f}")
json.dump(res, open(pvm.OUT + f"/boot{os.environ.get('TAG', '')}.json", "w"))
