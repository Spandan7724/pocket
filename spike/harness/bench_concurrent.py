"""0.8: N concurrent restores from one snapshot (reuses snapshots from bench_restore.py)."""
import json, os, sys, time
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, ".")
import pvm

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
MODES = {"fc": ["cow"], "ch": os.environ.get("CH_MODES", "copy").split(",")}
res = {}
for b, modes in MODES.items():
    sdir = os.path.join(pvm.OUT, f"snap-{b}")
    for mode in modes:
        t0 = time.monotonic()
        with ThreadPoolExecutor(N) as ex:
            vms = list(ex.map(lambda i: pvm.restore(b, f"c-{b}-{i}", sdir, mode=mode)[0], range(N)))
        wall = (time.monotonic() - t0) * 1e3
        # one control round trip per clone so every guest has actually run after restore
        for v in vms:
            v.ctl("PING")
        stats = [pvm.mem_stats(v.pid) for v in vms]
        rss = sum(s[0] for s in stats) / 1024
        pss = sum(s[1] for s in stats) / 1024
        for v in vms:
            v.kill()
        res[f"{b}-{mode}"] = {"wall_ms": wall, "total_rss_mib": rss, "total_pss_mib": pss}
        print(f"{b}-{mode}: {N} concurrent restores wall={wall:.1f} ms, total RSS={rss:.0f} MiB, total PSS={pss:.0f} MiB, PSS/VM={pss/N:.1f} MiB")
json.dump(res, open(pvm.OUT + f"/concurrent{os.environ.get('TAG', '')}.json", "w"))
