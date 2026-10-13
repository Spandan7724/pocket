"""0.12: guest touches 512 MiB then frees it; VMM RSS with and without free page reporting."""
import sys, time
sys.path.insert(0, ".")
import pvm

for b in ("fc", "ch"):
    for fpr in (False, True):
        vm = pvm.VM(b, f"fpr-{b}", mem_mib=1024, balloon=fpr)
        vm.boot()
        base = pvm.mem_stats(vm.pid)[0] / 1024
        s = pvm.vconnect(vm.vsock)
        s.sendall(b"ALLOC 512\n"); pvm.recv_line(s)
        peak = pvm.mem_stats(vm.pid)[0] / 1024
        s.sendall(b"FREE\n"); pvm.recv_line(s)
        samples = []
        for t in (0.5, 1, 2, 5):
            time.sleep(t - (samples[-1][0] if samples else 0))
            samples.append((t, pvm.mem_stats(vm.pid)[0] / 1024))
        s.close()
        vm.kill()
        print(f"{b} free_page_reporting={fpr}: RSS boot={base:.0f} MiB after alloc={peak:.0f} MiB after free: "
              + ", ".join(f"{t}s={r:.0f}" for t, r in samples) + f" -> returned {peak - samples[-1][1]:.0f} MiB")
