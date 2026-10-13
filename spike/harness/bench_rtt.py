"""0.11: 1-byte round trip host -> vsock UDS -> guest PTY echo -> back; vs a local PTY echo."""
import json, os, pty, sys, termios, time, tty
sys.path.insert(0, ".")
import pvm

N = 5000

def measure(send, recv):
    xs = []
    for i in range(N + 200):
        t0 = time.perf_counter_ns()
        send(b"x")
        recv()
        if i >= 200:
            xs.append((time.perf_counter_ns() - t0) / 1e3)
    return xs

def summary(name, xs):
    print(f"{name}: n={len(xs)} p50={pvm.pct(xs,50):.1f} us p95={pvm.pct(xs,95):.1f} us p99={pvm.pct(xs,99):.1f} us")

res = {}
pid, master = pty.fork()
if pid == 0:
    tty.setraw(0)
    while True:
        d = os.read(0, 4096)
        os.write(1, d)
time.sleep(0.2)
res["local_pty"] = measure(lambda b: os.write(master, b), lambda: os.read(master, 1))
os.kill(pid, 9)
summary("local pty", res["local_pty"])

for b in ("fc", "ch"):
    vm = pvm.VM(b, f"rtt-{b}")
    vm.boot()
    s = pvm.vconnect(vm.vsock)
    s.sendall(b"ECHO\n")
    assert pvm.recv_line(s) == "OK"
    res[b] = measure(s.sendall, lambda: s.recv(1))
    s.close()
    vm.kill()
    summary(f"{b} vsock+guest pty", res[b])
    print(f"  added vs local: p50={pvm.pct(res[b],50)-pvm.pct(res['local_pty'],50):.1f} us p95={pvm.pct(res[b],95)-pvm.pct(res['local_pty'],95):.1f} us")
json.dump(res, open(pvm.OUT + "/rtt.json", "w"))
