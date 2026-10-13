#!/usr/bin/env python3
"""M0 probe: can this host create and run a KVM guest? Stdlib only.

Checks /dev/kvm, the KVM API version, VM and vCPU creation, and on x86_64 runs a
12-byte real-mode guest that computes 2+2 and writes it to an I/O port.
Exit 0 only if every applicable check passes.
"""

import ctypes
import fcntl
import mmap
import os
import platform
import struct
import sys
import time

KVM_GET_API_VERSION = 0xAE00
KVM_CREATE_VM = 0xAE01
KVM_GET_VCPU_MMAP_SIZE = 0xAE04
KVM_CREATE_VCPU = 0xAE41
KVM_SET_USER_MEMORY_REGION = 0x4020AE46
KVM_RUN = 0xAE80
KVM_SET_REGS = 0x4090AE82
KVM_GET_SREGS = 0x8138AE83
KVM_SET_SREGS = 0x4138AE84

KVM_EXIT_IO = 2
KVM_EXIT_HLT = 5

GUEST_ADDR = 0x1000
# mov dx,0x3f8; add al,bl; add al,'0'; out dx,al; mov al,'\n'; out dx,al; hlt
GUEST_CODE = bytes([0xBA, 0xF8, 0x03, 0x00, 0xD8, 0x04, ord("0"), 0xEE, 0xB0, ord("\n"), 0xEE, 0xF4])


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}{'  ' + detail if detail else ''}")
    return ok


def run_guest(vm_fd):
    mem = mmap.mmap(-1, 0x1000, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, mmap.PROT_READ | mmap.PROT_WRITE)
    mem[: len(GUEST_CODE)] = GUEST_CODE
    host_addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    region = struct.pack("IIQQQ", 0, 0, GUEST_ADDR, 0x1000, host_addr)
    fcntl.ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, region)

    vcpu_fd = fcntl.ioctl(vm_fd, KVM_CREATE_VCPU, 0)
    run_size = fcntl.ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0)
    run = mmap.mmap(vcpu_fd, run_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)

    sregs = bytearray(312)
    fcntl.ioctl(vcpu_fd, KVM_GET_SREGS, sregs)
    struct.pack_into("Q", sregs, 0, 0)   # cs.base
    struct.pack_into("H", sregs, 12, 0)  # cs.selector
    fcntl.ioctl(vcpu_fd, KVM_SET_SREGS, bytes(sregs))

    regs = [0] * 18
    regs[0], regs[1] = 2, 2          # rax, rbx
    regs[16], regs[17] = GUEST_ADDR, 0x2  # rip, rflags
    fcntl.ioctl(vcpu_fd, KVM_SET_REGS, struct.pack("18Q", *regs))

    out = bytearray()
    start = time.perf_counter()
    for _ in range(16):
        fcntl.ioctl(vcpu_fd, KVM_RUN, 0)
        reason = struct.unpack_from("I", run, 8)[0]
        if reason == KVM_EXIT_HLT:
            break
        if reason != KVM_EXIT_IO:
            return False, f"unexpected exit reason {reason}"
        direction, size, port, count, data_off = struct.unpack_from("BBHIQ", run, 32)
        if port == 0x3F8 and direction == 1:
            out += run[data_off : data_off + size * count]
    elapsed_us = (time.perf_counter() - start) * 1e6
    return out == b"4\n", f"guest wrote {bytes(out)!r} in {elapsed_us:.0f} us"


print(f"host: {platform.platform()} ({platform.machine()})")
ok = check("/dev/kvm exists", os.path.exists("/dev/kvm"))
if ok:
    st = os.stat("/dev/kvm")
    print(f"      mode={oct(st.st_mode & 0o777)} uid={st.st_uid} gid={st.st_gid}")
    ok = check("/dev/kvm open rw", os.access("/dev/kvm", os.R_OK | os.W_OK))
if ok:
    kvm_fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    api = fcntl.ioctl(kvm_fd, KVM_GET_API_VERSION, 0)
    ok = check("KVM API version is 12", api == 12, f"got {api}")
if ok:
    vm_fd = fcntl.ioctl(kvm_fd, KVM_CREATE_VM, 0)
    ok = check("KVM_CREATE_VM", vm_fd >= 0)
if ok and platform.machine() == "x86_64":
    passed, detail = run_guest(vm_fd)
    ok = check("run real-mode guest (2+2 via port I/O)", passed, detail)
elif ok:
    print("SKIP  guest execution (x86_64 only)")

sys.exit(0 if ok else 1)
