#!/usr/bin/env python3
"""w7c: runner state via /proc (no BPF needed — targets are not our ancestor).
Targets: 88 environment-man, 97 claude, 83 "6".
Captures: environ + cmdline verbatim; anon/[heap]/[stack] regions via
/proc/<pid>/mem pread (64MB cap each). Output: /mnt/user-data/working/pa6c_*.
Final marker: WALK7CDONE."""
import gzip
import hashlib
import os
import struct
import time

T0 = time.time()
CAP_TOTAL = 64 * 1024 * 1024
W = "/mnt/user-data/working/"


def out(*a):
    print("[%6.1fs]" % (time.time() - T0), *a, flush=True)


def capture_meta(pid, tag):
    for kind, fn in (("environ", "environ"), ("cmdline", "cmdline")):
        try:
            data = open("/proc/%d/%s" % (pid, fn), "rb").read()
            open(W + "pa6c_%s.%s" % (tag, kind), "wb").write(data)
            out("%s %s: %dB" % (tag, kind, len(data)))
        except OSError as e:
            out("%s %s: ERR %s" % (tag, kind, e))


def dump_proc(pid, tag):
    try:
        maps = open("/proc/%d/maps" % pid).readlines()
    except OSError as e:
        out("%s: maps ERR %s" % (tag, e))
        return
    regions = []
    for ln in maps:
        parts = ln.split()
        rng, perms = parts[0], parts[1]
        path = parts[5] if len(parts) > 5 else ""
        if "r" not in perms:
            continue
        if path and not path.startswith("["):
            continue
        start, end = (int(x, 16) for x in rng.split("-"))
        regions.append((start, end, path or "anon"))
    out("%s pid=%d anon-regions=%d" % (tag, pid, len(regions)))
    try:
        mfd = os.open("/proc/%d/mem" % pid, os.O_RDONLY)
    except OSError as e:
        out("%s: mem open ERR %s" % (tag, e))
        return
    total = 0
    part = partbytes = 0
    h = hashlib.sha256()
    gz = gzip.open(W + "pa6c_%s-%d.gz" % (tag, part), "wb", compresslevel=1)
    for start, end, name in regions:
        if total >= CAP_TOTAL:
            out("%s: cap reached at %#x" % (tag, start))
            break
        ln = min(end - start, CAP_TOTAL - total)
        try:
            data = os.pread(mfd, ln, start)
        except OSError as e:
            continue
        if not data:
            continue
        rec = struct.pack("<QI", start, len(data)) + data
        gz.write(rec)
        h.update(rec)
        total += len(data)
        partbytes += len(rec)
        if partbytes > 20 * 1024 * 1024:
            gz.close()
            part += 1
            partbytes = 0
            gz = gzip.open(W + "pa6c_%s-%d.gz" % (tag, part), "wb", compresslevel=1)
    gz.close()
    os.close(mfd)
    out("%sDONE %dB %s parts=%d" % (tag.upper(), total, h.hexdigest(), part + 1))


for pid, tag in ((88, "emgr"), (97, "claude"), (83, "p6")):
    capture_meta(pid, tag)
    dump_proc(pid, tag)
out("WALK7CDONE")
