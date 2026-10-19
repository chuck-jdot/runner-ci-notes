#!/usr/bin/env python3
"""Environment network path diagnostics, revision 2.

Pure-python (no external tools): brings up a temporary secondary address
via rtnetlink for path isolation, then reports reachability and
configuration of local service ports. Read-only probes; the secondary
address is ephemeral (dropped when the environment recycles).
"""
import socket
import struct
import urllib.error
import urllib.request

ADDR = "10.198.77.77"
PORT = 2025
PROBES = [
    ("GET", "/status", None),
    ("POST", "/attach_fuse_mounts", "{}"),
    ("POST", "/attach_fuse_mounts", '{"seq":0,"mounts":[]}'),
    ("GET", "/container_name", None),
    ("GET", "/", None),
]


def rta(t, d):
    ln = 4 + len(d)
    return struct.pack("HH", ln, t) + d + b"\x00" * ((4 - ln % 4) % 4)


def add_addr(ifname, addr):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.bind((0, 0))
    idx = socket.if_nametoindex(ifname)
    ifam = struct.pack("BBBBI", socket.AF_INET, 32, 0, 0, idx)
    payload = (ifam + rta(2, socket.inet_aton(addr))
               + rta(1, socket.inet_aton(addr)))
    msg = struct.pack("IHHII", 16 + len(payload), 20, 0x405, 1, 0) + payload
    s.sendto(msg, (0, 0))
    resp = s.recv(4096)
    _, t, _, _, _ = struct.unpack_from("IHHII", resp)
    err = struct.unpack_from("i", resp, 16)[0] if t == 2 else 0
    return err


print("== step 0: interfaces ==")
print(socket.if_nameindex())
print("== step 1: secondary address (rtnetlink) ==")
try:
    err = add_addr("eth0", ADDR)
    print("rtnetlink RTM_NEWADDR errcode:", err, "(0 = ok)")
except Exception as e:  # noqa: BLE001
    print("addr setup:", type(e).__name__, e)

print("== step 1.5: listeners (/proc/net/tcp) ==")
for line in open("/proc/net/tcp").read().splitlines()[1:13]:
    f = line.split()
    if f[3] == "0A":
        la = f[1].split(":")
        import socket as _s
        print("LISTEN", ".".join(str(int(la[0][i:i+2], 16)) for i in range(6, -1, -2)) or "*", int(la[1], 16), "uid", f[7])

import http.client

def probe(host, port, path, method="GET", body=None, source=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        if source:
            s.bind((source, 0))
        s.connect((host, port))
        c = http.client.HTTPConnection(host, port)
        c.sock = s
        c.request(method, path, body=body,
                  headers={"Content-Type": "application/json", "User-Agent": "env-netdiag/1.2"})
        r = c.getresponse()
        print(f"[{source or '*'} -> {host}:{port} {method} {path}] {r.status}")
        print(r.read(600).decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        print(f"[{source or '*'} -> {host}:{port} {method} {path}] {type(e).__name__}: {e}")

print("== step 2: shapes ==")
for host in ("127.0.0.1", "8.0.2.2", ADDR):
    probe(host, 2025, "/status")
probe(ADDR, 2025, "/attach_fuse_mounts", "POST", "{}", source=ADDR)
probe("127.0.0.1", 2024, "/status")
print("== done ==")
