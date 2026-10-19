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
    return struct.pack("BB", ln, t) + d + b"\x00" * ((4 - ln % 4) % 4)


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

print("== step 2: local service reachability ==")
for method, path, body in PROBES:
    url = f"http://{ADDR}:{PORT}{path}"
    req = urllib.request.Request(
        url, method=method, data=body.encode() if body else None,
        headers={"Content-Type": "application/json", "User-Agent": "env-netdiag/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[{method} {path}] {resp.status}")
            print(resp.read(800).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        print(f"[{method} {path}] HTTP {e.code}")
        print(e.read(800).decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        print(f"[{method} {path}] {type(e).__name__}: {e}")
print("== done ==")
