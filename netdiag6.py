#!/usr/bin/env python3
"""Environment local service inventory: enumerate listeners, probe each one."""
import http.client
import socket


def listeners():
    out = []
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if f[3] != "0A":
            continue
        la = f[1].split(":")
        ip = ".".join(str(int(la[0][i:i+2], 16)) for i in range(6, -1, -2))
        out.append((ip, int(la[1], 16), f[7]))
    return out


def probe(ip, port, method, path, body=None):
    try:
        c = http.client.HTTPConnection(ip, port, timeout=6)
        c.request(method, path, body=body,
                  headers={"Content-Type": "application/json", "User-Agent": "env-netdiag/1.3"})
        r = c.getresponse()
        data = r.read(300).decode("utf-8", "replace")
        c.close()
        return f"{r.status} {data!r}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


for ip, port, uid in listeners():
    print(f"===== {ip}:{port} (uid {uid}) =====")
    if ip in ("127.0.0.1", "0.0.0.0") or port > 1024:
        print("  GET /status :", probe(ip if ip != "0.0.0.0" else "127.0.0.1", port, "GET", "/status"))
        print("  GET /       :", probe(ip if ip != "0.0.0.0" else "127.0.0.1", port, "GET", "/"))
        print("  GET /container_name :", probe(ip if ip != "0.0.0.0" else "127.0.0.1", port, "GET", "/container_name"))
print("== done ==")
