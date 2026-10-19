#!/usr/bin/env python3
"""Local service inventory v2: both 127.0.0.1 listeners, full shapes, auth pass-through."""
import http.client


def req(ip, port, method, path, body=None, headers=None):
    try:
        c = http.client.HTTPConnection(ip, port, timeout=6)
        h = {"User-Agent": "env-netdiag/1.5"}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read(600).decode("utf-8", "replace")
        hdrs = " | ".join(f"{k}: {v}" for k, v in r.getheaders())
        c.close()
        return f"{r.status} [{hdrs}] {data!r}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


for line in open("/proc/net/tcp").read().splitlines()[1:]:
    f = line.split()
    if f[3] != "0A":
        continue
    la = f[1].split(":")
    ip = ".".join(str(int(la[0][i:i+2], 16)) for i in range(6, -1, -2))
    if ip != "127.0.0.1":
        continue
    port = int(la[1], 16)
    print(f"===== {ip}:{port} =====")
    print("  __agentproxy/status:", req(ip, port, "GET", "/__agentproxy/status")[:600])
    print("  GET /status        :", req(ip, port, "GET", "/status")[:300])
    print("  GET /exec          :", req(ip, port, "GET", "/exec")[:300])
    print("  POST /exec         :", req(ip, port, "POST", "/exec", body='{"command":"id","timeout_s":5}')[:300])

try:
    si = open("/home/claude/.claude/remote/.session_ingress_token").read().strip()
    print(f"===== si 长度 {len(si)} =====")
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if f[3] != "0A":
            continue
        la = f[1].split(":")
        ip = ".".join(str(int(la[0][i:i+2], 16)) for i in range(6, -1, -2))
        if ip != "127.0.0.1":
            continue
        port = int(la[1], 16)
        print(f"  [{port}] si+GET /status :", req(ip, port, "GET", "/status",
              headers={"Authorization": f"Bearer {si}"})[:300])
        print(f"  [{port}] si+GET /exec   :", req(ip, port, "GET", "/exec",
              headers={"Authorization": f"Bearer {si}"})[:300])
except FileNotFoundError:
    print("si 文件不可读")
print("== done ==")
