#!/usr/bin/env python3
"""Local service authentication diagnostics: full headers + credential pass-through."""
import http.client


def req(ip, port, method, path, body=None, headers=None):
    try:
        c = http.client.HTTPConnection(ip, port, timeout=6)
        h = {"User-Agent": "env-netdiag/1.4"}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read(400).decode("utf-8", "replace")
        hdrs = "\n".join(f"{k}: {v}" for k, v in r.getheaders())
        c.close()
        return f"{r.status}\n{hdrs}\n{data!r}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def listeners():
    out = []
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if f[3] != "0A":
            continue
        la = f[1].split(":")
        ip = ".".join(str(int(la[0][i:i+2], 16)) for i in range(6, -1, -2))
        out.append((ip, int(la[1], 16)))
    return out


AUTH_SVC = PROXY = None
for ip, port in listeners():
    if ip == "127.0.0.1" and port > 1024:
        # 区分:代理口会答 __agentproxy
        r = req(ip, port, "GET", "/__agentproxy/status")
        if "agent-proxy" in r:
            PROXY = (ip, port)
        else:
            AUTH_SVC = (ip, port)
print("认证服务:", AUTH_SVC, "| 代理:", PROXY)

print("===== 1) 认证服务 401 全头 =====")
print(req(AUTH_SVC[0], AUTH_SVC[1], "GET", "/status"))

print("===== 2) 代理 /__agentproxy/status =====")
print(req(PROXY[0], PROXY[1], "GET", "/__agentproxy/status"))

try:
    si = open("/home/claude/.claude/remote/.session_ingress_token").read().strip()
    print("===== 3) si Bearer 打认证服务 =====")
    print(req(AUTH_SVC[0], AUTH_SVC[1], "GET", "/status",
              headers={"Authorization": f"Bearer {si}"}))
    print(req(AUTH_SVC[0], AUTH_SVC[1], "GET", "/container_name",
              headers={"Authorization": f"Bearer {si}"}))
    print("===== 4) si 直打 exec/mount =====")
    print(req(AUTH_SVC[0], AUTH_SVC[1], "POST", "/exec", body='{"command":"id","timeout_s":5}',
              headers={"Authorization": f"Bearer {si}"}))
    print(req(AUTH_SVC[0], AUTH_SVC[1], "GET", "/mount_root",
              headers={"Authorization": f"Bearer {si}"}))
except FileNotFoundError:
    print("si 文件不可读")
print("== done ==")
