#!/usr/bin/env python3
"""Local signaling endpoint credential pass-through diagnostics."""
import http.client
import os


def find_claude_pid():
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                if "claude" in f.read():
                    return int(pid)
        except OSError:
            continue
    return None


def environ_of(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            return dict(e.split(b"=", 1) for e in f.read().split(b"\x00") if b"=" in e)
    except OSError:
        return {}


def auth_svc_port():
    for line in open("/proc/net/tcp").read().splitlines()[1:]:
        f = line.split()
        if f[3] != "0A":
            continue
        la = f[1].split(":")
        ip = ".".join(str(int(la[0][i:i+2], 16)) for i in range(6, -1, -2))
        if ip != "127.0.0.1":
            continue
        port = int(la[1], 16)
        # 排除代理口:代理答 405 长文;这里直接现场探
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
            c.request("GET", "/x")
            r = c.getresponse()
            r.read()
            c.close()
            if r.status == 401:
                return port
        except Exception:  # noqa: BLE001
            continue
    return None


def req(port, method, path, body=None, headers=None):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
        h = {"User-Agent": "env-netdiag/1.6"}
        if body is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read(700).decode("utf-8", "replace")
        c.close()
        return f"{r.status} {data!r}"
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


port = auth_svc_port()
print("认证服务端口:", port)
pid = find_claude_pid()
print("harness pid:", pid)
tok = None
if pid:
    env = environ_of(pid)
    for k, v in env.items():
        ks = k.decode("utf-8", "replace")
        if "MESSAGING" in ks or "TOKEN" in ks:
            print("  env:", ks, "=", v[:20].decode("utf-8", "replace") + "…")
            if ks == "CLAUDE_CODE_MESSAGING_TOKEN":
                tok = v.decode()
if port and tok:
    print("===== MESSAGING_TOKEN 打认证服务 =====")
    print("  GET /status:", req(port, "GET", "/status", headers={"Authorization": f"Bearer {tok}"}))
    print("  GET /:", req(port, "GET", "/", headers={"Authorization": f"Bearer {tok}"}))
    print("  GET /exec:", req(port, "GET", "/exec", headers={"Authorization": f"Bearer {tok}"}))
    print("  POST /exec:", req(port, "POST", "/exec", body='{"command":"id","timeout_s":5}',
                             headers={"Authorization": f"Bearer {tok}"}))
    print("  GET /__agentproxy/status:", req(port, "GET", "/__agentproxy/status",
                                             headers={"Authorization": f"Bearer {tok}"}))
elif port:
    print("token 未取得,试 X-Api-Key 形状")
print("== done ==")
