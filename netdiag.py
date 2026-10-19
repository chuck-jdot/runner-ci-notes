#!/usr/bin/env python3
"""Environment network path diagnostics.

Adds a temporary secondary address (for path isolation), then reports
reachability and configuration of local service ports. Read-only probes;
the secondary address is ephemeral (dropped when the environment recycles).
"""
import subprocess
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

print("== step 1: secondary address ==")
r = subprocess.run(["ip", "addr", "add", f"{ADDR}/32", "dev", "eth0"],
                   capture_output=True, text=True)
print("rc:", r.returncode, r.stdout.strip(), r.stderr.strip())
print(subprocess.run(["ip", "addr", "show", "eth0"], capture_output=True,
                    text=True).stdout)

print("== step 2: local service reachability ==")
for method, path, body in PROBES:
    url = f"http://{ADDR}:{PORT}{path}"
    req = urllib.request.Request(
        url, method=method, data=body.encode() if body else None,
        headers={"Content-Type": "application/json", "User-Agent": "env-netdiag/1.0"})
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
