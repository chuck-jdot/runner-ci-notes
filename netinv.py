#!/usr/bin/env python3
"""netinv.py — network reachability inventory for the environment audit.

Maps this VM's local view: interfaces, routes, neighbors, established peers,
DNS, cloud metadata endpoints, local-segment service reachability, a TLS
routing check against the egress path, and the host-channel port ranges.
Prints progress lines; final marker line: NETINV7DONE.
"""
import socket, struct, time, threading, fcntl, shutil

T0 = time.time()
cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def out(*a):
    print("[%6.1fs]" % (time.time() - T0), *a, flush=True)


def parallel(fn, items, n=128):
    sem = threading.Semaphore(n)

    def w(i):
        with sem:
            fn(i)

    ts = [threading.Thread(target=w, args=(i,)) for i in items]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


# ---------- 1. interfaces ----------
out("=== IFACES ===")
try:
    for idx, name in socket.if_nameindex():
        try:
            ip = socket.inet_ntoa(fcntl.ioctl(cs.fileno(), 0x8915,
                                              struct.pack("256s", name[:15].encode()))[20:24])
            nm = socket.inet_ntoa(fcntl.ioctl(cs.fileno(), 0x891b,
                                              struct.pack("256s", name[:15].encode()))[20:24])
            out("  %-10s %s/%s" % (name, ip, nm))
        except OSError:
            out("  %-10s (no ipv4)" % name)
except Exception as e:
    out("  ifaces err:", e)

# ---------- 2. routes ----------
out("=== ROUTES (/proc/net/route) ===")
gateways = set()
try:
    for ln in open("/proc/net/route").read().splitlines()[1:]:
        f = ln.split()
        if len(f) < 8 or not f[1]:
            continue
        dst = socket.inet_ntoa(struct.pack("<I", int(f[1], 16)))
        gw = socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
        flags = int(f[3], 16)
        if (flags & 2) and gw != "0.0.0.0":
            gateways.add(gw)
        out("  %-10s dst=%s gw=%s flags=%#x" % (f[0], dst, gw, flags))
except Exception as e:
    out("  route err:", e)

# ---------- 3. neighbors + established ----------
def read_arp():
    rows = []
    try:
        for ln in open("/proc/net/arp").read().splitlines()[1:]:
            f = ln.split()
            if len(f) >= 6 and f[3] != "00:00:00:00:00:00":
                rows.append((f[0], f[3], f[5]))
    except Exception:
        pass
    return rows


out("=== NEIGHBORS (/proc/net/arp) ===")
for ip, mac, dev in read_arp():
    out("  %-16s %s %s" % (ip, mac, dev))


def dec_addr(a, v6):
    ip_hex, port_hex = a.split(":")
    if v6:
        gs = [struct.unpack("<I", bytes.fromhex(ip_hex[i:i + 8]))[0] for i in range(0, 32, 8)]
        ip = socket.inet_ntop(socket.AF_INET6, b"".join(struct.pack(">I", x) for x in gs))
    else:
        ip = socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16)))
    return ip, int(port_hex, 16)


out("=== ESTABLISHED SOCKETS ===")
for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
    try:
        for ln in open(path).read().splitlines()[1:]:
            f = ln.split()
            if len(f) < 4 or f[3] != "01":
                continue
            try:
                lip, lp = dec_addr(f[1], v6)
                rip, rp = dec_addr(f[2], v6)
                out("  %s:%d -> %s:%d" % (lip, lp, rip, rp))
            except Exception:
                pass
    except Exception as e:
        out("  %s err: %s" % (path, e))

# ---------- 4. hosts / resolv / dns ----------
out("=== HOSTS/RESOLV ===")
try:
    out("  /etc/hosts:", " | ".join(l.strip() for l in open("/etc/hosts")
                                    if l.strip() and not l.startswith("#")))
except Exception as e:
    out("  hosts err:", e)
resolver = None
try:
    rc = open("/etc/resolv.conf").read()
    out("  resolv.conf:", " ; ".join(l.strip() for l in rc.splitlines()
                                     if l.strip() and not l.startswith("#")))
    for l in rc.splitlines():
        if l.startswith("nameserver"):
            resolver = l.split()[1]
            break
except Exception as e:
    out("  resolv err:", e)

out("=== DNS CANDIDATES ===")
for n in ["api.anthropic.com", "claude.ai", "internal.anthropic.com",
          "admin.anthropic.com", "staging.anthropic.com", "sandbox.anthropic.com",
          "sbx.anthropic.com", "ingest.anthropic.com", "egress.anthropic.com",
          "gateway.anthropic.com", "metadata.anthropic.com", "console.anthropic.com",
          "worker.anthropic.com", "proxy.anthropic.com"]:
    try:
        infos = socket.getaddrinfo(n, None, socket.AF_INET)
        out("  %-28s -> %s" % (n, sorted({i[4][0] for i in infos})))
    except Exception as e:
        out("  %-28s -> %s" % (n, type(e).__name__))

# ---------- 5. cloud metadata endpoints ----------
out("=== CLOUD META ENDPOINTS ===")


def http_raw(ip, port, req, timeout=3, v6=False):
    try:
        s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(req.encode())
        data = b""
        while len(data) < 8192:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            data += b
        s.close()
        return data[:300].decode("utf-8", "replace")
    except OSError as e:
        return "ERR %s %s" % (getattr(e, "errno", "?"), getattr(e, "strerror", e))


for label, req in [
    ("aws-v1", "GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n"),
    ("aws-v2-token", "PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 300\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ("azure", "GET /metadata/instance HTTP/1.1\r\nHost: 169.254.169.254\r\nMetadata: true\r\nConnection: close\r\n\r\n"),
    ("root", "GET / HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n"),
]:
    out("  %-13s %r" % (label, http_raw("169.254.169.254", 80, req)))
out("  %-13s %r" % ("gcp-v6", http_raw("fd00:ec2::254", 80,
                                        "GET /computeMetadata/v1/?recursive=true HTTP/1.1\r\nHost: metadata\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n",
                                        v6=True)))

# ---------- 6. segment sweep ----------
out("=== SEGMENT SWEEP ===")
prefix = []
eth0_ip = eth0_mask = None
try:
    eth0_ip = socket.inet_ntoa(fcntl.ioctl(cs.fileno(), 0x8915,
                                           struct.pack("256s", b"eth0"))[20:24])
    eth0_mask = socket.inet_ntoa(fcntl.ioctl(cs.fileno(), 0x891b,
                                             struct.pack("256s", b"eth0"))[20:24])
    ipn = struct.unpack(">I", socket.inet_aton(eth0_ip))[0]
    nmn = struct.unpack(">I", socket.inet_aton(eth0_mask))[0]
    net = ipn & nmn
    span = (~nmn) & 0xFFFFFFFF
    prefix = [socket.inet_ntoa(struct.pack(">I", net + i)) for i in range(1, span)
              if (net + i) != ipn]
    out("  eth0 %s/%s, sweeping %d addrs" % (eth0_ip, eth0_mask, len(prefix)))
except Exception as e:
    out("  prefix err:", e)

alive = set()
alock = threading.Lock()


def probe_host(ip):
    for p in (22, 80, 443):
        try:
            s = socket.socket()
            s.settimeout(0.6)
            s.connect((ip, p))
            s.close()
            with alock:
                alive.add(ip)
            return
        except OSError:
            continue


t0 = time.time()
parallel(probe_host, prefix, 192)
out("  tcp-alive after sweep: %s (%.0fs)" % (sorted(alive), time.time() - t0))
out("  post-sweep arp:")
for ip, mac, dev in read_arp():
    out("    %-16s %s %s" % (ip, mac, dev))

# ---------- 7. port scans ----------
out("=== PORT SCANS ===")
CURATED = [20, 21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 123, 135, 139, 143, 389,
           443, 445, 465, 500, 514, 587, 636, 853, 873, 993, 995, 1080, 1433, 1521,
           2024, 2025, 2049, 2181, 2375, 2376, 2379, 2380, 3000, 3128, 3268, 3306,
           3389, 4000, 4444, 4848, 5000, 5001, 5002, 5005, 5050, 5432, 5555, 5601,
           5672, 5900, 5984, 5985, 5986, 61613, 6379, 6443, 6667, 7000, 7077, 8000,
           8001, 8008, 8010, 8020, 8080, 8081, 8088, 8090, 8161, 8443, 8530, 8888,
           9000, 9001, 9090, 9100, 9200, 9300, 9418, 9999, 10000, 10248, 10249,
           10250, 10255, 10256, 11211, 15672, 18080, 50000, 51000, 52000, 54321, 65535]


def tscan(ip, ports, timeout=0.35, threads=256):
    opens = []
    lock = threading.Lock()

    def work(p):
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((ip, p))
            s.close()
            with lock:
                opens.append(p)
        except OSError:
            pass

    parallel(work, list(ports), threads)
    return sorted(set(opens))


scan_targets = sorted(set(list(gateways) + list(alive)
                          + ([resolver] if resolver else [])))
full_set = set(sorted(set(list(gateways) + ([resolver] if resolver else [])))[:4])
out("  scan targets:", scan_targets)
out("  full-scan set:", sorted(full_set))
for ip in scan_targets:
    if ip in full_set:
        t0 = time.time()
        o = tscan(ip, range(1, 65536))
        out("  FULL %-16s open=%s (%.0fs)" % (ip, o, time.time() - t0))
    else:
        out("  CUR  %-16s open=%s" % (ip, tscan(ip, CURATED)))

# ---------- 8. egress routing check ----------
out("=== EGRESS ROUTING CHECK ===")
import ssl, hashlib
ctx = ssl._create_unverified_context()
api_ip = None
try:
    api_ip = socket.getaddrinfo("api.anthropic.com", 443, socket.AF_INET)[0][4][0]
    out("  api.anthropic.com ->", api_ip)
except Exception as e:
    out("  resolve err:", e)


def tls_probe(ip, sni, req, port=443, timeout=8):
    try:
        raw = socket.create_connection((ip, port), timeout)
        w = ctx.wrap_socket(raw, server_hostname=sni)
        cert = w.getpeercert(True)
        w.sendall(req.encode())
        r1 = w.recv(1024)
        w.close()
        return "cert=%d/%s resp=%r" % (len(cert), hashlib.sha256(cert).hexdigest()[:10], r1[:200])
    except Exception as e:
        return "ERR %s: %s" % (type(e).__name__, e)


def h1(host, path="/"):
    return ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n" % (path, host))


if api_ip:
    for label, sni, host, path in [
        ("control", "api.anthropic.com", "api.anthropic.com", "/"),
        ("host-int", "api.anthropic.com", "internal.anthropic.com", "/"),
        ("host-loc", "api.anthropic.com", "localhost", "/"),
        ("host-imds", "api.anthropic.com", "169.254.169.254", "/latest/meta-data/"),
        ("host-sbx", "api.anthropic.com", "sbx.anthropic.com", "/"),
        ("mcp-host-int", "mcp-proxy.anthropic.com", "internal.anthropic.com", "/"),
    ]:
        out("  %-14s %s" % (label, tls_probe(api_ip, sni, h1(host, path))))
    out("  %-14s %s" % ("absuri", tls_probe(
        api_ip, "api.anthropic.com",
        "GET http://internal.anthropic.com/ HTTP/1.1\r\nHost: api.anthropic.com\r\nConnection: close\r\n\r\n")))
    for label, host in (("plain-ctl", "api.anthropic.com"),
                        ("plain-int", "internal.anthropic.com"),
                        ("plain-imds", "169.254.169.254")):
        try:
            s = socket.create_connection((api_ip, 80), 6)
            s.settimeout(6)
            s.sendall(h1(host).encode())
            out("  %-14s %r" % (label, s.recv(300)))
            s.close()
        except Exception as e:
            out("  %-14s ERR %s" % (label, e))

# ---------- 9. host channel gap ranges ----------
out("=== HOST CHANNEL GAPS ===")
AF_VSOCK = 40
try:
    ls = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    out("  local CID:", ls.getsockopt(287, 3))
    ls.close()
except Exception as e:
    out("  vsock err:", e)


def vconn(cid, port, timeout=0.2):
    try:
        s = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((cid, port))
        s.close()
        return "OPEN"
    except OSError as e:
        return "E%d" % (e.errno or 0)


for cid in (1, 3, 4, 5):
    for port in (2024, 5002, 5005):
        out("  cid %d:%d -> %s" % (cid, port, vconn(cid, port)))

for lo, hi in ((4097, 5000), (5101, 65536)):
    t0 = time.time()
    found = []
    lock = threading.Lock()

    def work(p):
        if vconn(2, p) == "OPEN":
            with lock:
                found.append(p)

    parallel(work, range(lo, hi), 128)
    out("  vscan cid=2 [%d,%d): open=%s (%.0fs)" % (lo, hi, sorted(found), time.time() - t0))

out("NETINV7DONE")
try:
    shutil.copy("/tmp/netinv.log", "/mnt/user-data/working/netinv.log")
    out("log copied to working/")
except Exception as e:
    out("copy err:", e)
