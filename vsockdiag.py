#!/usr/bin/env python3
"""Environment telemetry uplink reachability diagnostics.

Checks the guest->host vsock telemetry ports with plain HTTP probes
(method/route shapes) and reports raw responses.
"""
import ctypes
import socket

libc = ctypes.CDLL(None, use_errno=True)
AF_VSOCK = 40


class SockaddrVM(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("rsvd", ctypes.c_ushort),
                ("port", ctypes.c_uint), ("cid", ctypes.c_uint),
                ("zero", ctypes.c_ubyte * 4)]


def vsock_http(cid, port, raw, timeout=6):
    fd = libc.socket(AF_VSOCK, socket.SOCK_STREAM, 0)
    if fd < 0:
        return f"socket errno {ctypes.get_errno()}"
    sa = SockaddrVM(AF_VSOCK, 0, port, cid)
    if libc.connect(fd, ctypes.byref(sa), ctypes.sizeof(sa)) != 0:
        e = ctypes.get_errno()
        libc.close(fd)
        return f"connect errno {e}"
    libc.send(fd, raw, len(raw), 0)
    libc.recv  # noqa
    import select
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        libc.close(fd)
        return "recv timeout"
    buf = ctypes.create_string_buffer(4096)
    n = libc.recv(fd, buf, 4096, 0)
    libc.close(fd)
    return buf.raw[:n].decode("utf-8", "replace") if n > 0 else "eof"


HOST_CID = 2
REQS = [
    ("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"),
    ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ("POST /v1/metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ("POST /v1/traces HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"),
    ("POST /v1/logs HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"),
    ("POST /v1/otlp/v1/metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ("POST /ingest HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ("POST /telemetry HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
]

for port in (5005, 5002):
    print(f"===== vsock CID{HOST_CID} :{port} =====")
    for req in REQS:
        first = req.split(" ")[0] + " " + req.split(" ")[1]
        resp = vsock_http(HOST_CID, port, req.encode())
        print(f"[{first}] {resp[:260]!r}")
print("== done ==")
