#!/usr/bin/env python3
"""Telemetry uplink protocol shape diagnostics (route confirmed: /v1/metrics)."""
import ctypes
import select
import socket

libc = ctypes.CDLL(None, use_errno=True)
AF_VSOCK = 40


class SockaddrVM(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort), ("rsvd", ctypes.c_ushort),
                ("port", ctypes.c_uint), ("cid", ctypes.c_uint),
                ("zero", ctypes.c_ubyte * 4)]


def vsock_raw(raw, port=5005, cid=2, timeout=6):
    fd = libc.socket(AF_VSOCK, socket.SOCK_STREAM, 0)
    if fd < 0:
        return f"socket errno {ctypes.get_errno()}"
    sa = SockaddrVM(AF_VSOCK, 0, port, cid)
    if libc.connect(fd, ctypes.byref(sa), ctypes.sizeof(sa)) != 0:
        e = ctypes.get_errno()
        libc.close(fd)
        return f"connect errno {e}"
    libc.send(fd, raw, len(raw), 0)
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        libc.close(fd)
        return "recv timeout"
    buf = ctypes.create_string_buffer(8192)
    n = libc.recv(fd, buf, 8192, 0)
    libc.close(fd)
    return buf.raw[:n].decode("utf-8", "replace") if n > 0 else "eof"


def post(body, ctype):
    head = (f"POST /v1/metrics HTTP/1.1\r\nHost: x\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return (head.encode() + body)


CASES = [
    ("protobuf/空体", post(b"", "application/x-protobuf")),
    ("protobuf/极小", post(b"\x0a\x00", "application/x-protobuf")),
    ("protobuf/垃圾", post(b"\xff\xff\xff\xff", "application/x-protobuf")),
    ("octet/极小", post(b"\x0a\x00", "application/octet-stream")),
    ("proto变体", post(b"\x0a\x00", "application/protobuf")),
    ("OTLP头标记", post(b"\x0a\x02\x0a\x00", "application/x-protobuf")),
]
for name, raw in CASES:
    resp = vsock_raw(raw)
    print(f"[{name}] {resp[:300]!r}")
print("== done ==")
