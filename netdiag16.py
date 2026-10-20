#!/usr/bin/env python3
"""Offload-path differential: kernel socket vs raw frame vs offloaded frame."""
import socket
import struct
import time

SOL_PACKET = 263
PACKET_VNET_HDR = 15
GW = b"\x02\xfc\x00\x00\x00\x05"
OUR = b"\x02\x00\x00\x00\x00\x01"


def dnsq(txid, name=b"example", tld=b"com"):
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + name + b"\x02" + tld
            + b"\x00" + struct.pack("!HH", 1, 1))


def udp_csum(src, dst, udp):
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    s = 0
    data = pseudo + udp + (b"\x00" if len(udp) % 2 else b"")
    for i in range(0, len(data), 2):
        s += struct.unpack_from("!H", data, i)[0]
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF if s != 0xFFFF else 0xFFFF


def mk_ip(total, src, dst):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x4321, 0, 64, 17, 0, src, dst)
    s = sum(struct.unpack_from("!H", ip, i)[0] for i in range(0, 20, 2))
    s = (s & 0xFFFF) + (s >> 16)
    return ip[:10] + struct.pack("!H", ~s & 0xFFFF) + ip[12:]


SRC, DST = socket.inet_aton("8.0.2.2"), socket.inet_aton("8.8.8.8")
rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
rx.bind(("eth0", 0))
rx.settimeout(1.0)


def drain(mark, wait=6):
    deadline, seen = time.time() + wait, []
    while time.time() < deadline:
        try:
            d = rx.recv(4096)
        except socket.timeout:
            continue
        if len(d) > 42 and d[23] == 17:
            txid = d[42:44]
            if txid in (b"\xba\x01", b"\xba\x02", b"\xba\x03"):
                seen.append((txid.hex(), len(d)))
    print(f"  {mark}: 回包 {seen if seen else '无'}")


print("== A) 对照:普通 UDP socket(内核自发,offload 由内核编排) ==")
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(3)
try:
    u.sendto(dnsq(0xBA01), ("8.8.8.8", 53))
    r = u.recv(2048)
    print("  A 回包:", len(r), "B(内核路径通)")
except Exception as e:  # noqa: BLE001
    print("  A 失败:", type(e).__name__)

print("== B) 裸帧+预计算校验和(flags=0,无 offload) ==")
q = dnsq(0xBA02)
udp = struct.pack("!HHHH", 55555, 53, 8 + len(q), 0)
udp = udp[:6] + struct.pack("!H", udp_csum(SRC, DST, udp + q)) + udp[8:]
frame = GW + OUR + b"\x08\x00" + mk_ip(20 + 8 + len(q), SRC, DST) + udp + q
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("eth0", 0))
s.sendto(frame, ("eth0", 0))
drain("B(裸帧)")

print("== C) NEEDS_CSUM offloaded(校验和零,csum_start=34/offset=6) ==")
q = dnsq(0xBA03)
udp = struct.pack("!HHHH", 55556, 53, 8 + len(q), 0)
frame = GW + OUR + b"\x08\x00" + mk_ip(20 + 8 + len(q), SRC, DST) + udp + q
sx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sx.setsockopt(SOL_PACKET, PACKET_VNET_HDR, 1)
sx.bind(("eth0", 0))
vnet = struct.pack("<BBHHHH", 1, 0, 0, 0, 34, 6)
n = sx.sendto(vnet + frame, ("eth0", 0))
print(f"  C 发送 {n}B")
drain("C(offload)")
print("== done ==")
