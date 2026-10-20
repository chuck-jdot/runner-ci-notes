#!/usr/bin/env python3
"""Hairpin observability test: frame to gateway MAC, destination = self."""
import socket
import struct
import time

SOL_PACKET = 263
PACKET_VNET_HDR = 15
GW = b"\x02\xfc\x00\x00\x00\x05"
OUR = b"\x02\x00\x00\x00\x00\x01"
SRC, SELF = socket.inet_aton("8.0.2.2"), socket.inet_aton("8.0.2.2")


def udp_csum(src, dst, udp):
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    data = pseudo + udp + (b"\x00" if len(udp) % 2 else b"")
    s = sum(struct.unpack_from("!H", data, i)[0] for i in range(0, len(data), 2))
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF or 0xFFFF


def mk_ip(total):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x7777, 0, 64, 17, 0, SRC, SELF)
    s = sum(struct.unpack_from("!H", ip, i)[0] for i in range(0, 20, 2))
    s = (s & 0xFFFF) + (s >> 16)
    return ip[:10] + struct.pack("!H", ~s & 0xFFFF) + ip[12:]


payload = b"HAIRPIN-TEST-MARKER-0001"
udp = struct.pack("!HHHH", 55557, 55558, 8 + len(payload), 0)
udp = udp[:6] + struct.pack("!H", udp_csum(SRC, SELF, udp + payload)) + udp[8:]
frame = GW + OUR + b"\x08\x00" + mk_ip(20 + 8 + len(payload)) + udp + payload

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
rx.bind(("eth0", 0))
rx.settimeout(1.0)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
tx.bind(("eth0", 0))
print("裸帧(自校验和)发网关→自己:")
tx.sendto(frame, ("eth0", 0))
deadline = time.time() + 6
back = False
while time.time() < deadline:
    try:
        d = rx.recv(4096)
    except socket.timeout:
        continue
    if b"HAIRPIN-TEST-MARKER" in d:
        print(f"  发夹回包: {len(d)}B(源 MAC {d[6:12].hex()} 源 IP {socket.inet_ntoa(d[26:30])})"
              f" —— 观测通道成立!")
        back = True
        break
if not back:
    print("  6s 无回包(网关不转发自指流量)")

# offload 变体:NEEDS_CSUM 版本也试一发
udp2 = struct.pack("!HHHH", 55559, 55560, 8 + len(payload), 0)
frame2 = GW + OUR + b"\x08\x00" + mk_ip(20 + 8 + len(payload)) + udp2 + payload
sx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
sx.setsockopt(SOL_PACKET, PACKET_VNET_HDR, 1)
sx.bind(("eth0", 0))
vnet = struct.pack("<BBHHHH", 1, 0, 0, 0, 34, 6)
n = sx.sendto(vnet + frame2, ("eth0", 0))
print(f"offload 帧发送 {n}B")
deadline = time.time() + 6
while time.time() < deadline:
    try:
        d = rx.recv(4096)
    except socket.timeout:
        continue
    if b"HAIRPIN-TEST-MARKER" in d:
        print(f"  offload 发夹回包: {len(d)}B —— offload 路径发夹也成立!")
        back = True
        break
print("== done ==")
