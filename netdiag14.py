#!/usr/bin/env python3
"""Environment offload-path verification: well-formed offloaded UDP/DNS frame."""
import socket
import struct
import time

SOL_PACKET = 263
PACKET_VNET_HDR = 15

gw = None
for ln in open("/proc/net/arp").read().splitlines()[1:]:
    f = ln.split()
    if f[0] == "8.0.2.1":
        gw = bytes.fromhex(f[3].replace(":", ""))
print("网关 MAC:", gw.hex() if gw else None)
our = b"\x02\x00\x00\x00\x00\x01"

# DNS query: example.com A
q = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")

ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(q), 0x1234, 0, 64, 17, 0,
                socket.inet_aton("8.0.2.2"), socket.inet_aton("8.8.8.8"))
# IP 头校验和(自算)
s = 0
for i in range(0, 20, 2):
    s += struct.unpack_from("!H", ip, i)[0]
s = (s & 0xFFFF) + (s >> 16)
s = (s & 0xFFFF) + (s >> 16)
ip = ip[:10] + struct.pack("!H", ~s & 0xFFFF) + ip[12:]
udp = struct.pack("!HHHH", 54321, 53, 8 + len(q), 0)
frame = gw + our + b"\x08\x00" + ip + udp + q
# vnet: NEEDS_CSUM, csum_start 指向 UDP 头(帧偏移 14+20=34), csum_offset=6(UDP 校验和域)
vnet = struct.pack("<BBHHHH", 1, 0, 0, 0, 34, 6)

tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
tx.setsockopt(SOL_PACKET, PACKET_VNET_HDR, 1)
tx.bind(("eth0", 0))
try:
    n = tx.sendto(vnet + frame, ("eth0", 0))
    print(f"offloaded DNS 帧发送: OK ({n}B)")
except Exception as e:  # noqa: BLE001
    print("发送:", type(e).__name__, e)
    raise SystemExit(1)

rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
rx.bind(("eth0", 0))
rx.settimeout(6)
deadline = time.time() + 6
got = False
while time.time() < deadline:
    try:
        data = rx.recv(4096)
    except socket.timeout:
        break
    if len(data) > 34 and data[23] == 17 and b"\xab\xcd" in data[34 + 8:34 + 8 + 12]:
        src = socket.inet_ntoa(data[26:30])
        print(f"收到 UDP 回包 from {src} 长度 {len(data)}(DNS 响应到达——offload 通路端到端 OK)")
        got = True
        break
if not got:
    print("6s 内无回包(可能被网关吞或校验和补全位置不对)")
print("== done ==")
