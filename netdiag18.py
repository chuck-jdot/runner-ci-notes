#!/usr/bin/env python3
"""ICMP quote readback test: does the first hop return errors that quote our packets?"""
import socket
import struct
import time

GW = b"\x02\xfc\x00\x00\x00\x05"
OUR = b"\x02\x00\x00\x00\x00\x01"
SRC = socket.inet_aton("8.0.2.2")


def mk_ip(total, dst, ttl, ident):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0, ttl, 17, 0, SRC, dst)
    s = sum(struct.unpack_from("!H", ip, i)[0] for i in range(0, 20, 2))
    s = (s & 0xFFFF) + (s >> 16)
    return ip[:10] + struct.pack("!H", ~s & 0xFFFF) + ip[12:]


def udp_csum(src, dst, udp):
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    data = pseudo + udp + (b"\x00" if len(udp) % 2 else b"")
    s = sum(struct.unpack_from("!H", data, i)[0] for i in range(0, len(data), 2))
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF or 0xFFFF


rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
rx.bind(("eth0", 0))
rx.settimeout(1.0)
tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
tx.bind(("eth0", 0))


def send_and_watch(tag, dst, ttl, wait=5):
    payload = b"Q" + tag.encode()
    udp = struct.pack("!HHHH", 55560, 53, 8 + len(payload), 0)
    udp = udp[:6] + struct.pack("!H", udp_csum(SRC, dst, udp + payload)) + udp[8:]
    frame = GW + OUR + b"\x08\x00" + mk_ip(20 + 8 + len(payload), dst, ttl, 0xBEEF) + udp + payload
    tx.sendto(frame, ("eth0", 0))
    print(f"[{tag}] dst={socket.inet_ntoa(dst)} ttl={ttl} 已发,听 {wait}s:")
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            d = rx.recv(4096)
        except socket.timeout:
            continue
        if len(d) < 34 or d[23] != 1:
            continue
        ihl = (d[14] & 0xF) * 4
        t, code = d[14 + ihl], d[14 + ihl + 1]
        quote = d[34 + 8:]
        print(f"  ICMP type={t} code={code} 引用 {len(quote)}B,含我们的标记: {tag.encode() in quote}"
              f"{' ← 读回通道成立!' if tag.encode() in quote else ''}")
        return True
    print("  无 ICMP 回应")
    return False


ok1 = send_and_watch("T1", socket.inet_aton("8.8.8.8"), 1)
ok2 = send_and_watch("T2", socket.inet_aton("1.1.1.1"), 64)
ok3 = send_and_watch("T3", socket.inet_aton("8.0.2.9"), 64)   # 同网段不存在地址
print("== done ==")
