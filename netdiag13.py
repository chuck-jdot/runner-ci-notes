#!/usr/bin/env python3
"""Environment packet-crafting capability inventory."""
import socket
import struct

print("mtu:", open("/sys/class/net/eth0/mtu").read().strip())

PACKET_VNET_HDR = 15
SOL_PACKET = 263
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    print("AF_PACKET: OK")
    try:
        s.setsockopt(SOL_PACKET, PACKET_VNET_HDR, 1)
        print("PACKET_VNET_HDR: OK(注入原语可用)")
    except Exception as e:  # noqa: BLE001
        print("PACKET_VNET_HDR:", type(e).__name__, e)
        s.close()
        raise SystemExit(1)

    # 良性发送测试:vnet_hdr(VIRTIO_NET_HDR_V1: flags=VIRTIO_NET_HDR_F_DATA_VALID?0)
    # + 以太帧(广播 ARP 请求形),csum_start 指向无害位置
    eth = (b"\xff\xff\xff\xff\xff\xff"      # dst 广播
           b"\x02\x00\x00\x00\x00\x01"      # src
           b"\x08\x06"                      # ARP
           b"\x00\x01\x08\x00\x06\x04\x00\x01"  # ARP 以太/IPv4/req
           b"\x02\x00\x00\x00\x00\x01"
           b"\x08\x00\x02\x01"
           b"\x00\x00\x00\x00\x00\x00"
           b"\x08\x00\x02\xfe")
    # vnet_hdr v1: flags(u8) gso_type(u8) hdr_len(u16) gso_size(u16) csum_start(u16) csum_offset(u16)
    vnet = struct.pack("<BBHHHH", 1, 0, 0, 0, 14, 0)
    try:
        n = s.sendto(vnet + eth, ("eth0", 0))
        print(f"vnet+帧 sendto: OK ({n}B)")
    except Exception as e:  # noqa: BLE001
        print("vnet+帧 sendto:", type(e).__name__, e)
    s.close()
except SystemExit:
    pass
print("== done ==")
