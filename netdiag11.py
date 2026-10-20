#!/usr/bin/env python3
"""Environment NIC offload capability inventory."""
import glob
import os
import socket
import subprocess

print("== 1) ethtool -k eth0 ==")
for cmd in (["ethtool", "-k", "eth0"], ["ethtool", "--show-features", "eth0"]):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        print(r.stdout[:1200])
        break
    else:
        print("ethtool 不可用:", r.stderr.strip()[:60])
        break

print("== 2) virtio feature 位掩码 ==")
for f in glob.glob("/sys/bus/virtio/devices/*/features"):
    v = open(f).read().strip()
    print(f, "=", v)
    try:
        bits = int(v, 0)
        names = {0: "VIRTIO_NET_F_CSUM(设备侧tx校验和)", 1: "GUEST_CSUM", 2: "CTRL_GUEST_OFFLOADS",
                 5: "MAC", 6: "GSO", 7: "GUEST_TSO4", 8: "GUEST_TSO6", 9: "GUEST_ECN",
                 10: "GUEST_UFO", 11: "HOST_TSO4", 12: "HOST_TSO6", 13: "HOST_ECN",
                 14: "HOST_UFO", 15: "MRG_RXBUF", 16: "STATUS", 17: "CTRL_VQ",
                 18: "CTRL_RX", 19: "CTRL_VLAN", 23: "GUEST_ANNOUNCE", 25: "MQ"}
        for b, n in names.items():
            if bits >> b & 1:
                print(f"  bit{b} {n}: ON")
    except ValueError:
        pass

print("== 3) MTU 与队列 ==")
print("  eth0 mtu:", open("/sys/class/net/eth0/mtu").read().strip())
print("  eth0 tx_queue_len:", open("/sys/class/net/eth0/tx_queue_len").read().strip())

print("== 4) 原始套接字可用性 ==")
for fam, name in ((socket.AF_PACKET, "AF_PACKET"), (socket.AF_INET, "AF_INET-SOCK_RAW")):
    try:
        s = socket.socket(fam, socket.SOCK_RAW, socket.IPPROTO_RAW if fam == socket.AF_INET else 0)
        s.close()
        print(f"  {name}: OK")
    except Exception as e:  # noqa: BLE001
        print(f"  {name}: {type(e).__name__} {e}")

print("== 5) dmesg virtio ==")
r = subprocess.run(["dmesg"], capture_output=True, text=True)
for ln in r.stdout.splitlines():
    if "virtio" in ln.lower() or "vnet" in ln.lower() or "eth0" in ln:
        print("  ", ln[:150])
print("== done ==")
