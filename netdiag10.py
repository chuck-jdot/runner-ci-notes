#!/usr/bin/env python3
"""Local message-channel self-test (the service's own documented example)."""
import glob
import json
import socket
import time


socks = glob.glob("/tmp/cc-socks/*.sock")
print("sockets:", socks)
for path in socks:
    print(f"===== {path} =====")
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(path)
        # 文档示例:auth 行(可选)+ user 消息行
        s.sendall(b'{"type":"user","message":{"role":"user","content":"channel self-test, reply nothing"}}\n')
        time.sleep(2)
        try:
            data = s.recv(4096)
            print("  无auth响应:", data.decode("utf-8", "replace")[:400])
        except socket.timeout:
            print("  无auth响应: recv timeout")
        s.close()
    except Exception as e:  # noqa: BLE001
        print("  连接失败:", type(e).__name__, e)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(path)
        s.sendall(b'{"type":"auth","token":"selftest"}\n')
        time.sleep(1)
        s.sendall(b'{"type":"user","message":{"role":"user","content":"hello"}}\n')
        time.sleep(2)
        try:
            data = s.recv(4096)
            print("  带auth响应:", data.decode("utf-8", "replace")[:400])
        except socket.timeout:
            print("  带auth响应: recv timeout")
        s.close()
    except Exception as e:  # noqa: BLE001
        print("  二连失败:", type(e).__name__, e)
print("== done ==")
