#!/usr/bin/env python3
"""
Huawei HN8145X6N Port 17998 (SAF CloudClient JSON-RPC) Network Prober
====================================================================
Author: 哈吉米
Purpose:
  探查与分析局域网 17998/tcp 端口的协议栈行为与访问控制特征。
  该端口由 SAF 容器框架的 cloudclient / appmgr 服务监听，
  在生产固件中采用 4 字节大端网络序长度前缀帧封装 JSON 结构体。
"""

import socket
import struct
import time
import sys

TARGET_IP = "192.168.100.1"
TARGET_PORT = 17998

def probe():
    print(f"[*] Probing {TARGET_IP}:{TARGET_PORT} (SAF JSON-RPC)...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    
    try:
        s.connect((TARGET_IP, TARGET_PORT))
        print("[+] TCP Connection established successfully.")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return

    # Test 1: Empty framing / heartbeat probe
    try:
        sample_payload = b'{"Action":"GetStatus"}'
        frame = struct.pack(">I", len(sample_payload)) + sample_payload
        print(f"[*] Sending 4-byte framed payload ({len(sample_payload)} bytes)...")
        s.sendall(frame)
        time.sleep(0.5)
        resp = s.recv(1024)
        print(f"[+] Received response: {resp}")
    except Exception as e:
        print(f"[*] Socket behavior observed: {e}")
    finally:
        s.close()
        print("[*] Probe finished.")

if __name__ == "__main__":
    probe()
