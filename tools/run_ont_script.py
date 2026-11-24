#!/usr/bin/env python3
"""
Huawei ONT (HN8145X6N) Automated Staging & Remote Script Runner
==============================================================
Author: 哈吉米
Purpose:
  自动化脚本下发与远端执行一体化工具：
  1. 动态生成或抓取本地执行脚本；
  2. 后台启动轻量级临时 HTTP 服务 (192.168.100.2:8888)；
  3. 通过 SSH 登录光猫受限 Shell，触发 busybox wget 远程拉取；
  4. 赋予执行权限并调用执行，实时回收标准输出与错误日志；
  5. 执行完毕后自动关闭临时 HTTP 服务器，实现零痕迹、高可靠分发。
"""

import http.server
import socketserver
import threading
import time
import os
import sys
import paramiko

ONT_IP = "192.168.100.1"
ONT_SSH_PORT = 22
ONT_USER = "root"
ONT_PASS = "admin"
HOST_IP = "192.168.100.2"
HOST_PORT = 8888

def run_remote_script(script_content, script_name="task_exec.sh", work_dir=None):
    if work_dir is None:
        work_dir = os.path.dirname(os.path.abspath(__file__))
    
    local_path = os.path.join(work_dir, script_name)
    with open(local_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(script_content)

    original_dir = os.getcwd()
    os.chdir(work_dir)

    # 1. 启动临时 HTTP 服务器
    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer((HOST_IP, HOST_PORT), QuietHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] 临时投递服务器已拉起: http://{HOST_IP}:{HOST_PORT}")

    try:
        # 2. 连接光猫 SSH 终端
        print(f"[*] 正在连接光猫 SSH ({ONT_IP}:{ONT_SSH_PORT})...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ONT_IP, port=ONT_SSH_PORT, username=ONT_USER, password=ONT_PASS, timeout=8)
        
        chan = ssh.invoke_shell()
        time.sleep(0.5)
        chan.send(b"su\n")
        time.sleep(0.4)
        chan.send(b"shell\n")
        time.sleep(0.4)

        # 3. 远端拉取并执行
        print(f"[*] 指挥光猫拉取载荷: http://{HOST_IP}:{HOST_PORT}/{script_name} -> /mnt/jffs2/{script_name}")
        chan.send(f"busybox wget http://{HOST_IP}:{HOST_PORT}/{script_name} -O /mnt/jffs2/{script_name}\n".encode())
        time.sleep(1.0)
        chan.send(f"busybox chmod 755 /mnt/jffs2/{script_name}\n".encode())
        time.sleep(0.4)
        chan.send(f"sh /mnt/jffs2/{script_name}\n".encode())
        time.sleep(2.5)

        # 4. 回收输出
        output = b""
        while chan.recv_ready():
            output += chan.recv(32768)
            time.sleep(0.1)

        ssh.close()
        return output.decode("utf-8", errors="ignore")

    finally:
        # 5. 清理与释放
        httpd.shutdown()
        httpd.server_close()
        os.chdir(original_dir)
        if os.path.exists(local_path):
            os.remove(local_path)
        print("[*] 临时投递服务器已安全释放。")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            code = f.read()
        res = run_remote_script(code, script_name="user_exec.sh")
        print("\n=== 执行回显 ===")
        print(res)
    else:
        sample_code = """#!/bin/sh
echo "=== REMOTE RUNNER ALIVE ==="
id
uname -a
cat /proc/ring0_gate 2>/dev/null || true
"""
        res = run_remote_script(sample_code, script_name="sample_test.sh")
        print("\n=== 执行回显 ===")
        print(res)
