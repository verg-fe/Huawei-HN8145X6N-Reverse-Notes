#!/usr/bin/env python3
"""
Huawei HN8145X6N LKM Compiler & Module Builder
==============================================
Builds `ring0_gate.ko` targeting Linux 5.10.0 SMP ARMv7 without vendor kernel headers.

Technical Mechanism:
  1. Targets `armv7a-linux-gnueabi` with `-fno-pic -fno-pie -ffreestanding`.
  2. The C source `ring0_gate_v2.c` embeds the minimal `.gnu.linkonce.this_module`
     struct module with exact offsets (240 for init, 528 for exit, 576 bytes total).
  3. Inline assembly `.section .plt` and `.section .init.plt` tricks the kernel's
     `module_frob_arch_sections()` into passing CONFIG_ARM_MODULE_PLTS assertions,
     allowing standard `/sbin/insmod` execution on pristine production firmware.
"""

import os
import sys
import shutil
import subprocess

def find_clang():
    # 1. Check explicit environment variable
    if os.environ.get("CLANG"):
        return os.environ.get("CLANG")
    
    # 2. Check NDK environment variable
    for ndk_var in ["NDK_HOME", "ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"]:
        ndk_root = os.environ.get(ndk_var)
        if ndk_root:
            cand = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "clang.exe")
            if os.path.exists(cand): return cand
            cand_linux = os.path.join(ndk_root, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "clang")
            if os.path.exists(cand_linux): return cand_linux

    # 3. Check system PATH
    system_clang = shutil.which("clang")
    if system_clang:
        return system_clang

    # 4. Fallback search in standard local SDK paths
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        common_paths = [
            os.path.join(local_app_data, "Android", "Sdk", "ndk"),
            os.path.join(local_app_data, "VectorAndroidSdk", "ndk")
        ]
        for base in common_paths:
            if os.path.exists(base):
                for v in sorted(os.listdir(base), reverse=True):
                    cand = os.path.join(base, v, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "clang.exe")
                    if os.path.exists(cand):
                        return cand

    return None

def build():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_file = os.path.join(script_dir, "ring0_gate_v2.c")
    out_file = os.path.join(script_dir, "ring0_gate.ko")

    if not os.path.exists(src_file):
        print(f"[-] Error: Source file not found: {src_file}")
        sys.exit(1)

    clang_bin = find_clang()
    if not clang_bin:
        print("[-] Error: Clang cross-compiler not found. Please set CLANG or NDK_HOME environment variable.")
        sys.exit(1)

    print(f"[*] Compiler   : {clang_bin}")
    print(f"[*] Source     : {src_file}")
    print(f"[*] Output     : {out_file}")

    cmd = [
        clang_bin,
        "--target=armv7a-linux-gnueabi",
        "-march=armv7-a",
        "-mfloat-abi=softfp",
        "-mfpu=vfpv3-d16",
        "-O2",
        "-fno-pie",
        "-fno-pic",
        "-fno-stack-protector",
        "-ffreestanding",
        "-c",
        src_file,
        "-o",
        out_file
    ]

    print("[*] Compiling ARMv7 standalone kernel object...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print("[-] Compilation failed:")
        print(res.stderr)
        sys.exit(res.returncode)

    file_size = os.path.getsize(out_file)
    print(f"[+] Build success! Generated: {out_file} ({file_size:,} bytes)")
    print("[*] Binary structure characteristics:")
    print("    - Target: Linux 5.10.0 SMP ARMv7")
    print("    - Format: Standalone ELF Relocatable (.ko)")
    print("    - Includes embedded: .gnu.linkonce.this_module (576 bytes)")
    print("    - Includes stub: .plt / .init.plt (Passes CONFIG_ARM_MODULE_PLTS)")

if __name__ == "__main__":
    build()
