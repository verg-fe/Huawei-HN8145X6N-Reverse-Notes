# 华为海思 ARMv7 内核态特权网关模块 (`ring0_gate`)

本目录归档了针对海思 SD5182H（Dual-Core ARMv7-A，Linux Kernel 5.10.0 SMP）底层定制的自包含可加载内核模块（LKM）源码与构建链。

---

## 0x01 文件清单
* **`ring0_gate_v2.c`**：自包含内核模块 C 源码。实现 `/proc/ring0_gate` 特权接口，提供：
  1. 用户态进程在内核态的 `commit_creds(prepare_kernel_cred(NULL))` 瞬态提权通道；
  2. 真实下发 25.0 dBm (~316 mW) 硬件极限饱和功率（参数 `"250"`，匹配板载康希通信 KCT FEM 物理 $P_{\text{sat}}$ 阈值），直通海思无线闭源驱动 `HWWIFI2_WIFI.ko`。
* **`build_ring0_v2.py`**：无内核树跨平台编译构建脚本。利用 Clang 交叉编译器直接编译出符合目标内核加载器要求的 ARMv7 单目标文件。
* **`ring0_gate.ko`**：编译产出的自包含 LKM 二进制文件（~7.5 KB）。

---

## 0x02 核心技术机制（无内核源码树构建）

在面对封闭定制固件时，通常面临三大内核加载阻碍：
1. **缺少目标版本 Kernel Headers**：无法使用标准的 `Kbuild` 流程生成模块；
2. **`CONFIG_ARM_MODULE_PLTS` 校验失败**：ARMv7 内核的 `module_frob_arch_sections()` 强制断言 `.plt` 和 `.init.plt` 节区必须存在，否则拒绝为超出跳转范围的符号重定位分配跳转桩，直接返回 `-ENOEXEC`；
3. **`struct module` 结构体校验崩溃**：内核加载器在解析 `.gnu.linkonce.this_module` 节区时，会严格按照目标内核的结构体内存对齐读取模块名称、`init` 函数指针和 `exit` 函数指针。一旦偏移错位，会导致内核跳入非法地址引发 Kernel Panic。

### 编译器级内联解法：
无需编写脆弱复杂的后处理 ELF 二进制重写工具，本项目采用纯编译器特性直接解决：
1. **节区伪装声明**：
   ```c
   __asm__(".section .plt, \"ax\", %progbits\n.byte 0\n");
   __asm__(".section .init.plt, \"a\", %progbits\n.byte 0\n");
   ```
   直接在 C 源码中通过内联汇编向 ELF 中插入非空的 `.plt` 与 `.init.plt` 节区头，天然满足内核加载器对节区存在的硬性检查。
2. **精确内存布局逆向打桩**：
   逆向解析 Linux 5.10.0 SMP 32-bit ARM 的 `struct module` 定义，构造精确占位结构体：
   ```c
   struct module {
       char pad0[12];
       char name[56];            /* MODULE_NAME_LEN = 56 */
       char pad1[240 - 12 - 56]; /* 填充至偏移 240 */
       int (*init)(void);        /* 目标内核 init 函数指针位置 */
       char pad2[528 - 240 - 4]; /* 填充至偏移 528 */
       void (*exit)(void);       /* 目标内核 exit 函数指针位置 */
       char pad3[576 - 528 - 4]; /* 填充至总尺寸 576 字节 */
   };
   ```
   并将其实例化在 `.gnu.linkonce.this_module` 节区中。
3. **体积与内存驻留数据**：
   - 静态 ELF 磁盘文件体积：~7.5 KB；
   - 内核内存物理驻留尺寸：约 5,195 字节（`lsmod` 报告的实际内存分配页面大小）。

---

## 0x03 用户态调用与提权原语

模块装载后向系统暴露只读/可写接口 `/proc/ring0_gate`：
* **读取状态**：`cat /proc/ring0_gate` 查看内核状态与提权统计计数；
* **瞬态提权**：调用进程向节点写入 `root`（在标准 ash/bash 或脚本环境中：`echo -n "root" > /proc/ring0_gate`），内核处理函数立即以当前线程上下文调用：
  ```c
  commit_creds(prepare_kernel_cred(NULL));
  ```
  使当前调用任务（`current`）瞬间获得真实的 `UID 0 / GID 0 (root)` 权限。

> [!WARNING] **注意受限壳（`srv_clid`）陷阱**：
> 在光猫默认的受限 CLI 提示符（`WAP(Dopra Linux) #`）下，命令解析器禁止直接输入重定向符 `>`（会报 `ERROR::Input para is not right`）。
> 且 Linux 的 `commit_creds()` 仅作用于当前任务，不会将特权“逆向传染”给父级受限 CLI 会话。实际调试与提权操作应通过脚本下发，或直接连接全功能 Root 终端（如本地 `192.168.100.1:2323` BusyBox ash 会话）。

---

## 0x04 25.0 dBm (~316 mW) 硬件极限满血激发实现

### 1. 为什么是 25.0 dBm？（尊重板载半导体物理现实）
* 标称 30 dBm (1000 mW) 是软件输入的校验上限，并非真实硬件输出能力；
* 板载外置射频前端芯片（康希通信 KCT8575 / KCT8547 高功率 FEM）的物理饱和输出功率（$P_{\text{sat}}$）为 **24.0 ~ 25.0 dBm（约 250 ~ 316 mW）**；
* 因此，**25.0 dBm（~316 mW）是硬件在不击穿硅芯片前提下所能释放的真正物理极限功率**！

### 2. 海思驱动传参换算与反汇编实证
海思闭源驱动 `wal_hipriv_set_txpower`（节区偏移 `0x1d97d4`）以 0.1 dBm 为输入步进单位：
```arm
; HWWIFI2_WIFI.ko 参数校验指令 (偏移 +0x1c8)
+1c8: 0xe3530f4b    cmp r3, #300      ; 最大允许 300 (30.0 dBm)
+1cc: 0x9a000017    bls valid_range   ; 若 <= 300 进入正常设置流程
```
为了让硬件以 25.0 dBm 输出，模块向驱动下发的字符串参数精确对应为 **`"250"`**（$250 \times 0.1\text{ dBm} = 25.0\text{ dBm}$）。

### 3. 操作指令与真机上机实测验证
用户态进程可通过 `/proc/ring0_gate` 触发满血激发：
```bash
# 激活硬件物理极限输出 25.0 dBm (~316 mW)
echo "wifi_pwr 25" > /proc/ring0_gate

# 查看生效回显
cat /proc/ring0_gate
```

#### 真机回显实测（华为 HN8145X6N 实机 100% 真实回显）：
在海思 SD5182H / Hi1152 Wi-Fi 架构中，2.4G 与 5G 虚拟访问点对应网络接口为 `vap0` 与 `vap8`（而非高通方案的 `ath0`/`ath8`）。
模块内置严格的 `dev != NULL` 空指针防御，当检测到接口名匹配时安全下发：
```text
=== [RING0_GATE KERNEL GATEWAY] ===
STATUS=READY
KERNEL_VER=5.10.0-SMP-ARMv7
CHIPSET=HiSilicon_Hi1152_Wi-Fi_6
FEM_HARDWARE_LIMIT=25.0_DBM (~316 mW / KCT_PSAT)
ESCALATION_COUNT=0
WIFI_PEAK_OVERDRIVE=DISPATCHED
TARGET_POWER_PARAM=250 (25.0 dBm)
VAP0_2.4G_RC=0
VAP8_5.0G_RC=0
COMMANDS=root, wifi_pwr 25 (or 250), wifi_pwr 1000
===================================
```

#### 内核环形缓冲区 (`dmesg`) 真实物理日志：
```text
[59064.525182] [RING0_GATE] Privilege escalation invoked: caller committed root creds (total: 1)
[59064.535720] [RING0_GATE] LKM safely removed from kernel.
[59064.618900] [RING0_GATE] LKM successfully initialized in DRAM (Linux 5.10.0 ARMv7)
[59064.625183] [RING0_GATE] Peak hardware overdrive (25.0 dBm / '250') dispatched: 2.4G(vap0) rc=0, 5G(vap8) rc=0
```
- **`VAP0_2.4G_RC=0`**：2.4GHz 射频驱动成功接收 `"250"` 功率参数；
- **`VAP8_5.0G_RC=0`**：5GHz 射频驱动成功接收 `"250"` 功率参数；
- 成功打通从 Ring 3 到 Ring 0 再到海思闭源 Wi-Fi 驱动的满血功率控制链，且零 Panic、零盲目传参。
