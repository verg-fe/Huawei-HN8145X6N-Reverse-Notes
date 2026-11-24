# 华为海思 ARMv7 内核态特权网关模块 (`ring0_gate`)

本目录归档了针对海思 SD5182H（Dual-Core ARMv7-A，Linux Kernel 5.10.0 SMP）底层定制的自包含可加载内核模块（LKM）源码与构建链。

---

## 0x01 文件清单
* **`ring0_gate_v2.c`**：自包含内核模块 C 源码。实现 `/proc/ring0_gate` 特权接口，提供：
  1. 用户态进程在内核态的 `commit_creds(prepare_kernel_cred(NULL))` 瞬态提权通道；
  2. 严格遵循内核空指针安全防护的驱动联动原语，向海思 Wi-Fi 驱动（`HWWIFI2_WIFI.ko`）注入 30.0 dBm (1000 mW 标称值，内部参数 `"300"`) 极限功率请求。
* **`build_ring0_v2.py`**：无内核树跨平台编译构建脚本。利用 Clang 交叉编译器直接编译出符合目标内核加载器要求的 ARMv7 单目标文件。
* **`ring0_gate.ko`**：编译产出的自包含 LKM 二进制文件（~7.0 KB）。

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
   - 静态 ELF 磁盘文件体积：~7.0 KB；
   - 内核内存物理驻留尺寸：约 5,195 字节（`lsmod` 报告的实际内存分配页面大小）。

---

## 0x03 用户态调用与提权原语

模块装载后向系统暴露只读/可写接口 `/proc/ring0_gate`：
* **读取状态**：`cat /proc/ring0_gate` 查看内核状态与提权统计计数；
* **瞬态提权**：调用进程向节点写入 `root`（例如：`echo -n "root" > /proc/ring0_gate`），内核处理函数立即以当前线程上下文调用：
  ```c
  commit_creds(prepare_kernel_cred(NULL));
  ```
  使非特权进程瞬间获得真实的 `UID 0 / GID 0 (root)` 权限。

---

## 0x04 海思 Wi-Fi 6 驱动逆向实证与功率参数解析

### 1. 海思 `wal_hipriv_set_txpower` 汇编级逆向证据
通过静态逆向光猫闭源无线驱动 `HWWIFI2_WIFI.ko`（海思凌霄 Hi1152 架构），我们定位并反汇编了内部私有接口 `wal_hipriv_set_txpower`（节区偏移 `0x1d97d4`）：
```arm
; HWWIFI2_WIFI.ko: wal_hipriv_set_txpower 参数校验逻辑 (偏移 +0x1c8)
+1c8: 0xe3530f4b    cmp r3, #300      ; 校验解析出的整数是否 <= 300 (0x12c)
+1cc: 0x9a000017    bls valid_range   ; 若 <= 300，进入有效参数下发分支
                    b   invalid_arg   ; 若 > 300，打印 "invalid argument!" 并返回失败
```

**关键技术发现**：
* **参数单位为 0.1 dBm**：驱动内部以 0.1 dBm 为步进单位，上限严格卡在 `300`（即 30.0 dBm，科学换算对应 1000 mW 理论上限）；
* **传参修正**：若错误传入 `"30"`，驱动将解析为 3.0 dBm（约 2 mW，导致发射功率衰减 98%）；必须显式传入 `"300"`，驱动才识别为 30.0 dBm 满血请求！

### 2. 内核严谨性：空指针防御与引用安全
在早期原型中，若网卡不存在直接传 NULL 会导致驱动内部解引用 `net_dev->priv` 发生 Data Abort。`ring0_gate_v2.c` 实施了严格的防御性编程：
```c
if (dev_2g) {
    g_ath0_ret = wal_hipriv_set_txpower(dev_2g, "300");
    if (dev_put) dev_put(dev_2g);
} else {
    g_ath0_ret = -19; /* -ENODEV: 严格阻断 NULL 传参，避免 Kernel Panic */
}
```

### 3. 工程客观定界：软件解除限制 vs 硬件物理边界
必须以严谨的工程态度指出：
1. **依赖前置**：模块通过弱符号调用海思驱动接口，前提是系统已成功加载 `HWWIFI2_WIFI.ko`；
2. **硬件物理天花板**：软件注入 30.0 dBm（300）指令可清零海思内部数字衰减器，促使外置 FEM（康希通信 KCT8575 / KCT8547）进入高增益输出。但实际物理有效辐射功率受限于板载 FEM 的饱和功率（$P_{\text{sat}}$）与散热条件，过高的驱动偏置可能导致 1024-QAM EVM 恶化。本模块提供底层驱动级的全功率调试原语，实际物理表现需结合外部功率计与场强仪综合标定。
