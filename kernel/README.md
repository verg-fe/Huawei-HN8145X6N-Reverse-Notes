# 华为海思 ARMv7 内核态特权网关模块 (`ring0_gate`)

本目录归档了针对海思 SD5182H（Dual-Core ARMv7-A，Linux Kernel 5.10.0 SMP）底层定制的自包含可加载内核模块（LKM）源码与构建链。

---

## 0x01 文件清单
* **`ring0_gate_v2.c`**：自包含内核模块 C 源码。实现 `/proc/ring0_gate` 特权接口，提供：
  1. 用户态进程在内核态的 `commit_creds(prepare_kernel_cred(NULL))` 瞬态提权通道；
  2. 真实联动海思无线驱动（`HWWIFI2_WIFI.ko`）导出接口，对 2.4G (`ath0`) 与 5G (`ath8`) 下发 30 dBm (1000 mW) 满血硬件激发指令。
* **`build_ring0_v2.py`**：无内核树跨平台编译构建脚本。利用 Clang 交叉编译器直接编译出符合目标内核加载器要求的 ARMv7 单目标文件。
* **`ring0_gate.ko`**：编译产出的自包含 LKM 二进制文件（~6.6 KB）。

---

## 0x02 核心技术机制（无内核源码树构建）

在面对封闭定制固件时，通常面临三大内核加载阻碍：
1. **缺少目标版本 Kernel Headers**：无法使用标准的 `Kbuild` 流程生成模块；
2. **`CONFIG_ARM_MODULE_PLTS` 校验失败**：ARMv7 内核的 `module_frob_arch_sections()` 强制断言 `.plt` 和 `.init.plt` 节区必须存在，否则拒绝为超出跳转范围的符号重定位分配跳转桩，直接返回 `-ENOEXEC`；
3. **`struct module` 结构体校验崩溃**：内核加载器在解析 `.gnu.linkonce.this_module` 节区时，会严格按照目标内核的结构体内存对齐读取模块名称、`init` 函数指针和 `exit` 函数指针。一旦偏移错位，会导致内核跳入非法地址引发 Kernel Panic。

### 优雅的编译器级绕过解法：
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
   - 静态 ELF 磁盘文件体积：~6.6 KB；
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

## 0x04 海思 Wi-Fi 6 驱动联动与 1000mW (30 dBm) 硬件满血激发

在目标设备上，Wi-Fi 射频输出功率默认受国家无线电管理委员会（SRRC）强制法规限制（2.4GHz 限制在 20 dBm / 100 mW 以内，并加注了高额数字衰减）。

为了达成大平层全屋强信号覆盖的实测需求，`ring0_gate_v2.c` 实现了与海思 Wi-Fi 闭源驱动（`HWWIFI2_WIFI.ko`）的真实底层联动：
1. **真实符号动态解析**：
   通过弱引用绑定海思驱动导出的核心调试接口：
   ```c
   extern int wal_hipriv_set_txpower(struct net_device *net_dev, const char *param) __attribute__((weak));
   extern struct net_device *dev_get_by_name(struct net *net, const char *name) __attribute__((weak));
   extern void dev_put(struct net_device *dev) __attribute__((weak));
   ```
2. **硬件全功率注入原语**：
   向 `/proc/ring0_gate` 写入指令 `wifi_pwr 1000` 或 `overdrive` 时，模块自动获取 2.4G 网卡（`ath0`）与 5G 网卡（`ath8`）的设备结构体，直接调用海思内部私有通信接口下发 **30 dBm（换算即为 1000 mW 满血功率指标）**：
   ```c
   wal_hipriv_set_txpower(dev_2g, "30");
   wal_hipriv_set_txpower(dev_5g, "30");
   ```
3. **物理激励效果**：
   海思 DMAC 固件接收到 30 dBm 指令后，清零内部数字衰减器（0dB），促使板载外置射频前端芯片（康希通信 KCT8575 / KCT8547 高功率 FEM）进入全功率饱和放大状态，实现全屋满格穿墙覆盖！
