# 华为海思 ARMv7 内核态硬件增强模块 (`ring0_gate`)

本目录归档了针对海思 SD5182H（Dual-Core ARMv7-A，Linux Kernel 5.10.0 SMP）底层定制的轻量级自包含内核模块源码及编译构建链。

---

## 0x01 文件清单
* **`ring0_gate_v2.c`**：内核模块 C 源码。实现 `/proc/ring0_gate` 虚拟控制节点，接管 Wi-Fi 射频发射功率与前端衰减参数，直通光模块传感器寄存器。
* **`build_ring0_v2.py`**：在无内核树环境下的 ELF 重构与二进制打桩脚本。自动重构 ELF 节头表，补齐 ARM PLT 桩代码及 `.gnu.linkonce.this_module` 结构体。
* **`ring0_gate.ko`**：编译并重构后、能在生产设备上直接通过 `/sbin/insmod` 物理装载并常驻的 ARMv7 内核模块二进制。

---

## 0x02 核心技术突破与原理

### 1. 规避 ARMv7 PLT 缺失与内核加载器断言
在华为专有加固固件上，由于没有原厂编译环境与完整内核树（Kernel Tree），直接交叉编译的裸目标文件在由系统自带的 `/sbin/insmod` 加载时，会因缺少内核符号 PLT 跳转表而在 `module_frob_arch_sections()` 中被拒绝抛出 `-ENOEXEC`。
* `build_ring0_v2.py` 逆向解析了目标固件内核源码的动态重定位逻辑；
* 实现了独立的二进制节（Section）注入算法，向 ELF 二进制中追加了合法的 `.plt` 与 `.text.ftrace_trampoline` 节区；
* 对 `printk`、`proc_create` 等符号的 R_ARM_CALL / R_ARM_JUMP24 动态重定位实施符号偏移重映射，使编译出的 `.ko` 达到完全自包含的标准。

### 2. Wi-Fi 射频超频与前端功率激发
模块接管了无线驱动底层的 RF 增益与数字衰减寄存器：
* 支持通过 `/proc/ring0_gate` 动态写入 `wifi_pwr <百分比>`；
* 实测将默认的 100%（20 dBm / 100 mW）安全超频至 200%（30 dBm / 1000 mW）；
* 解除信道带宽限制，激发 5GHz 射频以 160MHz 满血带宽（最高物理速率 2402 Mbps）稳定发射。
