# 华为海思 ARMv7 内核态特权网关模块 (`ring0_gate`)

本目录归档了针对海思 SD5182H（Dual-Core ARMv7-A，Linux Kernel 5.10.0 SMP）底层定制的自包含可加载内核模块（LKM）源码与构建链。

---

## 0x01 文件清单
* **`ring0_gate_v2.c`**：自包含内核模块 C 源码。实现 `/proc/ring0_gate` 特权接口，提供面向用户态进程的在内核 `commit_creds(prepare_kernel_cred(NULL))` 瞬态提权通道。
* **`build_ring0_v2.py`**：无内核树跨平台编译构建脚本。利用 Clang 交叉编译器直接编译出符合目标内核加载器要求的 ARMv7 单目标文件。
* **`ring0_gate.ko`**：编译产出的自包含 LKM 二进制文件。

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
   - 静态 ELF 磁盘文件体积：~4.6 KB 至 ~8.0 KB（视符号表与内联注释而定）；
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
