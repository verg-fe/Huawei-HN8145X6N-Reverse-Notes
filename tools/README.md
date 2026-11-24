# 华为 ONT 固件使能工具与二进制资产技术说明

本目录归档了在本次逆向攻坚中所整理、分析与逆向验证的华为光猫固件使能工具链与二进制分析资产。

---

## 0x01 二进制使能固件：`r23_all_shell.bin`

### 1. 基础元数据
* **文件名**：`r23_all_shell.bin`
* **文件大小**：115,403 字节 (~115 KB)
* **文件封装格式**：HWNP（Huawei Network Packet / 华为专有网络封装固件头）
* **Magic 标识**：`0x48574E50` (`HWNP`)

### 2. 适配芯片架构与主板 ID (Board IDs)
该固件包内部头部硬编码适配了多达 30 种华为海思平台的主板与产品代号：
```text
120 | 130 | 140 | 141 | 150 | 160 | 170 | 171 | 180 | 190 | 
1B1 | 1A1 | 1A0 | 1B0 | 1D0 | 1F1 | 201 | 211 | 221 | 230 | 
240 | 260 | 261 | 270 | 271 | 280 | 281 | 291 | 2A1 | 431
```

### 3. 适用设备型号范围
* **万兆 10G-EPON / XG-PON / XGS-PON 系列**：
  * OptiXstar HN8145X6, HN8145X6N, HN8145V, HN8346X6, HN8546X6
* **千兆 GPON / EPON 系列**：
  * EchoLife HS8145V, HS8145V5, HS8145C, HS8546V, HS8546V5
  * 移动/联通定制款：K662C, MA5671A, G-140W-ME (部分 OEM)
* **系统固件版本基线**：
  * 专为华为 Dopra Linux V300 / V500 系列（R019, R020, R021, R022，及 R023 早期版本）设计。

### 4. 固件内部结构解密
通过提取分析，该 115KB 固件实为轻量级指令覆盖包，打包了以下关键组件：
1. **`/var/UpgradeCheck.xml`**：
   ```xml
   <upgradecheck>
       <HardVerCheck CheckEnable="0"/>
       <LswChipCheck CheckEnable="0"/>
       <WifiChipCheck CheckEnable="0"/>
   </upgradecheck>
   ```
   强制将硬件校验、交换芯片校验、无线射频芯片校验置为 `0`，绕过原厂刷机防降级与跨机型限制。
2. **`/mnt/jffs2/ProductLineMode` & `/mnt/jffs2/equipment.tar.gz`**：
   向持久化配置分区注入产线装备模式标志位，引导光猫在重启后进入调试壳。
3. **`/mnt/jffs2/TelnetEnable`**：
   在持久化分区建立开窗标志，指示底层开机流程拉起 `telnetd` 守护进程。
4. **`/var/notsavedata`**：
   保护光猫出厂配置，避免刷写过程擦除运营商 LOID 及认证证书。

### ⚠️ 现网实证避坑与安全警告
> **特别注意**：本研究手记已在真实商业网关（Dopra R23C00SPC162 固件）上实证证实：**切勿在 2025/2026 年新版量产安全加固固件上盲目刷入此 bin**！  
> 新版固件因剥离了旧版向下兼容的装备脚本，盲刷该包将导致光猫进入异常的装备挂起模式（`basic_equip: 1`），使硬件转发流水线冻结、PON 光路丢弃，甚至引发驱动雪崩。新版固件建议严格采用手记中详述的 **D-Bus 应用管理器 IPC 逻辑调度机制** 实施内存级安全准入。

---

## 0x02 维护工具链说明

| 工具文件名 | 功能描述 | 适用场景与技术原理 |
| :--- | :--- | :--- |
| **`get_pwr` / `get_pwr.c`** | Hi1152 DMAC 微码实时功率表探针 | 静态链接 ARMv7 EABI 工具（调用 ioctl `0x8beb` / `wal_ioctl_get_current_power`），强制海思芯片微码将每阶 MCS 实际生效功率表 printk 打印至 dmesg，彻底打破 `/proc/vap0/sta_info` 硬编码的假 20dBm 迷局。 |
| **`alg_ctl` / `alg_ctl.c`** | 海思底层射频算法与 TPC 硬件调优客户端 | 静态链接 ARMv7 EABI 工具（调用 ioctl `0x8bfd` / `wal_iwpriv_char_extra_adapt`），直接与芯片微码 ALG 模块交互，实时读取/设定 TPC 硬件码字、功率补偿、温控阈值与信道校准。 |
| **`hi1152_rf_tuner.ko` / `hi1152_rf_tuner.c`** | 纯射频校准与 PCIe SRAM 调参内核模块 | 独立自包含 ARMv7 LKM，暴露 `/proc/hi1152_rf_tuner`，通过 `oal_pcie_devca_to_hostva` 直通映射并同步更新宿主 `g_dev_custom_info + 0x28` 与单芯片 DBDC `chip0` SRAM `0x1b2830 + 0x28` 中的 `cali_ofdm_max_pwr` 阈值，突破原厂 23.0/22.0 dBm 软钳位上限（严格保留原厂过温保护不变）。 |
| **`rf_probe` / `rf_probe.c`** | Hi1152 实时芯片结温与功率基准探针 | 静态零依赖 ARMv7 EABI WEXT ioctl 探针，直调 `wal_ioctl_get_param`（`0x8be1` / `0x02b9` -> `wal_ioctl_get_temp`）读取片上实时结温（°C）、`get_txpower`（`0x0071`）及 `wal_ioctl_get_stru_param`（`0x8be7` / `0x02ca`）回读 412 字节 `get_pwr_ref` 微码参考功率数组。 |
| **`run_ont_script.py`** | 临时 HTTP (8888) 投递与远程 SSH 执行一体化套件 | 动态拉起 8888 临时投递服务，通过 SSH 引导光猫执行 `busybox wget` 下载并执行脚本，执行完自动释放端口与日志。 |
| **`ONT_V100R002C00SPC253.exe`** | 华为原厂 ONT 维修与组播使能工具 | 通过 PC 物理网口（配置 `192.168.100.2`），利用 TFTP/FTP 组播协议向冷启动的光猫广播推送固件包 `r23_all_shell.bin`。 |
| **`HW_Dollar2.exe`** | 华为光猫开小贝壳 / Shell 开启辅助工具 | 用于老版本固件在 LAN 侧通过特定请求激活命令解释器。 |
| **`Huawei_Config_Crypto.exe`** | 配置文件加解密与打包工具 | 针对光猫导出的 `hw_ctree.xml` 实施 AES 密钥加解密，便于线下审查与参数导出。 |

---
*(免责声明：上述固件与工具仅用于安全测试与白帽学术研究，请在完全拥有合法授权的设备上展开实验。)*
