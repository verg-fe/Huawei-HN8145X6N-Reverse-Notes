# 华为 SAF 容器框架与 D-Bus 特权调度 PoC 资产

本目录归档了在华为 OptiXstar HN8145X6N（Dopra Linux R23 固件）上验证的应用管理器权限跃迁 PoC 代码。

---

## 0x01 文件清单
* **`delivery_server_8888.py`**：轻量级局域网文件投递 HTTP 服务器（8888 端口）。专为向光猫投递 Root 脚本（`run_root.sh`）与内核驱动（`ring0_gate.ko`）设计，具备精准客户端 IP 跟踪、CORS 支持与即时分发能力。
* **`appmgr_dbus_pwn.py`**：利用局域网开放的 `17998/tcp` 端口（SAF CloudClient JSON-RPC）或宿主 D-Bus 系统总线向核心特权守护进程 `/sbin/appmgr` 发起结构化消息注入，触发 root 脚本派生的自动化全流程脚本。
* **`poc_root.sh`**：在容器 root（UID 0）环境中执行的探针载荷，负责物理装载 `ring0_gate.ko` 并拉起调试 Telnetd 监听。

---

## 0x02 漏洞机理与调用链路

### 1. 业务逻辑调度缺陷
华为网关将增值服务（wifiaudit, b01odm, xrobot）封装在 SAF 容器中，由特权进程 `/sbin/appmgr`（UID 0）负责生命周期调度。  
分析 `appmgr` 发现，其在处理特定内部调试通道（如 `opmaintainv3` 维护组件）的 D-Bus 消息时：
* 只要字段满足 `InPlugin: 1` 且 `RunScript: 1`；
* 调度器将绕过插件数字签名校验机制；
* 直接从传入的 `URL` 参数执行指定脚本，且执行上下文继承了守护进程的 **`UID 0 (root)`** 完整权限。

### 2. 调用参数结构
```json
{
    "RPCMethod": "PostMsg",
    "AppName": "opmaintainv3",
    "Params": {
        "InPlugin": 1,
        "RunScript": 1,
        "Parameter": {
            "URL": "/ipks/run_root.sh",
            "Args": "start"
        }
    }
}
```
结合容器与宿主共享的挂载目录（`/opt/upt/apps/apps/ipks/`），实现从非特权受限 Shell 或局域网侧到全特权 Root 终端的可靠跃迁。
