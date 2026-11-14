# 手机 TUN 探针的复用边界

服务 Ghroth6/clashbox-meta 的设备决策试验。这是隔离实验，不是产品运行 ABI。

## 前置装载与 TCP/UDP 探针

以下说明对应「验证新版核心在当前手机的装载与上游 TUN 接入」，保留其来源与历史范围。

- `reused_descriptor.go`、`reused_descriptor_linux.go` 来自既有核心 `5fd99fde704fe7852d57119e822f08ee791c904a` 的 `mobile/runtime/descriptor.go` 和 `descriptor_linux.go`，仅将 package 改为 main。`reused_descriptor_types.go` 取自同提交 `contract.go` 的两个回执类型。
- 保留可选 Fstat 观察、一次关闭、非阻塞读写、唤醒管道、100 ms 取消兜底；没有将元信息查询失败改成 fd 无效。
- `packet_adapter.go` 的收发循环由同提交 `engine_gvisor.go` 的 readPump/writePump 缩成上游 `GVisorTun` 的实现。保留取消与管道唤醒，收尾等待两个循环退出后再关闭所拥有的 fd。不复制配置、策略、统计和旧运行状态机。
- `NewEndpoint` 提供 channel；其余由固定新版 `sing-tun v0.4.28` 的 `NewStack("gvisor")` 接管，包括栈装配及 TCP、UDP、ICMP forwarder 接线。当前合成用例只检查 IPv4 TCP/UDP，不构成 ICMP 或 IPv6 结论。
- echo Handler 和 kernelEcho 只是试验夹具：仅访问 198.18.85.2:18585，没有物理出站连接、规则、节点、订阅或 DNS。
- 只有标准 fd 构造实际遇到 Fstat 失败后才试 packet Adapter。原失败保留于同一次回执，不伪造成功的 Fstat 或修改依赖缓存。

系统 VPN 原 fd 始终归平台 destroy；标准接入和候选分别复制并消费自己的 fd。运行资源、线程、fd 与正常停止还须以目标设备回执核实。

## ICMP 与 fake-TCP 能力探针

当前 `cb_probe_tun` 进入 `ip_probe.go`，服务[核验当前手机 ICMP 与 Hysteria1 fake-TCP 能力](https://github.com/Ghroth6/clashbox-meta/issues/87)。前置已验证薄 fd Adapter，因此直接复用；没有恢复整个旧 runtime 或修改上游。

- `observedICMP` 仅记录输入/结果并委托固定上游 `sing_tun.ListenerHandler.PrepareConnection`；TCP/UDP 在本轮拒绝，fake-IP 使用上游 Pool/Enhancer。Adapter 增加实际入/出包观察。
- 平台 protect 使用 probe 专属文件握手连接实际 ArkTS `VpnConnection.protect`，序号匹配、4 秒失败超时，RawConn.Control 保持到回执返回；它是实验接线，不是拟定产品通信合同。
- `kernelPing` 是非特权 ICMP 客户端。TUNGETIFF 在设备被拒，接口名来自同轮 HDC 观察；SO_BINDTODEVICE 必须成功，之后仍以真实 TUN 包日志判断是否进入核心。自身地址的内核回应不能算核心转发。
- `stagedPing` 分别测上游的显式 bind 顺序与省略 bind 的独立受保护 socket。后一结果只证明 IPv4 外发基础能力，不证明候选已接入 TUN、identifier 映射或完整生命周期。RemoteAddr 可为空；历史不安全记录的失败保留在任务报告。
- fake-TCP 先核对 raw TCP socket；只有权限拒绝时才调用固定上游 Dial 复核同一早期错误。若 raw socket 获准则不自动进入 TCP/iptables/远端步骤，需重新准备受控对端和保护接线。
- 本轮没有 no_fake_tcp 裁剪、私有订阅、主机网络修改或提权。最终结论和各轮身份以协调仓的 `docs/delivery/verification/icmp-faketcp-2026-11-14.md` 为准。
