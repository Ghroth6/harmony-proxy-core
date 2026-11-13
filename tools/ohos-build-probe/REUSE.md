# 手机 TUN 探针的复用边界

服务 Ghroth6/clashbox-meta 的「验证新版核心在当前手机的装载与上游 TUN 接入」。这是隔离实验，不是产品运行 ABI。

- `reused_descriptor.go`、`reused_descriptor_linux.go` 来自既有核心 `5fd99fde704fe7852d57119e822f08ee791c904a` 的 `mobile/runtime/descriptor.go` 和 `descriptor_linux.go`，仅将 package 改为 main。`reused_descriptor_types.go` 取自同提交 `contract.go` 的两个回执类型。
- 保留可选 Fstat 观察、一次关闭、非阻塞读写、唤醒管道、100 ms 取消兜底；没有将元信息查询失败改成 fd 无效。
- `packet_adapter.go` 的收发循环由同提交 `engine_gvisor.go` 的 readPump/writePump 缩成上游 `GVisorTun` 的实现。保留取消与管道唤醒，收尾等待两个循环退出后再关闭所拥有的 fd。不复制配置、策略、统计和旧运行状态机。
- `NewEndpoint` 提供 channel；其余由固定新版 `sing-tun v0.4.28` 的 `NewStack("gvisor")` 接管，包括栈装配及 TCP、UDP、ICMP forwarder 接线。当前合成用例只检查 IPv4 TCP/UDP，不构成 ICMP 或 IPv6 结论。
- echo Handler 和 kernelEcho 只是试验夹具：仅访问 198.18.85.2:18585，没有物理出站连接、规则、节点、订阅或 DNS。
- 只有标准 fd 构造实际遇到 Fstat 失败后才试 packet Adapter。原失败保留于同一次回执，不伪造成功的 Fstat 或修改依赖缓存。

系统 VPN 原 fd 始终归平台 destroy；标准接入和候选分别复制并消费自己的 fd。运行资源、线程、fd 与正常停止还须以目标设备回执核实。
