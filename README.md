# harmony-proxy-core：Mihomo 的 OHOS 适配分支

本仓直接派生自 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)，维护 OHOS 所需的连接活动、流量分类、事件订阅与平台网络快照适配。以下合同已经宿主测试；原生库交付与设备验收状态以协调仓为准。

`NowTraffic(onlyProxy)` 返回上一秒的字节桶，读取不清零；`TotalTraffic(onlyProxy)` 保留初始化或 Reset 后的累计，包括已关闭连接。proxy 分类依据连接创建时固定的实际出口类型，不依赖名称或组的后续选择；Direct、Compatible、控制出口、组型和未知类型不算代理。内部 `pushToManager=false` 流量仍排除，计数、轮桶和 Reset 共享一个边界。字节上报保留官方 tracker 的缓冲 API 局限，不代表精确的线上传输字节。

`Tracker.LastActivity()` 初值为连接建立时间，随后记录可确认的 payload I/O，保留单调时钟并发更新不回退。TCP 空操作和失败尝试不刷新，UDP 成功的零长度包刷新；缓冲写入报错或复制回调未上报的部分传输无法确认，非空缓冲读取仅在长度增长时确认活动。该查询不改变 JSON 结构，也不决定空闲关闭策略。

URLTest、连接创建和 provider 初始化通过可注销订阅发布事件。回调同步执行且可能并发；cancel 不等待已经选中的回调，调用方须排除旧配置事件，不能等待 ApplyConfig 或它持有的应用锁。provider 初始化事件包括成功、失败和配置代际，不代表后续刷新或完整配置成功。

`platformnetwork.Publish` 校验并原子发布完整的网络快照，包含代际、DNS、接口地址/前缀和路由；非法或过期快照不替换现状。OHOS 在首个快照到达前按离线处理，离线不回落到原生接口或隐式公共系统 DNS。接口索引只能使用实测值，未知为零，不能用 NetworkID 代替。

选择组新增 `SetIdentity(proxy, provider)`：静态节点绑定对象，订阅节点绑定 provider 与节点名称，同 provider 刷新保留身份，其他 provider 新增同名节点不能接管选择。Selector 的目标失效时拒绝连接；URLTest/Fallback 保留健康判断及自动切换策略。`SelectedProxy()` 返回实际选择对象；旧 `Set`/`ForceSet`（包括空值）恢复原裸名语义并清除身份绑定。

传统 HTTP、SOCKS、Mixed、Redir、TProxy、SS、VMess、TUIC 的 `ReCreate*` 以及 `PatchTunnel`、`PatchInboundListeners` 返回实际构造、绑定与关闭错误。双协议入口仅在两者都成功后登记；Patch 失败回滚本次新建入口，未变更的原入口保留，已删除或替换的旧入口不自动恢复。已登记入口关闭失败时移出就绪集合，保留待清理所有权供下次停止重试。命名多地址与底层构造失败会关闭本次已取得的资源；若构造器内部回滚的 Close 本身失败，错误一并返回，不能保证资源已释放，也没有成功实例可供调用方重试。重复关闭不把已关闭句柄当作新错误，未知关闭错误仍返回。调用方必须处理错误并决定是否关闭剩余入口，不能把返回错误的配置当作就绪。该合同不覆盖 TUN、DNS/controller 或 provider 后台任务，也不是已接入连接全部结束的屏障。

完整宿主入口为 `scripts/test-interfaces.ps1`（Go 1.24.5，干净工作区；`-ModuleCache` 指定已有依赖缓存）。它离线运行接口包（包括 outboundgroup 选择回归）、限定 `TestListenerLifecycle` 的真实回环监听回归，以及独立进程的 OHOS 初始状态测试，将源码哈希、日志与结果集中写入本仓 `local/runs/<batch>/`，不修改上游 go.mod/go.sum。`scripts/test-statistic.ps1` 仍可单独验证统计包，采用相同的批次布局。两入口默认将 GOPATH、GOCACHE 和 GOMODCACHE 放在 `local/cache/` 下，批次目录中的 `inputs.json`、日志与 `result.json` 保留该次验证事实。旧批次是历史证据，重跑应由脚本生成新批次；缓存可以重建，证据的保留与迁移规则见协调仓的材料说明。Windows 上启用 ohos build tag 不等于 OHOS 二进制或真机验证；两入口均未启用 race detector。

嵌入应用可显式启用 `tunnel.EnableForwardingLifecycle`，随后按递增代次 Prepare、取得 BoundForwardingTunnel、完成入口构造、Activate。未启用时保留原有入口行为。绑定后的 tunnel 和根请求携带运行上下文，派生出站沿用原归属；显式内部管理上下文不归入转发。Cancel 立即关闭准入，Stop 等待专属资源关闭和已接入工作结束；迟到结果不能登记到新代，无法确认的关闭错误保留并阻止下一次启动。该能力不代替配置任务退休，也不承诺系统 TUN fd 已释放。

`dns.SetExternalIngressManaged(true)` 让配置更新只维护 resolver 与待启动的外部 DNS 配置。PrepareExternalIngress 验证真实 UDP/TCP 绑定，ActivateExternalIngress 开放 DNS/DoH；StopExternalIngress 取消并等待外部请求，同时保留内部 resolver 和共享上游查询。controller 的管理路由不随 DoH 停止。入口构造失败、关闭失败或等待超时必须由调用方汇总处理，不能直接报告就绪或已停止。

工程集成与验证步骤见 [clashbox-meta](https://github.com/Ghroth6/clashbox-meta)（私有，需权限）；标准工作空间中的协调仓位于 `../../meta`。自动化协作入口见 [AGENTS.md](AGENTS.md)。以下保留上游功能、文档和许可说明；上游功能列表不代表已在 OHOS 验证。

配置替换可通过 `executor.CancelConfigTasks` 先关闭旧 provider 与测速准入，再用 `RetireConfig(ctx)` 等待任务和当前可达节点池收尾；`ApplyConfigContext` 只有退休成功才发布新配置。同对象复用按身份判断，已取消对象不可重新采用，超时保留实际等待/关闭记录。Fetcher、健康检查、规则通知及 URLTest 有取消与完成屏障；资源、元信息、ETag、健康结果和地理库写入受所属配置的提交保护。旧无 context 入口继续保留包装。

节点、订阅列表与完整配置解析失败会清理本次候选资源，清理超时保留同一次操作、真实错误持续返回；成功发布转交所有权，已退休的 Config 不能再次发布。应用入口在重载与 Shutdown 时等待这些结果。

原生 parser 的节点适配器按实际使用登记租约，覆盖在途 TCP/UDP 创建及返回连接的完整 Close；半关闭不释放租约。provider 刷新关闭旧节点的新请求准入，现有连接自然结束后只关闭一次节点池；测速回调也属于待收尾任务。成功收尾的历史记录立即移除，错误保留并停止后续刷新。provider 取消时强制收尾仍活跃的历史节点，当前列表仍由 executor 按复用身份管理。URLTest 组在使用缓存前检查当前成员，避免新请求继续选中刷新前的对象。自定义 Parser 返回不具备 Retire/ForceRetire/WaitRetired 合同的借用对象维持上游行为，provider 不擅自取消其测速或关闭资源。

租约完成证明已登记调用、连接 Close 及 adapter.Close 已返回，不等于所有协议内部任务或系统句柄均已验收。AnyTLS 客户端等待在途创建、idle routine、session recvLoop、deadline watcher 与 session 清理，并保留关闭错误；网络切换后按代次排除旧池会话，不靠重试掩盖旧连接复用。服务端外部回调的完成不在该客户端合同内。smux/KCP 依赖缺少完整 worker 等待，部分关闭错误未上报。WireGuard 依赖等待 worker，但 Close 返回 void；QUIC 依赖也未完整传播 UDP Close 错误。详细剩余项与实际验证范围由协调仓设计和阶段检查点记录。

## 管理联网过渡

嵌入应用可启用 `forwarding.EnableManagementNetwork`，在平台路径切换前 Cancel，再 Wait 等待已登记请求、拨号和物理 socket 的实际收尾；确认路径有效后 Resume。关闭失败或等待未完成时不遗忘旧代。该网络代次与代理转发代次、配置任务归属独立：暂时收尾网络尝试不销毁 provider、健康检查或其调度。

HTTP、内部入口、DNS 共享查询、测速及资源下载传递网络代次；提交前检查所属代次，旧请求不能在恢复后重新进入新代或发布旧结果。首次 GeoIP/GeoSite/MMDB/ASN 下载也使用临时文件，检查 HTTP 状态、完整读写与关闭、候选格式后才替换目标；失败保留原文件。物理 socket 关闭与宿主回归不代替 OHOS 的 protect、destroy、fd 所有权及所有协议内部任务验收。

---

<h1 align="center">
  <img src="Meta.png" alt="Meta Kennel" width="200">
  <br>Meta Kernel<br>
</h1>

<h3 align="center">Another Mihomo Kernel.</h3>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/MetaCubeX/mihomo">
    <img src="https://goreportcard.com/badge/github.com/MetaCubeX/mihomo?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/MetaCubeX/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/MetaCubeX/mihomo/releases">
    <img src="https://img.shields.io/github/release/MetaCubeX/mihomo/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/MetaCubeX/mihomo">
    <img src="https://img.shields.io/badge/release-Meta-00b4f0?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, VLESS, Shadowsocks, Trojan, Snell, TUIC, Hysteria protocol support
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node
  based off latency
- Remote providers, allowing users to get node lists remotely instead of hard-coding in config
- Netfilter TCP redirecting. Deploy Mihomo on your Internet gateway with `iptables`.
- Comprehensive HTTP RESTful API controller

## Dashboard

A web dashboard with first-class support for this project has been created; it can be checked out at [metacubexd](https://github.com/MetaCubeX/metacubexd).

## Configration example

Configuration example is located at [/docs/config.yaml](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml).

## Docs

Documentation can be found in [mihomo Docs](https://wiki.metacubex.one/).

## For development

Requirements:
[Go 1.20 or newer](https://go.dev/dl/)

Build mihomo:

```shell
git clone https://github.com/MetaCubeX/mihomo.git
cd mihomo && go mod download
go build
```

Set go proxy if a connection to GitHub is not possible:

```shell
go env -w GOPROXY=https://goproxy.io,direct
```

Build with gvisor tun stack:

```shell
go build -tags with_gvisor
```

### IPTABLES configuration

Work on Linux OS which supported `iptables`

```yaml
# Enable the TPROXY listener
tproxy-port: 9898

iptables:
  enable: true # default is false
  inbound-interface: eth0 # detect the inbound interface, default is 'lo'
```

## Debugging

Check [wiki](https://wiki.metacubex.one/api/#debug) to get an instruction on using debug
API.

## Credits

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the GPL-3.0 license.

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**
