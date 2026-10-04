# harmony-proxy-core：Mihomo 的 OHOS 适配分支

本仓直接派生自 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)，维护 OHOS 所需的连接活动、流量分类、事件订阅与平台网络快照适配。以下合同已经宿主测试；原生库交付与设备验收状态以协调仓为准。

`NowTraffic(onlyProxy)` 返回上一秒的字节桶，读取不清零；`TotalTraffic(onlyProxy)` 保留初始化或 Reset 后的累计，包括已关闭连接。proxy 分类依据连接创建时固定的实际出口类型，不依赖名称或组的后续选择；Direct、Compatible、控制出口、组型和未知类型不算代理。内部 `pushToManager=false` 流量仍排除，计数、轮桶和 Reset 共享一个边界。字节上报保留官方 tracker 的缓冲 API 局限，不代表精确的线上传输字节。

`Tracker.LastActivity()` 初值为连接建立时间，随后记录可确认的 payload I/O，保留单调时钟并发更新不回退。TCP 空操作和失败尝试不刷新，UDP 成功的零长度包刷新；缓冲写入报错或复制回调未上报的部分传输无法确认，非空缓冲读取仅在长度增长时确认活动。该查询不改变 JSON 结构，也不决定空闲关闭策略。

URLTest、连接创建和 provider 初始化通过可注销订阅发布事件。回调同步执行且可能并发；cancel 不等待已经选中的回调，调用方须排除旧配置事件，不能等待 ApplyConfig 或它持有的应用锁。provider 初始化事件包括成功、失败和配置代际，不代表后续刷新或完整配置成功。

`platformnetwork.Publish` 校验并原子发布完整的网络快照，包含代际、DNS、接口地址/前缀和路由；非法或过期快照不替换现状。OHOS 在首个快照到达前按离线处理，离线不回落到原生接口或隐式公共系统 DNS。接口索引只能使用实测值，未知为零，不能用 NetworkID 代替。

选择组新增 `SetIdentity(proxy, provider)`：静态节点绑定对象，订阅节点绑定 provider 与节点名称，同 provider 刷新保留身份，其他 provider 新增同名节点不能接管选择。Selector 的目标失效时拒绝连接；URLTest/Fallback 保留健康判断及自动切换策略。`SelectedProxy()` 返回实际选择对象；旧 `Set`/`ForceSet`（包括空值）恢复原裸名语义并清除身份绑定。

完整宿主入口为 `scripts/test-interfaces.ps1`（Go 1.24.5，干净工作区；`-ModuleCache` 指定已有依赖缓存）。它离线运行接口包（包括 outboundgroup 选择回归）和独立进程的 OHOS 初始状态测试，将源码哈希、日志与结果集中写入本仓 `local/runs/<batch>/`，不修改上游 go.mod/go.sum。`scripts/test-statistic.ps1` 仍可单独验证统计包，采用相同的批次布局。两入口默认将 GOPATH、GOCACHE 和 GOMODCACHE 放在 `local/cache/` 下，批次目录中的 `inputs.json`、日志与 `result.json` 保留该次验证事实。旧批次是历史证据，重跑应由脚本生成新批次；缓存可以重建，证据的保留与迁移规则见协调仓的材料说明。Windows 上启用 ohos build tag 不等于 OHOS 二进制或真机验证；两入口均未启用 race detector。

工程集成与验证步骤见 [clashbox-meta](https://github.com/Ghroth6/clashbox-meta)（私有，需权限）；标准工作空间中的协调仓位于 `../../meta`。自动化协作入口见 [AGENTS.md](AGENTS.md)。以下保留上游功能、文档和许可说明；上游功能列表不代表已在 OHOS 验证。

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
