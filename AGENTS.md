# 官方 Mihomo fork 的 OHOS 适配源码

本仓属于 ClashBox 工程。开始先读本仓 README，再按 docs/agents/domain.md 定位所属协调仓并读取其当前状态与相关设计。任务归属与代码远端不同，见下方 Agent skills。

默认 Windows 本地；Python 由 uv 管理，具体环境和验证入口以协调仓 ENVIRONMENT.md、REPRODUCE.md 为准。源码、构建和验证在当前指定工作副本内进行；同仓并行使用独立工作副本并保留已有未提交修改。

公共工作空间和共享设备操作遵循工作空间根规则。独立 clone 缺少该入口时，先取得对应规则再进行公共变更、手机、VPN 或主机网络操作；常规源码检查可继续。

## Agent skills

### Issue tracker

任务集中在 `Ghroth6/clashbox-meta`。读取或发布任务前，读 `docs/agents/issue-tracker.md` 并显式指定任务仓。

### Triage labels

使用默认五项分流标签；评估或变更任务状态前读 `docs/agents/triage-labels.md`。

### Domain docs

采用 single-context；探索代码或记录术语、设计决策前读 `docs/agents/domain.md`。
