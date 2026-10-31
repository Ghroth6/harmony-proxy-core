# 官方 Mihomo fork 的 OHOS 适配源码

本仓承担 clashoh 的 Mihomo 派生后端，工程检出目录仍为 clashbox。开始先读本仓 README，再按 docs/agents/domain.md 定位所属应用与设计仓并读取其当前状态与相关设计。任务归属与代码远端不同，见下方 Agent skills。

实施、审查或报告完成前，读取所属 meta 的 `docs/engineering/process.md`「实施、审查与完成」，核对本次依据、范围和证据；委派审查也适用。独立副本按 [docs/agents/domain.md](docs/agents/domain.md#所属工程文档) 定位 meta，不依赖固定相邻路径。

默认 Windows 本地；Python 由 uv 管理。核心导出与构建先读 mobile/README.md，应用集成环境见所属应用仓 app/ENVIRONMENT.md，实际验收从该应用仓 docs/delivery/verification/README.md 定位。旧协调仓实验工具已退出当前树，查历史时从其 docs/reference/README.md 进入。源码、构建和验证在当前指定工作副本内进行；同仓并行使用独立工作副本并保留已有未提交修改。

公共工作空间和共享设备操作遵循工作空间根规则。独立 clone 缺少该入口时，先取得对应规则再进行公共变更、手机、VPN 或主机网络操作；常规源码检查可继续。

## Agent skills

### Issue tracker

任务集中在 `Ghroth6/clashbox-meta`。读取或发布任务前，读 `docs/agents/issue-tracker.md` 并显式指定任务仓。

### Triage labels

使用默认五项分流标签；评估或变更任务状态前读 `docs/agents/triage-labels.md`。

### Domain docs

采用 single-context；探索代码或记录术语、设计决策前读 `docs/agents/domain.md`。
