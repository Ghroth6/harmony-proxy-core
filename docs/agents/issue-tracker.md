# Issue tracker: GitHub

本仓任务归属 **Ghroth6/clashbox-meta**，范围：官方 Mihomo fork 的 OHOS 适配源码。任务与规格写入该仓的 GitHub Issues；代码提交与 PR 仍归实际改动的源码仓。跨仓引用使用完整 issue URL。

## 操作约定

使用 gh CLI，所有 issue 操作显式带 `--repo Ghroth6/clashbox-meta`；API 路径也显式使用该仓。不要根据当前源码仓 remote 推断任务仓库。执行前核对目标，写入后回读核实。

- 创建：`gh issue create --repo Ghroth6/clashbox-meta --title "标题" --body-file <正文文件>`。
- 读取：`gh issue view <编号> --repo Ghroth6/clashbox-meta --comments`；结合 `--json` 获取所需标签、正文和状态。
- 列表：`gh issue list --repo Ghroth6/clashbox-meta --state open --json number,title,labels,assignees,url`，按任务需要加标签过滤。
- 评论：`gh issue comment <编号> --repo Ghroth6/clashbox-meta --body-file <正文文件>`。
- 标签：`gh issue edit <编号> --repo Ghroth6/clashbox-meta --add-label <标签>` 或 `--remove-label <标签>`。
- 关闭：核对验收证据后，用 `gh issue close <编号> --repo Ghroth6/clashbox-meta`；未满足验收的事项保留未完成状态。

正文文件使用真实换行；凭据和原始私有日志保留在所属工程 local。只有当前任务授权的发布、评论或明确调用的 skill 流程才写入 tracker；读取本配置本身不会创建任务。

“publish to the issue tracker” 指向上述仓库；“fetch the relevant ticket” 读取对应 issue 及评论。跨项目任务只保留一个主 issue，相关工程用完整 URL 关联，避免两套状态。

**PRs as a request surface: no.**

## Wayfinder

Map 是带 `wayfinder:map` 的主 issue，保存 Notes / Decisions-so-far / Fog。Child 是所属项目 issue，使用 `wayfinder:<type>` 标签；优先用 GitHub 子 issue 关联，不可用时在 map 任务列表和 child 的 `Part of: <完整 URL>` 中双向关联。

阻塞优先使用 GitHub issue dependencies；API 使用 issue 的数字数据库 id（由 `gh api repos/<owner>/<repo>/issues/<编号> --jq .id` 读取），而非显示编号。不可用时写 `Blocked by: <完整 URL>` 并读取所指 issue 状态。所有 blocker 关闭只是解除阻塞，执行授权与验收准备仍按任务和 skill 判断。

查询 map 下未关闭的 child，核对阻塞与已有认领，再选择可推进事项。按已授权流程用 `gh issue edit <编号> --repo Ghroth6/clashbox-meta --add-assignee @me` 认领；同一 GitHub 账号不能区分本机多个会话，不能把 assignee 当作文件锁。

完成后在原任务记录结果与证据，满足验收才关闭，并在 map 更新指向原任务的链接。沿用已有权威文档，避免为每次更新复制新文档或 gist。Wayfinder 标签按实际使用创建，不属于本次五个 triage 标签的安装范围。
