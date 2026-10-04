# Domain docs

布局为 **single-context**：本仓 `GLOSSARY.md` 与 `docs/adr/`。探索相关代码、设计接口或编写规格前，先读术语表及相关 ADR；以后若出现 `GLOSSARY-MAP.md`，按其指向读取相关上下文。

文件不存在时继续工作，不创建占位术语表或 ADR。术语与决策在实际讨论明确后由 domain-modeling 按需沉淀。已有文件原样保留。

命名概念时使用术语表中的词汇；发现缺项时区分尚未确认的概念和现有概念的别名。输出与既有 ADR 冲突时明确指出冲突和理由，不静默覆盖决策。
## 所属工程文档

本仓的工程级目标和决定由 `Ghroth6/clashbox-meta` 维护，先读其 README.md、AGENTS.md 和 docs/agents/domain.md。标准工作空间内路径为 `../../meta/`；在独立 clone 或 worktree 中先定位实际协调仓，不能假设这个相对路径仍有效。

协调仓不在本机时，通过有权限的 GitHub CLI 读取对应仓文件，例如 `gh api repos/Ghroth6/clashbox-meta/contents/README.md -H 'Accept: application/vnd.github.raw+json'`。无法访问时说明缺失的工程上下文，继续不依赖它的检查；涉及未确认的工程决策时再请求补充。私有工程文档保留在协调仓，源码仓只保存指向和本源码模块专属决定。
