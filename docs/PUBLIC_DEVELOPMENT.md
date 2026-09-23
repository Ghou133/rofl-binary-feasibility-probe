# 公开源码维护说明

本文件定义公开克隆的日常维护路径，不解除 `SOURCE_FROZEN_DURING_MIGRATION`，
不改变 2026-08-21 的协议语义基线、证据等级、所有权或研究资产状态。

## 先选择正确入口

`src/cli.js` 调用的是 `src/semantic_pipeline.js` 的 16.15 整合管线。
`decode`、`analyze`、`batch`、`validate` 的语义范围仅为
`16.15.801.3452`。未知版本保持拒绝/不可用，不做近邻回退。

`src/semantic_api.js` 是另一条精确 build API 表面，包含 16.16 能力；
不能从 README 的库级能力表推断旧 CLI 已支持这些字段。具体 API 参数、所需
runtime image/profile、返回字段和证据等级以该模块与 `src/capability_manifest.js`
为准。本次不添加未经真实回放回归的统一 CLI，也不重写版本解码器。
`examples/level_transitions.js` 导入旧管线，因此也是 16.15 示例。

## 测试分层

公开日常入口为 `npm test` / `npm run test:public`：执行原 portable 套件，
然后执行本次定点维护测试。维护套件只需 Node >=22.15.0（带原生 Zstd）及
Python >=3.10 标准库。`npm run test:maintenance` 可单独运行。

原 `npm test` 的完整 Node 范围保留为 `npm run test:all`。CLI `validate`
仍枚举并运行 `test/*.test.js` 的全部 Node 文件，不会仅运行公共子集。
缺少私有输入的全量测试可能失败或按原规则跳过，不能称为完整回归通过。

`test:v3`、`test:v4` 为 Python 数据库层单元套件；`test-v3` 是 `test:v3`
的兼容别名。`test:entity-item` 显式运行 `tests/` 的原 Python 套件，包含
需要精确镜像的测试。没有删除、禁用这些测试，也没有让真实镜像缺失变成通过。

打包文件完整性测试在没有 `package_manifest.json` 的普通源码目录中会明确 skip。
Python 打包单元测试以合成目录验证打包器；它们不证明真实语料或整仓发布验证通过。

## 打包模式

```powershell
npm run package:source
npm run verify:source
```

纯源码包为 `dist/rofl-analyzer-source.zip`。`SOURCE_ONLY` 表示只取公开源码、
文档、测试、示例和仓库内已公开历史摘要，不从本机 `artifacts/` 补入材料。
`tests/`、`examples/` 和存在时的 `.github/` 也会纳入；缓存、二进制、环境文件
和原始回放仍排除。可选 Windows LCU 启动辅助脚本 `play-rofl.*` 不在解析器
handoff 包内，仍可从 Git 仓库单独取得；不要为包含它们而取消敏感内容扫描。

```powershell
npm run package:handoff
npm run verify:handoff
```

证据模式通过显式 `--with-evidence` 启用，写入原
`dist/rofl-analyzer-ai-handoff.zip`。原证据白名单必须全部存在且通过扫描，
缺少输入会失败，不能静默生成伪称完整的证据包。不要把整个 `artifacts/`
加入白名单。两种模式均声明未进行 raw re-decode，保留逐文件哈希和闭合清单验证。

运行脚本时 `--output` 可更改目标。`--validate` 根据包内 manifest 验证模式，
不与构建参数混用。验证在替换旧输出前执行；失败不应覆盖此前有效 ZIP。

## 维护边界与历史材料

`CLEANUP_REPORT.md` 的旧全文已归档至 `docs/history/CLEANUP_REPORT.md`；
其体积数字是过去的本地工作区统计，不是当前 Git 大小。
原长篇 AI 交接说明保存在 `docs/history/AI_HANDOFF-20260923.md`，
只用于历史追溯；根目录 `AI_HANDOFF.md` 是当前入口。

`clean:legacy` 和 `clean:legacy:dry-run` npm 别名已移除。旧
`scripts/cleanup_legacy_files.ps1` 仍保留作历史维护工具，不能把它当作新克隆
必须执行的清理步骤。本次没有执行它，也没有删除本机研究输入。
阶段报告、反例、版本解码器、research-v3/v4 与原始哈希桥仍保留。

普通文档、测试、打包和现有合同内修复只需仓库内说明，不要求取得私有治理目录。
涉及跨项目所有权、架构、公共能力晋升或研究资产状态时，维护者仍需在
`..\LOL_RESEARCH_SYSTEM_GOVERNANCE_V2` 中核对 `SYSTEM_NORTH_STAR.md`、
`SYSTEM_PROJECT_MAP.md`、`SYSTEM_DECISION_LOG.md`、`CAPABILITY_REGISTRY.md`、
`EVIDENCE_SOURCE_REGISTRY.md` 的相关部分，并按 `ARCHITECTURE_GATE_TEMPLATE.md`
记录真实审核结果。未取得该上下文则不做这类边界变更；不阻塞独立的日常维护。
不得伪造 PASS 或把历史 gate 当成新授权。

## 回归报告必须区分的内容

记录当前实际运行命令和环境，分别列出通过、失败、跳过以及未运行项。
公开测试、合成容器测试和归档哈希核对不是原始回放解码证明；源码维护改变文件
哈希，也不能把原 attestation 的源码身份改写成新文件身份。历史
`PUBLIC_RELEASE_SOURCE_HASHES.json` 保持不变；维护补丁不声称所有私有回归已通过。
