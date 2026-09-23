# 清理报告

本轮目标是保留一个可继续研究的本地工作区，并另行生成一个安全、轻量、适合交给
其他开发者或 AI 的源码与 bounded-evidence ZIP。

## 结果

- 清理前：约 22.93 GiB，2,801 个文件。
- 清理后本地工作区：约 5.19 GiB（之后新增的文档和小型 ZIP 只会造成很小变化）。
- 释放空间：约 17.7 GiB。
- 可重复执行的清理入口：`scripts/cleanup_legacy_files.ps1`；默认 dry-run，传 `-Apply`
  才删除。脚本拒绝删除工作区之外的目标，并可幂等重跑。

## 已删除类别

- 多代 V2/V3 review ZIP、stage、extract、audit-final 和它们的源码副本；
- smoke、failed、post-fix、single-run、重复 validation 和旧 CLI 输出；
- 每回放重复的 `replay_analysis.json`、`events.json`、timeline/inventory/raw-anchor 辅助物；
- 可从保留输入再生的大型 raw packet、all-shapes、decoded/intermediate JSONL；
- 已过时的入口文档、能力矩阵、协议报告和旧打包脚本；
- 带本机绝对路径、Match Details/oracle、PUUID 或其他玩家标识的旧审查包；
- `__pycache__`、`.pyc`、日志、临时查询导出和命名为 `_tmp` 的逆向草稿；
- 无许可证文件的上游源码快照、release archive 和历史二进制副本。

## 本地保留但不外发

- 4 个开发回放：用于本地真实输入测试；
- patch-pinned 客户端内存镜像和运行时字典：用于精确 16.15 语义解码；
- 当前 V4 扩展 DuckDB：用于本地 V3/V4 verifier 和研究查询；
- V3 ingest 所需事件 JSONL、V2 Ward/Path 输入以及仍有审计价值的当前 profile；
- 去重后的历史 publication 摘要和当前源码/测试。

这些文件不进入 `dist/rofl-analyzer-ai-handoff.zip`。交接包只含源码、测试、说明、
小型去路径摘要和严格白名单内的字段合同/profile。

## 保留边界

删除的是历史副本和可再生产物，不是声明所有历史研究都能从交接 ZIP 重新复现。
全量复现需要另行提供有授权的回放、精确运行时镜像和完整事件语料；详情见
`VALIDATION_STATUS.md` 与 `THIRD_PARTY_AND_DATA_NOTICE.md`。
