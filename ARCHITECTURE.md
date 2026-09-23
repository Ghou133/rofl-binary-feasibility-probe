# 代码结构与数据流

更新：2026-09-23。此文对应冻结的公开源码快照；精确字段契约以 `src/capability_manifest.js`、`src/semantic_api.js` 和版本 profile 为准。

```text
旧版 CLI（src/cli.js）
  → src/rofl.js → src/analysis.js       容器、raw inventory、前 N 条时间线、锚点
  → src/semantic_pipeline.js           仅 16.15.801.3452 的整合语义
  → src/cli_report.js                  基于本次实际执行结果生成报告
  → JSON、JSONL、CSV

独立库入口（src/semantic_api.js）
  → src/build_registry.js              精确 build 选择；拒绝邻版回退
  → src/decoders/                      版本绑定解码；含 16.16 独立表面
  → src/*state*.js、*manifest*.js       受限状态查询、逐字段能力登记

可选：已验证 Ward/Path JSONL → V2 pipeline
可选：解码结果 → research-v3/ DuckDB → research-v4/ 保护量增量研究层
```

两条入口不是一条已统一的调用链。旧 CLI 不会自动执行 16.16 API；本次维护
不新增跨版本 CLI 输出契约。参数与运行条件见 [公开维护说明](docs/PUBLIC_DEVELOPMENT.md)。

## 目录职责

| 路径 | 职责 | 公开版注意事项 |
| --- | --- | --- |
| `src/rofl.js`, `src/analysis.js` | 解析容器、严格遍历块、保留 raw 位置与 hash，生成清单 | 格式通过不等于语义已验证 |
| `src/build_registry.js`, `src/decoders/` | exact-build profile、opcode/字段布局和解码器 | 无通用邻版 fallback；运行时镜像作为外部输入 |
| `src/semantic_api.js`, `src/semantic_pipeline.js`, `src/capability_manifest.js` | 对外语义接口、事件归一化、逐字段等级与 manifest | 消费者只引用公开接口，不复制解码逻辑 |
| `src/ward_pipeline_v2.js`, `src/path_pipeline_v2.js`, `src/inventory_state_at.js`, `src/*stat*.js` | 受限 Ward/Path/库存/统计状态查询 | 直接事实、派生值、candidate 和 unavailable 分开；无地图行为解释 |
| `src/cli.js`, `src/cli_report.js`, `scripts/`, `examples/` | 用户命令、版本迁移、验证与历史研究脚本 | `scripts/` 中许多命令需要私有精确输入；以各脚本参数和新版本手册为准 |
| `play-rofl.ps1`, `play-rofl.cmd` | 可选的 Windows 本机回放启动辅助脚本 | 读取当前本机 League Client 的 LCU 连接来播放用户提供的文件；不参与 parser 语义管线或公共接口 |
| `test/`, `tests/` | Node/Python 单元、回归、负控和条件输入测试 | `npm test` 为公开套件；`test:all` 保留完整 Node 范围，V3/V4 与 entity/item Python 测试单列 |
| `research-v3/` | 历史 DuckDB 流式 ingest、研究查询与 verifier | 地图近似区域是旧研究层，不是 parser 的地图真值；未来归下游所有者 |
| `research-v4/` | V3 数据库上的保护量增量表、回填与 verifier | 不发布本机数据库或原始事件流 |
| `docs/`, `handoff-evidence/` | 协议说明、字段报告、小型历史摘要 | 历史 attestation 与本轮实际重跑分别标注 |
| `artifacts/`, `replay/`, `research-v3/output/`, `evidence/`, `dist/` | 本机输入、生成物、受限证据和打包输出 | 被 `.gitignore` 排除；保留在本机，不进入 GitHub |

## 使用边界

- `inspect` 可只看容器与 packet inventory；`decode`/`analyze` 共用 16.15 旧版语义管线；`batch` 对每场使用同一管线；`validate` 增加回归与可选 DETAILS 后验对照。
- 直接 Replay 字段带精确 build、源 SHA、packet/offset/hash 等 provenance。派生字段注明变换；`UNAVAILABLE` 用 `null`，不会猜数值零。
- `16.16` 的 scoreboard 是 keyframe、item route 是候选时不产生通用实时状态或交易事件。`stats_at` 在关键输入缺失时逐字段 fail closed。
- 本仓库不采集 Replay，不持有当前比赛状态，不管理地图真值、行为模型或 UI。`lol-inference-lab/replay/` 是迁移后的活跃实现目标；本仓库保留供哈希比较与回滚。

## 阅读顺序

先看 [README.md](README.md) 和 [AI_HANDOFF.md](AI_HANDOFF.md)，再读 [ROFL 格式](docs/ROFL_FORMAT.md)、`src/rofl.js`、`src/build_registry.js`、`src/semantic_api.js`、`src/semantic_pipeline.js`、相应 `src/decoders/` 与 [新版本手册](docs/ROFL_NEW_BUILD_PLAYBOOK.md)。字段状态以 [能力矩阵](docs/ROFL_CAPABILITY_MATRIX.md) 和 [验证状态](VALIDATION_STATUS.md) 校核。
