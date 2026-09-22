# 代码结构与数据流

更新：2026-09-23。此文对应冻结的公开源码快照；精确字段契约以 `src/capability_manifest.js`、`src/semantic_api.js` 和版本 profile 为准。

```text
.rofl
  → src/rofl.js                       容器、chunk/Zstd、packet block
  → src/analysis.js                   raw inventory、时间线、锚点
  → src/build_registry.js             精确 build 选择；拒绝邻版回退
  → src/semantic_api.js               对消费者开放的能力/查询接口
      → src/semantic_pipeline.js      事件编排与归一化
      → src/decoders/                build 绑定的二进制字段解码
      → src/*state*.js、*manifest*.js 受限状态查询与能力登记
  → src/cli.js                        inspect/decode/analyze/batch/validate
  → JSON、JSONL、CSV                   显式 provenance、证据等级、null

可选：已验证的 Ward/Path JSONL → src/ward_pipeline_v2.js、src/path_pipeline_v2.js
可选：解码结果 → research-v3/ DuckDB → research-v4/ 保护量增量研究层
```

## 目录职责

| 路径 | 职责 | 公开版注意事项 |
| --- | --- | --- |
| `src/rofl.js`, `src/analysis.js` | 解析容器、严格遍历块、保留 raw 位置与 hash，生成清单 | 格式通过不等于语义已验证 |
| `src/build_registry.js`, `src/decoders/` | exact-build profile、opcode/字段布局和解码器 | 无通用邻版 fallback；运行时镜像作为外部输入 |
| `src/semantic_api.js`, `src/semantic_pipeline.js`, `src/capability_manifest.js` | 对外语义接口、事件归一化、逐字段等级与 manifest | 消费者只引用公开接口，不复制解码逻辑 |
| `src/ward_pipeline_v2.js`, `src/path_pipeline_v2.js`, `src/inventory_state_at.js`, `src/*stat*.js` | 受限 Ward/Path/库存/统计状态查询 | 直接事实、派生值、candidate 和 unavailable 分开；无地图行为解释 |
| `src/cli.js`, `scripts/`, `examples/` | 用户命令、版本迁移、验证与历史研究脚本 | `scripts/` 中许多命令需要私有精确输入；以各脚本参数和新版本手册为准 |
| `play-rofl.ps1`, `play-rofl.cmd` | 可选的 Windows 本机回放启动辅助脚本 | 读取当前本机 League Client 的 LCU 连接来播放用户提供的文件；不参与 parser 语义管线或公共接口 |
| `test/`, `tests/` | Node/Python 单元、回归、负控和条件输入测试 | 公开克隆优先运行 portable/V3/V4 单元测试；全量测试不等于可复现历史语料 |
| `research-v3/` | 历史 DuckDB 流式 ingest、研究查询与 verifier | 地图近似区域是旧研究层，不是 parser 的地图真值；未来归下游所有者 |
| `research-v4/` | V3 数据库上的保护量增量表、回填与 verifier | 不发布本机数据库或原始事件流 |
| `docs/`, `handoff-evidence/` | 协议说明、字段报告、小型历史摘要 | 历史 attestation 与本轮实际重跑分别标注 |
| `artifacts/`, `replay/`, `research-v3/output/`, `evidence/`, `dist/` | 本机输入、生成物、受限证据和打包输出 | 被 `.gitignore` 排除；保留在本机，不进入 GitHub |

## 使用边界

- `inspect` 可只看容器与 packet inventory；`decode`/`analyze` 当前共用语义管线；`batch` 对每场使用同一管线；`validate` 增加回归与可选 DETAILS 后验对照。
- 直接 Replay 字段带精确 build、源 SHA、packet/offset/hash 等 provenance。派生字段注明变换；`UNAVAILABLE` 用 `null`，不会猜数值零。
- `16.16` 的 scoreboard 是 keyframe、item route 是候选时不产生通用实时状态或交易事件。`stats_at` 在关键输入缺失时逐字段 fail closed。
- 本仓库不采集 Replay，不持有当前比赛状态，不管理地图真值、行为模型或 UI。`lol-inference-lab/replay/` 是迁移后的活跃实现目标；本仓库保留供哈希比较与回滚。

## 阅读顺序

先看 [README.md](README.md) 和 [AI_HANDOFF.md](AI_HANDOFF.md)，再读 [ROFL 格式](docs/ROFL_FORMAT.md)、`src/rofl.js`、`src/build_registry.js`、`src/semantic_api.js`、`src/semantic_pipeline.js`、相应 `src/decoders/` 与 [新版本手册](docs/ROFL_NEW_BUILD_PLAYBOOK.md)。字段状态以 [能力矩阵](docs/ROFL_CAPABILITY_MATRIX.md) 和 [验证状态](VALIDATION_STATUS.md) 校核。
