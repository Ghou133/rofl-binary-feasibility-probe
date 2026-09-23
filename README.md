# ROFL Analyzer

精确版本绑定的《英雄联盟》`.rofl` 回放研究工具：解析容器和数据包，输出带来源、证据等级和明确边界的语义事实。

> **协议研究仍处于 `SOURCE_FROZEN_DURING_MIGRATION`。** 语义基线截至 2026-08-21，公开源码基线发布于 2026-09-23。本次维护修正解析安全、无效计算、报告与打包，不增加已验证语义、不解除冻结、不删除研究证据。迁移目标仍为 `lol-inference-lab/replay/`，不是两套独立活跃实现。

[使用与维护](docs/PUBLIC_DEVELOPMENT.md) · [代码结构](ARCHITECTURE.md) · [路线图](ROADMAP.md) · [历史验证记录](VALIDATION_STATUS.md) · [AI 接手入口](AI_HANDOFF.md)

## 能力与入口

**项目库支持的字段，不等于主 CLI 已经接入的字段。** 本仓库不是通用回放查看器，也不会对未知补丁回退使用邻近版本的 opcode、RVA 或字段布局。

| 入口 / 层 | 当前提供 | 使用边界 |
| --- | --- | --- |
| `inspect` / `src/rofl.js` | RIOT 头、metadata、chunk/Zstd、packet framing、原始清单与锚点 | 容器结构可解析，不代表该版本语义已验证 |
| `decode` / `analyze` / `batch` / `validate` | 旧版整合语义管线：死亡、伤害、施法、Buff、等级和保护量等 | **仅 `16.15.801.3452`**；这四个命令未分发到 16.16 语义 API |
| `src/semantic_api.js` 与精确 build profiles | `16.16.805.0442` 的 HeroPath、等级、WardSpawn、伤害、死亡、重生、XP/lane-CS keyframe、受限 ItemState 和 gameplay-tail 等 | 独立 API 的逐字段能力；需要外部精确镜像、profiles 或对应已验证输入，不是主 CLI 的完整分析模式 |
| V2 Ward / Path | 已验证位置、守卫事件及受限派生关联 | 来源 SHA 必须与回放一致；类型、匹配、生命周期和位置插值与直接字段分级 |
| `research-v3/`、`research-v4/` | DuckDB 研究查询、保护量增量表和验证器 | 保留的真实功能，不是因版本号旧就可删除的目录；全量重建需要私有输入 |

两版都保留“直接、派生、部分、候选、不可用”的区别。完整 Cast/Buff/Protection、CurrentHP、当前 Armor/MR、护盾实例与剩余量、effective heal/overheal、普通野怪清野等能力不能从现有有限字段外推。`stats_at` / `statsAt` 有逐字段 fail-closed 接口，但当前不发布 MaxHP/Armor/MR 数值；库存部分状态不是通用买卖事件。

完整字段合同以 [能力矩阵](docs/ROFL_CAPABILITY_MATRIX.md)、[版本矩阵](docs/PROTOCOL_VERSION_MATRIX.md) 和 `src/capability_manifest.js` 为准。`READY`、`EVIDENCE_EXHAUSTED`、`SEMANTIC_RECOVERY_SATURATED` 均不表示 `FULLY_PARSED`。

## 环境

Node.js **>=22.15.0**，且必须具有原生 Zstandard 支持；Python >=3.10。日常部署应使用所选受支持 Node 分支的修补版本，而不是仅满足最低功能版本。

公开 Node 单元测试不需要 npm 第三方依赖。Python 打包测试只用标准库；V3/V4 数据库和精确解码工具按需安装：

```powershell
python -m pip install -r requirements.txt
```

依赖文件包括 DuckDB、Unicorn 和逆向辅助工具 Capstone/pefile。`package.json` 的 `private: true` 防止误发 npm，不影响 GitHub 源码许可；无 npm 运行依赖，因此没有锁文件。

## 快速开始

```powershell
node src/cli.js --help
npm test
```

`npm test` 现在是公开测试入口。原来完整 Node 测试的范围保留为 `npm run test:all`；CLI `validate` 仍运行完整 Node 套件，不会用公共测试替代其验收。

只解析一个结构兼容回放的容器：

```powershell
node src/cli.js inspect "D:\Replays\example.rofl" --out-dir "work\inspect"
```

执行 **16.15.801.3452** 的旧版整合语义分析：

```powershell
node src/cli.js analyze "D:\Replays\example.rofl" `
  --decoder-image "D:\PrivateInputs\league_16.15.801.3452.memory.bin" `
  --out-dir "work\analysis"
```

运行时镜像不随公开源码提供；默认查找位置为 `artifacts/runtime_probe/league_16.15.801.3452.memory.bin`，必须匹配解码器固定 SHA。缺少镜像不是零事件，也不能通过取消版本校验解决。

附加 V2 数据时，可显式传入 `--ward-spawns`、`--ward-lifecycles`、`--hero-positions` 的同回放 SHA 验证 JSONL。过滤已有守卫事件：

```powershell
node src/cli.js ward-events "D:\Data\ward_events.jsonl" `
  --viewer-team 100 --perspective enemy --role support `
  --from-minute 3 --to-minute 15 --output "work\enemy-support-wards.csv"
```

`examples/level_transitions.js` 也是 **16.15** 管线示例，不是 16.16 通用入口。16.16 的能力和依赖应从 `src/semantic_api.js` 及 [新版本手册](docs/ROFL_NEW_BUILD_PLAYBOOK.md) 核对；本次没有添加未经真实输入回归的统一 CLI。

## 命令与输出

`decode` 与 `analyze` 共用一条管线，没有不同输出契约；`batch` 对目录中的每个回放执行同一管线。`validate` 额外运行完整 Node 回归，可用 `--details-dir` 做验证对照；Match Details 不进入解码规则。

默认时间线保留前 `--timeline-limit` 条。`--sample-stride` 仅为兼容旧命令保留，已弃用且不改变输出；不再计算最终会被截掉的间隔样本。

主要产物包括 `replay_analysis.json`、容器与 packet 清单、时间线样本、原始锚点、各事件 JSONL 和 ADC 死亡窗口；V2 输入提供对应 Ward/position 数据。每条事实保留适用的回放 SHA、packet/offset/hash、版本和证据等级。没有执行语义解码时，报告不会把静态能力表或空事件数组说成已验证结果。

默认不输出 Riot ID / PUUID；`--include-private-metadata` 只用于显式本地需求，不应用于外发数据。分析产物仍可能包含本地路径、回放身份和原始包摘录，不能将“省略玩家字段”等同于可直接公开。外部文件运行前后监测可通过 `ROFL_UPSTREAM_PATHS` 配置。

## 验证与打包

| 命令 | 范围 / 输入 |
| --- | --- |
| `npm test` / `npm run test:public` | 原 portable 测试，加本次解析器、采样、报告和 Python 打包测试；不需要私有回放 |
| `npm run test:maintenance` | 本次新增定点维护测试；Node + Python 标准库 |
| `npm run test:all` | 原完整 Node 套件；部分测试需要未公开的精确输入和本地证据 |
| `npm run test:v3` / `npm run test:v4` | 数据库层单元测试，需安装对应 Python 依赖 |
| `npm run test:entity-item` | 原 `tests/` 内 Python 测试，包含精确镜像测试，需私有输入；不是公共快速测试 |
| `npm run package:source` / `npm run verify:source` | 公开源码包，不读取本机 `artifacts/` |
| `npm run package:handoff` / `npm run verify:handoff` | 显式 bounded-evidence 包；必须另行提供完整的原有证据白名单 |

纯源码包写入 `dist/rofl-analyzer-source.zip`，含源码、测试、示例、文档及仓库内公开历史摘要，manifest 模式为 `SOURCE_ONLY`。证据包写入 `dist/rofl-analyzer-ai-handoff.zip`，模式为 `SOURCE_AND_BOUNDED_EVIDENCE`。两者都校验逐文件 SHA、闭合文件清单和重新解压结果，并声明 `raw_redecode_performed: false`。这不是原始回放重解码证明。

旧 `clean:legacy` npm 删除入口已移除；历史脚本未执行，也不作为新克隆的维护步骤。历史清理规模与记录见 [归档清理报告](docs/history/CLEANUP_REPORT.md)。

## 项目结构与继续开发

```text
src/                    容器解析、语义接口、精确版本解码与受限状态查询
src/cli.js              16.15 旧版 CLI 编排
src/cli_report.js       本次执行结果驱动的验收报告
scripts/                解码、研究与维护工具；多数研究命令需要外部输入
test/, tests/           Node/Python 测试，公共与私有输入范围分别列明
research-v3/, research-v4/  数据库研究层
examples/               使用示例
handoff-evidence/        公开历史摘要，不是本次重跑
```

容器安全与公开维护使用本仓库内说明；跨项目架构、能力晋升或研究资产状态变化仍需维护者的 V2 治理审核。普通贡献者不需要为了运行单元测试取得仓库外的私有治理目录。详见 [公开维护说明](docs/PUBLIC_DEVELOPMENT.md)。

本次没有改写 `PUBLIC_RELEASE_SOURCE_HASHES.json`、版本解码映射或历史 attestation。历史 10/14 场语料、数据库哈希和精确字段计数仍见 [VALIDATION_STATUS.md](VALIDATION_STATUS.md)，不能归为维护补丁后的重新验证。V2 旧 holdout 曾被处理，V4 外扩验证也不是统计学盲测。

## 许可与数据

原创代码和文档按 [GPL-3.0-only](LICENSE) 提供；回放、客户端镜像、第三方二进制及玩家数据不随源码重新分发。许可与数据边界见 [THIRD_PARTY_AND_DATA_NOTICE.md](THIRD_PARTY_AND_DATA_NOTICE.md)。
