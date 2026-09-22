# SOURCE_FROZEN_DURING_MIGRATION

Active protocol development is frozen in this source repository as of
`2026-08-21`. The completed Dynamic Defense stage ended at
`EVIDENCE_EXHAUSTED / C_EVIDENCE_EXHAUSTED`. Preservation-first migration is in
progress to `lol-inference-lab/replay/`; do not develop both copies independently.
This repository remains the read-only safety source until conservation and
regression gates pass. No deletion is authorized.

# ROFL Analyzer：精确版本 ROFL 回放研究工具

> **公开源码快照（2026-09-23）**：本仓库按 [GPL-3.0-only](LICENSE) 开放原创代码与文档。
> 当前语义基线截至 2026-08-21，源码处于迁移冻结期；长期开发入口是
> `lol-inference-lab/replay/`。公开源码本身不代表全量回放复现或新能力发布。
> 见 [路线图](ROADMAP.md)、[代码结构](ARCHITECTURE.md)、
> [当前验证状态](VALIDATION_STATUS.md) 与
> [第三方数据说明](THIRD_PARTY_AND_DATA_NOTICE.md)。

这是一个面向《英雄联盟》`.rofl` 回放的可审计研究项目。它能解析
ROFL 容器和数据包，并在**精确版本 `16.15.801.3452` 与
`16.16.805.0442`** 上按各自 build profile 解码已验证事件。它不是通用
回放查看器，也不会把某个版本的 opcode、RVA 或字段布局回退到邻近版本。

如果你把项目交给另一位开发者或 AI，请先读 [AI_HANDOFF.md](AI_HANDOFF.md)。
默认交接包只含源码、测试、协议说明和小型去路径证据，不含玩家数据、
回放、DuckDB、客户端内存镜像或完整解码语料。

## 目的与当前进度

目标是把 `.rofl` 的版本绑定二进制协议转换为有来源、可核验的语义事实，供研究层通过公开接口使用。解析器只负责回放协议；地图知识、行为推断、语料采集、在线运行和 UI 属于其他项目。

| 状态 | 当前交付 | 边界 |
| --- | --- | --- |
| 已实现 | ROFL 容器、chunk/Zstd、packet framing、原始清单；精确 build 注册、语义 API、能力 manifest、证据等级和 fail-closed 输出 | 容器可解析不等于任意 build 的语义可用 |
| 已实现，按字段限定 | `16.15.801.3452` 的旧版受验证语义；`16.16.805.0442` 的 HeroPath、等级、WardSpawn、伤害、死亡、重生、XP/lane-CS keyframe、受限 gameplay-tail、ItemState 等 | 各字段的 direct/derived/partial 等级见能力 manifest 与下文；不跨 build 套用 |
| 部分实现或候选 | `16.16` Cast/Buff/Protection 的受限字段，inventory special-slot，stat 查询接口与条件公式；buy/sell、total gold、jungle CS 等候选 | 不能将候选解释成完整交易或当前战斗状态；MaxHP/Armor/MR 不发布数值 |
| 未实现或不可用 | 任意新版本自动语义支持、完整 Cast/Buff/Protection、CurrentHP/当前 Armor/MR、伤害阶段与来源归因、护盾实例/剩余量、effective heal/overheal、通用 ItemEvent、Sweeper activation、普通野怪清野事件 | 缺少精确版本证据时保持 `UNKNOWN`/`UNAVAILABLE`/`null` |

近期工作的完整顺序、补全条件和停止准则见 [ROADMAP.md](ROADMAP.md)。目录职责、公开接口和数据流见 [ARCHITECTURE.md](ARCHITECTURE.md)。本仓库的公开仅改变源码可见性，不改变冻结状态或既有能力等级。

## 项目能做什么

| 层 | 功能 | 当前边界 |
| --- | --- | --- |
| 容器层 | 校验 `RIOT` 头、版本、尾部 metadata、签名区、17 字节 chunk、Zstd 解压和 packet block framing | 可用于任意结构兼容的 ROFL；语义不随之自动支持 |
| V1 语义 | Hero Death、英雄间伤害、CastSpell、Buff、LevelTransition、参与者映射、ADC 死亡前战斗窗口 | 只对 `16.15.801.3452` 启用；LevelAfter 映射同样严格 build-bound |
| V2 视野/位置 | WardSpawn、守卫类型/队伍派生、守卫生命周期、英雄 PathPacket 和 1 秒位置 | 16.15/16.16 Ward 坐标直接；16.16 Spawn READY，Lifecycle PARTIAL；队伍、类型、匹配和插值为派生事实 |
| 16.16 深语义 | 以 `16.16.805.0442` 精确 profile 发布的路径、等级、视野、战斗、记分板、HeroRespawn 与受限 gameplay-tail 字段 | resolver support level=`DEEP_SEMANTIC_READY`；每项字段仍按 direct/derived/candidate/unavailable 分级，绝不近邻 build 回退 |
| V3 研究库 | 把十场回放的事件流式导入 DuckDB，生成伤害归因、守卫/位置/ADC 上下文、Parquet 和查询 | 样本仅 10 场，不代表总体；V3 verifier 已确认当前 DB 是冻结 V3 加受认可的 V4 增量 |
| V4 保护量 | 直接上报治疗量、护盾生成量、目标总护盾吸收量，以及 ADC 保护上下文 | 治疗 raw/effective/overheal 未区分；吸收不能归因到施法者或护盾实例 |

历史发布证据记录的主要规模是：10 场 V3 回放、14 场 V4 profile、
27,625 条英雄伤害、1,357 个 WardSpawn、159,765 个一秒位置、81,652
条直接治疗上报、5,080 条规范化护盾生成、2 条目标总吸收。它们是
2026-08-11 的历史 attestation，不是本轮清理后重新跑出的全量解码。
便携包内的 `handoff-evidence/` 明确标注这一边界。

## 环境

- Node.js `>=22`，需要原生 Zstandard 支持。
- Python `>=3.10`。
- `pip install -r requirements.txt`：DuckDB、Unicorn，以及逆向工具使用的
  Capstone/pefile。只看源码或运行 Node 的纯逻辑测试时不一定需要全部依赖。
- Windows 批处理入口：`run_rofl_analyzer.bat`、`rofl-research.cmd`；核心
  Node/Python 命令本身可跨平台运行，部分内存扫描开发脚本只适用于 Windows。

项目没有 npm 第三方运行依赖，因此没有生成 `package-lock.json`。
`package.json` 的 `private: true` 仅防止误发 npm 包，不影响 GitHub 源码按 GPL-3.0-only 公开。
公开克隆可直接运行 `test:portable` 与 V3/V4 单元套件；完整 `npm test` 中的部分历史测试需要未公开的精确输入与本地证据。

## 快速开始

安装 Python 依赖并检查命令：

```powershell
python -m pip install -r requirements.txt
node src/cli.js --help
npm run test:portable
npm run test:v3
npm run test:v4
```

只解析容器，不运行精确语义解码：

```powershell
node src/cli.js inspect "D:\Replays\example.rofl" --out-dir "work\inspect"
```

对受支持版本执行语义分析。精确语义必须另行提供与回放 build 对应、SHA 固定的
运行时镜像；下面是 16.15 示例，其默认工作目录路径是
`artifacts/runtime_probe/league_16.15.801.3452.memory.bin`：

```powershell
node src/cli.js analyze "D:\Replays\example.rofl" `
  --decoder-image "D:\PrivateInputs\league_16.15.801.3452.memory.bin" `
  --out-dir "work\analysis"
```

附加 V2 Ward/Path 事实时，显式提供相同回放 SHA 的验证 JSONL：

```powershell
node src/cli.js analyze "D:\Replays\example.rofl" `
  --decoder-image "D:\PrivateInputs\league_16.15.801.3452.memory.bin" `
  --ward-spawns "D:\PrivateInputs\ward_spawns.jsonl" `
  --ward-lifecycles "D:\PrivateInputs\ward_lifecycle.jsonl" `
  --hero-positions "D:\PrivateInputs\hero_positions_1s.jsonl" `
  --out-dir "work\v2-analysis"
```

只读取英雄 Lv2/Lv3/Lv4 时间可使用独立的上游 LevelTransition 接口：

```powershell
node examples/level_transitions.js "D:\Replays\example.rofl" 100
```

代码接口为 `runLevelTransitionDecoder(replay).events` 与
`queryLevelTransitions(events, { participantId, levels: [2, 3, 4] })`。

`ward-events` 可过滤现成的 Ward JSON/JSONL，也可在本地工作目录中使用
默认 Ward 数据集：

```powershell
node src/cli.js ward-events "D:\Data\ward_events.jsonl" `
  --viewer-team 100 --perspective enemy --role support `
  --from-minute 3 --to-minute 15 --output "work\enemy-support-wards.csv"
```

V3 DuckDB 工作流：

```powershell
python research-v3/cli.py init
python research-v3/cli.py ingest "D:\Replays"
python research-v3/cli.py status
python research-v3/cli.py wards --role support --output "work\support-wards.csv"
```

## CLI 命令差别

- `inspect`：只做容器和 raw packet inventory。
- `decode`、`analyze`：当前实现走同一语义管线；名称不同但没有独立输出契约。
- `batch`：递归发现目录中的 `.rofl`，逐个走同一管线。
- `validate`：在分析后额外运行完整 Node 测试，并可用 `--details-dir` 做
  后验对照。Match Details 不进入解码规则。
- `ward-events`：读取/过滤已经按精确 build 解码的 Ward 行，不自行推断
  opcode，也不把生命周期补全或估算。

默认不会输出 Riot ID 或 PUUID。只有显式使用
`--include-private-metadata` 才会把这些字段写入分析产物；不要在外发数据上使用。
如需监控本机外部数据库在运行前后未变化，可将其路径以系统路径分隔符放入
`ROFL_UPSTREAM_PATHS` 环境变量。项目不再内置任何用户名或本机绝对路径。

## 输出

单回放输出通常包含：

- `replay_analysis.json`：容器、packet、语义、能力和 provenance 总览；
- `rofl_inventory.json`、`packet_type_inventory.csv`；
- `packet_timeline_sample.jsonl`、`raw_packet_anchors.json`；
- `death_events.jsonl`、`damage_events.jsonl`、`spell_events.jsonl`、
  `buff_events.jsonl`、`shield_events.jsonl`、`heal_events.jsonl`、
  `level_transition_events.jsonl`；
- `adc_deaths.jsonl`；提供 V2 输入时还会输出 Ward 和 position 数据。

每个直接/派生事件尽量保留回放 SHA-256、chunk/block/payload offset、
packet ID、时间戳和 payload hash。`UNAVAILABLE` 必须保持 `null`，不能把
“没观测到”或“解码器不可用”写成数值零。

## 16.16 当前语义基线

精确 build `16.16.805.0442` 的 resolver support level 为
`DEEP_SEMANTIC_READY`，downstream gate 为
`RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`；capability manifest release status 为
`SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL`。Damage `0x017f` 已对 latest-four 的
266,332/266,332 行完成 exact-runtime full-consume；直接字段为时间、source、
target、记录 amount 与 damage type，amount 的伤害阶段及技能/普攻/item/rune/
passive 归因仍未知。HeroDeath `0x0112` 已对 301/301 P0 行验证 victim 与
killer；assists、kill credit 和其余 inner fields 仍不可用或未知。HeroRespawn
`0x0265` 已对 latest-four 282/282 行 exact native full-consume；每行唯一对应
301 个 P0 death 之一（余下 19 个为 terminal death）。它直接发布重生发生/时间和
协议坐标，但不赋予 map/基地/战略语义；Talon 的已审计例为 `250195 ms`。

HeroStats `0x010c` 是约 60 秒 cadence 的累计 keyframe scoreboard，不是实时
战斗状态。1,390/1,390 P0 行验证 raw XP 与 lane CS；只有 `floor(raw XP)`
是获准的派生整数。Total gold 有 1 个保留异常、jungle CS 有 15 个 floor
异常，二者都保持 `CANDIDATE`，current gold 仍不可用。Item `0x0137`/
`0x04b3` 虽分别 1,601/1,601 与 1,013/1,013 full-consume，却因 447 个 buy
route extras、953 个 non-sale removals、14 个 purchase misses 和 0/52 undo
matches，只登记 buy/sell candidate 与 undo unavailable，不产生 universal ItemEvent；
ItemState snapshots、ItemSwap、ItemSubstitutionMap 和受限 SupportQuest stage 则按各自
exact-build direct/derived contract 发布，绝不反推 transaction cause。

另外六条 exact-build gameplay-tail public 路由只发布其受限协议字段：Cooldown
Broadcast `0x00b8`、Missile movement-complete count `0x03d4`、Face direction
`0x01ab`、Instant stop attack `0x00e4`、Minion basic-attack position `0x01b5` 和
Wall-tracking cache keyframe `0x0298`。它们不证明技能冷却语义、攻击归因、目标
语义或任何地图事实。Buff、CastSpell、Heal/Shield 与 Protection 现有的是
exact-build field-specific direct/partial surfaces，未命名/未验证字段仍为
null/UNKNOWN；不得把它们扩展成全语义事件。

## 16.16 Stat 与派生战斗状态边界

`ROFL_STAT_SEMANTIC_MAPPING_AND_DERIVED_COMBAT_STATE_V1` 已完成本地安全证据闭包，
状态为 `EVIDENCE_EXHAUSTED`，停止条件为 `C_EVIDENCE_EXHAUSTED`。`0x042f` registry
接收 130,490 条唯一 exact-build 行；本地事件只观测到 selector `194`，其四 lane
仅证明结构关系。静态 consumer 链唯一验证 `selector 11 / lane 0 -> MANA_REGEN`，但在
该 registry 中观测数为 0，不能外推其他 selector。`0x0412` 的 714 条 adjustment
记录中，660 条同 replay/entity 严格前后配对均为 selector `194→194` 且四 lane
delta 全零，因此获准的 modifier dependency edge 为 0，flat/percent 语义仍未知。

公共 `stats_at(hero, t, options)` / `statsAt(...)` 已实现为逐字段 fail-closed 查询。
MaxHP、Armor、MR 的公式顺序只有 algorithm-conformance 级条件实现；当前缺少精确
build 的 champion base/growth、完整 item/rune/buff/exception 状态与 P0 公式绑定，
所以不发布任何这三项数值，也没有新增公共语义。`inventory_state_at(...)` 只在 53 条
受治理 `0x006c` special-slot 直接行上给出 partial/per-slot provenance；完整 inventory、
rune state/proc 不会被写成空或零。Damage 只保留 direct type 与 recorded amount，
stage/mitigation 不可用；`0x01e1` 的 12/12 行只发布 target-total
`SHIELD_ABSORBED`，HealReported 可直接上报，但 CurrentHP、effective heal、overheal、
shield remaining/source/instance/lifecycle 均不可计算。

Full semantic baseline 对 latest-four 的 288 条 route、7,223,748 个 packet
逐一守恒：27 registered、3 decoded、79 classified、179 unknown（对应 packet
数为 1,531,741、2,332,337、1,135,531、2,224,139）；completeness gate 为 `READY`，
stale manifest/inventory route 为 0。`0x01e1` 来自另一组精确 build 治理语料，
不在 latest-four 288-route inventory 中；baseline 只通过
`evidence/exact_build_route_attestations/` 的哈希清单和 12 条重新解码机器行接受这一个
外部路由证明。它是 accounting/research gate，而不是所有
route 已解码或所有能力都可用。深恢复队列另有 137 route rows、56 capability rows，
actionable 均为 0，16 个 domains 均已在当前本地安全证据下 exhaust，7/7 saturation
checks PASS，最终状态为 `SEMANTIC_RECOVERY_SATURATED`，明确**不是**
`FULLY_PARSED`。最终测试数以
`artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json`
机器 attestation 为准。受保护 Jungle Objective Holdout 未被读取、枚举、
哈希、解码、测试或消费。

## 明确做不到

- 不支持对任意新补丁套用 16.15 的 RVA、offset 或语义 profile。
- 不恢复直接 CurrentHP、临时 HP 数量或临时最大生命值修改。MaxHP/Armor/MR
  只有缺输入即逐字段返回 null 的条件计算器；当前证据不授权任何 production 数值。
- 直接治疗上报尚不能证明是 raw heal、effective heal 或 overheal。
- 不恢复护盾剩余量、过期未使用量或多护盾消耗顺序。
- 目标总吸收量不能归因到施法者、技能、Buff 或具体护盾实例。
- Ward 移除原因和击杀者不可用；匹配失败或歧义的生命周期不会猜测。
- Path 位置是校准和插值结果，不代表完整移动状态或逐帧真实位置。
- 不把 Match Details、Wiki 公式或 CastSpell 目标位置伪装成直接回放事实。
- 不从 10 场/14 profile 的研究语料推导总体玩家、英雄或版本结论。
- 不提供普通野怪或 camp clear 直接事件；`0x0313` 只是不可用于 camp
  clear 的候选，`0x02eb` 已为 camp clear 否定。
- 16.16 只提供约 60 秒 keyframe 的 raw XP 与 lane-CS 累计快照，不提供精确
  XP/CS 事件时间。Jungle CS 与 total gold 保持 candidate，current gold 与
  spend/income delta 不可用；item buy/sell 仅为不能发布的 candidate，undo/transform/
  destroy 不可用。独立 ItemState snapshot、swap/substitution 与受限 SupportQuest stage
  不是 universal buy/sell/undo event。这些状态都不是数值零。
- DETAILS `SKILL_LEVEL_UP` 不能替代真实英雄升级时间；玩家可延迟加点。

## 项目边界与下游发现规则

本项目是 ROFL 协议级 source of truth：负责 packet registry、decoder、字段
语义、证据等级、版本兼容和回归。`lol-inference-lab` 以及其他研究项目是
下游 consumer，负责行为解释。

下游若发现新的 packet、decoder、字段语义、版本差异或 verification
evidence，应先或同时提交回本项目。验证后的协议能力不得长期只保留在下游。
Hero Path 属于本项目；“进入某个野区 polygon”、打野路线、视野习惯和 gank
语义仍属于下游推导。

## 尚未验证或需要重新验证

- 当前 `research-v3/output/replay_research.duckdb` 为 3,186,372,608 字节，
  SHA-256 为 `097ffd264b68b4b06ab93a6cb7f020d110a08aaa99fadd3b78b7fba29716f1b3`。
  它与冻结 V3 发布数据库不同，是因为容器增加了 V4 表；当前 `verify-v3`
  已把这一差异判定为 `EXPECTED_ADDITIVE_V4_CONTAINER_CHANGE` 并通过。旧 manifest
  仍只绑定冻结 V3 表面，所以若要发布一个“包含 V4 的新统一 bundle”，仍需另行生成
  一套原子 manifest，而不能把旧哈希说成当前整个容器的哈希。
- 本轮清理没有重新执行 14 回放 V4 全量 backfill；历史 V4 摘要被保留，
  但干净机器端到端重建仍需要外部回放和运行时镜像。
- V2 没有真正未见过的 blind holdout；旧 holdout 已被前序流程处理过。
- V4 外扩的 4 场是 external-corpus validation，不是 blinded statistical holdout。
- `decode` 与 `analyze` 的命名差异尚未形成不同实现契约。
- 多数研究/构建脚本有单元或摘要证据，但不是每个顶层 CLI 命令都有完整
  end-to-end 自动测试。
- 回放、客户端内存镜像和第三方逆向材料能否对外重新分发没有在技术测试中
  得到法律验证；默认交接包全部排除。见 `THIRD_PARTY_AND_DATA_NOTICE.md`。

本次实际运行结果、跳过原因和历史证据边界见 `VALIDATION_STATUS.md`。

## 验证与打包

本地完整工作区（具备回放、运行时镜像和事实输入）可运行：

```powershell
npm test
npm run verify:multi-build
npm run validate-ward-spawn-current
npm run validate-level-transitions
npm run verify-v2
npm run test:v3
npm run verify-v3
npm run test:v4
npm run verify-v4
```

便携 AI 交接包：

```powershell
npm run package:handoff
npm run verify:handoff
```

交接包会写入 `dist/rofl-analyzer-ai-handoff.zip`，使用闭包 manifest 和
逐文件 SHA-256，并在 fresh extraction 后验证。它明确声明
`raw_redecode_performed: false`。

## 继续阅读

- `AI_HANDOFF.md`：给人类和 AI 的接手顺序、架构与事实边界；
- `VALIDATION_STATUS.md`：本次实际执行的验证、未执行项与原因；
- `CLEANUP_REPORT.md`：删除类别、保留原则和体积变化；
- `docs/ROFL_FORMAT.md`：容器和 block framing（已重写为无乱码版本）；
- `docs/ROFL_CAPABILITY_MATRIX.md`：统一协议能力与负结果矩阵；
- `docs/PROTOCOL_VERSION_MATRIX.md`：容器/语义/LevelAfter 的版本门控；
- `docs/ROFL_UPSTREAM_CAPABILITY_SYNC_V1.md`：本轮同步证据、哈希和结果；
- `docs/DOWNSTREAM_MIGRATION_NOTE.md`：`lol-inference-lab` 的接口迁移步骤；
- `docs/V2_WARD_STATUS.md`：Ward/Path 协议与验证边界；
- `docs/PROTECTION_V4_CAPABILITY_MATRIX.md`：V4 字段级合同；
- `docs/PROTECTION_V4_COMPLETION_REPORT.md`：历史 V4 完成报告；
- `research-v3/README.md`、`research-v4/README.md`：数据库层使用说明。
