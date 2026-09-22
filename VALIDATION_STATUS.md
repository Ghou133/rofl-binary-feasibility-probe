# 当前验证状态

## 2026-09-23 公开源码快照检查

本节是公开准备时的新运行结果，不替代下文 2026-08-21 的 exact-build 语义 attestation，也不表示从公开仓库重建了原始语料。

| 检查 | 本次结果 | 证据边界 |
| --- | --- | --- |
| `npm test` | 582 项：580 pass、0 fail、2 skip | 在本地完整工作区运行；两个受控 P0 审计因其私有 Replay 路径未提供而跳过；其余测试包含本机未公开的 artifacts，不能把该计数归给干净克隆 |
| `npm run test:portable` | 25/25 pass | 无原始 Replay/镜像依赖 |
| `npm run test:v3` | 38 项：37 pass、1 skip | 既有冻结 V3 publication fixture 缺席；不是受保护 Jungle Objective Holdout |
| `npm run test:v4` | 17/17 pass | 合成/单元级验证，未重跑 14 场 backfill |
| 路径清理聚焦测试 | 15 项：13 pass、2 skip | route-pair、oracle/quantization 相关；两项跳过需要私有受控 Replay |
| `npm run package:handoff` | PASS | 429 条目、428 个 payload 文件，大小 1,831,262 字节；禁用内容扫描与 fresh extraction 均通过，未做原始 Replay 重解码 |

公开前移除了源码中的本机用户路径。四组历史研究 manifest 曾绑定原始脚本/测试哈希；原 manifest 保持原样，本地原文件和 SHA 保存在未公开的 `artifacts/public_release_preimages_20260923/`。`PUBLIC_RELEASE_SOURCE_HASHES.json` 独立绑定旧/公开源码身份，测试同时验证原 manifest 身份和公开副本身份。这不构成历史研究重跑。

公开 Git 不包含 `artifacts/`、`replay/`、`evidence/`、`research-v3/output/`、`dist/`。干净克隆可运行 portable 与 V3/V4 单元套件；全量 exact-build 回归需另行提供合法取得、SHA 匹配的输入。公开文件清单与干净克隆验证以本次 Git 提交后的记录为准。

本文件区分三件事：当前 exact-build 机器证明、仅检查的历史证明、因私有输入缺失而未执行的重建。
当前语义基线日期为 2026-08-21；最终交接 ZIP 的哈希以 `dist/` 中的 sidecar 为准。

## 2026-08-21 当前 exact-build 语义、Stat 与战斗状态基线

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| Full semantic completeness gate | `READY` | 288/288 routes、7,223,748/7,223,748 packets 守恒；27 registered、3 decoded、79 classified、179 unknown；stale route = 0；`0x01e1` 由独立发布、哈希绑定且重新解码的 12 行 exact-build attestation 覆盖；baseline SHA-256 `81a0e647090b2bac4b4790c77dbce345d3b28533087262f54beeeeaea923eb21`；无 fallback 或 silent discard |
| Deep semantic saturation gate | `SEMANTIC_RECOVERY_SATURATED` | 137 route rows / 56 capability rows，actionable = 0 / 0；16 domains locally exhausted；7/7 checks PASS。queue/saturation/closure/ledger SHA-256 分别为 `a1b8af410832d5136c6f707f4c68afd52a87f235ab3800e3bffedd97f96eb498` / `450e36236e680e47c306a03cfc8d8cc16ac6633841dd80d6eba7c1cfb9fc9158` / `fed274955e1501b381669282dc53cd71eda97740adbb88bfa106f9a883764877` / `fb6c968b970c4e076525a1a25af8889b78f1fcc80c0c16977ab94e917702e14c`。此为证据饱和，**非** `FULLY_PARSED` |
| Requested A–Z capability enumeration | PASS | 69/69 exact-build capability records present，0 missing；`map` 现为 required domain，未恢复项保持显式 UNAVAILABLE/UNKNOWN |
| Stat selector registry `0x042f` | `EVIDENCE_EXHAUSTED` / field-specific | 130,490 unique accepted rows；event-observed selector 只有 `194`，仅获准 STRUCTURAL；静态 consumer chain 唯一验证 `selector 11 / lane 0 -> MANA_REGEN`，该 selector 在 registry 中观测数为 0；Python negative/positive tests 6/6 |
| Modifier dependency `0x0412` | `EVIDENCE_EXHAUSTED` | 714/714 rows；660 个严格同 replay/entity before/after pair 全为 selector `194→194` 且四 lane delta `[0,0,0,0]`；promoted dependency edges = 0，flat/percent/op/value 均未获授权 |
| `stats_at` / MaxHP / Armor / MR | API PASS / values unavailable | `stats_at(hero,t,options)` 与 `statsAt(...)` 为真实逐字段 fail-closed API；公式仅通过 algorithm-conformance；exact champion base/growth、完整 item/rune/buff/exception inputs 与 P0 公式绑定缺失，因此 public derived values = 0、public semantic changes = 0 |
| `inventory_state_at` | PARTIAL / exact-build | 53/53 governed `0x006c` special-slot direct rows；per-slot provenance、carried state 与 ambiguity 分离；完整 inventory、rune state/proc 明确 UNAVAILABLE，不是零 |
| Exact combat dataflow | `EVIDENCE_EXHAUSTED` | 5 route bindings、2,836 条 raw-image matched instructions、8 个 bounded contiguous intervals、21 anchors；Damage stage/mitigation、CurrentHP、HealEffective/Overheal、ShieldRemaining/source/instance/lifecycle 均无晋级；`0x01e1` 只保留 12/12 target-total absorbed rows |
| Integrated Stat/Combat A–Z + Q1–Q8 | PASS / fail-closed | 79/79 capability records classified；verified stat mappings = 1、modifier edges = 0、public semantic changes = 0；integration stop condition `C_EVIDENCE_EXHAUSTED`，machine report/manifest 非空且确定性 |
| Damage `0x017f` | PASS | latest-four 266,332/266,332 exact-runtime full-consume；time/source/target/recorded amount/type direct，amount stage 与 source-kind attribution 未知 |
| HeroDeath `0x0112` / HeroRespawn `0x0265` | PASS | Death P0 301/301 且 0–1 ms 验证 victim+killer；Respawn 282/282 exact full-consume，唯一对应其中 301 deaths，余下 19 terminal；assists、kill credit 与 death inner fields 仍 unavailable/unknown；Talon audited respawn = `250195 ms` |
| HeroStats `0x010c` | PASS / field-specific | P0 1,390/1,390 full-consume；raw XP 与 lane CS verified，XP integer 为 floor-derived；total gold/jungle CS candidate-only，current gold unavailable |
| Item transaction vs. state | CANDIDATE / bounded partial | `0x0137` / `0x04b3` 的 buy/sell 因 extra/missing/collision 反例不发布，undo 对 52 anchors 为 0 direct matches；独立 ItemState snapshot、swap/substitution 与受限 SupportQuest stage 按其 field contract 发布，不反推 transaction cause |
| Gameplay-tail public routes | PASS / bounded | `0x00b8` cooldown broadcast、`0x03d4` missile count、`0x01ab` face direction、`0x00e4` instant stop、`0x01b5` minion attack position、`0x0298` wall-cache keyframe；不命名未验证字段，不产生 map/attack/spell 推论 |
| Buff / Cast / Protection | PARTIAL / field-specific | exact-build public fields按 capability manifest 输出；Heal reported、Shield generated 为 direct；剩余字段未命名或未验证时为 null/UNKNOWN，禁止外推为完整语义事件 |
| Machine regression attestation | PASS | 本轮 fresh：`npm test` 525/525；selector Python 6/6；V4 17/17；V3 37/38 pass、1 个因包内无历史 frozen V3 publication fixture 的既有条件 skip（不是本任务受保护的 Jungle Objective Holdout）。合计 586 tests / 585 pass / 0 fail / 1 skip；focused Stat/Combat Node 59/59 与 baseline attestation 10/10 均已包含在 `npm test`，不重复计数 |
| Protected Jungle Objective Holdout | UNTOUCHED | 未读取、枚举、哈希、解码、测试或消费，不是任何当前 artifact 的输入 |

`READY` 表示 baseline accounting 可审计；`EVIDENCE_EXHAUSTED` 表示 Stat/Combat
任务在当前本地安全证据下没有可晋级语义；`SEMANTIC_RECOVERY_SATURATED` 表示当前
本地安全证据下不存在可行动队列。三者都不表示所有 route 已解码，也不授予 candidate
字段、runtime item 分支或未命名 partial 字段任何语义晋升权限。

## 2026-08-13 历史实际重跑（以下计数不是当前 gate）

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| `npm test` | PASS，81/81 | 包括 exact multi-build registry、无邻版 fallback、16.16 独立 LevelAfter mapping、逐字段 confidence、公共 event build metadata、raw-chunk/时间序与真实 16.15 回放回归 |
| `npm run validate-level-transitions` | PASS | 12 回放、4,045/4,045 完整解码、494/494 paired DETAILS anchors、0 缺失、120/120 单调参与者序列；逐行校验 source packet、payload SHA、runtime/profile 与 decoder input/output/script hashes |
| `npm run test:portable` | PASS，25/25 | 不依赖回放、DuckDB 或运行时镜像 |
| `npm run test:v3` | PASS，38 个测试，1 个条件跳过 | 跳过项需要已排除的完整 frozen-holdout artifacts |
| `npm run test:v4` | PASS，17/17 | V4 schema、idempotence、NULL honesty 和 verifier 单元测试 |
| `npm run validate-ward-spawn-current` | PASS | 17,406 个 `0x0353` 包、1,357 个 WardSpawn、464 个黄色守卫匹配、637 个生命周期 |
| `npm run verify-v2` | PASS | 测试与保存的 V2 源文件哈希/摘要通过；10 回放 Ward 数据集重建因缺 6 个私有回放明确记为未运行 |
| `npm run verify-v3` | PASS | 当前 3,186,372,608 字节 DB 被识别为冻结 V3 加受认可的 V4 增量，分类为 `EXPECTED_ADDITIVE_V4_CONTAINER_CHANGE` |
| `npm run verify-v4` | PASS，`PROTECTION_V4_COMPLETE` | 14 profiles；81,652 heal rows；5,080 canonical shield-generated rows；2 absorption rows；全部 NULL-honesty 检查通过 |

## MULTI_BUILD_ROFL_SUPPORT_V1（2026-08-13 历史运行）

新 Replay 二进制头实读为 `16.16.805.0442`。找到 100 场、100 个唯一 SHA-256，
总计 1,246,155,114 字节；40 场 deterministic bounded sample 严格遍历
55,552,224 blocks，header/chunk/Zstd/framing/timestamp 全部 PASS，framing error=0。
100/100 Replay 在验证前后 SHA-256 不变。

新 runtime image 通过只读进程模块转储获得：35,213,312 字节，SHA-256
`0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55`。
旧 build 的 11 个 semantic Replay block IDs 在 40 场新样本中全部为 0，且旧 RVA
全部漂移。根因归类为 build-specific Replay route / runtime registration migration，
而不是 container detector 失败；证据不足以把未恢复能力解释成统一 opcode permutation。

16.16 P0 已恢复并 exact-build 注册：HeroPath `0x00f6` 在 8 场 bounded 130 秒窗口
18,001/18,001 runtime full-consume、18,001/18,001 shared plaintext grammar full-consume，
24,314 个英雄 path records，8/8 场均覆盖 10 人。240 个 DETAILS 位置锚点 direct axis
p50=2.24、p95=173.26，swapped p50=2,667.94；5 场十人轨迹图已人工检查。

LevelTransition 的原候选 `0x01e8` 已证伪；实测 route 为 `0x0314`。20 场中
2,325/2,325 champion-param packets exact full-consume，2,356 个 DETAILS `LEVEL_UP`
锚点命中 2,295 个唯一事件（±2ms），180 个 participant sequences，field_10 mapping
零冲突。P0 映射为 `242→Lv2`、`194→Lv3`、`210→Lv4`。

该次历史 fresh regression 共 15 组、45.73 秒：Node 81/81、multi-build runtime validator 4/4、portable 25/25、16.16
Path/Level runtime gate、自动 profile/API 冒烟、无 LevelTransition 数据的真实 Replay 状态冒烟、旧 16.15 LevelTransition/Damage/Death/CastSpell/Ward/V2、
V3 38（1 条既有条件跳过）及 V4 17/17 全部 PASS。

该历史阶段已被当前 deep-recovery 发布覆盖。当前 resolver support level 为
`DEEP_SEMANTIC_READY`，downstream gate 为
`RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`。当时 CastSpell/Buff/Protection 的
“unavailable”仅是历史快照，不能覆盖当前 exact-build field-specific partial
surfaces；total gold/jungle CS 仍 candidate，item buy/sell 仍不授权消费，undo/
transform/destroy unavailable，API 不发 universal ItemEvent；独立 ItemState/swap/
substitution/SupportQuest fields 受各自 contract 限制。

V3 当前数据库 SHA-256：
`097ffd264b68b4b06ab93a6cb7f020d110a08aaa99fadd3b78b7fba29716f1b3`。
冻结 V3 manifest 所记录的基础容器 SHA-256：
`a31dcc6c5d849d2a70baa713753a38faaad04afe6793963afe2d1779406e8a85`。
差异本身不是静默忽略：V3 verifier 会检查当前表面恰好是冻结 V3 加指定 V4 表，
并把每个冻结 V3 表与 manifest 绑定的 Parquet 做双向行比较。

## 尚未执行或无法从交接包执行

- 未从原始 10/14 回放重新做整库 V3/V4 backfill。交接包故意不包含这些回放、
  运行时内存镜像和完整 decoded JSONL。
- 10 回放 `validate_ward_v2.js` 重建未运行：工作区只保留 4 个开发回放，其他 6 个
  私有/外部回放已排除。保存的 V2 哈希和 bounded evidence 通过，但这不等于重建。
- 历史 V2 没有真正未见过的 blind holdout；这与当前受保护的 Jungle Objective
  Holdout 不同，后者在本轮保持未读取/枚举/哈希/解码/测试/消费。
- V4 额外 4 场是 external-corpus validation，不是 blinded statistical holdout。
- 没有跨操作系统验证全部 Windows 专用逆向/内存扫描脚本。
- 没有对回放、客户端镜像或第三方逆向材料的再分发权做法律确认。
- 当前旧 V3 manifest 只绑定冻结 V3 发布面；虽然 V3/V4 verifier 均接受当前数据库，
  若要把整个 V4 扩展 DuckDB 对外作为一个新发布，仍应创建新的统一 manifest。

## 历史证据（不算本次重跑）

`handoff-evidence/` 和 `artifacts/protection_v4_publication/` 中的小型摘要来自
2026-08-11 的历史 attestation。本次对其做闭包哈希和内容扫描，但没有用交接包重新
生成那些全语料统计。任何 AI 都应把 `HISTORICAL_ATTESTED_SUMMARY_NOT_A_FRESH_RAW_REDECODE`
视为事实边界，而不是“已经独立复现”。

## 交接包验证口径

交接 ZIP 必须同时满足：闭包 manifest 与实际条目完全一致、逐文件 SHA-256 一致、
无绝对用户路径/凭证选项/玩家标识 payload、fresh extraction 安全、体积低于 25 MiB。
在 fresh extraction 中只承诺运行 `test:portable`、V3 单元测试、V4 单元测试和
bounded-evidence 的 `verify-v2` 模式；不承诺 raw re-decode。
