# ROFL CONTROLLED GROUND TRUTH AND SEMANTIC FINGERPRINT V1 — FINAL REPORT

`PROJECT_CONTEXT_LOADED = YES`  
`ARCHITECTURE_GATE = PASS`

本阶段只扩展 Parser 所有的 exact-build Replay protocol semantic、provenance、regression 与 migration contract。没有修改 frozen V1/V2 baseline，没有取得 map truth、behavior inference、采集、Akari runtime/state/cache 或 UI 职责。

## A. STATUS

`EXTERNAL_INPUT_REQUIRED`

- `SUCCESS_A — Infrastructure = PASS`：八项要求均已实际实现、接入、构建并测试。
- `SUCCESS_B — P0 Semantic Breakthrough = NOT ACHIEVED`：没有把任何 P0 protocol field 误晋级。
- `SUCCESS_C — Full P0 = NOT ACHIEVED`。
- 本地 actionable route/capability 均为 0；已有 P0 machine truth 已全部转换并执行 alignment，但没有可与之对齐的唯一 protocol-field candidate。

这不是 `framework complete → stop`。现有证据、自动 case、fingerprint、negative control、migration contract、regression integration、全 capability traversal 与精确失败原因均已执行完；剩余步骤确实依赖新的独立高密度 controlled Replay。

## B. CURRENT BUILD

- 当前 pinned exact build：`16.16.805.0442`。
- 当前研究状态：`SEMANTIC_RECOVERY_SATURATED`，不是 `FULLY_PARSED`。
- 已注册 exact builds：`16.15.801.3452`、`16.16.805.0442`。
- 没有发现已注册或已显式提供的新 exact-build Replay，因此没有声称某个后继版本已经存在，也没有运行伪造的新版本迁移。
- Nearest-build fallback 永久为 `FORBIDDEN`。

## C. CALIBRATION INFRASTRUCTURE

已实现并接入公开 Parser API：

- `SemanticFingerprint` 与稳定 canonical SHA-256。
- `GroundTruthOracle` 与 DETAILS P0 machine conversion。
- `MigrationOracle` 与 deterministic decision engine。
- `ManualValidationCaseGenerator`（5–20、information-gain 排序、只针对自动未决 capability）。
- `ControlledCalibrationImporter`（显式 allowlist、strict exact build、SHA-256 provenance）。
- `ExceptionRegistry`（champion/mechanic + exact-build scope）。
- `AutomatedMigrationDecision`。
- `RegressionIntegration`。

阶段构建器读取并校验了 V2 final report、79-capability manifest、saturation、research queue、176-route/199-capability decision ledger、negative-evidence registry、runtime registration、packet inventory、exact-build profiles、legacy fingerprints、migration artifact、regression attestation、P0 DETAILS truth、controlled request specification、semantic API 与 regression entrypoint。构建入口是 `npm run build:controlled-ground-truth-fingerprint`。

## D. SEMANTIC FINGERPRINT SYSTEM

- 当前 build 的 79 个 public canonical capabilities 均有 registry row：`VERIFIED 29 / UNKNOWN 4 / UNAVAILABLE 46`。
- 这 29 项的 semantic availability 已验证，但它们的完整 migration fingerprint 仍有显式未知维度；因此 `promotion_eligible = 0 / verified-incomplete revalidation = 29 / total non-promotable = 79`。`VERIFIED` 不再被误读为“完整指纹可自动晋级”。
- Verified fingerprint 保存 structural、behavioral、cross-field invariant、ground-truth reference、negative control、exception、exact-build verification 与 migration policy。
- Route/field/offset 只存在于独立 `build_bindings`；semantic truth 中禁止这些 key。
- 每项 provenance 必须绑定 exact build、一个 Replay SHA 或 Replay-set manifest SHA，以及 source SHA。
- `UNKNOWN` / `UNAVAILABLE` dimension 在 matcher 中固定计 0，不能通过复制未知值获得 full pass。
- Verified-but-incomplete records 必须逐项列出 `completeness.incomplete_dimensions`、使用 `REVALIDATE_IF_AMBIGUOUS`，并明确 `promotion_eligible:false`；缺少或伪造该 contract 会被 validator 拒绝。
- P0 四项均为 `UNAVAILABLE`、`promotion_eligible = false`；没有为填满 schema 伪造 structural 或 behavioral truth。

产物：`artifacts/controlled_ground_truth_semantic_fingerprint_v1/semantic_fingerprints.json` 与版本化 schema。

## E. GROUND TRUTH ORACLE

- 从 1,430 个现有 DETAILS P0 anchors 自动生成 5,720 条 machine oracle records。
- `CURRENT_HP / MAX_HP / ARMOR / MAGIC_RESIST` 各 1,430 条。
- 每条保存 case、Replay SHA、exact build、timestamp、entity/champion、semantic、observed value、before/after、source、machine/manual、confidence、notes 与原始 frame-boundary evidence。
- Oracle truth 不包含 route、packet、payload、offset 或 discriminator。
- Baseline alignment 守恒：5,720 oracle / 0 candidate match / 5,720 unmatched / 0 promotion。

产物：`ground_truth_oracle.json`、`p0_alignment_baseline.json`。

## F. MIGRATION ORACLE

每个候选计算且保存：

- `STRUCTURAL_MATCH_SCORE`
- `BEHAVIORAL_MATCH_SCORE`
- `CROSS_FIELD_MATCH_SCORE`
- `GROUND_TRUTH_ORACLE_SCORE`
- negative-control、invariant、regression 与 exception audit gates

所有 score 为 `[0, 1]` 数字；unknown 不得成为 `null` 或获得分数。只有一个 eligible candidate 且所有证据/gate 通过时才自动选择；被拒绝 lookalike 与失败原因仍完整保留。多个 eligible candidates、结构/行为冲突或 ground truth 无法区分时才输出 manual；`SEMANTIC_CHANGED` 必须有显式 change evidence。

Decision 与 candidate provenance 必须同时绑定 source build、target build、run id，以及 source fingerprint SHA-256 或明确的 regression-report schema/run chain。任意非空对象不能再绕过 provenance。显式 semantic-change evidence 优先于所有满分/gate，绝不允许矛盾候选自动晋级。

七种结果均通过 deterministic contract test：`AUTO_VERIFIED`、`AUTO_VERIFIED_WITH_ROUTE_MOVE`、`AUTO_VERIFIED_WITH_FIELD_SHIFT`、`REVALIDATED_MACHINE_ONLY`、`MANUAL_VALIDATION_REQUIRED`、`SEMANTIC_CHANGED`、`UNSUPPORTED`。

## G. CURRENT HP

`UNAVAILABLE / NOT_PROMOTED`

- 已有 1,430 条 independent machine truth。
- 当前 bounded exact-build route search 的 promotion decision 为 `REJECT`，evidence exhausted。
- 没有 candidate decoder rows 可对齐。
- 下一条必要证据：同 timestamp 的 hero scalar carrier，或带 sub-second HP truth 的安全 paired oracle。

## H. MAX HP

`UNAVAILABLE / NOT_PROMOTED`

- 已有 1,430 条 independent machine truth。
- 现有 item/level frame anchors 只能形成 bounded ground-truth cases；分钟级 frame 不能证明某个 protocol field。
- 当前 promotion decision 为 `REJECT`，evidence exhausted。
- 下一条必要证据同 G；controlled HP-item buy/undo/sell step 提供最高 information gain。

## I. ARMOR

`UNAVAILABLE / NOT_PROMOTED`

- 已有 1,430 条 independent machine truth。
- 已保存 Armor item step case，但当前无唯一 protocol candidate；值“像 Armor”不计证据。
- 当前 promotion decision 为 `REJECT`，evidence exhausted。
- 需要同英雄、单变量、可重复的 buy/undo/sell response 与 sub-second truth/candidate carrier。

## J. MAGIC RESIST

`UNAVAILABLE / NOT_PROMOTED`

- 已有 1,430 条 independent machine truth。
- 已保存 MR item step case；没有用“数值大概像 40”晋级。
- 当前 promotion decision 为 `REJECT`，evidence exhausted。
- 需要与 Armor 相同的 controlled step response。

## K. OTHER HERO STATE

- `CURRENT_MANA / MAX_MANA / ATTACK_DAMAGE / ABILITY_POWER / ATTACK_SPEED / MOVE_SPEED` 仍为 `UNAVAILABLE`。
- `CURRENT_RESOURCE` 的 bounded promotion decision 为 `REJECT`，evidence exhausted。
- `0x0412` temporary stat-adjustment neutral floats 与 `0x00dd` attack-speed-cap neutral floats只保留 research structure；字段角色未命名。
- 受控 timed buff/stat step 与独立 cap-component toggle 是下一证据，不在 P0 之前扩散执行。

## L. DAMAGE STAGE

`RECORDED_COMPONENT_STAGE_UNKNOWN / NOT_PROMOTED`

- 7,934 decoded rows，75 DETAILS damage anchors，6 个 exact matched anchors。
- Physical / magic / true 各 2，type mismatch 为 0。
- Recorded-component mean absolute residual `0.2680529753`，max `0.4387931824`，符合整数 DETAILS rounding。
- 这只证明 decoded float 跟随 reported component；不能区分 `POST_MITIGATION / APPLIED / DISPLAY / EFFECTIVE_HP_LOSS`。
- 下一证据：same-time pre/post HP 且控制 shield/heal/regen，或 exact unmitigated input + Armor/MR。

## M. DAMAGE MITIGATION

`UNAVAILABLE / NOT_PROMOTED`

- Effective HP-loss residual：`NOT_COMPUTABLE`。
- Pre-mitigation residual：`NOT_COMPUTABLE`。
- Post-mitigation stage test：`UNDERDETERMINED`。
- 游戏公式仍只能作为 `MECHANICS_DERIVED_VALIDATOR`，不能反向证明 packet field。

## N. SHIELD

- `SHIELD_GENERATED = VERIFIED_DIRECT / PASS`。
- `SHIELD_ABSORBED = UNAVAILABLE`。
- `SHIELD_REMAINING = UNAVAILABLE`。
- Generated amount 不被重命名为 absorbed/remaining；下一 controlled case 必须是单 shield、单 target、单 hit、无 concurrent heal。

## O. HEAL

- `HEAL_REPORTED = VERIFIED_DIRECT / PASS`。
- `HEAL_EFFECTIVE = UNAVAILABLE`。
- `OVERHEAL = UNAVAILABLE`。
- `min(reported, MaxHP - HP_before)` 只能标 `VERIFIED_DERIVED`，不能冒充 Replay direct field。

## P. SPELL / MISSILE

- `CAST_SPELL = VERIFIED_DIRECT / PARTIAL`。
- Human-readable spell identity、target/channel/recast、missile ownership 与 damage causality 仍不完整。
- `MISSILE = UNAVAILABLE`。
- Timestamp proximity causality 明确为 `FORBIDDEN`。

## Q. ENTITY CALIBRATION

- Generic NPC/entity taxonomy truth 仍不可用；没有把 runtime name、Building_Die 或 hero proximity 自动解释为具体实体/建筑/营地。
- Parser 本阶段未取得 map/objective ownership。
- 低优先级 lifecycle calibration 等 P0 出现可行动结果后再推进。

## R. ITEM CALIBRATION

- `ITEM_STATE = VERIFIED_DIRECT / PARTIAL`，只发布 snapshot/set/swap/substitution 能证明的字段。
- `ITEM_BUY`、`ITEM_SELL` 仍为 candidate subsets，不能把整条 generic route 命名为交易。
- `ITEM_UNDO`、`ITEM_TRANSFORM` 仍为 `UNAVAILABLE`。
- 新 Replay 的 HP/Armor/MR 单动作 buy/undo/sell 同时为 P0 提供最高信息增益。

## S. VISION CALIBRATION

- `WARD_SPAWN = VERIFIED_DERIVED / PASS`，特殊/地图/未知实体仍被排除。
- Sweeper held 为 `UNVERIFIED`；activation/interval/owner/position 不可用。
- 本阶段没有因 P0 blocker 扩散到新的 sweeper 人工实验。

## T. EXCEPTION REGISTRY

- 已注册 1 个 exact-build champion exception：`HERO_RESPAWN_YONE_REINCARNATE_SCALAR_V1`。
- 该例外只否定把 Yone reincarnate scalar 当作 universal resource；不否定 verified respawn occurrence。
- Registry 支持 `CHAMPION_EXCEPTION` 与 `MECHANIC_EXCEPTION`，并要求 semantic + build + provenance scope。

## U. AUTOMATIC MIGRATION TEST

- 七状态 contract test：`PASS`。
- 真实 matcher → GroundTruthAlignment → RegressionIntegration → MigrationDecision handoff：`PASS`。
- Route move 与 field shift 可自动分类；unknown、negative-control failure、machine-suite failure 与 alignment residual 均 fail closed 并保留。
- 即使候选四分全满且三 gate PASS，只要存在有效 semantic-change evidence，结果仍强制为 `SEMANTIC_CHANGED`。
- 当前没有新 exact build，因此真实 new-build run 状态为 `NOT_RUN_NO_NEW_EXACT_BUILD_REGISTERED_OR_SUPPLIED`。

## V. MANUAL VALIDATION REQUIRED

- 当前生成的 manual task 数：`0`。
- 原因：还没有候选可让人工在具体 timestamp 区分；现在要求用户读数会是低信息、泛化的“看 Replay”，违反 contract。
- Policy：`FORBIDDEN_UNLESS_AUTOMATIC_EVIDENCE_IS_UNRESOLVED`。
- 一旦新 Replay 自动扫描留下多个候选，generator 只输出最高 information-gain 的具体 5–20 cases，包含 Replay/build/time/champion/variable/before/after/原因/竞争假设。

## W. NEW REPLAY REQUIRED

`NEED_CALIBRATION_REPLAY = YES`  
`Priority = HP_ARMOR_MR`  
`Recommended count = 1`  
`Maximum = 3 only if the first replay remains ambiguous`

首个 Replay 请使用同一个 subject champion，最多一个 helper；避免团战、同时 buff、同时 damage/heal/shield。记录 `MM:SS | ACTION | ITEM/EFFECT | NOTE`，依次执行：

1. 记录开始时间与 champion。
2. 单次隔离受击；随后不治疗，等待自然回复。
3. 单次可控治疗；无同时伤害或护盾。
4. 单次护盾后承受一次隔离攻击；无同时治疗。
5. 死亡一次并记录复活时刻。
6. 无 item/buff 改变时升一级。
7. 购买一件仅增加 HP 的物品后立即 Undo；再买一次后 Sell。
8. 购买一件仅增加 Armor 的物品后立即 Undo；再买一次后 Sell。
9. 购买一件仅增加 MR 的物品后立即 Undo；再买一次后 Sell。

交付仅需：一个 `.rofl`、champion 名、上述简短时间/动作日志。当前不要求用户理解 binary，也不要求自行选择字段或填写 HP 数值；自动 importer/matcher 先运行，只有仍歧义时才生成精确人工读数 case。

首选 exact build 是 `16.16.805.0442`。若该 build 已无法运行，提供当前可运行 build 的一个 Replay；系统先按其真实四段 exact build 执行 full semantic migration，绝不借用 16.16 decoder。

## X. REGRESSION

- Focused semantic/fingerprint/oracle suite：`34 / 34 PASS`。
- Full Node suite：`412 / 412 PASS`。
- Research V3：`38 tests, 37 PASS, 1 SKIP`；skip 原因为该 package 不含完整 frozen artifact，不是失败。
- Research V4：`17 / 17 PASS`。
- 合计 full regression：`467 tests, 466 PASS, 1 expected SKIP, 0 FAIL`。
- Stage 在两个独立临时输出目录重复构建，artifact manifest 完全一致；所有 21 output hashes/byte sizes 复核通过。
- P0 zero-promotion、semantic-only truth、strict exact build、undeclared input、API surface 与 public-capability conservation 均有测试。

没有运行会触碰受保护证据的 V2 verification entrypoint；阶段 artifact boundary 明确记录 enumerated/read/hashed/decoded/tested/consumed 全为 false。

## Y. NEXT BUILD READINESS

- 全部 79 public capabilities 必须逐项迁移，不能只迁移高价值项。
- 自动流程已冻结为 structural → behavioral → cross-field → ground-truth → negative controls → regression → unique promotion。
- 未来 diff 同时检测 `NEW_PACKET / NEW_COMPONENT / NEW_RUNTIME_TYPE / NEW_CALLBACK / NEW_ENTITY_FAMILY`。
- 历史 16.15 → 16.16 全能力结果守恒：2 unchanged、12 route moved、15 field shift、4 needs revalidation、46 unsupported。
- 历史结果没有现成四维 fingerprint score，因此禁止事后无证据自动改写；新 build 必须产生真实 matcher/regression evidence。
- `AUTO FIRST / MANUAL LAST` 与 passing capability 不重复人工验证已经写入 `PROJECT_CHARTER.md`、`project_contract.json`、patch migration protocol 与 new-build playbook。

## Z. HARD BLOCKER

`NO_INDEPENDENT_HIGH_DENSITY_CONTROLLED_REPLAY_WITH_ONE_VARIABLE_STEPS`

当前本地 actionable route = 0，actionable capability = 0。15 个关键 lookalike/route search 已保存为 exhausted/repurposed/negative control；P0 persistent-state 与 damage-stage promotion 均为 `NO_PROMOTION`。真正缺少的是：

- same-timestamp hero scalar carrier，或 sub-second HP/defense/resource truth；
- damage stage 所需的 same-time pre/post HP 或 exact unmitigated input；
- controlled temporary-stat/cap-component toggles。

除 W 中的一个高密度 Replay 外，当前没有更小、仍具独立信息增益的本地动作。
