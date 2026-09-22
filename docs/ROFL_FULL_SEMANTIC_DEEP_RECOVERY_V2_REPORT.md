# ROFL Full Semantic Deep Recovery V2 — A–Z 机器事实报告

适用构建：`16.16.805.0442`  
生成日期：`2026-08-20`  
解析策略：`exact-build only`；`nearest-build fallback = FORBIDDEN`

本报告是本轮深层语义恢复的最终、可审计事实汇总。它描述“现有受治理证据是否已被穷尽”，不把证据饱和解释成所有包、所有字段或所有玩法语义均已恢复。

事实层次在全文中固定如下：

| 层次 | 含义 | 是否可由消费者作为公开语义使用 |
|---|---|---:|
| **已发布语义** | `artifacts/semantic_coverage_v1/capability_manifest.json` 中当前 exact build 的 `PASS` 或 `PARTIAL`，并由公开 semantic API 按其限制发布 | 是，仅限声明字段与边界 |
| **研究级结构语义** | native inverse、完整消费、字段布局或精确回调操作已经验证，但尚无足够 gameplay identity / causality | 否 |
| **候选** | 有相关性、局部对齐或命名线索，但仍有反例、歧义或缺少独立真值 | 否 |
| **拒绝 / 改作他用** | 原假设已被负证据否决；若为 `REPURPOSE`，只保留更窄、更中性的结构用途 | 否 |

核心事实来源：

- `artifacts/full_semantic_deep_recovery_v2/semantic_saturation_report.json`
- `artifacts/full_semantic_deep_recovery_v2/semantic_research_queue.json`
- `artifacts/full_semantic_deep_recovery_v2/decision_ledger/decision_ledger.json`
- `artifacts/full_semantic_deep_recovery_v2/saturation_closure/semantic_capability_domain_closure_16_16.json`
- `artifacts/semantic_coverage_v1/capability_manifest.json`
- `artifacts/full_semantic_deep_recovery_v2/migration/migration_16_15_to_16_16_deep_semantics.json`
- `artifacts/full_semantic_deep_recovery_v2/regression/semantic_api_smoke_11191203388.json`
- `artifacts/full_semantic_baseline_v1/artifact_manifest.json`
- `artifacts/full_semantic_baseline_v1/regression/semantic_api_smoke_11191203388.json`
- `artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json`

closure / ledger 固定的专项输入如下；C–R 的域结论均回指这些专项制品，而不是从 route name 猜测：

| 专项 | Artifact | SHA-256 |
|---|---|---|
| hero state / damage / defense | `artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json` | `fc13dce5e0c89b9d556074af3c2b7b13138eb855b9c101327dbddd9c4e900eab` |
| buff / spell | `artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json` | `22a40272b47870bf43b3f15d8c43615f0cd1482d128025313fb50b4e99f20195` |
| entity / item | `artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json` | `c5614f613bb3116833cc15c1e42486272a7f4431184629ffaca1b89f943485e7` |
| item-family saturation | `artifacts/full_semantic_deep_recovery_v2/item_family_saturation/item_family_saturation_decisions_16_16.json` | `78f75b6af35ecb3ffca6817cbe26680f3d53c4243c2d0a52e6215e5fb62712a8` |
| residual P7 | `artifacts/full_semantic_deep_recovery_v2/residual_p7_wave/residual_p7_wave_machine_decisions_16_16.json` | `bf89434aa66246c657b3704ea5a1496f14c6e8815a38a7700acc6e0b5cc75a2c` |
| hero respawn | `artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json` | `e3801ae6e3946dfff7c11c7ed13637e02ef9eb8094caa3242543eb2d5f4f59d3` |

## A. STATUS

```text
PROJECT_CONTEXT_LOADED = YES
ARCHITECTURE_GATE = PASS
STATUS = SEMANTIC_RECOVERY_SATURATED
```

该状态严格表示：在构建 `16.16.805.0442`、当前治理允许的本地安全证据内，高价值域、重点高频路由、候选队列、负证据和回归门均已执行并收敛；剩余缺口需要新的外部证据。它不是包解码百分比，也不代表通用全解析。

解析器只拥有 replay protocol semantics，不声明 map truth、行为推断、离线语料采集、Akari 运行时获取/缓存/状态或 UI。受保护的 Jungle Objective Holdout 未被枚举、读取、哈希、解码、测试或消费；饱和报告中的六项边界标志均为 `false`。本轮未联网。

## B. SEMANTIC SATURATION

饱和门的直接机器事实：

- `saturated = true`；最终状态为 `SEMANTIC_RECOVERY_SATURATED`。
- 研究队列含 `137` 条 route research rows，`actionable_route_count = 0`。
- 能力缺口含 `57` 条 rows，`actionable_capability_count = 0`。
- `16` 条 high-frequency gameplay routes 均完成深研。
- `16/16` 个域均为 `actual_reverse_engineering_executed = true`、`evidence_exhausted = true`、`new_actionable_hypotheses = false`。
- 七项饱和检查全部 `PASS`：高频路由、高价值域、候选收敛、外部证据边界、无本地高优先级 unknown、回归、无静默 fallback/discard。
- 最终 closure 聚焦检查为 `37/37 PASS`；闭合 `49` 个 active capability gaps 与全部 `16` 个域。

域级计数如下。`structural`、`semantic`、`candidate`、`unknown` 是饱和报告的研究计数，不应相加为互斥分类；其中 `semantic` 也不自动等于公开发布权限。

| Domain | Routes | Packets | Structural | Semantic | Candidate | Unknown | Capability gaps |
|---|---:|---:|---:|---:|---:|---:|---:|
| state | 8 | 76,597 | 1 | 1 | 5 | 2 | 12 |
| combat | 14 | 624,203 | 7 | 7 | 7 | 0 | 6 |
| protection | 0 | 0 | 0 | 0 | 0 | 0 | 6 |
| buff | 8 | 335,718 | 5 | 5 | 3 | 0 | 2 |
| spell | 16 | 166,126 | 3 | 2 | 14 | 0 | 8 |
| missile | 8 | 208,579 | 0 | 0 | 8 | 0 | 1 |
| entity | 11 | 57,965 | 0 | 0 | 6 | 5 | 3 |
| item | 0 | 0 | 0 | 0 | 0 | 0 | 6 |
| economy | 21 | 572,692 | 6 | 6 | 14 | 1 | 2 |
| minion | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| jungle | 0 | 0 | 0 | 0 | 0 | 0 | 3 |
| objective | 1 | 4,111 | 0 | 0 | 1 | 0 | 1 |
| structure | 2 | 43 | 0 | 0 | 2 | 0 | 1 |
| vision | 5 | 2,422,990 | 2 | 1 | 3 | 1 | 3 |
| movement | 8 | 407,956 | 3 | 3 | 5 | 0 | 1 |
| map | 0 | 0 | 0 | 0 | 0 | 0 | 1 |

域表覆盖 `102` 条研究路由、`4,876,980` 个已观察包。表中的零路由域表示研究队列没有把路由直接归入该域，并不证明 replay 中没有相关包；例如 item-family 路由归入 `economy`，protection 语义则由组合事件流发布。

公开能力表当前有 `79` 条记录：`PASS 22`、`PARTIAL 7`、`CANDIDATE_ONLY 3`、`UNAVAILABLE 46`、`UNVERIFIED 1`；证据级别为 `VERIFIED_DIRECT 24`、`VERIFIED_DERIVED 5`、`CANDIDATE 3`、`UNAVAILABLE 46`、`UNVERIFIED 1`。因此公开可用面是 `29` 个 `PASS/PARTIAL` 能力，而不是研究账本中所有 `PROMOTE` 项。三层 release 信号必须分别读取：capability manifest 的 `release_status = SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL`，build `support_level = DEEP_SEMANTIC_READY`，downstream gate 为 `RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`；其中 `PARTIAL` 明确禁止把 79 项描述成全部语义可用。

物化完整性：`artifact_manifest.json` 自身排除，只封装队列与饱和报告；最终 queue SHA-256 为 `078e4fbe486c6c321b47621339a83a01c84e901af4b681000ac1ad5460e5f33d`（`byte_count = 256550`），saturation SHA-256 为 `2c473a18841d2c82b78d13ee2d677924d3add410727ad918e2373d3df6e1d0f7`（`byte_count = 15954`）。最终 closure SHA-256 为 `fed274955e1501b381669282dc53cd71eda97740adbb88bfa106f9a883764877`，decision ledger SHA-256 为 `fb6c968b970c4e076525a1a25af8889b78f1fcc80c0c16977ab94e917702e14c`，decision-ledger manifest SHA-256 为 `da9689d80a9b35ba9b30a574dea28138a88a63c8874fa4b60a7c4062d1a8993f`。外层 deep-recovery artifact manifest SHA-256 为 `d7ba8f1c22847faca3c4d5f40f8e5a0a6087be5051997252565e6c99c24ca2e4`。

## C. HERO STATE

已发布：`HERO_PATH`、`LEVEL_TRANSITION`、`HERO_DEATH`、`HERO_DEATH_TIMER`、`HERO_RESPAWN`。

- `0x0074` 发布死亡倒计时语义。
- `0x0265 PKT_HeroReincarnateAlive_s` 发布复活发生与协议坐标：`282/282` 行完整消费，`282` 个复活路由事件与 `301` 个死亡中的 `282` 个唯一匹配；其余 `19` 个死亡均为参与者最终死亡，未伪造复活。
- `0x0265` 的 `x/z` 只是协议坐标。已观察两组出生位置，但不得把它们提升为地图真值或战略标签。
- 复活包的 neutral scalar 在 `274/282` 行与相邻 power-max floor 一致，但存在 Yone 等反例，因此仍是研究候选，不发布字段角色。
- `HERO_DEATH` 可发布直接 killer 字段；这不等于 `HERO_KILL_CREDIT`，后者仍不可用。

未恢复并保持不可用：current/max HP、armor、magic resist、attack damage、ability power、move/attack speed、current/max mana、temporary HP、temporary stats 以及持续性的英雄资源状态。

研究结论：`0x0412`、`0x00dd` 只有中性字段布局；`0x01dc` 为 empty/zero vectors；`0x03dc` 是历史 stat-stone；`0x00d2` 是 health-bar visibility；`0x02cf` 是 nonhero presentation ticks；`0x010c` 是 scoreboard keyframe；`0x0345` 在有界语料中为 NPC-only；`0x02d4` 是辅助 bitpacked batch；`0x0474` 为 champion-specific。它们均不足以发布持续英雄状态。

## D. DAMAGE

`0x017f PKT_UnitApplyDamage_s` 已发布 `DAMAGE` 与 `DAMAGE_TYPE`：当前四局 exact-build replay 的 `266,332/266,332` 行均完整消费，直接保留时间、source entity、target entity、amount 和 type code。

damage type 的独立锚点验证为 `6/6`：physical `2`、magic `2`、true `2`，无类型不匹配。另一个受控验证集解码 `7,934` 行、建立 `75` 个 DETAILS 锚点，最终选择的六个一一对应样本中，记录 amount 与 DETAILS 四舍五入分量的平均绝对残差为 `0.2681`、最大 `0.4388`。

严格边界：amount 的语义阶段仍未知，不能命名为 pre-mitigation、post-mitigation 或 effective HP loss；`DAMAGE_STAGE` 与 `DAMAGE_MITIGATION` 仍不可用。未恢复 current HP，故不能计算有效生命损失或用差分反推减伤。

## E. DEFENSE

没有已发布的持续防御状态。`ARMOR`、`MAGIC_RESIST`、temporary defensive stats、damage mitigation 均为 `UNAVAILABLE`。本地邻域、scoreboard keyframe、历史 stat-stone 与 champion/NPC 专属路由均不能形成可靠的当前防御时间序列。

研究上已否决“把高频标量或中性结构字段直接命名为 armor/MR”的做法。没有独立真值和同步状态链时，相关字段只能保持 neutral、candidate 或 reject，不能进入 canonical API。

## F. SHIELD / HEAL

已发布：

- `SHIELD_GENERATED`：`0x0371` 内 `0x00ed` receive/application 事件共 `1,107` 行；每行均有一个 byte-identical `0x00ee` grant duplicate。canonical 仅保留 receive/application，在严格重复配对门下抑制重复 grant。
- `HEAL_REPORTED`：`0x0371` 内 `0x004b` 共 `28,404` 行，发布 source、target 和 reported/gross amount。参与者汇总中 `37/40` 在 SUMMARY totalHeal 的 `10%` 内，`40/40` 在 `25%` 内。

未发布：shield absorbed、shield remaining、shield lifecycle、effective heal、overheal。shield amount 只表示生成/应用量；heal amount 只表示 reported/gross，不能改名为实际生效治疗。

## G. BUFF

`BUFF` 以 `PARTIAL` 发布，精确操作族为：`0x0326 add`、`0x0123 update-count`、`0x041f update-counter`、`0x043c replace`、`0x045b remove`。四局语料共 `354,854/354,854` 行 native full-consume。

公开字段仅限精确操作、routing entity、slot/index，以及存在时的稳定 numeric buff identifier。routing entity 不是 gameplay target；未恢复 human-readable buff identity、source causality、通用 stack count、duration 或 expiry。`1,861` 个 first-update 反例否决了把 add 路由的某一字段普遍解释为 stack；keyframe/persistent 行也否决了通用 duration/expiry 命名。`DEBUFF` 仍不可用。

## H. SPELL / MISSILE

`CAST_SPELL` 以 `PARTIAL` 发布：`0x01cf` 有 `21,013/21,013` 行完整消费、`235` 个 numeric spell keys；`19,868` 行可在 `1 ms` 窗口内与 on-event timing 对齐，participant name match `16,439`，保留 `192` 个 mismatch。numeric key 不是人类可读技能身份；target、channel/recast、cast result、missile ownership 与 damage causality 均未发布。

通用 `MISSILE` 能力仍 `UNAVAILABLE`。研究级 `0x008a/0x0135/0x0465/0x02e1/0x02e0` 只能描述 lifecycle association，不能提供通用 missile ID、owner、spell 或 target。

另有两个更窄的已发布协议语义：

- `MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT`（`0x03d4`，`PASS`）：语料 `85,503` 行，当前只观察到 `count = 1`，不得外推更大值。
- `ABILITY_COOLDOWN_BROADCAST`（`0x00b8`，`PARTIAL`）：发布 subject、time、spell slot key 和 neutral numeric fields；四个 f32 不命名为 start/end/duration/current cooldown。

P7 研究波次另将 `0x04ce StartSpellTargeter`、`0x046e AddSpellModifier`、`0x00fc MissileScriptTrigger` 等精确结构标为 research-only；其名称来自回调/注册结构，不构成目标、归属或因果语义。

## I. DAMAGE ATTRIBUTION

`DAMAGE_SOURCE_ATTRIBUTION` 仅以 `PARTIAL` 发布：`0x017f` 直接 source entity 可用；仅当 source 落在精确 champion network-id 范围时才派生 participant。未识别的数字字段保持原值，非英雄 source 保持 `UNKNOWN_ENTITY`。

尚不能把伤害归因到 basic attack、spell、item、rune 或 passive。cast→damage 的 exact key/source/time union 命中率仅 `31.05%`；反向 damage→cast 命中率仅 `5.71%`，不足以建立因果链。`0x0199` 是负对照；`0x0310` 已改作中性 item storage route；“以伤害邻近死亡推断 kill credit”的假设被拒绝。

`HERO_DEATH` 的直接 killer 字段与 gameplay kill-credit 仍必须分开：前者是已验证包字段，后者需要额外语义规则与真值。

## J. ENTITY TAXONOMY

通用 `NPC_CLASSIFICATION`、`NPC_SPAWN`、`NPC_DEATH`、`NPC_DESPAWN` 均未发布。`entity` 域在饱和报告中有 `11` 条路由、`57,965` 个包，其中 `6` 条候选、`5` 条 unknown；这些计数代表研究覆盖，不代表可公开的实体 taxonomy。

本轮保留了部分专用回调的结构身份，但拒绝从 vtable/consumer 名称、ID 范围或邻近事件推导通用“英雄/小兵/野怪/建筑/目标物”分类。generic normalized entity events 因缺少跨生命周期的直接 runtime surface 而被拒绝；需要新的外部实体类型真值后方可重开。

## K. ITEM

已发布：

- `ITEM_STATE`（`PARTIAL`）：`0x0311` broadcast snapshot `1,425` 行中 `1,271` 行完整消费、`154` 行显式失败；`0x02ea` map-view snapshot `299/299`；`0x006c` special-slot set `53/53`。只对成功行发布 item ID、slot、stack；失败行与原始计数完整保留。
- `ITEM_SWAP`（`0x01e8`，`PASS`）：`258/258`，两个 slot 均落在 `0..5`；路由自身没有 item identity。
- `ITEM_SUBSTITUTION_MAP`（`0x005a`，`PASS`）：`8/8`，只观察到 `1001→2422` 与 `2420→2421` 两种映射；map update 不等于 inventory transform。
- `SUPPORT_QUEST_ITEM_STAGE`（`0x0064` 有界子集，`PASS`）：仅发布 canonical ten-row groups 与 utility participants `5/10`；`16/16` 阶段转换对齐，`18,944` 个 residual rows 保持未分类。

`0x0137` 和 `0x04b3` 是 transition carriers，不是通用 buy/sell 路由：前者 `1,601` 行，仅 `1,154` 个 DETAILS purchase 匹配且有 `447` extras、`14` misses；后者 `1,013` 行，全部 `60` 个 DETAILS sales 对齐但还有 `953` 个 non-sale rows。因此 `ITEM_BUY`、`ITEM_SELL` 仍为 `CANDIDATE_ONLY`，不会发出 canonical ItemEvent。

其他边界：`0x0310` 的 `17,802/17,802` 中性值不普遍命名为 charges；`0x041b` 只形成 item `2138/2139/2140` 的 purchase-miss 候选；`ITEM_UNDO` 的 `52/52` snapshot 邻接和 `51/52` direction 只形成派生候选，并有 `3363` logical 对 `3340` physical 的残差；`ITEM_TRANSFORM`、`ITEM_DESTROY`、`ITEM_UNDO` 均未发布。

item-family 饱和审计保持 extras 守恒且双射：`447` 个 add extras 中只有 `48` 个 time-zero cause-bounded，另 `399` 个 cause opaque；`953` 个 remove extras 虽有结构分类，但 cause 均 opaque，且 `837` 个完整、`116` 个不完整。当前本地无法再分割。

## L. ECONOMY

已发布：

- `XP`（`PASS`）：`0x010c` scoreboard keyframe 的 cumulative raw XP；`1,390/1,390` 完整消费且 `floor(raw)` 与 DETAILS 一致。约 `60 s` cadence 不提供精确 XP 事件时间。
- `CS`（`PARTIAL`）：只发布 cumulative lane minions killed；`1,390/1,390` 与 DETAILS 一致。jungle CS 与 combined CS 不可用。

`GOLD` 为 `CANDIDATE_ONLY`：候选字段 `floor` 对 DETAILS 为 `1,389/1,390`，保留的一处反例是 game `11191336852` participant `4`、`2220711 ms`：raw `20593.97265625` 对 DETAILS `20591`。current gold、spend、passive income 与 transaction deltas 均不可用。

物品 buy/sell 不能用作经济事件，snapshot 也不能反推交易原因。`economy` 域的 `21` 条路由与 `572,692` 个包中，只有明确发布的 bounded fields 可供消费者使用。

## M. MINION

`LANE_MINION_LIFECYCLE` 以及通用 NPC spawn/death/despawn 均不可用。已发布的 `BASIC_ATTACK_POSITION_MINION`（`0x01b5`，`PASS`）只提供 subject、time、直接 target entity 与二分量 position；四局中有 `52,986` 行，`571` 个分层 native 样本完整消费。

该回调描述 attack-position 协议，不是 hit、damage、kill、spawn 或 minion lifecycle。多数样本并不在 `10 ms` 内邻近 Damage，这一负证据禁止把它改名为攻击命中事件。

## N. JUNGLE

`JUNGLE_MONSTER_LIFECYCLE`、`CAMP_CLEAR`、`CAMP_STATE` 均为 `UNAVAILABLE`。`CS` 中的 jungle score 候选只有 `1,375/1,390` floor matches，未发布；任何 generic NPC、damage 或 position 邻域都不能替代野怪身份、营地成员关系或清营状态。

当前结论完全来自允许的公开/本地安全制品与能力表。本轮没有接触受保护 holdout；因此也没有用其内容支持、反驳或校准任何 jungle 语义。

## O. OBJECTIVES

公开 `OBJECTIVE` 能力为 `UNAVAILABLE`。饱和报告的 objective 域只有 `1` 条候选路由、`4,111` 个包、`1` 个能力缺口；这是研究候选计数，不是 objective spawn、state、kill、owner、timer 或 reward 的已发布语义。

本地没有独立 objective identity / lifecycle 真值，故无法把 generic NPC、building、damage/death 邻域或路线名称提升为目标物事件。域闭包只表示当前安全证据已经穷尽。

## P. STRUCTURES

公开 `STRUCTURE` 能力仍为 `UNAVAILABLE`。structure 域观察到 `2` 条候选、`43` 个包。

P7 研究级结构结果：

- `0x011a` turret flags：`30` 行，精确 u32；观察到 bit `0x10`，但没有 subtype、team、lane、location 或 map 语义。
- `0x0433 Building_Die`：`13` 行，只能发布于研究账本中的 occurrence/layout；没有 building subtype、team、map、killer 或 cause。

两者均为 research-only，不进入公开 STRUCTURE API。building-death 的更深身份需要外部 live concrete vtable / labeled runtime surface。

## Q. VISION

已发布 `WARD_SPAWN`（`PASS`）与 `WARD_LIFECYCLE`（`PARTIAL`）。生命周期只对 direct corpse signal 的保守 observed end 生效，`end_reason` 未知；估计结束不会被发出。特殊、地图或未知实体不会被提升为玩家 ward。

`SWEEPER` 是唯一 `UNVERIFIED` 能力：held/trinket state 缺少验证路由，activation、interval、owner、position 均不可用；`UNVERIFIED` 不代表零观察。`VISIBILITY_STATE` 也不可用。

vision 域共 `5` 条路由、`2,422,990` 个包：结构 `2`、语义 `1`、候选 `3`、unknown `1`。这些高频计数不能绕过 ward-specific 发布边界。

## R. MAP MECHANICS

公开 `MAP_MECHANIC` 为 `UNAVAILABLE`，map 域闭包决定为 `REJECT`。解析器不得将协议坐标、route name、wall cache、spawn cluster、turret flags 或 building occurrence 改写为 map truth、lane、base、objective pit、terrain 或战略区域。

`WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT`（`0x0298`，`PASS`）只发布 keyframe cache selector、coordinate pair 与 neutral cache fields：`77,706/77,706` 行均 keyframe-only，`768` 个分层 native 样本完整消费。它不是实时墙体碰撞或地图几何事件。

`FACE_DIRECTION_VECTOR`（`0x01ab`，`PASS`）只表示单位方向向量，不是位置或路径。P7 的 `0x0441 SetMovementDriver` 仅为 research-only 结构语义，也不能推出 dash、knockback、pathing mode 或地图机制。

## S. UNKNOWN ROUTE REDUCTION

最终回写 inventory 仍守恒 `288` 条路由、`7,223,748` 个包：`KNOWN 27 / 1,531,741`，`DECODED 3 / 2,332,337`，`CLASSIFIED 79 / 1,135,531`，`UNKNOWN 179 / 2,224,139`。inventory SHA-256 为 `16bcd31f6540d1ab69bfec75ee53f5ff768e0b370c0ea7c1b9a3ac5f8aba6561`；observed-registry 同步后 `stale_inventory_decode_status_routes = []`，baseline gate 为 `READY`、blocker `0`。`artifact_manifest.json` 固定的 baseline SHA-256 为 `88540a9ac58b929360c7764cd97227293bd4897bd31ed2145242c112a50a823f`、observed registry 为 `e6dd44cc038c254a52ddc16fe6d6a06cd70bb4e072226a5fe6b2312dbf9b6b86`、completeness gate 为 `ed77bf5f8cad3292513d22711379f1c5d034d43701e9ec641629fa7b99f62a0e`。

实际完成的是“语义决策债务”收敛：decision ledger 有 `176` 条 route decisions（`PROMOTE 81`、`REPURPOSE 76`、`KEEP 15`、`REJECT 4`，`172` 个唯一 route decisions 已穷尽）、`199` 条 capability decisions（`PROMOTE 106`、`KEEP 59`、`REPURPOSE 16`、`REJECT 18`，`196` 个唯一 capability decisions 已穷尽），以及 `18` 条 domain decisions（`KEEP 15`、`REPURPOSE 2`、`REJECT 1`，`18` 个唯一 domain decisions 已穷尽）。当前 route queue 为 `137` 行、local actionable 为 `0`。`REPURPOSE` 将错误 gameplay 名称收窄为中性协议用途，`REJECT` 保留负证据，均不等于丢包。

因此，本轮既有 registry 的可审计回写，也有“本地可行动 unknown/candidate = 0”的决策债务闭包；仍不能把剩余 `179` 条 UNKNOWN 宣称为已经获得 gameplay identity。

## T. CLASSIFIED → SEMANTIC PROMOTIONS

公开升格只按 capability manifest 计。当前 exact build 共 `29` 个 `PASS/PARTIAL`；其中 `22` 个唯一能力在 `2026-08-20` 引入或升格：

- hero：`HERO_DEATH`、`HERO_DEATH_TIMER`、`HERO_RESPAWN`；
- combat/protection：`DAMAGE`、`DAMAGE_TYPE`、`DAMAGE_SOURCE_ATTRIBUTION`、`BUFF`、`SHIELD_GENERATED`、`HEAL_REPORTED`；
- spell/movement tail：`CAST_SPELL`、`ABILITY_COOLDOWN_BROADCAST`、`MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT`、`FACE_DIRECTION_VECTOR`、`INSTANT_STOP_ATTACK`、`BASIC_ATTACK_POSITION_MINION`、`WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT`；
- item/economy：`ITEM_STATE`、`ITEM_SWAP`、`ITEM_SUBSTITUTION_MAP`、`SUPPORT_QUEST_ITEM_STAGE`、`XP`、`CS`。

其余已发布能力为既有的 `ROFL_CONTAINER`、`PACKET_FRAMING`、`PARTICIPANT_MAPPING`、`HERO_PATH`、`LEVEL_TRANSITION`、`WARD_SPAWN`、`WARD_LIFECYCLE`。

研究账本另有 `PROMOTE`：route `81`、capability `106`。这些只表示“对某个精确结构/受限研究命题做出正决定”，不自动授权 canonical API。典型 research-only promotions 包括 P7 七条结构路由：`StartSpellTargeter`、`SetMovementDriver`、`AddFakeBuffs`、`AddSpellModifier`、`MissileScriptTrigger`、turret flags、`Building_Die`。它们仍保持中性字段和外部证据门。

典型 `REPURPOSE`：`0x0310` 从 charges 假设改为 neutral item storage；keyframe snapshot 从 live mutation 改为 snapshot-only；wall route 从实时 map mechanic 改为 component cache snapshot；routing entity 与 gameplay target 分离。

## U. NEGATIVE EVIDENCE

decision ledger 汇总 `269` 条 negative-evidence statements；这类反例与成功解码同等进入闭包。关键负证据包括：

- `0x017f` amount 阶段未知；无 current HP，不能推导 effective loss 或 mitigation。
- cast→damage `31.05%`、damage→cast `5.71%`，否决通用技能伤害归因。
- buff first-update 反例 `1,861`，否决通用 stack；keyframe/persistent 行否决通用 duration。
- `0x0137` 有 `447` extras 与 `14` purchase misses；`0x04b3` 有 `953` non-sale，否决整路由 buy/sell 命名。
- gold `1,389/1,390` 且保留一处不匹配，禁止发布。
- inventory snapshot 有 `154` 个显式 full-consume failures；它们被守恒保留，不能静默丢弃。
- `0x0310` 数值、`0x0405` group/cooldown adjacency、`0x0199` 负对照均不足以支持先前 gameplay 名称。
- `0x0298` 全部 keyframe-only，否决 live wall-collision 解释。
- structure/objective/NPC 的 route/vtable 邻域不足以建立 subtype、team、map、killer 或 cause。

全局门确认 exact-build registry 守恒，无静默 fallback、无静默 discard。`UNAVAILABLE` 只表示没有恢复出 exact-build verified replay semantic，不证明协议中不存在该能力。

## V. MANUAL VALIDATION NEEDED

当前发布与饱和闭包的 release-blocking manual validation 数量为 `0`；不需要再对同一批本地 bytes 做人工猜名才能成立。以下五项仅是未来收到独立外部真值后可执行的高信息量盲审 case，不是当前本地任务：

| Replay | Build | Timestamp | Champion/entity | Prediction | What to inspect | Competing hypotheses |
|---|---|---|---|---|---|---|
| `V-01` 外部标注战斗 trace | `16.16.805.0442` | 单次无护盾受击 `T0 ± 2 s` | 固定 armor/MR 英雄 | `0x017f amount` 与某一伤害阶段一一对应 | raw damage、pre/post mitigation、HP delta 的逐帧对齐 | pre-mitigation / post-mitigation / UI-display amount |
| `V-02` 外部标注 protection trace | `16.16.805.0442` | 单次 shield→damage→heal `T0 ± 3 s` | 单英雄、单来源 shield/heal | canonical protection 分类与独立 ledger 一致 | source、target、amount、shield absorb、heal effective/overheal | shield-generated / heal-reported / generic protection update |
| `V-03` 外部标注 buff trace | `16.16.805.0442` | 首次施加及一次刷新 `T0 ± 5 s` | 单英雄、单 buff | 候选字段只在 stack 或 duration 单变量改变时变化 | first update、keyframe、persistent 行的候选标量 | stack / duration / application ordinal / opaque state |
| `V-04` 外部标注 shop trace | `16.16.805.0442` | request→answer→mutation `T0 ± 5 s` | 单英雄 inventory | `0x0137/0x04b3` 的窄事件角色与 mutation 真值一致 | item id、slot、count、gold、undo/transform 标签 | buy / sell / generic answer / destroy / transform |
| `V-05` 外部标注 respawn trace | `16.16.805.0442` | `0x0265` 前后 `T0 ± 2 s` | Yone 与一个非 Yone 对照英雄 | neutral scalar 是否跨英雄遵循同一投影 | scalar、power-max floor、spawn coordinates、hero identity | stable property projection / champion-specific branch / opaque scalar |

## W. NEW REPLAY NEEDED

当前饱和状态所需新 replay 数量为 `0`；所有本地可执行研究已经闭包。若要扩展能力面，只接受治理批准、带独立标签的外部新证据。五项 controlled-replay 请求规格如下；它们不是对当前本地 corpus 的继续扫描：

| Replay | Build | Timestamp | Champion/entity | Prediction | What to inspect | Competing hypotheses |
|---|---|---|---|---|---|---|
| `W-01 HP/Armor/MR calibration` | `16.16.805.0442` | 每次属性阶跃 `T0 ± 3 s` | 同一英雄，逐次只改 HP/armor/MR 一项 | 持续状态候选会随唯一自变量稳定迁移 | current/max HP、resource、armor、MR、temporary HP/stats | direct state field / derived display field / unrelated scalar |
| `W-02 spell–missile causality` | `16.16.805.0442` | cast、spawn、hit 各 `±2 s` | 单施法者、单目标、单弹道技能 | owner/target/ability 链在重复试验中保持一致 | cast id、spell identity、missile id、owner、target、hit、damage | causal chain / temporal adjacency / routing-entity alias |
| `W-03 entity lifecycle calibration` | `16.16.805.0442` | spawn→update→death/despawn 全程 | 各一个 minion、jungle NPC、generic entity | concrete runtime type 可稳定拆分 generic entity 流 | type/vtable、network id、spawn、death、despawn、camp membership | concrete subtype / generic wrapper / recycled identifier |
| `W-04 objective/structure calibration` | `16.16.805.0442` | spawn/activation/damage/death `±5 s` | 一个 objective 与一座 structure | `0x011a/0x0433` 只在独立标签支持时获得窄身份 | concrete building/object type、team、killer、cause、flags | objective/structure subtype / generic building event / cache state |
| `W-05 sweeper/vision calibration` | `16.16.805.0442` | activation→reveal→expiry `T0 ± 5 s` | 单英雄、单 sweeper、单 ward | sweeper 事件可与 owner/position/visibility state 唯一对齐 | activation、owner、position、reveal state、ward lifecycle | sweeper semantic / generic vision update / proximity correlation |

## X. REGRESSION

研究级深层输出制品 `artifacts/full_semantic_deep_recovery_v2/regression/semantic_api_smoke_11191203388.json` 为 `PASS`；build `support_level = DEEP_SEMANTIC_READY`，downstream gate 为 `RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`。样例 replay `11191203388` 的主要输出计数：path packets `41,252` / path events `47,665`；level `142/142`；damage `59,160`；death `96`；death timer `96`；respawn route/hero/canonical `91/91/91`；buff `72,605`；cast `5,772`；protection route `7,296`、canonical `6,263`、unclassified `879`；item route `41,424`、support quest stage `6,574`、materializer pending `4,350`。

gameplay tail canonical total 为 `106,298`：ability cooldown `16,817`、basic attack position minion `11,584`、face direction `21,376`、instant stop attack `21,935`、missile movement complete `18,824`、wall tracking cache `15,762`。所有命名 gate 均为 true。

全套 baseline attestation：`PASS`，`433` tests、`432` passed、`0` failed、`1` skipped；npm `378/378`，V3 沿用既有 `37/38`（含 `1` 项治理性 skip），V4 `17/17`。attestation SHA-256 为 `3362106eb81a9e179e550b198dd9745458a92c43bab43b08939a2a6009343e5c`。legacy `verify-v2` 本轮未运行，因为该脚本硬编码了受保护 Holdout 路径；执行它会越过本轮证据边界。严格 public semantic API smoke 实际执行并为 `PASS`，SHA-256 `af921648eda875a32da4973258d90601d7d6b1aff9aa168d21006644548c5507`。inventory/baseline 定向测试另为 `9/9` PASS，stale routes 为 `0`。skip 不被伪装成通过，且没有访问受保护边界。

## Y. PATCH MIGRATION IMPACT

迁移事实来自 `migration_16_15_to_16_16_deep_semantics.json`：previous `16.15.801.3452` → current `16.16.805.0442`，status `MIGRATION_ANALYSIS_COMPLETE`。两份迁移制品内容一致，SHA-256 均为 `bd91c59d8272649016ff855a01a6cfdfdfa41957d2b81fa77ecf30ee28a5f3f5`。路由面 previous `296`、current `288`：`NEW_PACKET 219`、`PAYLOAD_SHAPE_CHANGED 69`、`REMOVED_PACKET 227`；守恒关系为 previous `69 + 227 = 296`、current `69 + 219 = 288`。

能力迁移状态：`UNCHANGED_VERIFIED 2`、`ROUTE_MOVED 12`、`FIELD_SHIFT 15`、`NEEDS_REVALIDATION 4`、`SEMANTIC_CHANGED 0`、`UNKNOWN 0`、`UNSUPPORTED 46`。四个需重验证能力是 `GOLD`、`ITEM_BUY`、`ITEM_SELL`、`SWEEPER`，它们在当前构建分别保持 candidate/unverified，而不是通过旧构建 fallback 发布。

`HERO_RESPAWN` 与六条 gameplay tail 能力——`ABILITY_COOLDOWN_BROADCAST`、`BASIC_ATTACK_POSITION_MINION`、`FACE_DIRECTION_VECTOR`、`INSTANT_STOP_ATTACK`、`MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT`、`WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT`——均从旧构建 `UNAVAILABLE` 迁为 16.16 的 `FIELD_SHIFT`，并由 exact route/profile 直接验证。这是精确构建迁移结果，不赋予旧构建同名路由兼容性。

迁移结论：16.15 的数值 route identity、payload offsets 和局部 decoder 不能直接沿用；当前 API 只允许 manifest 中 `16.16.805.0442` 的 exact-build profile。不存在 nearest-build silent fallback。

## Z. REMAINING ACTIONABLE HYPOTHESES

```text
CURRENT_LOCAL_ACTIONABLE_HYPOTHESES = 0
ACTIONABLE_ROUTE_COUNT = 0
ACTIONABLE_CAPABILITY_COUNT = 0
```

以下仅是“获得外部新证据后才可重开”的 hypotheses；它们都没有当前本地动作：

1. **英雄持续状态**：外部 sub-second runtime state/telemetry 可验证 current/max HP、资源、防御与临时属性字段；没有该真值时保持 unavailable。
2. **伤害阶段与减伤**：外部同步的 pre-mitigation、post-mitigation、HP delta、shield/mitigation ledger 可命名 `0x017f amount` 的阶段；现有 replay 不能区分。
3. **技能、Buff 与导弹因果**：外部受控单技能/单 buff trace，含 spell identity、owner、target、stack、duration、missile lifecycle 与 damage causality，才可消除邻域歧义。
4. **通用实体 taxonomy**：外部 live concrete runtime type / vtable surface 与完整生命周期标签，才可把 generic entity 事件分类为 hero/minion/jungle/structure/objective。
5. **物品交易与原因**：外部 shop request/answer、完整 mutation trace、undo 标签及 exact-build item recipe graph，才可区分 buy/sell/undo/transform/destroy；现有 extras 不能本地再分割。
6. **小兵与野区生命周期**：外部带 identity、spawn/death/despawn、camp membership 与 clear/state 标签的 trace，才可建立 minion/jungle semantics。
7. **目标物与建筑**：外部 labeled objective/structure runtime trace 与 concrete building type，才可赋予 `0x011a/0x0433` subtype、team、lane/map、killer/cause。
8. **视野与扫描**：外部 sweeper activation、owner、position、visibility-state 标签，才可从 `UNVERIFIED` 升格。
9. **地图机制**：外部权威 map/mechanic truth 与同步 runtime trace，才可把坐标/cache/flags 连接到地图语义；解析器自身不得推断。
10. **稀有分支**：外部针对 `0x0265` neutral scalar、`0x03d4 count > 1` 及 P7 稀有路由的受控触发 trace，才可验证当前未命名字段。

在这些外部证据出现之前，继续扫描、相关性排序、重复反汇编或人工猜名不会改变本轮闭包。最终结论保持：`SEMANTIC_RECOVERY_SATURATED`。
