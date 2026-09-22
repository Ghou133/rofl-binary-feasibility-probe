# 开发路线与待补全项

更新：2026-09-23。这里描述的是后续工作入口和验收条件，不表示任务已实施。当前仓库状态为 `SOURCE_FROZEN_DURING_MIGRATION`；长期开发进入 `lol-inference-lab/replay/`，本仓库保留为可比较的源码快照。任何跨项目接口、能力等级或资产状态变更先按 V2 架构门禁处理。

## 当前基线

1. 容器、chunk 解压、packet framing 与原始清单已实现；语义能力只对精确注册的 build 开放。
2. `16.15.801.3452` 有冻结的旧版语义 profile。`16.16.805.0442` 的 resolver 是 `DEEP_SEMANTIC_READY`，manifest 状态为 `SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL`；这是**逐字段部分覆盖**。
3. `16.16` 的 latest-four baseline 对 288 条 route、7,223,748 个 packet 完成守恒；27 registered、3 decoded、79 classified、179 unknown。`READY` 是清单完整性，`SEMANTIC_RECOVERY_SATURATED` 是现有本地安全证据耗尽，均非 `FULLY_PARSED`。
4. V3/V4 的 10/14 场统计是历史 attestation；公开源码没有原始 Replay、镜像、数据库或全量 JSONL，不能在干净克隆上重建这些统计。

更细的字段状态和反例见 [README.md](README.md)、[VALIDATION_STATUS.md](VALIDATION_STATUS.md)、[docs/ROFL_CAPABILITY_MATRIX.md](docs/ROFL_CAPABILITY_MATRIX.md) 与 [AI_HANDOFF.md](AI_HANDOFF.md)。

## 待实施的路线

| 顺序 | 待做工作 | 当前障碍或未实施部分 | 完成条件 |
| --- | --- | --- | --- |
| 1. 迁移守恒 | 在 `lol-inference-lab/replay/` 收敛 parser 源码、测试、profiles、manifest、负例与证据引用；把历史 V3/V4 研究层交给相应下游所有者 | 源仓库仍冻结，不能凭复制文件宣称迁移完成 | 文件/哈希/接口逐项对应，回归和差异检查通过，失败证据保留；然后才按治理决定是否标记源仓库为归档 |
| 2. 可移植开发体验 | 补足公开克隆可运行的合成 fixtures、缺输入提示、跨平台脚本和精简入口 | 私有回放/运行时镜像缺席时，大量 exact-build 端到端验证不可执行；部分脚本是 Windows 研究工具 | `test:portable` 和 V3/V4 单元测试在干净环境通过；私有输入测试准确 skip 或 fail closed，不伪造通过；命令文档与实际参数一致 |
| 3. 新 build 迁移 | 按 [新版本手册](docs/ROFL_NEW_BUILD_PLAYBOOK.md) 收集有授权的精确版本输入，执行格式、结构、语义三级门禁 | 未为任意新 build 证明 route、runtime image、字段和负例；不能复制 16.15/16.16 profile | 构建注册、SHA 与语义 fingerprint/ground truth/negative controls、精确 build 回归通过；自动优先，人工仅处理自动证据未解决的最小能力 |
| 4. 16.16 语义缺口 | 仅针对新证据可区分的 CastSpell、Buff、Protection、item 交易、stat/战斗状态和 Sweeper 问题重开研究 | 现有局部证据已饱和；多个字段仍为 partial、candidate 或 unavailable | 每个晋级字段都有原始 packet/runtime 绑定、独立锚点、反例消除、精确 build 回归、能力登记；不满足则保持 null/UNKNOWN |
| 5. V3/V4 可重复发布 | 若获授权数据，重跑全量 backfill，并为 V4 扩展数据库建立统一原子 manifest | 公开仓库没有 10/14 场语料、镜像、完整事件流；旧 V3 manifest 只覆盖冻结 V3 表面 | 输入来源与 SHA、逐表/逐文件守恒、fresh verifier、V4 扩展整体 manifest 与数据库哈希相互对应 |

## 具体未解决问题

- **战斗状态**：CurrentHP、当前 MaxHP/Armor/MR、减抗/穿透及运算顺序、伤害 amount 所处阶段和技能/普攻/item/rune/passive 归因没有可发布闭包。`stats_at` 是真实接口，但输入缺失时逐字段返回 `null`。
- **治疗与护盾**：reported heal 不能分成 raw/effective/overheal；target-total shield absorbed 不能分配给施法者或护盾实例；剩余量、消耗顺序、生命周期没有证据。
- **物品与记分板**：ItemState/swap/substitution 是受限状态事实；通用 buy/sell/undo/use 事件未证明。约 60 秒的 XP/lane-CS 是累计 keyframe，total gold/jungle CS 仍是候选，current gold 不可用。
- **视野与路径**：Ward lifecycle 部分可用；移除原因/击杀者未知。位置插值不是逐帧地图真值。Sweeper held 未验证、activation 不可用。
- **覆盖范围**：普通野怪/camp clear 直接事件未恢复，Cast/Buff/Protection 仍有未命名字段。未注册 build 的语义输出应拒绝，而非邻版回退。
- **工程优化**：清理历史研究脚本的私有输入依赖，完善 CLI 命令的端到端覆盖、可移植 fixtures、错误诊断和跨平台运行；不得用测试数量替代真实回放证明。

## 研究方法与停止条件

每项新能力先列出字段、候选假设、需要的独立可观测量和负控，再在合法取得的精确 build 输入上验证。Match Details 只用于独立校验，不生成 Replay 事实。失败和歧义保留原记录；没有区分能力的新输入时停止局部研究，不把 `EVIDENCE_EXHAUSTED` 改写成全局不可能。

本路线不包含地图知识、行为推断、离线语料收集、Akari 在线获取/缓存/状态或 UI。这些任务由其所属项目负责，下游使用本项目已发布的语义接口。
