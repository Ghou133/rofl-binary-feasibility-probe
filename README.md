# ROFL Analyzer

精确版本绑定的《英雄联盟》`.rofl` 回放研究工具：解析容器和数据包，输出带来源、证据等级和明确边界的语义事实。

> **当前开发分支：16.19。** `codex/16-19-development` 已获授权继续适配、接通 CLI/API 并研究新字段。`16.19.820.7193` 与 `16.19.821.7343` 的死亡候选输出仍是实验结果，不是已发布的可靠语义能力。2026-08-21 的公开语义基线及 `SOURCE_FROZEN_DURING_MIGRATION` 记录保留为历史状态；本分支不覆盖旧版证据。

[使用与维护](docs/PUBLIC_DEVELOPMENT.md) · [代码结构](ARCHITECTURE.md) · [路线图](ROADMAP.md) · [历史验证记录](VALIDATION_STATUS.md) · [AI 接手入口](AI_HANDOFF.md)

## 能力与入口

**项目库支持的字段，不等于主 CLI 已经接入的字段。** 本仓库不是通用回放查看器，也不会对未知补丁回退使用邻近版本的 opcode、RVA 或字段布局。

| 入口 / 层 | 当前提供 | 使用边界 |
| --- | --- | --- |
| `inspect` / `src/rofl.js` | RIOT 头、metadata、chunk/Zstd、packet framing、原始清单与锚点 | 容器结构可解析，不代表该版本语义已验证 |
| `capabilities` | 从回放容器读取完整 build，查询已登记能力、入口及尾部字段输入预检 | 不解压 packet、不运行语义解码；候选能力仍需逐回放校验 |
| `decode` / `analyze` / `batch` / `validate` | `16.15.801.3452` 旧版整合管线；16.19 精确 build 的指定能力实验入口 | 16.19 必须显式传 `--events`；16.16 语义 API 尚未由主 CLI 分发；`validate` 还会运行完整 Node 套件 |
| `16.19.820.7193 --events hero_death` | HN/KR 结构指纹与回放尾部死亡总数同时匹配时，输出候选受害者和回放时间 | 仅写入 `hero_death_candidates`，状态为 `CANDIDATE`；无杀手、助攻或重生推断，其他完整 build 不复用 |
| `16.19.821.7343 --events hero_death` | KR `0x0259/0x0438/0x031b` 同刻路由与十名参与者回放尾部死亡数均匹配时，输出候选受害者和时间；精确 821 运行时变换还从 `0x0438` 解出来源 ID | 仅写入 `hero_death_candidates`，状态为 `CANDIDATE`；653 个英雄来源 ID 的计数与 110 人的击杀结算一致时才输出 `killer_participant_id_candidate`，2 个非英雄来源只保留原 ID。孤立 `0x0259` 不输出；单次助攻候选在独立入口，确认的死亡语义仍未知 |
| `16.19.821.7343 --events hero_assist` | 在已校验的死亡核心旁配对两种同参与者、同时间的 `0x040a/44` 包，并与十人 `ASSISTS` 结算核对，输出每次死亡的候选助攻参与者列表 | 仅写入 `hero_assist_candidates`，状态为 `CANDIDATE`；两个非英雄来源的列表保持未知；不把孤立或单一形状 `0x040a` 解释为助攻，也不声称已确定回调字段名称 |
| `16.19.821.7343 --events hero_respawn` | KR `0x0048` 经精确 821 运行时确认为 `PKT_HeroReincarnateAlive_s` 路由；解出两项浮点值和一项可选浮点值，并与候选死亡核心、结算 `TOTAL_TIME_SPENT_DEAD` 对照 | 仅写入 `hero_respawn_candidates`，状态为 `CANDIDATE`；浮点值的游戏含义和回调的具体状态效果未确定。同刻 `0x018d` 实为库存 MapView 结构指纹；保留时间差、未返回的末次死亡与额外库存包，不以计时值预测返回 |
| `16.19.821.7343 --events hero_death_timer` | KR `0x0259` 五字节载荷经精确 821 镜像反序列化与浮点变换，655 个已匹配死亡核心输出候选计时秒数；两包孤立 `0x0259` 排除 | 仅写入 `hero_death_timer_candidates`，状态为 `CANDIDATE`；607 次观察到的返回中有两次显著早于计时值，故不将计时值当作返回预测；48 个末次未返回计时越过回放结束 |
| `16.19.821.7343 --events hero_deaths_snapshot` | KR `0x0089` 关键帧字节 1182 与精确 821 镜像中的计数字节变换相符，输出候选累计死亡次数快照 | 仅写入 `hero_deaths_snapshot_candidates`；末帧与结算可差 1 并保留差值；不是逐次死亡事件。精确镜像已验证完整载荷和字节向量，字段语义仍为候选 |
| `16.19.821.7343 --events hero_champion_kills_snapshot` | KR `0x0089` 关键帧原始字节 434/1186 镜像，并按精确 821 镜像的计数字节变换输出候选累计英雄击杀数快照 | 仅写入 `hero_champion_kills_snapshot_candidates`；旧有限编码表以外的高值已可解，字段语义仍为候选；保留结算差值，不推断击杀时点或击杀者 |
| `16.19.821.7343 --events hero_assists_snapshot` | KR `0x0089` 关键帧原始字节 1178 按精确 821 镜像的计数字节变换输出候选累计助攻数快照 | 仅写入 `hero_assists_snapshot_candidates`；五份回放中旧编码表无法识别的高值已可解，字段语义仍为候选；不推断单次助攻或参与者关系 |
| `16.19.821.7343 --events hero_kill_stats_snapshot` | 精确 821 原生 `0x0089` 向量偏移 `0x58..0x6c` 的六项累计击杀统计候选；11 份回放共 3,270 条快照 | 仅写入 `hero_kill_stats_snapshot_candidates`，状态为 `CANDIDATE`；保留逐字段结算尾差，不推断逐次击杀；四杀仅一名玩家有正值，证据稀疏 |
| `16.19.821.7343 --events hero_missions_minions_killed_snapshot` | KR `0x0089` 关键帧按精确 821 镜像的字节变换解出字节 374/373 的低位和高位候选计数；字节 372/371 解出为零 | 仅写入 `hero_missions_minions_killed_snapshot_candidates`；与结算数值字段 `Missions_MinionsKilled` 对照，不将其标为标准 `MINIONS_KILLED`；保留尾部差值，不推导逐次补刀或完整 HeroStats 载荷 |
| `16.19.821.7343 --events hero_ward_stats_snapshot` | KR `0x0089` 关键帧字节 834/838/842 经精确 821 计数字节变换得到探测守卫、拆眼和插眼累计候选值；11 份回放共 3,270 个快照 | 仅写入 `hero_ward_stats_snapshot_candidates`，状态为 `CANDIDATE`；三项结算尾部差值保留，不推导守卫事件或位置；字段语义仍为候选 |
| `16.19.821.7343 --events hero_missions_cannon_minions_killed_snapshot` | 同一关键帧字节 450 经精确 821 变换得到 `Missions_CannonMinionsKilled` 累计候选值；11 份回放共 3,270 个快照 | 仅写入 `hero_missions_cannon_minions_killed_snapshot_candidates`，状态为 `CANDIDATE`；不标为普通补刀或逐次炮车击杀；保留结算差值，字段语义仍为候选 |
| `16.19.821.7343 --events hero_minions_killed_snapshot` | 精确 821 原生 `0x0089` 向量偏移 `0x3c` 的 `f32LE` 候选累计标准补刀数；11 份回放共 3,270 个快照，末帧 73/110 人与 `MINIONS_KILLED` 结算相等 | 仅写入 `hero_minions_killed_snapshot_candidates`，状态为 `CANDIDATE`；与偏移 `0x378` 的 `Missions_MinionsKilled` 区分，保留尾部差值，不推导逐次补刀或目标 |
| `16.19.821.7343 --events hero_jungle_minions_killed_snapshot` | 精确 821 原生 `0x0089` 向量偏移 `0x40/0x44/0x48` 的三项野怪计数候选浮点快照；11 份回放共 3,270 条 | 仅写入 `hero_jungle_minions_killed_snapshot_candidates`，状态为 `CANDIDATE`；保留原始小数、取整值及三项结算尾差，不推断逐次击杀、野怪类型或位置 |
| `16.19.821.7343 --events hero_experience_snapshot` | `0x0089` 关键帧反向字节向量的 `0x28` 浮点候选经验值；11 份回放共 3,270 个快照 | 仅写入 `hero_experience_snapshot_candidates`；保留与 `EXP` 结算的尾部差值，不推导升级阈值或经验来源 |
| `16.19.821.7343 --events hero_vision_score_snapshot` | 同一向量 `0x1b0` 浮点候选视野分；11 份回放的 110 人均从零开始并不超过各自结算值 | 仅写入 `hero_vision_score_snapshot_candidates`；不推导守卫、探测或视野行为 |
| `16.19.821.7343 --events hero_gold_earned_snapshot` | 同一向量 `0x38` 浮点候选已赚金币；110 人首帧均为 500，序列单调且在 `GOLD_EARNED` 结算内 | 仅写入 `hero_gold_earned_snapshot_candidates`；末帧均落后于结算并保留差额，不推导收入事件 |
| `16.19.821.7343 --events hero_gold_spent_snapshot` | 同一向量 `0x34` 浮点候选已花金币；末帧 92/110 人与 `GOLD_SPENT` 结算相等 | 仅写入 `hero_gold_spent_snapshot_candidates`；保留一次观察到的下降，不推导购买、退款或出售 |
| `16.19.821.7343 --events hero_damage_totals_snapshot` | 同一原生向量 `0x1e0/0x1d0/0x1f0` 的候选对英雄伤害、总伤害和承伤累计浮点快照 | 仅写入 `hero_damage_totals_snapshot_candidates`；逐项保留结算尾差，不推导单次伤害、来源或目标 |
| `16.19.821.7343 --events hero_damage_taken_from_champions_snapshot` | 同一原生向量 `0x200` 的候选对英雄承伤累计浮点快照 | 仅写入 `hero_damage_taken_from_champions_snapshot_candidates`；不推导逐次伤害或来源 |
| `16.19.821.7343 --events hero_damage_self_mitigated_snapshot` | 同一原生向量 `0x208` 的候选自我减伤累计浮点快照 | 仅写入 `hero_damage_self_mitigated_snapshot_candidates`；不推导减伤行为或来源 |
| `16.19.821.7343 --events hero_longest_living_time_snapshot` | 同一原生向量 `0x244` 的候选最长存活时间浮点快照；末帧 109/110 人与结算取整值一致 | 仅写入 `hero_longest_living_time_snapshot_candidates`；保留一个 426 秒尾差，不推断单次存活区间 |
| `16.19.821.7343 --events hero_total_time_spent_dead_snapshot` | 同一原生向量 `0x248` 的候选累计死亡时间浮点快照；末帧 94/110 人与结算取整值一致 | 仅写入 `hero_total_time_spent_dead_snapshot_candidates`；不推断单次死亡时长或复活时点 |
| `16.19.821.7343 --events hero_total_heal_snapshot` | 同一原生向量 `0x234` 的候选累计治疗上报值；末帧 57/110 人与结算一致 | 仅写入 `hero_total_heal_snapshot_candidates`；不推断有效治疗、过量治疗、来源或目标 |
| `16.19.821.7343 --events hero_total_units_healed_snapshot` | 同一原生向量 `0x23c` 的候选累计被治疗单位数；末帧 109/110 人与结算一致 | 仅写入 `hero_total_units_healed_snapshot_candidates`；不推断单次治疗或受治疗者 |
| `16.19.821.7343 --events hero_epic_monster_damage_snapshot` | 同一原生向量 `0x21c` 的候选史诗野怪伤害累计浮点快照；末帧取整值与结算 110/110 一致 | 仅写入 `hero_epic_monster_damage_snapshot_candidates`；不推断具体目标或单次伤害 |
| `16.19.821.7343 --events hero_crowd_control_time_snapshot` | 同一原生向量 `0x230` 的候选对英雄控制时间累计浮点快照；末帧 59/110 人与结算取整值一致 | 仅写入 `hero_crowd_control_time_snapshot_candidates`；不推断单位、控制技能、目标或单次控制事件 |
| `16.19.821.7343 --events hero_structure_objective_damage_snapshot` | 同一原生向量 `0x210/0x214` 的相同建筑类伤害候选值，以及 `0x218` 的目标伤害候选值；末帧各有 82/110 人与结算取整值一致 | 仅写入 `hero_structure_objective_damage_snapshot_candidates`；11 份回放中建筑与防御塔结算均相同，不能区分两个镜像槽位的语义；保留尾差，不推断单次伤害或目标 |
| `16.19.821.7343 --events hero_level_state` | KR `0x0197` 精确 821 运行时解码器及查表变换输出观察到的候选等级值，覆盖等级 1–20 | 仅写入 `hero_level_state_candidates`；覆盖 1,613 个选定英雄包的 76 种载荷形状经完整消费验证，重复观测与一个中间等级缺口保留；参与者映射仍是候选，不补造升级事件 |
| `16.19.821.7343 --events hero_inventory_packet --runtime-image PATH` | 精确 821 镜像原生反序列化 KR `0x018d` MapView，逐包输出候选槽位与物品 ID 记录，以及回调先清空再应用记录所得的 0–9 槽单包候选快照 | 仅写入 `hero_inventory_packet_candidates`；无记录的槽位为 `null` 并注明回调清空依据；不推断购买、出售或包间持续库存状态；额外原始参数变体不映射参与者 |
| `16.19.821.7343 --events hero_inventory_broadcast_packet --runtime-image PATH` | 精确 821 镜像原生反序列化 KR `0x0357` Broadcast，逐包输出候选槽位与物品 ID 记录及 0–9 槽单包候选快照 | 仅写入 `hero_inventory_broadcast_packet_candidates`；包内物品 `0` 与未列出的 `null` 槽位分开保留；不推断购买、出售或包间持续库存状态；非典型原始参数不映射参与者 |
| `16.19.821.7343 --events hero_inventory_set_item_packet --runtime-image PATH` | 精确 821 镜像原生反序列化 KR `0x002d` SetItem，输出单包候选槽位和物品键及原始包来源 | 仅写入 `hero_inventory_set_item_packet_candidates`；当前 11 份回放只观察到候选槽位 8；不推断购买、出售、替换或包间库存状态 |
| `16.19.821.7343 --events params_heal_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` OnEvent 的注册子事件 `0x004b` ParamsHeal，输出处理函数读取的候选上报浮点值、两个匿名整数和原始包来源 | 仅写入 `params_heal_packet_candidates`，状态为 `CANDIDATE`；不推断有效治疗量、施法者或目标；与同路由的 44 字节助攻候选包分别计数 |
| `16.19.821.7343 --events shielding_params_packet_pair --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x00f0/0x00ef` 两种 ShieldingParams 子包，以相同时间和载荷形成候选配对，保留两包来源、匿名整数和不透明浮点字段 | 仅写入 `shielding_params_packet_pair_candidates`，状态为 `CANDIDATE`；不把浮点字段解释为生成或吸收的护盾量，也不推断施加者或接收者 |
| `16.19.821.7343 --events stealth_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0101/0x0102` 子包，保留镜像事件名表中的 OnEnterStealth/OnExitStealth 标签、匿名 `+0x04` 整数和原始包来源 | 仅写入 `stealth_event_packet_candidates`，状态为 `CANDIDATE`；同长度其他子事件明确排除，不推断参与者、实际可见性变化或隐身持续状态 |
| `16.19.821.7343 --events champion_die_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0004` 子包，保留 OnChampionDie 镜像名表标签、回调读取的匿名 `+0x04` 整数和原始包来源 | 仅写入 `champion_die_event_packet_candidates`，状态为 `CANDIDATE`；排除同长度其他子事件，不推断实际死亡、受害者、击杀者或状态变化 |
| `16.19.821.7343 --events champion_kill_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0007` 子包，保留 OnChampionKill 镜像名表标签、回调读取的匿名 `+0x04/+0x58/+0x5c` 整数和原始包来源 | 仅写入 `champion_kill_event_packet_candidates`，状态为 `CANDIDATE`；排除同长度其他子事件，不推断实际击杀、击杀者、受害者或状态变化 |
| `16.19.821.7343 --events cast_spell_ans_packet --runtime-image PATH` | 精确 821 镜像原生完整消费 KR `0x01da` CastSpellAns 包，输出原始包来源、两个回调变换后的不透明字段，以及嵌套对象 `+0xe0` 的受保护浮点与 `+0x140` 的受保护字节候选值及其原始字节 | 仅写入 `cast_spell_ans_packet_candidates`；不声称一次成功施法，也不推断技能、槽位、施法者、目标或这两个字段的游戏含义；镜像按完整 SHA-256 校验 |
| `16.19.821.7343 --events direct_input_movement_turn_packet --runtime-image PATH` | 精确 821 镜像原生完整消费 KR `0x00ba` DirectInputMovementDriverServerTurnData 包，输出三个回调变换后的匿名 f32 字段与原始包来源 | 仅写入 `direct_input_movement_turn_packet_candidates`，状态为 `CANDIDATE`；不将字段标为世界坐标、英雄路径或参与者位置；仅接受已观察到的 13 字节 `0x85` 形状 |
| `16.19.821.7343 --events set_movement_driver_packet --runtime-image PATH` | 精确 821 镜像原生完整消费 KR `0x0335` SetMovementDriver 包，输出回调变换后的匿名分发字节和原始包来源 | 仅写入 `set_movement_driver_packet_candidates`，状态为 `CANDIDATE`；不声称驱动状态已改变，也不推断位置、路径或参与者；仅接受两种已观察到的包形状 |
| `16.19.821.7343 --events npc_buff_add_packet,npc_buff_remove_packet --runtime-image PATH` | 分别解码 KR `0x00ae/0x047c` 原生包，并在两项均成功时汇总相同不透明 `(u32, u8)` 键的重合与时序歧义 | 逐包候选分别写入两个 JSONL；`candidate_associations.npc_buff_add_remove_opaque_key` 仅含回放内统计，不配对单个包，不推断 Buff 名称、归属或生命周期 |
| `16.19.820.7193 --events hero_death_timer` | HN 路由的计时 float、同刻 Hero_Die 和后续复活时间相互校验时，输出候选计时秒数 | 仅写入 `hero_death_timer_candidates`；该 profile 仅用于 820 HN 路由，821 KR 使用独立精确版本的候选 profile；不产生确认的死亡或重生事件 |
| `16.19.820.7193 --events hero_respawn` | 将 HN 已观察且与计时包唯一配对的 `0x0357` 包输出为候选复活时点 | 仅写入 `hero_respawn_candidates`；依赖完整的 HN 计时候选校验，不补造回放结束后的复活 |
| `16.19.820.7193 --events hero_level_state` | HN `0x02b3` 包中观察到的候选英雄等级值及原始包来源 | 仅写入 `hero_level_state_candidates`；同等级的独立包保留为重复观测，不补造升级事件；KR 路由未适配 |
| `16.19.820.7193 --events hero_minions_killed_snapshot` | HN `0x0276` HeroStats keyframe 中已观察到的候选 `MINIONS_KILLED` 数值 | 仅写入 `hero_minions_killed_snapshot_candidates`；不是连续补刀事件，尾部差额不插值；KR 同号包不匹配 HN 指纹 |
| `16.19.820.7193 --events hero_jungle_minions_killed_snapshot` | 同一 HN keyframe 中 `0x40/0x44/0x48` 的原始浮点值及向下取整后的中立野怪总数、己方野区和敌方野区候选快照 | 仅写入 `hero_jungle_minions_killed_snapshot_candidates`；一场回放的尾部相关性，不推导逐次清野事件 |
| `16.19.820.7193 --events hero_kill_stats_snapshot` | 同一 HN keyframe 中已观察到的最大连杀、连杀次数、最大多杀及双杀至四杀计数候选快照 | 仅写入 `hero_kill_stats_snapshot_candidates`；六项尾部相关性来自一场回放，不推导击杀事件或时间 |
| `16.19.820.7193 --events hero_ward_stats_snapshot` | 同一 HN keyframe 中已观察到的插眼、拆眼与探测守卫计数候选快照 | 仅写入 `hero_ward_stats_snapshot_candidates`；不推导守卫生成、位置、生命周期或拆除事件 |
| `16.19.820.7193 --events hero_damage_totals_snapshot` | 同一 HN keyframe 中三处浮点值及其向下取整值，对应英雄伤害、总伤害与承伤的候选累计快照 | 仅写入 `hero_damage_totals_snapshot_candidates`；一场回放的尾部相关性，不推导逐次伤害、目标、来源或减伤 |
| `16.19.820.7193 --events hero_damage_taken_from_champions_snapshot` | HN HeroStats keyframe `0x200` 的原始浮点值及取整后的候选对英雄承伤快照 | 仅写入 `hero_damage_taken_from_champions_snapshot_candidates`；尾部相关性不证明逐次伤害或来源 |
| `16.19.820.7193 --events hero_damage_self_mitigated_snapshot` | HN HeroStats keyframe `0x208` 的原始浮点值及取整后的候选自我减伤快照 | 仅写入 `hero_damage_self_mitigated_snapshot_candidates`；不推导逐次减伤事件 |
| `16.19.820.7193 --events hero_longest_living_time_snapshot` | HN HeroStats keyframe `0x244` 的原始浮点值及取整后的候选最长存活时间快照 | 仅写入 `hero_longest_living_time_snapshot_candidates`；三场尾部对照为 10/10、10/10、9/10，不推导单次存活或死亡时长 |
| `16.19.820.7193 --events hero_total_time_spent_dead_snapshot` | HN HeroStats keyframe `0x248` 的原始浮点值及取整后的候选累计死亡时间快照 | 仅写入 `hero_total_time_spent_dead_snapshot_candidates`；三场尾部相关性仍为候选，不推导逐次死亡时长 |
| `16.19.820.7193 --events hero_total_heal_snapshot` | 同一 HN keyframe 中 `0x234` 的候选累计治疗上报值 | 仅写入 `hero_total_heal_snapshot_candidates`；一场回放的尾部相关性，不推导逐次治疗、有效治疗或过量治疗 |
| `16.19.820.7193 --events hero_total_units_healed_snapshot` | HN HeroStats keyframe `0x23c` 的原始 u32 候选治疗单位计数快照 | 仅写入 `hero_total_units_healed_snapshot_candidates`；多数尾部值为 1，参与者映射仍为候选，不推导逐次治疗或目标 |
| `16.19.820.7193 --events hero_vision_score_snapshot` | 同一 HN keyframe 中 `0x1b0` 原始浮点值及取整后的候选视野得分 | 仅写入 `hero_vision_score_snapshot_candidates`；一场回放的尾部相关性，不推导守卫或视野事件 |
| `16.19.820.7193 --events hero_epic_monster_damage_snapshot` | 同一 HN keyframe 中 `0x21c` 原始浮点值及取整后的候选史诗野怪伤害累计值 | 仅写入 `hero_epic_monster_damage_snapshot_candidates`；一场回放的尾部相关性，不推导逐次伤害或目标归属 |
| `16.19.820.7193 --events hero_crowd_control_time_snapshot` | 同一 HN keyframe 中 `0x230` 原始浮点值及取整后的候选英雄控制时长累计快照 | 仅写入 `hero_crowd_control_time_snapshot_candidates`；一场回放的结算栏相关性，不推导逐次控制、目标或来源 |
| `16.19.820.7193 --events hero_structure_objective_damage_snapshot` | 同一 HN keyframe 中 `0x210/0x214` 镜像值和 `0x218` 原始浮点值及取整后的候选结构/目标伤害累计快照 | 仅写入 `hero_structure_objective_damage_snapshot_candidates`；BUILDINGS/TURRETS 在该场回放无法区分，`0x218` 与已有史诗野怪字段存在算术依赖，不推导逐次伤害或目标身份 |
| `16.19.820.7193 --events hero_experience_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x28` 浮点候选经验值 | 仅写入 `hero_experience_snapshot_candidates`；小数及尾部差额保留，不推导升级或经验获取时点；KR 的 HN profile 不可用 |
| `16.19.820.7193 --events hero_gold_earned_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x38` 浮点候选已赚金币值 | 仅写入 `hero_gold_earned_snapshot_candidates`；一场 HN 回放的字段相关性，不推导金币收入事件；KR 的 HN profile 不可用 |
| `16.19.820.7193 --events hero_gold_spent_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x34` 候选已花金币值 | 仅写入 `hero_gold_spent_snapshot_candidates`；保留数值下降，不推导退款、出售或购买；KR 的 HN profile 不可用 |
| `16.19.820.7193 --events hero_champion_kills_snapshot` | 同一 HN HeroStats keyframe 中两处镜像值一致的候选英雄击杀数 | 仅写入 `hero_champion_kills_snapshot_candidates`；`0x4c` 与 `0x33c` 尚未确定唯一存储位置，不推导逐次击杀事件 |
| `16.19.820.7193 --events hero_deaths_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x50` 候选死亡次数 | 仅写入 `hero_deaths_snapshot_candidates`；与本回放死亡候选累计数吻合，不推导新的死亡事件或时间 |
| `16.19.820.7193 --events hero_assists_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x54` 候选助攻次数 | 仅写入 `hero_assists_snapshot_candidates`；缺少独立助攻事件锚点，不推导助攻时点或归属 |
| `16.19.820.7193 --events hero_inventory_mapview` | 使用精确运行时镜像解码 HN `0x0420` 包中已观察到的候选物品槽与物品 ID | 仅写入 `hero_inventory_mapview_candidates`；不构造连续库存状态、购买或出售事件；其他路由不可复用 |
| `16.19.820.7193 --events hero_inventory_set_item` | 使用精确运行时镜像解码 HN `0x03b7` SetItem 包中的候选槽位与物品键 | 仅写入 `hero_inventory_set_item_candidates`；其中一个非标准 raw param 不映射参与者，不推导买卖或物品变化 |
| `16.19.820.7193 --events hero_inventory_broadcast` | 使用精确运行时镜像解码 HN `0x03ef` Broadcast 包中的候选槽位、物品键和有界参与者映射 | 仅写入 `hero_inventory_broadcast_candidates`；三场回放仍只支持候选参与者映射，flag 3 含义未分类，不推导买卖、交换或库存变化 |
| `16.19.820.7193 --events npc_buff_remove_packet` | 使用精确运行时镜像解码 HN `0x043c` BuffRemove2 包中的候选浮点秒数、槽索引与查找令牌 | 仅写入 `npc_buff_remove_packet_candidates`；保留原始参数与包来源，不推断 Buff 归属、名称或移除成功 |
| `16.19.820.7193 --events npc_buff_add_packet` | 使用精确运行时镜像解码 HN `0x03ed` BuffAdd2 包中 game/keyframe 均有的候选原始标量；已观察到的 41 字节 keyframe 另带不透明向量标记 | 仅写入 `npc_buff_add_packet_candidates`；两个浮点字段只按偏移命名，不推断持续时间、Buff 归属或应用成功 |
| `src/semantic_api.js` 与精确 build profiles | `16.16.805.0442` 的 HeroPath、等级、WardSpawn、伤害、死亡、重生、XP/lane-CS keyframe、受限 ItemState 和 gameplay-tail 等 | 独立 API 的逐字段能力；需要外部精确镜像、profiles 或对应已验证输入，不是主 CLI 的完整分析模式 |
| V2 Ward / Path | 已验证位置、守卫事件及受限派生关联 | 来源 SHA 必须与回放一致；类型、匹配、生命周期和位置插值与直接字段分级 |
| `research-v3/`、`research-v4/` | DuckDB 研究查询、保护量增量表和验证器 | 保留的真实功能，不是因版本号旧就可删除的目录；全量重建需要私有输入 |

各版本都保留“直接、派生、部分、候选、不可用”的区别。完整 Cast/Buff/Protection、CurrentHP、当前 Armor/MR、护盾实例与剩余量、effective heal/overheal、逐次普通野怪清野等能力不能从现有有限字段外推。`stats_at` / `statsAt` 有逐字段 fail-closed 接口，但当前不发布 MaxHP/Armor/MR 数值；库存部分状态不是通用买卖事件。

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

查询该回放完整版本的能力和缺少的输入：

```powershell
node src/cli.js capabilities "D:\Replays\example-16.19.820.7193.rofl"
node src/cli.js capabilities "D:\Replays\example-16.19.820.7193.rofl" --json
```

查询只读容器、metadata、chunk 描述和精确 build 注册表，不遍历 packet；`--json`
输出逐能力状态、所需输入、已知缺项以及尚待运行的校验；16.19 还检查尾部十名参与者的
`NUM_DEATHS` 或 `LEVEL` 是否齐备且在候选范围内。16.19 列出精确
build 注册表中的候选能力；MapView 和 SetItem 物品槽候选额外要求显式指定精确运行时镜像，
查询只检查文件是否存在，镜像哈希和包解码留待实际运行；查询不是成功解码证明。
16.15/16.16 的外部文件仅按完整管线入口做存在性预检；单项能力的依赖和
镜像哈希仍标记为未核验。

对完整版本为 **16.19.820.7193** 的回放运行实验死亡候选解码：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.820.7193.rofl" `
  --events hero_death --out-dir "work\16-19-death-candidate"
```

`semantic_run.json` 逐能力记录实际执行、候选、缺输入、不支持和失败；
`hero_death_candidates.jsonl` 只在结构指纹与死亡总数校验均通过时产生。
`inspect` 不要求镜像或语义 profile。死亡候选没有使用运行时镜像，传入镜像路径不会使其成为已验证语义。

完整 build 为 **16.19.821.7343** 的 KR 回放使用同一入口，但采用独立的 821 路由配置：

```powershell
node src/cli.js capabilities "D:\Replays\example-16.19.821.7343.rofl" --json
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events hero_death --out-dir "work\16-19-821-death-candidate"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events params_heal_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-heal-report"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events shielding_params_packet_pair `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-shield-reports"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events stealth_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-stealth-reports"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events champion_die_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-champion-die-reports"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events champion_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-champion-kill-reports"
```

821 的候选死亡记录保留原始包来源及未配对路由的负例计数。该 build 的运行时镜像已从真实回放进程捕获；当前死亡包的计时浮点和 Hero_Die 来源 ID 均有独立候选解码，单次助攻候选在 `hero_assist` 入口。可追加 `hero_assist,hero_respawn,hero_death_timer,hero_deaths_snapshot,hero_champion_kills_snapshot,hero_assists_snapshot,hero_missions_minions_killed_snapshot,hero_ward_stats_snapshot,hero_missions_cannon_minions_killed_snapshot,hero_experience_snapshot,hero_vision_score_snapshot,hero_gold_earned_snapshot,hero_gold_spent_snapshot,hero_damage_totals_snapshot,hero_damage_taken_from_champions_snapshot,hero_damage_self_mitigated_snapshot,hero_structure_objective_damage_snapshot,hero_longest_living_time_snapshot,hero_total_time_spent_dead_snapshot,hero_total_heal_snapshot,hero_total_units_healed_snapshot,hero_epic_monster_damage_snapshot,hero_crowd_control_time_snapshot,hero_level_state` 到 `--events`；计数、浮点、计时和等级使用已固定的精确镜像变换，CLI 运行时无需再次提供镜像。库存 `hero_inventory_packet`、广播包 `hero_inventory_broadcast_packet`、单包 `hero_inventory_set_item_packet`、治疗上报包 `params_heal_packet`、护盾配对包 `shielding_params_packet_pair`、隐身名表子包 `stealth_event_packet`、CastSpellAns 包 `cast_spell_ans_packet`、DirectInput turn 包 `direct_input_movement_turn_packet` 和 SetMovementDriver 包 `set_movement_driver_packet` 需要 `--runtime-image` 指向同一完整 build 的镜像。各能力独立报告状态；载荷形状超出已验证范围、解码值违反参与者结算上界等情况仍会保留其他已通过能力的候选输出，并明确标出失败项。11 份现有 KR 回放中的等级 20 和高击杀/助攻编码均已被相应变换覆盖。计时值不用于预测返回时点。

对 HN 路由的同一完整 build，可单独选择计时候选，或用
`--events hero_death,hero_death_timer` 一起运行。计时输出包含原始包引用、
候选参与者、解出的秒数，以及存在匹配时的复活包引用；它要求十名参与者的死亡总数、
同刻 Hero_Die 配对及复活时序都通过校验。未执行的旧版事件汇总计数为
`null`，不会把未解码误写成零事件。

在 820 HN 路由中，`--events hero_respawn` 可单独查询已观察到的候选复活时点，也可与计时候选
同时选择。输出按复活包时间排序，保留复活、计时和 Hero_Die 的原始包引用；
它复用计时能力的配对校验，不产生已确认的 `respawn_events`。

对 HN 路由可单独运行 `--events hero_level_state`，也可与上述候选能力组合。
输出中的 `level_after_candidate` 是已观察到的等级字段，`missing_level_updates`
列出该回放里没有对应包的等级；它不是完整的升级时间线，也不会写入已确认的
`level_transition_events`。该候选只绑定完整 build `16.19.820.7193`。

`batch` 可接收回放文件或目录，并逐回放保存能力结果。例如：

```powershell
node src/cli.js batch "D:\Replays\HN-example.rofl" "D:\Replays\KR-example.rofl" `
  --events hero_death,hero_respawn,hero_level_state --out-dir "work\16-19-batch"
```

有能力不可用的回放会保留已成功的候选输出，汇总状态为 `PARTIAL`。

只读取已观察到的 HN HeroStats keyframe 候选快照：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.820.7193.rofl" `
  --events hero_damage_self_mitigated_snapshot,hero_longest_living_time_snapshot,hero_total_time_spent_dead_snapshot,hero_total_units_healed_snapshot `
  --out-dir "work\16-19-hero-stats-snapshots"
```

输出包含每名英雄的候选快照值与原始包引用，并在逐能力结果中列出最后快照到回放尾部的差额。
它不推导两次 keyframe 之间的变化或单次事件，也不发布为确认事件；其他候选快照可由 `capabilities` 查询后加入 `--events`。

读取 HN `0x0420` MapView、`0x03b7` SetItem 与 `0x03ef` Broadcast 包内已观察到的候选槽位和物品键，需提供精确版本的外部运行时镜像：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.820.7193.rofl" `
  --events hero_inventory_mapview,hero_inventory_set_item,hero_inventory_broadcast `
  --runtime-image "D:\PrivateInputs\league_16.19.820.7193.memory.bin" `
  --out-dir "work\16-19-mapview-candidates"
```

每条记录保留原始包来源；这三项候选不要求回放尾部 `statsJson`，也不推导库存状态或交易事件。Broadcast 仅对十个常规原始参数和已观察到的两个变体给出参与者候选；其他参数保留空值。三场回放的尾部对照仍不足以确认包归属。

BuffAdd2 与 BuffRemove2 的包字段候选使用相同的精确镜像参数，可单独或一起运行：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.820.7193.rofl" `
  --events npc_buff_add_packet,npc_buff_remove_packet `
  --runtime-image "D:\PrivateInputs\league_16.19.820.7193.memory.bin" `
  --out-dir "work\16-19-buff-remove-candidates"
```

大量 Buff 包的 JSONL 逐行保留候选状态和原始包来源；共用的字段置信度与限制说明写在同目录的 `semantic_run.json` 对应能力结果中。

16.19 `decode` 或 `batch` 使用 `--events` 时，可额外指定 `--event-jsonl-only` 减少大量事件的重复输出。此模式仍写入每项事件的完整 JSONL、`semantic_run.json` 和各报告；`replay_analysis.json` 中的 `events` 为 `null`，同时记录 `event_storage: "JSONL_ONLY"`、`event_jsonl_files` 相对路径与 `event_counts`，不生成重复的 `events.json`。输出 manifest 只散列实际生成的文件。默认模式保持原有三份事件输出；此选项不适用于 `inspect`、旧版回放或未指定 `--events` 的调用。

对已解码的 821 库存包按物品 ID 查询单包记录：

```powershell
node src/cli.js query-events "work\16-19-821-inventory\replays\KR_example" `
  --event hero_inventory_packet_candidates --item-id 3340 --limit 20
```

`--item-id` 接受十进制或 `0x` 十六进制 uint32，只匹配 821 MapView/Broadcast 当包 `records_candidate[].item_id_candidate` 或 SetItem 当包 `item_id_candidate`，不查询回调空槽、包间库存或买卖事件。Broadcast 中解出的物品 `0` 可以精确查询；当前 SetItem 样本只观察到正值。输出仍是未修改的原始 JSONL 行；汇总中的 `item_id_unavailable_count` 区分字段不可用与已检查后的零命中。其他事件流不能使用此过滤器。

对 821 治疗上报或护盾双包中的匿名整数精确查询：

```powershell
node src/cli.js query-events "work\16-19-821-heal-report\replays\KR_example" `
  --event params_heal_packet_candidates --opaque-u32 0x400000b3 --limit 20
```

`--opaque-u32` 同时支持 `shielding_params_packet_pair_candidates` 和 `stealth_event_packet_candidates`，匹配各记录中已解码的匿名 u32 字段；它不使用外层 `raw_param` 代替字段，也不赋予治疗者、受治疗者、施盾者、隐身参与者或目标角色。十进制、十六进制和 `0` 均可精确查询；汇总保留字段不可用数与已检查后的零命中。

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

`examples/level_transitions.js` 也是 **16.15** 管线示例，不是 16.16 通用入口。16.16 的能力和依赖应从 `src/semantic_api.js` 及 [新版本手册](docs/ROFL_NEW_BUILD_PLAYBOOK.md) 核对。16.19 的实验入口只运行指定能力，不把 16.16 解码器用于 16.19。

## 命令与输出

`16.15` 的 `decode` 与 `analyze` 共用旧管线。`16.19` 通过精确 build API 执行 `--events` 指定的实验能力；`capabilities` 可先查询精确 build 和外部输入缺项，不会创建输出目录。`batch` 逐回放记录成功、候选和失败，不以某项成功掩盖另一项失败。`validate` 额外运行完整 Node 回归，可用 `--details-dir` 做验证对照；Match Details 不进入解码规则。

默认时间线保留前 `--timeline-limit` 条。`--sample-stride` 仅为兼容旧命令保留，已弃用且不改变输出；不再计算最终会被截掉的间隔样本。

主要产物包括 `replay_analysis.json`、容器与 packet 清单、时间线样本、原始锚点、各事件 JSONL 和 ADC 死亡窗口；V2 输入提供对应 Ward/position 数据。每条事实保留适用的回放 SHA、packet/offset/hash、版本和证据等级。没有执行语义解码时，报告不会把静态能力表或空事件数组说成已验证结果。

默认不输出 Riot ID / PUUID；`--include-private-metadata` 只用于显式本地需求，不应用于外发数据。分析产物仍可能包含本地路径、回放身份和原始包摘录，不能将“省略玩家字段”等同于可直接公开。外部文件运行前后监测可通过 `ROFL_UPSTREAM_PATHS` 配置。

## 验证与打包

| 命令 | 范围 / 输入 |
| --- | --- |
| `npm test` / `npm run test:public` | portable、维护及 16.19 合成解码/CLI 测试；不需要私有回放 |
| `npm run test:16-19` | 当前 16.19 候选解码、独立能力和 CLI/API 合成测试；不等于真实回放验证 |
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
src/cli.js              16.15 旧版 CLI 与 16.19 精确 build 选项分发
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
