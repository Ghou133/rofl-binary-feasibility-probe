# ROFL Analyzer

精确版本绑定的《英雄联盟》`.rofl` 回放研究工具：解析容器和数据包，输出带来源、证据等级和明确边界的语义事实。

> **当前开发分支：16.19。** `codex/16-19-development` 已获授权继续适配、接通 CLI/API 并研究新字段。`16.19.820.7193` 与 `16.19.821.7343` 的死亡候选输出仍是实验结果，不是已发布的可靠语义能力。2026-08-21 的公开语义基线及 `SOURCE_FROZEN_DURING_MIGRATION` 记录保留为历史状态；本分支不覆盖旧版证据。

[使用与维护](docs/PUBLIC_DEVELOPMENT.md) · [代码结构](ARCHITECTURE.md) · [路线图](ROADMAP.md) · [历史验证记录](VALIDATION_STATUS.md) · [AI 接手入口](AI_HANDOFF.md)

## 能力与入口

**项目库支持的字段，不等于主 CLI 已经接入的字段。** 本仓库不是通用回放查看器，也不会对未知补丁回退使用邻近版本的 opcode、RVA 或字段布局。

| 入口 / 层 | 当前提供 | 使用边界 |
| --- | --- | --- |
| `inspect` / `src/rofl.js` | RIOT 头、metadata、chunk/Zstd、packet framing、原始清单与锚点 | 容器结构可解析，不代表该版本语义已验证 |
| `capabilities` | 从回放容器读取完整 build，查询已登记能力、入口及输入依赖预检 | 不解压 packet、不运行语义解码；候选能力仍需逐回放校验 |
| `decode` / `analyze` / `batch` / `validate` | `16.15.801.3452` 旧版整合管线；16.19 精确 build 的指定能力实验入口 | 16.19 必须显式传 `--events`；16.16 语义 API 尚未由主 CLI 分发；`validate` 还会运行完整 Node 套件 |
| `16.19.820.7193 --events hero_death` | HN/KR 结构指纹与回放尾部死亡总数同时匹配时，输出候选受害者和回放时间 | 仅写入 `hero_death_candidates`，状态为 `CANDIDATE`；无杀手、助攻或重生推断，其他完整 build 不复用 |
| `16.19.821.7343 --events hero_death` | KR `0x0259/0x0438/0x031b` 同刻路由与十名参与者回放尾部死亡数均匹配时，输出候选受害者和时间；精确 821 运行时变换还从 `0x0438` 解出来源 ID | 仅写入 `hero_death_candidates`，状态为 `CANDIDATE`；653 个英雄来源 ID 的计数与 110 人的击杀结算一致时才输出 `killer_participant_id_candidate`，2 个非英雄来源只保留原 ID。孤立 `0x0259` 不输出；单次助攻候选在独立入口，确认的死亡语义仍未知 |
| `16.19.821.7343 --events hero_assist [--runtime-image PATH]` | 在已校验的死亡核心旁配对两种同参与者、同时间的 `0x040a/44` 包，并与十人 `ASSISTS` 结算核对，输出每次死亡的候选助攻参与者列表；提供同 build 镜像时，还原生核对两种子包 ID `0x0056/0x0057` | 仅写入 `hero_assist_candidates`，状态为 `CANDIDATE`；两个非英雄来源的列表保持未知；孤立或单一形状 `0x040a` 仍被排除；子包身份不证明有效助攻或参与者角色 |
| `16.19.821.7343 --events hero_respawn` | KR `0x0048` 经精确 821 运行时确认为 `PKT_HeroReincarnateAlive_s` 路由；解出两项浮点值和一项可选浮点值，并与候选死亡核心、结算 `TOTAL_TIME_SPENT_DEAD` 对照 | 仅写入 `hero_respawn_candidates`，状态为 `CANDIDATE`；浮点值的游戏含义和回调的具体状态效果未确定。同刻 `0x018d` 实为库存 MapView 结构指纹；保留时间差、未返回的末次死亡与额外库存包，不以计时值预测返回 |
| `16.19.821.7343 --events hero_death_timer` | KR `0x0259` 五字节载荷经精确 821 镜像反序列化与浮点变换，655 个已匹配死亡核心输出候选计时秒数；两包孤立 `0x0259` 排除 | 仅写入 `hero_death_timer_candidates`，状态为 `CANDIDATE`；607 次观察到的返回中有两次显著早于计时值，故不将计时值当作返回预测；48 个末次未返回计时越过回放结束 |
| `16.19.821.7343 --events hero_assist,hero_death_timer,hero_respawn` | 按同一原始 `0x0259` 死亡包引用关联三项独立候选，将受害者、来源、助攻列表、计时值以及观察到的返回或回放结束前未返回状态放入逐次记录 | 另写入 `hero_death_episode_candidates` 和关联状态，仍为 `CANDIDATE`；不以计时值预测返回，也不把参与者映射或游戏效果升级为确认语义 |
| `16.19.821.7343 --events hero_deaths_snapshot` | KR `0x0089` 关键帧字节 1182 与精确 821 镜像中的计数字节变换相符，输出候选累计死亡次数快照 | 仅写入 `hero_deaths_snapshot_candidates`；末帧与结算可差 1 并保留差值；不是逐次死亡事件。精确镜像已验证完整载荷和字节向量，字段语义仍为候选 |
| `16.19.821.7343 --events hero_champion_kills_snapshot` | KR `0x0089` 关键帧原始字节 434/1186 镜像，并按精确 821 镜像的计数字节变换输出候选累计英雄击杀数快照 | 仅写入 `hero_champion_kills_snapshot_candidates`；旧有限编码表以外的高值已可解，字段语义仍为候选；保留结算差值，不推断击杀时点或击杀者 |
| `16.19.821.7343 --events hero_assists_snapshot` | KR `0x0089` 关键帧原始字节 1178 按精确 821 镜像的计数字节变换输出候选累计助攻数快照 | 仅写入 `hero_assists_snapshot_candidates`；五份回放中旧编码表无法识别的高值已可解，字段语义仍为候选；不推断单次助攻或参与者关系 |
| `16.19.821.7343 --events hero_kill_stats_snapshot` | 精确 821 原生 `0x0089` 向量偏移 `0x58..0x6c` 的六项累计击杀统计候选；11 份回放共 3,270 条快照 | 仅写入 `hero_kill_stats_snapshot_candidates`，状态为 `CANDIDATE`；保留逐字段结算尾差，不推断逐次击杀；四杀仅一名玩家有正值，证据稀疏 |
| `16.19.821.7343 --events hero_missions_minions_killed_snapshot` | KR `0x0089` 关键帧按精确 821 镜像的字节变换解出字节 374/373 的低位和高位候选计数；字节 372/371 解出为零 | 仅写入 `hero_missions_minions_killed_snapshot_candidates`；与结算数值字段 `Missions_MinionsKilled` 对照，不将其标为标准 `MINIONS_KILLED`；保留尾部差值，不推导逐次补刀或完整 HeroStats 载荷 |
| `16.19.821.7343 --events hero_ward_stats_snapshot` | KR `0x0089` 关键帧字节 834/838/842 经精确 821 计数字节变换得到探测守卫、拆眼和插眼累计候选值；11 份回放共 3,270 个快照 | 仅写入 `hero_ward_stats_snapshot_candidates`，状态为 `CANDIDATE`；三项结算尾部差值保留，不推导守卫事件或位置；字段语义仍为候选 |
| `16.19.821.7343 --events hero_ward_stats_snapshot,hero_inventory_broadcast_packet --runtime-image PATH` | 按同一关键帧、时间和规范英雄原始参数，将 `0x0089` 眼位累计候选与 `0x0357` 广播包内物品候选一一关联 | 另写入 `ward_inventory_keyframe_pair_candidates`；仅是同帧观察，不推导插眼、物品交易或包间持续状态；游戏流广播单独保留并排除关联 |
| `16.19.821.7343 --events hero_missions_cannon_minions_killed_snapshot` | 同一关键帧字节 450 经精确 821 变换得到 `Missions_CannonMinionsKilled` 累计候选值；11 份回放共 3,270 个快照 | 仅写入 `hero_missions_cannon_minions_killed_snapshot_candidates`，状态为 `CANDIDATE`；不标为普通补刀或逐次炮车击杀；保留结算差值，字段语义仍为候选 |
| `16.19.821.7343 --events hero_minions_killed_snapshot` | 精确 821 原生 `0x0089` 向量偏移 `0x3c` 的 `f32LE` 候选累计标准补刀数；11 份回放共 3,270 个快照，末帧 73/110 人与 `MINIONS_KILLED` 结算相等 | 仅写入 `hero_minions_killed_snapshot_candidates`，状态为 `CANDIDATE`；与偏移 `0x378` 的 `Missions_MinionsKilled` 区分，保留尾部差值，不推导逐次补刀或目标 |
| `16.19.821.7343 --events increment_minion_kills_packet --runtime-image PATH` | 精确 821 镜像原生完整消费游戏流 `0x03a7` IncrementMinionKills 三字节包，解出回调对象查找键，并与回放原始参数逐包核对；现有 11 份回放共 279 包 | 仅写入 `increment_minion_kills_packet_candidates`，状态为 `CANDIDATE`；对象查找和条件写入是否实际发生仍是 `UNKNOWN`，不输出逐次补刀、补刀增量或参与者身份 |
| `16.19.821.7343 --events increment_minion_kills_packet,hero_minions_killed_snapshot --runtime-image PATH` 的关联输出 | 用同一候选原始键将 `0x03a7` 包与相邻 `0x0089` 标准补刀计数快照配对；11 份回放有 278 个严格区间包、1 个关键帧时刻包单列 | 另写入 `increment_minion_keyframe_bracket_candidates`；保留包与两端快照引用和端点差值，不把端点差值归因于单个包，不确认实际补刀或参与者身份 |
| `16.19.821.7343 --events hero_jungle_minions_killed_snapshot` | 精确 821 原生 `0x0089` 向量偏移 `0x40/0x44/0x48` 的三项野怪计数候选浮点快照；11 份回放共 3,270 条 | 仅写入 `hero_jungle_minions_killed_snapshot_candidates`，状态为 `CANDIDATE`；保留原始小数、取整值及三项结算尾差，不推断逐次击杀、野怪类型或位置 |
| `16.19.821.7343 --events hero_experience_snapshot` | `0x0089` 关键帧反向字节向量的 `0x28` 浮点候选经验值；11 份回放共 3,270 个快照 | 写入 `hero_experience_snapshot_candidates`，保留与 `EXP` 结算的尾部差值；不推导升级阈值或经验来源 |
| `16.19.821.7343 --events hero_experience_snapshot` 的派生输出 | 比较同一候选参与者的相邻完整关键帧经验值端点，保留两端原始包引用与浮点、取整差值；11 份回放中 3,160 个区间有 2,931 个上升端点 | 另写入 `experience_keyframe_interval_difference_candidates`；229 个端点相同区间只计数，不推断区间内的经验来源、次数、发生时刻或升级门槛 |
| `16.19.821.7343 --events hero_level_state,hero_experience_snapshot` 的关联输出 | 将同一候选参与者的较高等级包放入两个相邻且完整的经验关键帧时间端点之间；11 份回放有 1,564 条夹持记录，涉及 1,495 个不同的参与者区间 | 另写入 `level_experience_keyframe_bracket_candidates`；每行保留等级包和两端经验包引用。只报告时间及候选参与者一致，不定位经验获取时刻、来源或升级门槛；末帧后的 25 条等级包不插值 |
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
| `16.19.821.7343 --events hero_inventory_broadcast_packet --runtime-image PATH` | 精确 821 镜像原生反序列化 KR `0x0357` Broadcast，逐包输出候选槽位与物品 ID 记录及 0–9 槽单包候选快照 | 来源流写入 `hero_inventory_broadcast_packet_candidates`；包内物品 `0` 与未列出的 `null` 槽位分开保留；不推断购买、出售或包间持续库存状态；非典型原始参数不映射参与者 |
| `16.19.821.7343 --events hero_inventory_broadcast_packet --runtime-image PATH` 的派生输出 | 比较同一候选参与者在相邻完整关键帧的十槽端点观察，列出端点值不同的槽位及两端原始包引用；11 份回放有 1,759 条候选差异 | 另写入 `inventory_keyframe_interval_difference_candidates`；3,160 个区间中 1,401 个端点相同；不推断精确变化时间、买卖、交换、替换事件或区间内持续状态，61 条不完整游戏流广播单独排除 |
| `16.19.821.7343 --events hero_inventory_broadcast_packet --runtime-image PATH` 的游戏流关联 | 将游戏流 `0x0357` 包的明确槽位记录与同一规范原始参数的相邻完整关键帧两端逐槽比较；11 份回放有 55 条严格区间内包、421 条槽位比较 | 另写入 `inventory_game_broadcast_keyframe_bracket_candidates`，保留三份原始包引用和未记录槽位；4 条非规范参数、2 条末帧之后的包保留为排除证据；不推断持续库存、交易或变化时刻 |
| `16.19.821.7343 --events hero_inventory_set_item_packet --runtime-image PATH` | 精确 821 镜像原生反序列化 KR `0x002d` SetItem，输出单包候选槽位和物品键及原始包来源 | 仅写入 `hero_inventory_set_item_packet_candidates`；当前 11 份回放只观察到候选槽位 8；不推断购买、出售、替换或包间库存状态 |
| `16.19.821.7343 --events params_heal_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` OnEvent 的注册子事件 `0x004b` ParamsHeal，输出处理函数读取的候选上报浮点值、两个匿名整数和原始包来源 | 仅写入 `params_heal_packet_candidates`，状态为 `CANDIDATE`；不推断有效治疗量、施法者或目标；与同路由的 44 字节助攻候选包分别计数 |
| `16.19.821.7343 --events shielding_params_packet_pair --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x00f0/0x00ef` 两种 ShieldingParams 子包，以相同时间和载荷形成候选配对，保留两包来源、匿名整数和不透明浮点字段 | 仅写入 `shielding_params_packet_pair_candidates`，状态为 `CANDIDATE`；不把浮点字段解释为生成或吸收的护盾量，也不推断施加者或接收者 |
| `16.19.821.7343 --events stealth_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0101/0x0102` 子包，保留镜像事件名表中的 OnEnterStealth/OnExitStealth 标签、匿名 `+0x04` 整数和原始包来源 | 仅写入 `stealth_event_packet_candidates`，状态为 `CANDIDATE`；同长度其他子事件明确排除，不推断参与者、实际可见性变化或隐身持续状态 |
| `16.19.821.7343 --events champion_die_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0004` 子包，保留 OnChampionDie 镜像名表标签、回调用作对象树查找键的 `+0x04` 整数和原始包来源 | 仅写入 `champion_die_event_packet_candidates`，状态为 `CANDIDATE`；排除同长度其他子事件，不推断实际死亡、对象查找成功、受害者、击杀者或状态变化 |
| `16.19.821.7343 --events champion_kill_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0007` 子包，保留 OnChampionKill 镜像名表标签、回调用作同一对象树查找键的 `+0x04` 及匿名 `+0x58/+0x5c` 整数和原始包来源 | 仅写入 `champion_kill_event_packet_candidates`，状态为 `CANDIDATE`；排除同长度其他子事件，不推断实际击杀、对象查找成功、击杀者、受害者或状态变化 |
| `16.19.821.7343 --events champion_multiple_kill_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0009` 子包，保留 OnChampionMultipleKill 镜像名表标签、作为对象查找键的 `+0x04`、控制 `+0x10` 键数组遍历的 `+0x0c`、原样传入后续虚调用的 `+0x08` 和原始包来源 | 仅写入 `champion_multiple_kill_event_packet_candidates`，状态为 `CANDIDATE`；不把包标记或整数解释为实际多杀、等级、击杀者、受害者或状态变化 |
| `16.19.821.7343 --events champion_double_kill_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x000b` 子包，保留 OnChampionDoubleKill 镜像名表标签、原生子包摘要与原始包来源 | 仅写入 `champion_double_kill_event_packet_candidates`，状态为 `CANDIDATE`；同为 104 字节的其他子事件按原生 ID 排除；不推断实际双杀、回调字段、参与者或状态变化 |
| `16.19.821.7343 --events champion_triple_quadra_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x000c/0x000d` 子包，保留 OnChampionTripleKill/OnChampionQuadraKill 镜像名表标签、原生子包摘要与原始包来源 | 有目标包时写入 `champion_triple_quadra_event_packet_candidates`，状态为 `CANDIDATE`；无目标包时为 `PROFILE_UNAVAILABLE`；不推断实际连续击杀、回调字段、参与者或状态变化 |
| `16.19.821.7343 --events on_shutdown_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x00e8` 子包，保留 OnShutdown 镜像名表标签、匿名 `+0x04/+0x58/+0x5c` 整数和原始包来源 | 仅写入 `on_shutdown_event_packet_candidates`，状态为 `CANDIDATE`；不推断实际 shutdown 效果、对象角色或状态变化 |
| `16.19.821.7343 --events resurrect_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x002d` 子包，保留 OnResurrect 镜像名表标签、匿名原生子包 `+0x04/+0x08` 整数和原始包来源 | 有此包形状的回放写入 `resurrect_event_packet_candidates`，状态为 `CANDIDATE`；无此形状的回放报告 `PROFILE_UNAVAILABLE`；不推断实际复活、对象角色或状态变化 |
| `16.19.821.7343 --events revive_ally_event_packet --runtime-image PATH` | 精确 821 镜像按 SHA-256 校验并完整反序列化 KR `0x040a` 的 `0x002c` 子包，保留 OnReviveAlly 镜像名表标签、匿名原生子包 `+0x04` 整数及原始包来源 | 有目标包时写入 `revive_ally_event_packet_candidates`，状态为 `CANDIDATE`；无目标包时报告 `PROFILE_UNAVAILABLE`；同长度异类子事件保留为排除证据，不推断实际复活、对象角色或状态变化 |
| `16.19.821.7343 --events first_blood_assist_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR game-stream `0x040a` 的 `0x0017` 子包，保留 OnFirstBloodAssist 镜像名表标签、匿名 8 字节子包和原始来源 | 只写入 `first_blood_assist_event_packet_candidates`，状态为 `CANDIDATE`；无目标包为 `PROFILE_UNAVAILABLE`，同长度 `0x002c` 排除；不推断实际首杀、助攻或参与者 |
| `16.19.821.7343 --events objective_steal_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR game-stream `0x040a/133` 的 `0x00be`、`0x00d6` 子包，保留 OnKillDragonSteal/OnKillWormSteal 镜像名表标签、匿名 124 字节子包和原始来源 | 只写入 `objective_steal_event_packet_candidates`，状态为 `CANDIDATE`；无该形状为 `PROFILE_UNAVAILABLE`；11 份回放仅两份各有一个目标包，不推断实际抢夺、目标状态、行动者或游戏效果 |
| `16.19.821.7343 --events turret_plate_event_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0107` 子包，保留 OnTurretPlateDestroyed 镜像名表标签、匿名原生子包 `+0x04` 整数和原始包来源 | 仅写入 `turret_plate_event_packet_candidates`，状态为 `CANDIDATE`；排除同长度其他子事件，不推断镀层破坏、建筑、参与者或状态变化 |
| `16.19.821.7343 --events objective_bounty_claimed_packet --runtime-image PATH` | 精确 821 镜像完整反序列化 KR `0x040a` 的 `0x0113` 子包，保留 OnObjectiveBountyClaimed 镜像名表标签、匿名八字节子包及 `blob_u32_0x04`、原始包来源 | 有目标包时写入 `objective_bounty_claimed_packet_candidates`，状态为 `CANDIDATE`；无目标包时报告 `PROFILE_UNAVAILABLE` 并保留同长度异类包引用；不推断实际悬赏发放、对象、行动者、队伍或状态变化 |
| `16.19.821.7343 --events objective_bounty_claimed_packet,turret_plate_event_packet,turret_die_event_packet --runtime-image PATH` | 在三个独立候选包源均可用时，验证同回放、chunk、毫秒的 `plate < die < claim` 顺序与三个匿名原生整数相等，并保留三个原始包引用 | 另写入 `objective_bounty_turret_pair_candidates` 和关联汇总；未匹配 claim 留在原包流并计入拒绝原因，不推断悬赏发放、建筑或参与者身份 |
| `16.19.821.7343 --events dampener_die_event_packet --runtime-image PATH` | 精确 821 镜像按 SHA-256 校验并完整反序列化 KR `0x040a` 的 `0x0035` 子包，保留 OnDampenerDie 镜像名表标签、匿名 108 字节原生子包及原始包来源 | 有目标包时写入 `dampener_die_event_packet_candidates`，状态为 `CANDIDATE`；无目标包时报告 `PROFILE_UNAVAILABLE`；同长度异类子事件作为排除证据，不推断建筑实际毁坏、建筑身份、参与者或状态变化 |
| `16.19.821.7343 --events turret_die_event_packet --runtime-image PATH` | 精确 821 镜像按 SHA-256 校验并完整反序列化 KR `0x040a` 的 `0x003b` 子包，保留 OnTurretDie 镜像名表标签、匿名 108 字节原生子包内容及 SHA-256、原始包来源 | 仅写入 `turret_die_event_packet_candidates`，状态为 `CANDIDATE`；同长度异类子事件作为排除证据，不推断实际防御塔死亡、建筑身份、参与者或状态变化 |
| `16.19.821.7343 --events turret_first_blood_event_packet --runtime-image PATH` | 精确 821 镜像按 SHA-256 校验并完整反序列化 KR `0x040a` 的 `0x003d` 子包，保留 OnTurretFirstBlood 镜像名表标签、匿名 108 字节原生子包内容及 SHA-256、原始包来源 | 仅写入 `turret_first_blood_event_packet_candidates`，状态为 `CANDIDATE`；同长度异类子事件作为排除证据，不推断实际首座防御塔死亡、建筑身份、参与者或状态变化 |
| `16.19.821.7343 --events hq_kill_event_packet --runtime-image PATH` | 精确 821 镜像按 SHA-256 校验并完整反序列化 KR `0x040a` 的 `0x0046` 子包，保留 OnHQKill 镜像名表标签、匿名 108 字节原生子包内容及 SHA-256、原始包来源 | 仅写入 `hq_kill_event_packet_candidates`，状态为 `CANDIDATE`；同长度异类子事件作为排除证据，不推断实际主基地毁坏、胜者、行动者或状态变化 |
| `16.19.821.7343 --events turret_die_event_packet,turret_first_blood_event_packet --runtime-image PATH` | 两类子包分别通过精确镜像校验后，检查 `0x003d` 是否在同一 chunk、同一毫秒中位于唯一较早的 `0x003b` 之后，中间没有其他 `0x040a` OnEvent 包；重新核对回放原始包来源 | 成功时另写入 `turret_first_blood_die_pair_candidates` 和 `candidate_associations.turret_first_blood_die_pair`，均为包级 `CANDIDATE`；不推断实际首座防御塔死亡、建筑或参与者身份 |
| `16.19.821.7343 --events cast_spell_ans_packet --runtime-image PATH` | 精确 821 镜像原生完整消费 KR `0x01da` CastSpellAns 包，输出原始包来源、两个回调变换后的不透明字段，以及嵌套对象 `+0xe0` 的受保护浮点与 `+0x24/+0x140` 的受保护字节候选值和原始字节；11 份回放共 63,496 包 | 仅写入 `cast_spell_ans_packet_candidates`；不声称一次成功施法，也不推断技能、槽位、施法者、目标或这些字段的游戏含义；镜像按完整 SHA-256 校验 |
| `16.19.821.7343 --events cast_spell_ans_packet --cast-packet-v5 --runtime-image PATH` | 显式选择 CastSpellAns V5，在原有候选字段外保留嵌套对象的受保护原始四字节 `raw_u32_0x1c_hex` 和回调变换后的匿名 `opaque_u32_0x1c`；11 份原始 KR 回放的 63,496/63,496 个包通过原生完整消费 | V4 仍是默认 profile；V5 只写入 `cast_spell_ans_packet_candidates` 的 `CANDIDATE` 行，不确认施法者、技能、目标、施法成功或游戏效果；API 用 `castPacketProfile: 'v5'` 显式选择 |
| `16.19.821.7343 --events cast_spell_ans_packet --cast-packet-v6 --runtime-image PATH` | 显式选择 CastSpellAns V6，保留 V5 字段并追加嵌套对象的受保护原始四字节 `raw_u32_0x4c_hex` 和回调变换后的匿名 `opaque_u32_0x4c`；11 份原始 KR 回放的 63,496/63,496 个包通过原生完整消费 | V4 仍是默认 profile，V5 保存结果保持原身份；V6 只输出 `CANDIDATE`，不确认施法者、技能、目标、施法成功或游戏效果；API 用 `castPacketProfile: 'v6'` 显式选择 |
| `16.19.821.7343 --events direct_input_movement_turn_packet --runtime-image PATH` | 精确 821 镜像原生完整消费 KR `0x00ba` DirectInputMovementDriverServerTurnData 包，输出三个回调变换后的匿名 f32 字段与原始包来源 | 仅写入 `direct_input_movement_turn_packet_candidates`，状态为 `CANDIDATE`；不将字段标为世界坐标、英雄路径或参与者位置；仅接受已观察到的 13 字节 `0x85` 形状 |
| `16.19.821.7343 --events set_movement_driver_packet --runtime-image PATH` | 精确 821 镜像原生完整消费 KR `0x0335` SetMovementDriver 包，输出回调变换后的匿名分发字节和原始包来源 | 仅写入 `set_movement_driver_packet_candidates`，状态为 `CANDIDATE`；不声称驱动状态已改变，也不推断位置、路径或参与者；仅接受两种已观察到的包形状 |
| `16.19.821.7343 --events face_direction_packet --runtime-image PATH` | 对 KR `0x038e` 已观察到的 13/17 字节包形状使用精确 821 镜像，输出包内向量、可选标量候选值和原始包来源 | 仅写入 `face_direction_packet_candidates`，状态为 `CANDIDATE`；不据原始参数认定行动者，不推断世界位置、路径或方向效果；其他 build 与未观察到的形状明确拒绝 |
| `16.19.821.7343 --events circular_movement_restriction_packet --runtime-image PATH` | 对 KR `0x0464` 已观察到的一字节零记录包与 24 字节单记录包，按精确 821 镜像验证回调字节变换，保留包内匿名标量、三浮点值及原始包引用；11 份回放共 68,242 包 | 仅写入 `circular_movement_restriction_packet_candidates`，状态为 `CANDIDATE`；原生探针完整消费了 129 个单记录包，生产解码只接受已验证形状；不推断行动者、世界位置、英雄路径、接收者或实际限制效果 |
| `16.19.821.7343 --events unit_apply_damage_packet --runtime-image PATH` | 精确 821 镜像注册 KR 游戏流 `0x005f` UnitApplyDamage；每次运行用 Python + Unicorn 原生完整消费全部待输出包，11 份回放共 628,909 包；v5 新增匿名回调对象 `+0x18` f32、四字节受保护编码、原始读取偏移或常量零来源；继续输出原始包来源、选择位、匿名 `+0x10` u32、`+0x20` f32，以及 `+0x24/+0x2c` 两个对象查找键候选 | 仅写入 `unit_apply_damage_packet_candidates`，状态为 `CANDIDATE`；`+0x18` 在 828 包中来自原始读取，在 628,081 包中为常量零；旧 `callback_f32_*` 字段仍只覆盖原先 6,501 包。匿名字段不能证明伤害类型、实际数值、查找成功、生命变化或确定的来源与目标 |
| `16.19.821.7343 --events show_health_bar_packet --runtime-image PATH` | 精确 821 镜像注册 KR `0x0165` ShowHealthBar；两种已观察的单字节载荷经 Python + Unicorn 逐包完整消费，输出原始包引用、回调字节与零标记候选；11 份回放共 89,515 包 | 仅写入 `show_health_bar_packet_candidates`，状态为 `CANDIDATE`；未知载荷、镜像或原生见证不符时整项失败；不推断血量、伤害、参与者身份或实际显示效果 |
| `16.19.821.7343 --events unit_apply_damage_roster_key_pair --runtime-image PATH` | 将原生验证的 `0x005f` 完整原始参数与同回放完整十人 `0x0089` HeroStats 阵容键精确配对，输出两个来源引用和阵容一侧的候选参与者标签；11 份回放匹配 49,473/628,909 包 | 仅写入 `unit_apply_damage_roster_key_candidates`，状态为 `CANDIDATE`；10,284 个 `+0x100` 别名和其他键明确排除，不把阵容标签当作伤害包行动者、来源或目标，也不推断实际伤害 |
| `16.19.821.7343 --events unit_apply_damage_lookup_roster_key_pair --runtime-image PATH` | 将原生回调解出的 `0x005f` 对象 `+0x24` 完整查找键与同回放完整十人 `0x0089` HeroStats 阵容键精确配对，保留原始参数与查找键的关系及两个来源引用；11 份回放匹配 62,860/628,909 包，其中 10,284 包的原始参数为匹配键 `+0x100` | 另写入 `unit_apply_damage_lookup_roster_key_candidates`，状态为 `CANDIDATE`；阵容标签仅属于查找键共现，不能确定对象查找成功、行动者、来源、目标、实际伤害或血量变化 |
| `16.19.821.7343 --events unit_apply_damage_lookup2c_roster_key_pair --runtime-image PATH` | 独立检查原生回调对象 `+0x2c` 完整查找键与同回放完整十人 HeroStats 阵容键的精确共现，同时保留 `+0x24` 键、原始参数关系和两个来源引用；11 份回放匹配 173,125/628,909 包 | 另写入 `unit_apply_damage_lookup2c_roster_key_candidates`，状态为 `CANDIDATE`；阵容标签仅属于 `+0x2c` 键共现，不能确定查找成功、行动者、来源、目标、击杀者或伤害效果 |
| `16.19.821.7343 --events hero_death_damage_lookup_key_cooccurrence --runtime-image PATH` | 以每个 `hero_death` 候选死亡为锚点，收集同一 chunk、同一毫秒中原生 `0x005f` 包 `+0x24` 键等于候选受害者完整阵容键的所有包，并逐包记录 `+0x2c` 是否等于死亡路由解出的来源 ID；重新核对死亡路由、伤害包和完整十人 HeroStats 原始来源 | 另写入 `hero_death_damage_lookup_key_cooccurrence_candidates`，每个死亡锚点一行，保留零匹配、多包、非阵容 `+0x2c` 和不相等的证据；状态为 `CANDIDATE`，不指定致死包，也不推断伤害行动者、来源、目标、对象查找成功或实际效果 |
| `16.19.821.7343 --events face_direction_keyframe_roster_pair --runtime-image PATH` | 自动解码 FaceDirection 包和 `0x0089` 标准补刀快照，在同一关键帧按完整原始参数及先后顺序配对规范英雄行 | 仅写入 `face_direction_keyframe_roster_pair_candidates`；参与者标签来自 HeroStats 阵容，不能当作 FaceDirection 包的行动者；不推断方向效果、位置或路径 |
| `16.19.821.7343 --events npc_buff_add_packet,npc_buff_remove_packet --runtime-image PATH` | 分别解码 KR `0x00ae/0x047c` 原生包，并在两项均成功时汇总相同不透明 `(u32, u8)` 键的重合与时序歧义 | 逐包候选分别写入两个 JSONL；`candidate_associations.npc_buff_add_remove_opaque_key` 仅含回放内统计，不配对单个包，不推断 Buff 名称、归属或生命周期 |
| `16.19.821.7343 --events npc_buff_update_num_counter_packet --runtime-image PATH` | 精确 821 镜像完整消费 KR `0x0194` BuffUpdateNumCounter 包，保留四个按对象偏移命名的匿名回调字段、受保护原始字节与包来源 | 仅写入 `npc_buff_update_num_counter_packet_candidates`，状态为 `CANDIDATE`；不推断 Buff 名称、归属、计数含义或生命周期 |
| `16.19.821.7343 --events npc_buff_update_count_packet --runtime-image PATH` | 精确 821 镜像完整消费 KR `0x02d9` BuffUpdateCount 包，保留五个按对象偏移命名的匿名回调字段、受保护原始字节与包来源 | 仅写入 `npc_buff_update_count_packet_candidates`，状态为 `CANDIDATE`；不推断 Buff 名称、归属、计数含义或生命周期 |
| `16.19.821.7343 --events npc_buff_replace_packet --runtime-image PATH` | 精确 821 镜像完整消费 KR `0x01ad` BuffReplace 包，保留四个按对象偏移命名的匿名回调字段、受保护原始字节与包来源 | 仅写入 `npc_buff_replace_packet_candidates`，状态为 `CANDIDATE`；不推断 Buff 替换、名称、归属或生命周期 |
| `16.19.821.7343 --events set_spell_timer_from_buff_packet --runtime-image PATH` | 精确 821 镜像完整消费 KR `0x00fd` SetSpellTimerFromBuff 包，保留六个按对象偏移命名的匿名回调字段、受保护原始字节与包来源 | 仅写入 `set_spell_timer_from_buff_packet_candidates`，状态为 `CANDIDATE`；不推断 Buff、法术身份或实际计时效果 |
| `16.19.821.7343 --events set_spell_level_packet --runtime-image PATH` | 精确 821 镜像完整消费 KR `0x025d` SetSpellLevel 包，保留两个按对象偏移命名的匿名回调整数、受保护原始字节与包来源 | 仅写入 `set_spell_level_packet_candidates`，状态为 `CANDIDATE`；不推断法术身份、等级、归属或实际效果 |
| `16.19.821.7343 --events set_spell_level_packet --spell-level-packet-v2 --runtime-image PATH` | 显式运行原生回调与合成接收器写入见证，在 V1 匿名字段之外添加接收器表索引候选、回退来源、0..6 截断标量候选及正值标志写入 | V1 仍为默认；V2 只输出 `CANDIDATE`，合成表索引不识别真实法术或实际等级变化；API 用 `setSpellLevelProfile: 'v2'` 显式选择 |
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
  --events hero_death,champion_die_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-death-pairs"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events hero_death,champion_die_event_packet,champion_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-champion-packet-groups"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events hero_death,champion_die_event_packet,champion_multiple_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-multiple-kill-packet-groups"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events champion_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-champion-kill-reports"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events champion_multiple_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-multiple-kill-reports"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events champion_double_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-double-kill-markers"
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events hero_death,champion_die_event_packet,champion_multiple_kill_event_packet,champion_double_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-double-kill-groups"
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events hero_death,champion_die_event_packet,champion_multiple_kill_event_packet,champion_triple_quadra_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-triple-quadra-groups"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events hero_death,champion_die_event_packet,on_shutdown_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-on-shutdown-packet-groups"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events resurrect_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-on-resurrect-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events revive_ally_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-on-revive-ally-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events first_blood_assist_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-on-first-blood-assist-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events objective_steal_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-objective-steal-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events turret_plate_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-turret-plate-event-packets"
node src/cli.js batch "D:\Replays\16.19.821.7343" `
  --events objective_bounty_claimed_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-objective-bounty-claim-packets"
node src/cli.js batch "D:\Replays\16.19.821.7343" `
  --events objective_bounty_claimed_packet,turret_plate_event_packet,turret_die_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-objective-bounty-turret-pairs"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events dampener_die_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-dampener-die-event-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events turret_die_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-turret-die-event-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events turret_first_blood_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-turret-first-blood-event-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events hq_kill_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-hq-kill-event-packets"
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events turret_die_event_packet,turret_first_blood_event_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-turret-first-blood-die-pairs"
```

同时选择 `hero_death,champion_die_event_packet` 后，成功的逐包关联写入
`champion_die_hero_death_pair_candidates.jsonl`，汇总和拒绝原因写入
`semantic_run.json` 的 `candidate_associations.champion_die_hero_death_pair`。
关联要求同一回放、同一 chunk 和毫秒唯一配对，`+0x04` 与 Hero_Die 来源候选值相等，
且外层参数低字节相等；任一行冲突时整份回放不输出关联候选。
11 份 KR 821 回放有 655/655 个候选配对，完整外层参数仅 333/655 相等。
这仍不是已确认的死亡或对象、击杀者身份。

同时选择上述三类能力后，`champion_kill_die_hero_death_pair_candidates.jsonl`
记录 OnChampionKill 子包与前述两条路由的候选包组；汇总写入
`semantic_run.json` 的 `candidate_associations.champion_kill_die_hero_death_pair`。
11 份 KR 821 回放中 581/581 个 Kill 子包形成唯一包组，另有 74 条 Die/Hero
配对没有同刻 Kill 子包。每组要求 Kill 外层参数等于 Die 子包 `+0x04` 与
Hero_Die 来源候选值，Kill 子包 `+0x04` 在清除 `0x100` 位后等于 Hero_Die
受害者原始参数；包序、完整 build 和原始来源均须通过校验。该对应关系只表示
包级候选，不确认实际击杀、受害者或击杀者。

同时选择 `hero_death,champion_die_event_packet,champion_multiple_kill_event_packet`
后，`champion_multiple_kill_die_hero_death_pair_candidates.jsonl` 记录第三种
候选包组。11 份 KR 821 回放有 653/653 个 Multi 子包唯一配对，另有 2 条
Die/Hero 配对没有 Multi 子包；其中 72 个 Multi 包组没有同刻 Kill 子包。
Multi 外层参数等于 Die 子包 `+0x04` 和 Hero_Die 来源候选值，Multi 子包
`+0x04` 清除 `0x100` 位后等于 Hero_Die 受害者原始参数。
该分组也只说明包的对应关系，不确认实际多杀或对象角色。

独立选择 `champion_double_kill_event_packet` 可查询镜像标为
OnChampionDoubleKill 的 `0x000b` 当包标记。11 份 KR 821 回放中 654 个同长度包有
63 个目标、591 个其他子事件；目标 63 个均能与已有 Multi/Die/Hero 候选包组
同回放、同 chunk、同毫秒唯一对应，但此入口不写入已确认的双杀或对象字段。
原生子包仅保留 SHA-256 摘要和来源，不把匿名偏移解释为回调字段。

同时选择 `hero_death,champion_die_event_packet,champion_multiple_kill_event_packet,champion_double_kill_event_packet`
后，`champion_double_kill_multi_group_candidates.jsonl` 写入这项独立的候选包组关联，
汇总与拒绝原因位于 `semantic_run.json` 的
`candidate_associations.champion_double_kill_multi_group`。当前 11 份 KR 821 回放
均为 `CANDIDATE`，共 63/63 个 `0x000b` 标记与 Multi/Die/Hero 包组一一对应；
关联还要求相同外层参数、Die/`0x000b`/Multi/Hero 原始包顺序，且匹配的 Multi
匿名 `+0x08` 为 `2`。其余 590 个 Multi 包组不满足该匿名值。
这只报告精确 build 的包级关系，不确认实际双杀、计数含义或参与者角色。

独立选择 `champion_triple_quadra_event_packet` 可查看镜像标为
OnChampionTripleKill/OnChampionQuadraKill 的当包标记。同时选上
`hero_death,champion_die_event_packet,champion_multiple_kill_event_packet` 后，
`champion_triple_quadra_multi_group_candidates.jsonl` 记录与 Multi/Die/Hero 的
候选包组关联，汇总和拒绝原因在 `semantic_run.json` 的
`candidate_associations.champion_triple_quadra_multi_group`。11 份 KR 821 回放中
有 9 条 `0x000c` 和 1 条 `0x000d`，均与同回放、同 chunk、同毫秒的 Multi 包组
一一对应；匹配的匿名 Multi `+0x08` 分别为 `3` 和 `4`。5 份回放为
`CANDIDATE`，另外 6 份未见目标子包，逐回放报告 `PROFILE_UNAVAILABLE`，
批处理为 `PARTIAL`。这不是对实际连续击杀或对象角色的确认。

同时选择 `hero_death,champion_die_event_packet,on_shutdown_event_packet`
后，`on_shutdown_die_hero_death_pair_candidates.jsonl` 记录第三种候选包组，
汇总与拒绝原因在 `semantic_run.json` 的
`candidate_associations.on_shutdown_die_hero_death_pair`。11 份 KR 821 回放
观察到 72/72 个 OnShutdown 子包与 Die/Hero_Die 候选包同 chunk、同毫秒唯一对应；
外层参数等于 Die 子包 `+0x04` 和 Hero_Die 来源候选值，OnShutdown 子包
`+0x04` 清除 `0x100` 位后等于 Hero_Die 受害者原始参数。原始包顺序、
来源身份或字段关系冲突时，整份回放不输出这一关联候选。
OnShutdown 只是镜像中的事件标签，未确认游戏内 shutdown 效果或参与者角色。

`resurrect_event_packet` 是独立的包标记，不与 `hero_respawn` 自动配对。
11 份 KR 821 回放中 7 份有 29 个原生完整消费的 `0x002d` 子包，另 4 份未见该形状，
按回放分别报告 `CANDIDATE` 与 `PROFILE_UNAVAILABLE`。包标签与字段不足以确认复活行为。

`revive_ally_event_packet` 同样只报告独立的包标记和匿名字段。
11 份 KR 821 回放仅 1 份有 3 个经精确镜像原生完整消费的 `0x002c` 子包；
9 个同为 16 字节的异类子事件保留为排除对照，另外 10 份回放报告 `PROFILE_UNAVAILABLE`。
镜像名表中的 OnReviveAlly 不证明实际复活、发起者、接收者或状态变化。

`first_blood_assist_event_packet` 仅报告独立的包标记、匿名原生子包和来源。
11 份 KR 821 回放中，8 份有 9 个原生完整消费的 `0x0017` 子包，
3 个同长度 `0x002c` 子包被原生身份校验排除；另 3 份回放为
`PROFILE_UNAVAILABLE`。镜像名表中的 OnFirstBloodAssist 不证明实际首杀、
助攻归属或游戏效果。
保存的候选流可用 `query-events --event first_blood_assist_event_packet_candidates`
读取，并用 `--child-event-id 0x0017`、`--raw-param` 或时间范围筛选。
查询校验精确 build、原生镜像来源、子包标记、匿名 8 字节子包哈希及原始包引用；
它不重新运行原生解码，也不将标记解释为实际首杀或助攻。

```powershell
node src/cli.js query-events "work\16-19-821-first-blood-assist" `
  --event first_blood_assist_event_packet_candidates --child-event-id 0x0017
```

`objective_steal_event_packet` 只报告两种精确镜像命名的包标记、
匿名原生子包和原始来源。11 份 KR 821 回放中仅两份各有一个原生完整消费的
`0x040a/133` 包；其余回放没有该形状。该包不能证明实际抢夺、
目标状态变化、行动者或游戏效果。
保存的候选流可用 `query-events` 按时间、原始包参数或子包 ID 筛选；
`0x00be` 是 OnKillDragonSteal 镜像标签，`0x00d6` 是 OnKillWormSteal。
查询校验精确 build、镜像来源、两个子包计数、匿名 124 字节 blob 哈希和
原始包引用；不重新运行原生解码，也不解释游戏效果。
精确镜像中两种子事件的共同回调 RVA `0x2ce720` 接收的类型化对象尚无法与
这 124 字节 blob 对齐；两份原始包的原生测试 3/3 通过，但没有据此提升任何
子对象字段，blob 内偏移仍保持匿名。

```powershell
node src/cli.js query-events "work\16-19-821-objective-steal" `
  --event objective_steal_event_packet_candidates --child-event-id 0x00be
```

`turret_plate_event_packet` 只报告 `0x0107` 子包的匿名当包字段和来源。
11 份 KR 821 回放中观察到 657 个目标子包；同为 17 字节的其他子事件 4964 个作为排除对照，
不进入该候选流。镜像中的事件名不足以确认游戏内镀层效果或对象角色。

同时选择 `objective_bounty_claimed_packet,turret_plate_event_packet,turret_die_event_packet`
可得到独立的三包关联候选。11 份 KR 821 回放有 11 条 claim 包、10 条唯一的
同 chunk/毫秒且原生匿名整数相等的 `plate < die < claim` 关联；剩余一条 claim
保留在包流中，并以 `NO_SAME_KEY_PLATE_OR_DIE` 记录为未匹配。四份无 claim 的回放
报告 `PROFILE_UNAVAILABLE`，关联为 `MISSING_INPUT`；批处理因此为 `PARTIAL`。
这不确认悬赏支付、炮塔破坏、对象、行动者、队伍或游戏状态。

`dampener_die_event_packet` 只报告 `0x0035` 子包的匿名 108 字节内容及来源。
精确镜像原生解码在 11 份 KR 821 回放的 831 个同为 116 字节的包中识别出 18 个目标，
分布于 10 份回放；813 个异类子事件作为排除对照。剩余一份回放未见目标，
应报告 `PROFILE_UNAVAILABLE`。OnDampenerDie 是镜像名表标签，不确认建筑实际毁坏、
建筑身份、参与者或状态变化。

`turret_die_event_packet` 只报告 `0x003b` 子包的匿名 108 字节内容、哈希及来源。
11 份 KR 821 回放均有目标包，共 136 个通过精确镜像原生完整消费和子事件身份校验；
同为 116 字节的 695 个异类子事件按已观察的原始形状排除，保留来源以供核查。
这 11 份回放共扫描 18,235,209 个 block，未发现 framing 错误。OnTurretDie 是镜像名表标签，
不确认实际防御塔死亡、建筑身份、参与者或状态变化。

`turret_first_blood_event_packet` 独立报告 `0x003d` 子包的匿名 108 字节内容、哈希及来源。
11 份 KR 821 回放各有一个目标包，共 11 个通过精确镜像原生完整消费和子事件身份校验；
同为 116 字节的 820 个异类子事件按已观察的原始形状排除，保留来源以供核查。
这 11 份回放共扫描 18,235,209 个 block，未发现 framing 错误。OnTurretFirstBlood 是镜像名表标签，
不确认实际首座防御塔死亡、建筑身份、参与者或状态变化。单独选择此能力时不输出关联。

同时选择 `turret_die_event_packet,turret_first_blood_event_packet` 后，另写入
`turret_first_blood_die_pair_candidates.jsonl`；汇总和拒绝原因位于
`semantic_run.json` 的 `candidate_associations.turret_first_blood_die_pair`。
关联要求两项独立候选均通过同一精确 build 镜像校验，原始包来源与回放一致，
且 `0x003d` 与唯一较早的 `0x003b` 位于同一 chunk、同一毫秒，中间没有其他
`0x040a` OnEvent 包。11 份 KR 821 回放中的 11 个首塔标签包各形成一个候选配对；
136 个 OnTurretDie 标签包中有 125 个未配对。原始外层参数和匿名子包 `+0x04`
并非相等条件。任一配对缺失、重复或来源冲突时，整份回放不输出关联行。
这只证明受限的包级顺序关系，不确认实际首塔死亡、建筑、参与者或状态效果。

`hero_assist` 不提供镜像时保留已有的回放形状、配对、死亡核心和结算尾部候选校验，
并标记 `native_child_identity_status=NOT_CHECKED`。提供完整 821 镜像时，
对选中的全部 `0x040a/44` 包执行原生解码；只有子包身份分别与两种原始形状吻合时才输出候选，
失败则只使该能力失败。11 份 KR 821 回放中，1,379 条第一形状均解为 `0x0056`，
1,097 条第二形状均解为 `0x0057`；其中 1,097 组进入候选配对，282 条第一形状保留为排除证据。
这 1,097 组的子包 `+0x04` 都与同刻 Hero_Die 原始参数清除 `0x100` 位后的数值相同，
第二子包 `+0x20` 都与独立解码的 Hero_Die 来源 ID 相同；原始参数直接相同的有 1,047 组，
相差 `0x100` 的有 50 组。启用镜像时，这两项相等关系也是候选输出条件。
字段仍按匿名偏移命名；这些相等关系不证明助攻生效、对象身份或游戏内行为。

821 的候选死亡记录保留原始包来源及未配对路由的负例计数。该 build 的运行时镜像已从真实回放进程捕获；当前死亡包的计时浮点和 Hero_Die 来源 ID 均有独立候选解码，单次助攻候选在 `hero_assist` 入口。可追加 `hero_assist,hero_respawn,hero_death_timer,hero_deaths_snapshot,hero_champion_kills_snapshot,hero_assists_snapshot,hero_missions_minions_killed_snapshot,hero_ward_stats_snapshot,hero_missions_cannon_minions_killed_snapshot,hero_experience_snapshot,hero_vision_score_snapshot,hero_gold_earned_snapshot,hero_gold_spent_snapshot,hero_damage_totals_snapshot,hero_damage_taken_from_champions_snapshot,hero_damage_self_mitigated_snapshot,hero_structure_objective_damage_snapshot,hero_longest_living_time_snapshot,hero_total_time_spent_dead_snapshot,hero_total_heal_snapshot,hero_total_units_healed_snapshot,hero_epic_monster_damage_snapshot,hero_crowd_control_time_snapshot,hero_level_state` 到 `--events`；计数、浮点、计时和等级使用已固定的精确镜像变换，CLI 运行时无需再次提供镜像。库存 `hero_inventory_packet`、广播包 `hero_inventory_broadcast_packet`、单包 `hero_inventory_set_item_packet`、治疗上报包 `params_heal_packet`、护盾配对包 `shielding_params_packet_pair`、隐身名表子包 `stealth_event_packet`、CastSpellAns 包 `cast_spell_ans_packet`、DirectInput turn 包 `direct_input_movement_turn_packet`、SetMovementDriver 包 `set_movement_driver_packet`、OnChampionDie 子包 `champion_die_event_packet` 和 OnChampionKill 子包 `champion_kill_event_packet` 需要 `--runtime-image` 指向同一完整 build 的镜像。各能力独立报告状态；载荷形状超出已验证范围、解码值违反参与者结算上界等情况仍会保留其他已通过能力的候选输出，并明确标出失败项。11 份现有 KR 回放中的等级 20 和高击杀/助攻编码均已被相应变换覆盖。计时值不用于预测返回时点。

`circular_movement_restriction_packet` 也需要 `--runtime-image` 指向完整的 `16.19.821.7343` 镜像；无需将镜像提交到仓库。输出按包保留零记录和单记录两种形状，匿名三浮点值不是已确认的坐标或路径。

只选择 `hero_experience_snapshot` 还会输出 `experience_keyframe_interval_difference_candidates.jsonl`：每行是同一候选参与者在相邻完整关键帧的正端点差，包含两端时间、原始包引用、候选经验浮点值与取整值。`semantic_run.json` 的 `candidate_associations.experience_keyframe_interval_difference` 同时记录正差与端点相同的区间数。查询使用当前端点时间，支持 `--participant` 和 `--latest-per-participant`；末帧至结算的差额不插值。

同时选择 `hero_level_state,hero_experience_snapshot` 时，还会输出 `level_experience_keyframe_bracket_candidates.jsonl`。每行记录一个等级包严格位于同一候选参与者的两份相邻经验快照之间，并保留三个原始包引用及整段采样端点差；多次等级包共用区间时，差值不分摊。可用 `query-events --event level_experience_keyframe_bracket_candidates --level-after 2` 查询保存结果。`--level-after` 只接受 1..20，查询先校验关联、上游等级和经验 JSONL 的原始来源与精确 build 变换，再返回未经修改的行。等级 1 在当前关联中属于明确排除项，因此筛选值 1 的零命中表示已校验后的零，不代表字段不可用。

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events hero_experience_snapshot --event-jsonl-only `
  --out-dir "work\16-19-821-experience"

node src/cli.js query-events "work\16-19-821-experience" `
  --event experience_keyframe_interval_difference_candidates `
  --participant 1 --latest-per-participant
```

OnShutdown 子包 `on_shutdown_event_packet`、OnResurrect 子包
`resurrect_event_packet`、OnReviveAlly 子包 `revive_ally_event_packet`、
OnTurretPlateDestroyed 子包 `turret_plate_event_packet`、
OnDampenerDie 子包 `dampener_die_event_packet`、
OnTurretDie 子包 `turret_die_event_packet`
及 OnTurretFirstBlood 子包 `turret_first_blood_event_packet`
也需要 `--runtime-image` 指向同一完整 build 的镜像。
这些能力仅报告包候选，不能由镜像中的事件名称推断游戏效果。

821 的 BuffUpdateNumCounter 可单独读取包内匿名字段：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events npc_buff_update_num_counter_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-buff-update-counter"
```

`npc_buff_update_num_counter_packet_candidates.jsonl` 保留受保护原始字节、
原生回调变换后的 `+0x10/+0x14/+0x18/+0x1c` 匿名字段和原始包引用。
该候选不绑定 Buff 身份、目标或游戏内计数含义。

同时选择 `npc_buff_add_packet,npc_buff_update_num_counter_packet` 时，
`semantic_run.json` 的 `candidate_associations.npc_buff_add_update_num_counter_opaque_pair`
汇总同一回放中匿名 `(u32,u8)` 字段组合、原始包参数及更早游戏流 Add 包的计数。
该统计保留关键帧与游戏流的区别；重复出现会导致歧义，不输出逐包配对或 Buff 生命周期。
可对 BuffAdd2、BuffRemove2 或 BuffUpdateNumCounter 候选使用
`query-events --opaque-pair U32:U8`，同时筛选对应的两个匿名字段。
支持十进制或 `0x` 整数；筛选结果仍是原始候选包，不表示跨包配对。

821 的 BuffUpdateCount 可独立选择 `--events npc_buff_update_count_packet`，
并用同 build 的 `--runtime-image` 输出 `npc_buff_update_count_packet_candidates.jsonl`。
`0x02d9` 候选包含 `+0x10/+0x11` 匿名字节、`+0x14` 匿名整数及
`+0x18/+0x1c` 匿名浮点。解码必须同时匹配包 ID、游戏流、已观察载荷长度、
镜像哈希及原生完整消费；这些字段不构成 Buff 身份或计数语义。
现有 11 份 KR 821 回放的实际 CLI 批处理得到 151,495/151,495 个候选包，
11 份均为 `CANDIDATE`，容器 framing 错误为零。
`query-events --event npc_buff_update_count_packet_candidates --opaque-u32 VALUE`
可按解码后的匿名 `+0x14` 整数筛选，仍输出原始候选行。

821 的 BuffReplace 可独立选择 `--events npc_buff_replace_packet`，
并用同 build 的 `--runtime-image` 输出 `npc_buff_replace_packet_candidates.jsonl`。
`0x01ad` 候选保留 `+0x10` 匿名字节、`+0x14/+0x1c` 匿名浮点、
`+0x18` 匿名整数及原始对象字节。镜像中的包名及回调调用不足以证明
游戏内 Buff 替换或其实体归属。
11 份 KR 821 回放的实际 CLI 批处理得到 23,351/23,351 个候选包，
11 份均为 `CANDIDATE`，容器 framing 错误为零。
`query-events --event npc_buff_replace_packet_candidates --opaque-u32 VALUE`
可按解码后的匿名 `+0x18` 整数筛选，不改变候选行。

821 的 SetSpellTimerFromBuff 可独立选择
`--events set_spell_timer_from_buff_packet --runtime-image PATH`，输出
`set_spell_timer_from_buff_packet_candidates.jsonl`。候选包含两个匿名字节、
一个匿名浮点、两个匿名整数和一个匿名分发字节；偏移与原始字节保留在行内。
11 份 KR 821 回放的 CLI 批处理得到 5,481/5,481 个候选包，
11 份均为 `CANDIDATE`，零 framing 错误。包名及分发路径不足以确认游戏内计时变化。
`query-events --event set_spell_timer_from_buff_packet_candidates --opaque-u32 VALUE`
可按匿名 `opaque_u32_0x18` 或 `opaque_u32_0x1c` 精确筛选，输出仍保留完整候选行。
外层 `raw_param`、匿名浮点和字节均不参与匹配；字段缺失与已检查的零命中分别报告。

821 的 SetSpellLevel 可独立选择
`--events set_spell_level_packet --runtime-image PATH`，输出
`set_spell_level_packet_candidates.jsonl`。候选保留对象 `+0x10/+0x14`
两个回调转换后的匿名整数、原始对象字节和包来源。11 份 KR 821 回放的
实际 CLI 批处理得到 342/342 个候选包，11 份均为 `CANDIDATE`、
精确镜像 `MATCHED_USED`、零 framing 错误。包名及回调读取路径不足以确认
法术身份、等级变化、归属或游戏内效果。
`query-events --event set_spell_level_packet_candidates --opaque-u32 VALUE`
可按匿名 `opaque_u32_0x10` 或 `opaque_u32_0x14` 精确筛选，输出仍保留完整候选行。
外层 `raw_param` 不参与匹配；字段缺失与已检查的零命中分别报告。

SetSpellLevel V2 需显式指定 `--spell-level-packet-v2`，API 可传入
`setSpellLevelProfile: 'v2'`。V2 保存结果可使用
`query-events --event set_spell_level_packet_candidates --spell-level-receiver-index 12`
或 `--spell-level-clamped-scalar 6` 筛选；查询会逐行复核原始对象字节、
精确镜像证据和接收器候选，即使设置 `--limit 1` 也会检查剩余行。
V1 保存结果对这两个筛选条件明确报告字段不可用。11 份精确 821 KR
回放的 V2 CLI 批处理得到 342/342 个候选包，11/11 为 `CANDIDATE`，
零 framing 错误；接收器索引 12 命中 278 行，截断标量 6 命中 22 行。
这些字段来自合成接收器见证，不确认真实接收器、法术身份或等级变化。

821 的 `hero_inventory_packet`、`hero_deaths_snapshot` 与至少一种移动包路由一起选择时，
`semantic_run.json` 和 API 的 `candidate_associations.movement_full_param_participant_candidate`
会给出回放级完整 `raw_param` 候选关联。它要求十人快照、最新库存包与回放结算物品
七槽唯一匹配，并逐场报告匹配或排除的移动包数量。例如：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events hero_inventory_packet,hero_deaths_snapshot,direct_input_movement_turn_packet,set_movement_driver_packet `
  --runtime-image "D:\PrivateInputs\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --out-dir "work\16-19-821-movement-association"
```

这是独立的候选汇总；单条移动事件不新增参与者字段。非标准完整参数变体仍不绑定，
候选键共享的行数不证明每个包的行动者。缺少所选能力或证据不完整时，关联状态会明确为
`UNAVAILABLE` 或 `DECODE_FAILED`。

821 的 `0x038e` FaceDirection 包可单独输出候选字段。该路由每场可有数万个包，
`--event-jsonl-only` 可减少磁盘上的重复事件文件：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events face_direction_packet `
  --runtime-image "D:\PrivateInputs\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-face-direction"
```

`face_direction_packet_candidates.jsonl` 保留 13/17 字节包的候选向量、17 字节包的
可选标量及原始包引用。它不建立包的行动者、世界坐标、英雄路径或实际方向变化。

若只需同关键帧 HeroStats 阵容配对，可选择 `--events face_direction_keyframe_roster_pair`
并提供同一镜像。此选择会在内部读取两个来源，只输出
`face_direction_keyframe_roster_pair_candidates.jsonl`；每行保留 FaceDirection 与
HeroStats 两个原始包引用。查询时用 `--participant 4` 按 HeroStats 阵容候选标签
筛选；`--latest-per-participant` 返回每场每位候选参与者最后一条已观察到的关键帧配对。
不能据此认定 FaceDirection 包的行动者。

单独检查 821 IncrementMinionKills 包的候选协议字段：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events increment_minion_kills_packet `
  --runtime-image "D:\PrivateInputs\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --out-dir "work\16-19-821-increment-minion-kills"
```

输出保留每包的选择字节、原始参数、镜像回调生成的对象查找键和原始包引用；条件计数写入与实际补刀效果均保持 `UNKNOWN`。这 279 包不能代替回放结算中的补刀总数，也不用于推算未观察到的包间状态。

保存产物可按时间和原始参数查询这一路由，例如：

```powershell
node src/cli.js query-events "work\16-19-821-increment-minion-kills" `
  --event increment_minion_kills_packet_candidates `
  --raw-param 0x400000b1 --limit 20
```

查询会校验精确 build、镜像与回调变换身份、逐行包引用和 `UNKNOWN` 状态，然后原样输出 JSONL。该路由未建立参与者身份；`--participant` 不会将原始参数解释为参与者，`--latest-per-participant` 不适用。

同时选择补刀计数包和标准 `MINIONS_KILLED` 关键帧快照时，还会生成逐包的**候选关键帧区间关联**：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events increment_minion_kills_packet,hero_minions_killed_snapshot `
  --runtime-image "D:\PrivateInputs\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-minion-brackets"

node src/cli.js query-events "work\16-19-821-minion-brackets" `
  --event increment_minion_keyframe_bracket_candidates `
  --participant 4 --raw-param 0x400000b1 --limit 20
```

关联记录保留包与前后快照的原始引用、同一候选原始键及两端计数。它只说明包落在该候选参与者两次观察之间；端点差值不归因于这个包，也不确认补刀、条件计数写入或实际参与者身份。
保存产物查询会校验精确 build、镜像、两路来源 JSONL、完整关键帧名单和每条关联；未夹在区间内的包保留在关联元数据中，不混入查询结果。

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

对完整 build `16.19.821.7343` 的 KR 回放，可一次输出逐次死亡的三个独立候选来源及关联记录：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events hero_assist,hero_death_timer,hero_respawn --event-jsonl-only `
  --out-dir "work\16-19-821-death-episodes"
```

每场的 `hero_death_episode_candidates.jsonl` 按原始 `0x0259` 包连接候选受害者、来源、助攻列表和计时值；`return_observation_status` 区分已观察到的 `0x0048` 返回与回放结束前未观察到返回。`semantic_run.json` 的 `candidate_associations.hero_death_episode` 记录关联状态。三项来源中任一不可用时，关联不可用，已成功的来源事件仍保留。计时值不用于推算返回时点。

对精确 821 的 KR 回放，同时观察关键帧眼位累计候选和物品广播包：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events hero_ward_stats_snapshot,hero_inventory_broadcast_packet `
  --runtime-image "D:\PrivateInputs\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-ward-inventory"
```

逐场的 `ward_inventory_keyframe_pair_candidates.jsonl` 保留两种来源包引用、眼位累计候选和同关键帧物品包候选。`semantic_run.json` 中的 `candidate_associations.ward_inventory_keyframe_pair` 记录配对与排除的游戏流广播数。缺少镜像时，眼位统计候选仍可输出，关联明确标为缺少输入。

只选择 `hero_inventory_broadcast_packet` 也会生成 `inventory_keyframe_interval_difference_candidates.jsonl`。每行列出同一候选参与者的前后关键帧时间、不同槽位的两个候选物品键，以及两端原始包引用；`semantic_run.json` 的 `candidate_associations.inventory_keyframe_interval_difference` 分别记录端点不同、端点相同和排除的游戏流包数。端点相同不证明区间内没有变化；端点不同也不表示发生了一次特定交易。

保存的区间差异可按参与者、当前端点时间、原始参数、差异槽位和该槽位**当前端点**的物品键查询：

```powershell
node src/cli.js query-events "work\16-19-821-ward-inventory" `
  --event inventory_keyframe_interval_difference_candidates `
  --participant 1 --slot 7 --item-id 2001 --limit 20

node src/cli.js query-events "work\16-19-821-ward-inventory" `
  --event inventory_keyframe_interval_difference_candidates `
  --slot 7 --previous-item-id 2001 --item-id 2002 --limit 20

node src/cli.js query-events "work\16-19-821-ward-inventory" `
  --event inventory_keyframe_interval_difference_candidates `
  --endpoint-reversed-pair --limit 20
```

`--previous-item-id` 只用于这类区间差异，筛选前端点物品键；与 `--slot`、`--item-id` 合用时，所有条件必须落在同一条差异槽位记录。两个物品键均可为 `0`；同一槽位前后值相等不会生成差异行。`--latest-per-participant --to-ms 600000` 取截止时间前每场每人最后一条符合筛选条件的差异记录，仍不表示截止时的持续库存状态。查询校验保存的关联元数据与行来源，缺镜像的场次标为不可查询。

`--endpoint-reversed-pair` 只选择恰好两个槽位发生差异、两个非零物品键在前后端点交叉且在两端完整 10 槽快照中各自唯一的行。查询读取并校验保存的 Broadcast 来源快照，原样输出区间 JSONL；这只表示相邻关键帧的端点模式，不确定区间内动作或变化时刻。

`query-events DIR --event inventory_game_broadcast_keyframe_bracket_candidates` 可读取上表的游戏流关联，按 `--participant`、`--raw-param`、`--slot`、`--item-id`、时间范围或 `--comparison-to-endpoints` 筛选，并校验保存的 Broadcast 来源、完整关键帧及三个原始包引用。比较标签必须是 `SAME_AS_BOTH_ENDPOINTS`、`DIFFERS_FROM_EQUAL_ENDPOINTS`、`SAME_AS_PREVIOUS_ENDPOINT`、`SAME_AS_NEXT_ENDPOINT`、`DIFFERS_FROM_BOTH_ENDPOINTS` 之一，大小写固定。标签与 `--slot`、`--item-id` 同时使用时必须落在**同一条游戏包明确记录的槽位**；`--item-id` 指该记录的游戏包物品键，`0` 有效。游戏包未明确记录的槽位保持不可用；相同端点之间出现不同的包值也只表示三次包观测。

```powershell
node src/cli.js query-events "work\16-19-821-inventory-game-bracket-batch" `
  --event inventory_game_broadcast_keyframe_bracket_candidates `
  --comparison-to-endpoints DIFFERS_FROM_EQUAL_ENDPOINTS --slot 0 --item-id 3866
```

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

`query-events` 也可直接读取 `batch` 或 `decode` 的输出根目录，包括只含一场回放的根目录。从 `manifest.json` 逐场校验回放身份、目录清单和每场元数据及所查 JSONL 的 SHA-256，再把匹配行原样输出；单场产物还可传入 `replays/<回放名>` 目录。`--limit` 作用于整批输出，仍会检查所有可用场次的完整行数。汇总列出每场 `COMPLETE` 或 `UNAVAILABLE` 和原有能力状态；部分场次缺少包形状时返回 `PARTIAL`，不会把缺失当作零命中。全部场次不可查询时命令失败，已创建的输出文件会清理。

```powershell
node src/cli.js query-events "work\16-19-821-batch" `
  --event resurrect_event_packet_candidates --limit 20 `
  --output "work\resurrect-query.jsonl"
node src/cli.js query-events "work\16-19-821-triple-quadra-groups" `
  --event champion_triple_quadra_multi_group_candidates --child-event-id 0x000d `
  --output "work\quadra-named-packet-groups.jsonl"
node src/cli.js query-events "work\16-19-821-revive-ally-batch" `
  --event revive_ally_event_packet_candidates --opaque-u32 0x400000b6
node src/cli.js query-events "work\16-19-821-turret-first-blood-die-pairs" `
  --event turret_first_blood_die_pair_candidates --raw-param 0x4000008c
node src/cli.js query-events "work\16-19-821-dampener-die-event-packets" `
  --event dampener_die_event_packet_candidates --raw-param 0x4000018f
node src/cli.js query-events "work\16-19-821-hq-kill-event-packets" `
  --event hq_kill_event_packet_candidates --child-event-id 0x0046 --limit 20
node src/cli.js query-events "work\16-19-821-objective-bounty-claim-packets" `
  --event objective_bounty_claimed_packet_candidates --child-event-id 0x0113
node src/cli.js query-events "work\16-19-821-objective-bounty-turret-pairs" `
  --event objective_bounty_turret_pair_candidates --opaque-u32 0x4000008c
```

炮塔候选配对可按回放毫秒或任一原始包的 `--raw-param` 查询；查询保留原 JSONL 行，
并核对双源能力、精确镜像与候选关联的产物身份。原始参数不代表建筑或参与者身份。
`dampener_die_event_packet_candidates` 也可按时间或原始参数查询；批量结果会单独列出
`PROFILE_UNAVAILABLE` 的回放，不能把它当作零命中。
`hq_kill_event_packet_candidates` 还可按时间、原始参数或精确子事件 ID `0x0046` 查询，输出保持原 JSONL 行。查询校验完整 `16.19.821.7343`、已保存的镜像哈希/候选元数据、`0x4918`、匿名子包哈希和原始包引用；批量查询另校验 manifest 文件哈希。这里校验的是保存产物及来源引用，**不会重新打开原始 ROFL 逐字节核对**。`OnHQKill` 只是精确镜像的标签；不据此断言主基地实际毁坏、胜者、行动者或状态变化。缺镜像或无目标包的场次仍标为不可用。
`objective_bounty_claimed_packet_candidates` 可按匿名 `blob_u32_0x04`、时间、原始参数或子事件 ID `0x0113` 查询；三包关联可按相等的匿名整数、时间或三包任一原始参数查询。关联查询逐条核对 claim、plate、die 三份保存的候选包 JSONL 的字段、子包哈希和原始包引用；批量入口还核对三份源文件的 manifest 哈希。它输出原 JSONL 行，不在查询时重新解码回放。未匹配 claim 不会误报成三包关联，缺少目标子事件的回放仍列为不可用。

按 821 单次助攻候选的参与者列表查询，可输入单场或 `batch` 输出目录：

```powershell
node src/cli.js query-events "work\16-19-821-assists" `
  --event hero_assist_candidates --assisting-participant 2 --limit 20
```

`--assisting-participant` 只接受 `1..10`，仅匹配精确 `16.19.821.7343` 的
`hero_assist_candidates` 或 `hero_death_episode_candidates`；输出保留原 JSONL 行。非英雄来源的 `null` 列表计入
`assisting_participant_unavailable_count`，已核对的空列表是可用的零助攻候选。
筛选不会把候选助攻提升为已确认的游戏事件。

`--killer-participant 1..10` 可查询同一完整 build 的 `hero_death_candidates`
、`hero_assist_candidates` 或 `hero_death_episode_candidates` 中的候选击杀者，也可与 `--participant`（受害者）及
助攻列表筛选同时使用。非英雄来源的空击杀者计入
`killer_participant_unavailable_count`；已核对且没有匹配行时正常返回零命中。

```powershell
node src/cli.js query-events "work\16-19-821-deaths" `
  --event hero_death_candidates --killer-participant 6 --limit 20
```

逐死亡关联的查询也接受 `--assisting-participant`、时间和原始参数筛选。例如：

```powershell
node src/cli.js query-events "work\16-19-821-death-episodes" `
  --event hero_death_episode_candidates --participant 6 `
  --killer-participant 2 --assisting-participant 1 --limit 20
```

查询核对三项来源能力、关联计数和逐行包引用，输出原 JSONL 行；缺少任一来源的回放在批量结果中单独标为不可查询。筛选值仍是候选参与者映射。

对精确 821 的物品包、等级、经验、三种伤害快照及逐死亡候选，可在每场回放里取每位已映射参与者截止时间前最后一条**已观察到**的记录：

```powershell
node src/cli.js query-events "work\16-19-821-inventory-batch" `
  --event hero_inventory_broadcast_packet_candidates `
  --latest-per-participant --to-ms 600000 `
  --output "work\latest-observed-inventory.jsonl"
```

结果按场次、参与者排列，同一时间取原 JSONL 中较晚的一行；不提供 `--to-ms` 则取回放内最后观察。`matched_count` 统计过滤后的所有行，`selected_count` 统计每场每人选中的行，`latest_participant_unavailable_count` 统计过滤后无法映射参与者的行，`--limit` 仅限制写出行数。与物品或槽位筛选合用时，选择的是最后一条**符合筛选条件的观察**，不表示物品在截止时间仍然存在；任何结果都不填补观察之间的状态。

同关键帧眼位统计与物品广播配对候选也可按参与者、时间、原始参数以及**当包同一条记录**的物品和槽位查询：

```powershell
node src/cli.js query-events "work\16-19-821-ward-inventory-batch" `
  --event ward_inventory_keyframe_pair_candidates `
  --participant 1 --from-ms 0 --to-ms 0 `
  --raw-param 0x400000ae --item-id 2001 --slot 7 --limit 20
```

`--item-id 0` 也可匹配 Broadcast 当包的空槽记录。`--latest-per-participant` 取每场每人最后一条符合筛选条件的原始配对行；结果仅表示同关键帧的两个候选观察，不推断插眼、交易或后续物品状态。查询会检查保存产物的来源能力、关联计数、回放身份和双包引用；缺少镜像导致关联不可用的场次会明确报告，不计作零命中。

对已解码的 821 库存包按物品 ID 查询单包记录：

```powershell
node src/cli.js query-events "work\16-19-821-inventory\replays\KR_example" `
  --event hero_inventory_packet_candidates --item-id 3340 --limit 20
```

`--item-id` 接受十进制或 `0x` 十六进制 uint32，匹配 821 MapView/Broadcast 当包 `records_candidate[].item_id_candidate`、SetItem 当包 `item_id_candidate`，以及上文明确列出的库存关联记录：配对当包物品键、区间后端点物品键、游戏包区间比较记录的游戏包物品键。不查询回调空槽、包间持续库存或买卖事件。Broadcast 中解出的物品 `0` 可以精确查询；当前 SetItem 样本只观察到正值。输出仍是未修改的原始 JSONL 行；汇总中的 `item_id_unavailable_count` 区分字段不可用与已检查后的零命中。其他事件流不能使用此过滤器。

`--slot 0..9` 查询同样三种精确 821 库存候选包及上文库存关联中的明确记录槽位；MapView/Broadcast 只查 `records_candidate[].slot_candidate`，SetItem 查当包 `slot_candidate`。与 `--item-id` 同时使用时，两个值必须来自同一条记录。未记录槽位和包间状态不参与匹配；`slot_unavailable_count` 区分字段不可用与已检查后的零命中。

对 821 治疗上报或护盾双包中的匿名整数精确查询：

```powershell
node src/cli.js query-events "work\16-19-821-heal-report\replays\KR_example" `
  --event params_heal_packet_candidates --opaque-u32 0x400000b3 --limit 20
```

`--opaque-u32` 同时支持 `shielding_params_packet_pair_candidates`、`stealth_event_packet_candidates`、`npc_buff_add_packet_candidates`、`npc_buff_remove_packet_candidates`、`champion_die_event_packet_candidates`、`champion_kill_event_packet_candidates`、`champion_multiple_kill_event_packet_candidates`、`on_shutdown_event_packet_candidates`、`resurrect_event_packet_candidates`、`revive_ally_event_packet_candidates`、`turret_plate_event_packet_candidates`、`objective_bounty_claimed_packet_candidates` 和 `objective_bounty_turret_pair_candidates`，匹配各记录中已解码的匿名标量 u32 字段；BuffAdd2/BuffRemove2 只匹配 `opaque_u32_0x10`。不查询多杀子包的 `+0x10` 列表，也不使用外层 `raw_param` 代替字段或赋予治疗、护盾、Buff、隐身、死亡、击杀、复活参与者或建筑角色。十进制、十六进制和 `0` 均可精确查询；汇总保留字段不可用数与已检查后的零命中。
`npc_buff_update_num_counter_packet_candidates` 也接受该筛选，匹配匿名
`opaque_u32_0x14` 或 `opaque_u32_0x1c`，输出行保留两个字段以供区分。

对 821 CastSpellAns 候选包中已解码的不透明有符号整数精确查询：

```powershell
node src/cli.js query-events "work\16-19-821-cast\replays\KR_example" `
  --event cast_spell_ans_packet_candidates --opaque-i32 0 --limit 20
```

`--opaque-i32` 只接受十进制有符号 int32（含 `0` 和负数），只匹配当包的 `opaque_i32_0x14c`，不赋予技能、槽位或施法者含义。JSONL 行原样输出；汇总中的 `opaque_i32_unavailable_count` 区分字段缺失与已检查后的零命中，已出现但无效的字段会使查询失败。

嵌套对象 `+0x24` 的不透明回调字节可以用 `--cast-nested-bits 8` 或 `--cast-nested-bits 0x8` 精确筛选（范围 0..255）。保存结果查询会先核对精确 821 profile、镜像及回调摘要、原始包引用与字节变换；旧版 v3 CastSpellAns 产物报告该字段不可用，已检查但未匹配则返回零命中。字段数值不指代技能、槽位、角色或施法结果。

显式使用 `--cast-packet-v5` 生成的保存结果可按匿名 `opaque_u32_0x1c` 查询；
`--cast-nested-u32` 接受十进制或 `0x` 十六进制 uint32，按完整精确 build、
V5 profile、镜像与变换摘要、原始包引用及受保护原始四字节校验全部行，
然后原样输出匹配的 JSONL 行。V3/V4 产物会明确报告该字段不可用，
已检查但未匹配则是零命中，数值不指代施法者、技能、目标或效果。

```powershell
node src/cli.js decode "D:\Replays\example-16.19.821.7343.rofl" `
  --events cast_spell_ans_packet --cast-packet-v5 `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-cast-v5"
node src/cli.js query-events "work\16-19-821-cast-v5\replays\KR_example" `
  --event cast_spell_ans_packet_candidates --cast-nested-u32 0 --limit 20
```

V6 再提供一个独立的匿名 `+0x4c` u32。可用
`query-events --event cast_spell_ans_packet_candidates --cast-nested-u32-0x4c VALUE`
筛选保存结果；V3/V4/V5 产物明确报告该字段不可用，V6 查询还会复核 V5
字段的原始字节与变换。V6 可用 `--cast-packet-v6` 生成，不能与
`--cast-packet-v5` 同时指定。

对 821 移动限制包的保存结果，可用 `--packet-record-count 1` 找出单记录包，或用 `0` 查看空记录包：

```powershell
node src/cli.js query-events "work\16-19-821-circular" `
  --event circular_movement_restriction_packet_candidates `
  --packet-record-count 1 --limit 20
```

查询核对每行的原始包哈希、来源引用、精确镜像变换和匿名字段，再原样输出。11 份回放的保存结果中，单记录 129 行、零记录 68,113 行；`packet_record_count_checked_count` 与不可用数会分开报告。单记录的三个浮点值不是已确认的英雄位置或路径。

对精确 821 的伤害包、伤害包原始参数与阵容键配对、血条显示包候选能力，可一次处理同一目录中的回放：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events unit_apply_damage_packet,unit_apply_damage_roster_key_pair,show_health_bar_packet `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-combat-packets"
```

单独提取原生 `+0x24` 查找键与完整 HeroStats 阵容键的候选配对：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events unit_apply_damage_lookup_roster_key_pair `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-damage-lookup-roster"
```

该能力会校验原生伤害包、完整十人阵容和独立的原始参数配对；输出的候选参与者标签来自阵容键。11 份回放匹配 62,860 包，包括先前原始参数配对排除的 10,284 个 `+0x100` 别名；对象查找是否成功和伤害包中的角色仍为 `UNKNOWN`。

可查询已保存的关联。`--raw-param` 仅筛选伤害包原始参数，不把解码查找键或阵容键当作原始参数：

```powershell
node src/cli.js query-events "work\16-19-821-damage-lookup-roster" `
  --event unit_apply_damage_lookup_roster_key_candidates `
  --raw-param 0x400001ae --limit 20
```

同样可以单独提取与查询 `+0x2c` 键的阵容共现候选：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events unit_apply_damage_lookup2c_roster_key_pair `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-damage-lookup2c-roster"
node src/cli.js query-events "work\16-19-821-damage-lookup2c-roster" `
  --event unit_apply_damage_lookup2c_roster_key_candidates `
  --raw-param 0x400000ae --limit 20
```

保存查询仍按原始伤害包参数筛选，并逐行核对已保存的候选字段、原始字节和来源引用；它不会重新打开 ROFL，物理包核对发生在解码阶段。`+0x24` 与 `+0x2c` 可以同时落在阵容内，也可以分别落在阵容外；不能把其中一个字段的标签转给另一个字段，或从同一回放毫秒选出唯一致死包。11 份回放的 CLI 输出为 11/11 `CANDIDATE`、零 framing 错误；其中两键都在阵容内的有 34,712 包，仅 15 包是相同键。

按死亡锚点查看同刻原生查找键的共现候选时，只需选择关联能力；CLI/API 会运行并核对 `hero_death`、原生 `unit_apply_damage_packet`、`hero_minions_killed_snapshot` 和原始参数阵容键配对这四项来源：

```powershell
node src/cli.js batch "D:\Replays\KR-16.19.821.7343" `
  --events hero_death_damage_lookup_key_cooccurrence `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-death-damage-lookup"
```

API 可调用 `decodeSemanticReplay(parseReplayFile(replayPath), { capabilities: ['hero_death_damage_lookup_key_cooccurrence'], runtimeImagePath: imagePath })`，从 `events.hero_death_damage_lookup_key_cooccurrence_candidates` 读取逐次结果，并从 `capability_results.hero_death_damage_lookup_key_cooccurrence` 读取来源状态与计数。

逐次结果写入 `hero_death_damage_lookup_key_cooccurrence_candidates.jsonl`，汇总和来源状态写入 `semantic_run.json` 的 `capability_results.hero_death_damage_lookup_key_cooccurrence`。每行保留死亡锚点、候选受害者完整阵容键、死亡来源 ID、所有同 chunk 同毫秒且 `+0x24` 键相等的伤害包原始引用，并分别统计这些包中 `+0x2c` 键等于死亡来源 ID 的数量。死亡候选的原始参数可能是阵容键 `+0x100` 别名，因此关联使用候选参与者的完整阵容键，不把原始参数直接当作查找键。多包全部保留；`NO_SAME_TIME_MATCH`、`DIE_SOURCE_UNAVAILABLE` 和零包均有各自含义。11 份精确 build 回放的本能力批量运行是 11/11 `CANDIDATE`、零 framing 错误：655 个死亡锚点对应 1,035 个同刻候选伤害包，227 个锚点有多个包；633 个锚点至少有一包的 `+0x2c` 与死亡来源 ID 相等，22 个没有。即使两个键同时相等，包的致死关系、行动者、来源、目标、对象查找结果和实际血量效果仍为 `UNKNOWN`。

保存结果可按候选受害者或嵌套伤害包的**原始参数**查询；`--raw-param` 不筛选死亡路由原始参数或解码查找键。查询先完整核对所有保存行和来源引用，再应用 `--limit`，不重新打开原始 ROFL：

`--die-source-key2c-match has|none|unavailable` 可筛选死亡来源 ID 与同刻候选包 `+0x2c` 键的验证状态；`none` 保留零包与不相等的锚点，状态不表示致死关系。

```powershell
node src/cli.js query-events "work\16-19-821-death-damage-lookup" `
  --event hero_death_damage_lookup_key_cooccurrence_candidates `
  --participant 1 --limit 20
```

对 821 `UnitApplyDamage` 保存结果，仅筛选具有上述旧版匿名回调浮点值的包：

```powershell
node src/cli.js query-events "work\16-19-821-unit-damage" `
  --event unit_apply_damage_packet_candidates `
  --damage-callback-f32-available --limit 20
```

v3 到 v6 伤害包保存结果还可按两个独立的原生对象查找键筛选。以下两个条件同时给出时，必须由同一包满足；`--raw-param` 仍单独表示原始包参数：

```powershell
node src/cli.js query-events "work\16-19-821-unit-damage" `
  --event unit_apply_damage_packet_candidates `
  --damage-lookup-key24 0x400000ae --damage-lookup-key2c 0x400000b3 `
  --limit 20
```

查找键筛选仅接受精确 `16.19.821.7343` 的 v3/v4/v5/v6 保存产物，核对全部行、原始字节和原生见证元数据，`--limit` 不缩短核对范围；缺失或更早的产物会明确拒绝。两个键可分别筛选，不能据此认定伤害包的施加者、目标、致死关系或实际伤害。

v4/v5/v6 保存结果还可筛选匿名 `+0x10` u32；数值零有效，旧 v1/v2/v3 保存结果不具有该字段：

```powershell
node src/cli.js query-events "work\16-19-821-unit-damage-v4" `
  --event unit_apply_damage_packet_candidates `
  --damage-callback-u32-0x10 0 --limit 20
```

v5/v6 保存结果可单独筛出原生读取匿名 `+0x18` 浮点值的包；已保存的 v5 十一份回放共匹配 828 包，常量零包不在此筛选中：

```powershell
node src/cli.js query-events "work\16-19-821-unit-damage-v5" `
  --event unit_apply_damage_packet_candidates `
  --damage-callback-f32-0x18-raw --limit 20
```

新 v6 解码需显式指定 `--damage-packet-v6`；API 使用 `decodeSemanticReplay(replay, { capabilities: ['unit_apply_damage_packet'], runtimeImagePath, damagePacketProfile: 'v6' })`。默认继续使用 v5。保存结果可按匿名 `+0x1c` u32 筛选，包括零：

```powershell
node src/cli.js decode "D:\Replays\KR_8392938200.rofl" `
  --events unit_apply_damage_packet --damage-packet-v6 `
  --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" `
  --event-jsonl-only --out-dir "work\16-19-821-unit-damage-v6"
node src/cli.js query-events "work\16-19-821-unit-damage-v6" `
  --event unit_apply_damage_packet_candidates `
  --damage-callback-u32-0x1c 0 --limit 20
```

查询校验精确 build、镜像和变换标识、保存的全包原生见证状态与有序输入摘要，以及每行原始包哈希与来源引用；v2 校验全部匿名原生 `+0x20` 浮点值的读取偏移或常量来源，v3 另校验两项查找键的固定字节变换和 `raw_param` 关系汇总，v4 再校验 `+0x10` 的变换、编码字节、来源和计数，v5 再校验 `+0x18` 的变换、编码字节、读取偏移或常量来源及计数，v6 再校验 `+0x1c` 的选择位、原生调用点、可变长度原始读取、编码变换、来源和计数；旧 v1-v5 产物仍按各自合同读取。达到输出上限后仍检查余下行，不重新运行原生解码或打开原始回放。旧版 `callback_f32_*` 筛选的含义保持不变：11 份回放共 628,909 行，其中 6,501 行可用，622,408 行为 `UNAVAILABLE_SHAPE`。匿名字段不代表实际伤害量、施加者或目标。

血条显示包的匿名回调零标记可在保存结果中筛选：

```powershell
node src/cli.js query-events "work\16-19-821-combat-packets" `
  --event show_health_bar_packet_candidates `
  --show-health-zero-flag 1 --limit 20
```

查询会核对精确 build、镜像与回调表、逐包原始引用、载荷哈希、有序原生输入摘要和全部行计数；`--limit` 仅限制输出。11 份回放中标记 `1` 有 27,702 行，标记 `0` 有 61,813 行。这只是回调字节候选，不代表真实血条显示或血量变化。

三个 KR 821 候选包组 JSONL 也能使用 `query-events`，按时间、原始参数或
各组子包直接解码的 `+0x04` 匿名整数筛选。例如：

```powershell
node src/cli.js query-events "work\16-19-821-champion-packet-groups\replays\KR_example" `
  --event champion_kill_die_hero_death_pair_candidates `
  --from-ms 100000 --to-ms 200000 --opaque-u32 0x400000ae --limit 20
```

`--raw-param` 可命中包组中任一原始包引用；查询只返回未经修改的候选行，
并检查关联 profile、上游能力状态、回放身份和行数。

按精确解码的 821 OnEvent 子事件 ID 查询 OnEnterStealth 标签（`0x0101`）：

```powershell
node src/cli.js query-events "work\16-19-821-stealth-reports\replays\KR_example" `
  --event stealth_event_packet_candidates --child-event-id 0x0101 --limit 20
```

`--child-event-id` 对隐身候选接受 `0x0101/0x0102`，对
`champion_double_kill_event_packet_candidates` 及
`champion_double_kill_multi_group_candidates` 接受 `0x000b`，对
`champion_triple_quadra_event_packet_candidates` 及
`champion_triple_quadra_multi_group_candidates` 接受 `0x000c/0x000d`；
也可输入对应十进制值。查询只匹配精确镜像解出的子 ID，包组使用其中命名子包的
ID，不从外层 `raw_param` 或 Multi 的匿名 `+0x08` 推断。
汇总保留 `child_event_id_unavailable_count`，输出未经修改的 JSONL 行。
这些镜像标签不证明隐身状态或实际连续击杀。

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

`16.15` 的 `decode` 与 `analyze` 共用旧管线。`16.19` 通过精确 build API 执行 `--events` 指定的实验能力；`capabilities` 可先查询精确 build 和外部输入缺项，不会创建输出目录。对 `unit_apply_damage_packet` 和 `show_health_bar_packet`，它还检查所选 Python 能否导入 Unicorn；镜像哈希和逐包原生解码仍留到实际 `decode`/`batch` 执行。`batch` 逐回放记录成功、候选和失败，不以某项成功掩盖另一项失败。`validate` 额外运行完整 Node 回归，可用 `--details-dir` 做验证对照；Match Details 不进入解码规则。

默认时间线保留前 `--timeline-limit` 条。`--sample-stride` 仅为兼容旧命令保留，已弃用且不改变输出；不再计算最终会被截掉的间隔样本。

主要产物包括 `replay_analysis.json`、容器与 packet 清单、时间线样本、原始锚点、各事件 JSONL 和 ADC 死亡窗口；V2 输入提供对应 Ward/position 数据。每条事实保留适用的回放 SHA、packet/offset/hash、版本和证据等级。没有执行语义解码时，报告不会把静态能力表或空事件数组说成已验证结果。

默认不输出 Riot ID / PUUID；`--include-private-metadata` 只用于显式本地需求，不应用于外发数据。分析产物仍可能包含本地路径、回放身份和原始包摘录，不能将“省略玩家字段”等同于可直接公开。外部文件运行前后监测可通过 `ROFL_UPSTREAM_PATHS` 配置。

## 验证与打包

| 命令 | 范围 / 输入 |
| --- | --- |
| `npm test` / `npm run test:public` | portable、维护及 16.19 合成解码/CLI 测试；不需要私有回放 |
| `npm run test:16-19` | 当前 16.19 候选解码、独立能力和 CLI/API 合成测试；不等于真实回放验证 |
| `npm run test:16-19-revive-ally` | OnReviveAlly 候选解码及 CLI/API 合成测试；有本机精确镜像与原始包输入时另运行真实包原生验证，否则该输入专属检查明确跳过 |
| `npm run test:16-19-first-blood-assist` | OnFirstBloodAssist 子包候选、同长度异类对照及 CLI/API 合成测试；真实回放另用精确镜像运行 |
| `npm run test:16-19-objective-steal` | 两种精确 821 子包标记、失败状态及 CLI/API 合成测试；设置 `ROFL_821_RUNTIME_IMAGE` 和 `ROFL_821_REPLAY_DIR` 后运行两份原始回放的原生正例与负例，否则三项私有输入测试明确跳过 |
| `npm run test:16-19-turret-die` | OnTurretDie 候选解码及 CLI/API 合成测试；有本机精确镜像与原始包输入时另运行真实包原生验证，否则该输入专属检查明确跳过 |
| `npm run test:16-19-turret-first-blood` | OnTurretFirstBlood 候选解码及 CLI/API 合成测试；有本机精确镜像与原始包输入时另运行真实包原生验证，否则该输入专属检查明确跳过 |
| `npm run test:16-19-hq-kill` | OnHQKill 包级候选解码及 CLI/API 合成测试；有本机精确镜像与原始包输入时另运行真实包原生验证，否则该输入专属检查明确跳过 |
| `npm run test:16-19-unit-apply-damage` | UnitApplyDamage 包级候选、原生负例、CLI/API 和保存结果查询；真实回放与精确镜像缺失时，输入专属整合测试明确跳过，执行原生检查还需 Python + Unicorn |
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
