# ROFL Analyzer

精确版本绑定的《英雄联盟》`.rofl` 回放研究工具：解析容器和数据包，输出带来源、证据等级和明确边界的语义事实。

> **当前开发分支：16.19。** `codex/16-19-development` 已获授权继续适配、接通 CLI/API 并研究新字段。`16.19.820.7193` 的死亡候选输出仍是实验结果，不是已发布的可靠语义能力。2026-08-21 的公开语义基线及 `SOURCE_FROZEN_DURING_MIGRATION` 记录保留为历史状态；本分支不覆盖旧版证据。

[使用与维护](docs/PUBLIC_DEVELOPMENT.md) · [代码结构](ARCHITECTURE.md) · [路线图](ROADMAP.md) · [历史验证记录](VALIDATION_STATUS.md) · [AI 接手入口](AI_HANDOFF.md)

## 能力与入口

**项目库支持的字段，不等于主 CLI 已经接入的字段。** 本仓库不是通用回放查看器，也不会对未知补丁回退使用邻近版本的 opcode、RVA 或字段布局。

| 入口 / 层 | 当前提供 | 使用边界 |
| --- | --- | --- |
| `inspect` / `src/rofl.js` | RIOT 头、metadata、chunk/Zstd、packet framing、原始清单与锚点 | 容器结构可解析，不代表该版本语义已验证 |
| `capabilities` | 从回放容器读取完整 build，查询已登记能力、入口及尾部字段输入预检 | 不解压 packet、不运行语义解码；候选能力仍需逐回放校验 |
| `decode` / `analyze` / `batch` / `validate` | `16.15.801.3452` 旧版整合管线；16.19 精确 build 的指定能力实验入口 | 16.19 必须显式传 `--events`；16.16 语义 API 尚未由主 CLI 分发；`validate` 还会运行完整 Node 套件 |
| `16.19.820.7193 --events hero_death` | HN/KR 结构指纹与回放尾部死亡总数同时匹配时，输出候选受害者和回放时间 | 仅写入 `hero_death_candidates`，状态为 `CANDIDATE`；无杀手、助攻或重生推断，其他完整 build 不复用 |
| `16.19.820.7193 --events hero_death_timer` | HN 路由的计时 float、同刻 Hero_Die 和后续复活时间相互校验时，输出候选计时秒数 | 仅写入 `hero_death_timer_candidates`；目前只覆盖 HN 路由，KR 回放会报 `PROFILE_UNAVAILABLE`，不产生确认的死亡或重生事件 |
| `16.19.820.7193 --events hero_respawn` | 将 HN 已观察且与计时包唯一配对的 `0x0357` 包输出为候选复活时点 | 仅写入 `hero_respawn_candidates`；依赖完整的 HN 计时候选校验，不补造回放结束后的复活 |
| `16.19.820.7193 --events hero_level_state` | HN `0x02b3` 包中观察到的候选英雄等级值及原始包来源 | 仅写入 `hero_level_state_candidates`；逐参与者列出未观察到的升级值，不补造事件；KR 路由未适配 |
| `16.19.820.7193 --events hero_minions_killed_snapshot` | HN `0x0276` HeroStats keyframe 中已观察到的候选 `MINIONS_KILLED` 数值 | 仅写入 `hero_minions_killed_snapshot_candidates`；不是连续补刀事件，尾部差额不插值；KR 同号包不匹配 HN 指纹 |
| `16.19.820.7193 --events hero_experience_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x28` 浮点候选经验值 | 仅写入 `hero_experience_snapshot_candidates`；小数及尾部差额保留，不推导升级或经验获取时点；KR 的 HN profile 不可用 |
| `16.19.820.7193 --events hero_gold_earned_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x38` 浮点候选已赚金币值 | 仅写入 `hero_gold_earned_snapshot_candidates`；一场 HN 回放的字段相关性，不推导金币收入事件；KR 的 HN profile 不可用 |
| `16.19.820.7193 --events hero_gold_spent_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x34` 候选已花金币值 | 仅写入 `hero_gold_spent_snapshot_candidates`；保留数值下降，不推导退款、出售或购买；KR 的 HN profile 不可用 |
| `16.19.820.7193 --events hero_champion_kills_snapshot` | 同一 HN HeroStats keyframe 中两处镜像值一致的候选英雄击杀数 | 仅写入 `hero_champion_kills_snapshot_candidates`；`0x4c` 与 `0x33c` 尚未确定唯一存储位置，不推导逐次击杀事件 |
| `16.19.820.7193 --events hero_deaths_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x50` 候选死亡次数 | 仅写入 `hero_deaths_snapshot_candidates`；与本回放死亡候选累计数吻合，不推导新的死亡事件或时间 |
| `16.19.820.7193 --events hero_assists_snapshot` | 同一 HN HeroStats keyframe 中已观察到的 `0x54` 候选助攻次数 | 仅写入 `hero_assists_snapshot_candidates`；缺少独立助攻事件锚点，不推导助攻时点或归属 |
| `src/semantic_api.js` 与精确 build profiles | `16.16.805.0442` 的 HeroPath、等级、WardSpawn、伤害、死亡、重生、XP/lane-CS keyframe、受限 ItemState 和 gameplay-tail 等 | 独立 API 的逐字段能力；需要外部精确镜像、profiles 或对应已验证输入，不是主 CLI 的完整分析模式 |
| V2 Ward / Path | 已验证位置、守卫事件及受限派生关联 | 来源 SHA 必须与回放一致；类型、匹配、生命周期和位置插值与直接字段分级 |
| `research-v3/`、`research-v4/` | DuckDB 研究查询、保护量增量表和验证器 | 保留的真实功能，不是因版本号旧就可删除的目录；全量重建需要私有输入 |

各版本都保留“直接、派生、部分、候选、不可用”的区别。完整 Cast/Buff/Protection、CurrentHP、当前 Armor/MR、护盾实例与剩余量、effective heal/overheal、普通野怪清野等能力不能从现有有限字段外推。`stats_at` / `statsAt` 有逐字段 fail-closed 接口，但当前不发布 MaxHP/Armor/MR 数值；库存部分状态不是通用买卖事件。

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
build 注册表中的候选能力，运行时镜像对这些候选路径不要求；查询不是成功解码证明。
16.15/16.16 的外部文件仅按完整管线入口做存在性预检；单项能力的依赖和
镜像哈希仍标记为未核验。

对完整版本为 **16.19.820.7193** 的回放运行实验死亡候选解码：

```powershell
node src/cli.js decode "D:\Replays\example-16.19.820.7193.rofl" `
  --events hero_death --out-dir "work\16-19-death-candidate"
```

`semantic_run.json` 逐能力记录实际执行、候选、缺输入、不支持和失败；
`hero_death_candidates.jsonl` 只在结构指纹与死亡总数校验均通过时产生。
`inspect` 不要求镜像或语义 profile。实验候选没有使用运行时镜像，传入镜像路径不会使其成为已验证语义。

对 HN 路由的同一完整 build，可单独选择计时候选，或用
`--events hero_death,hero_death_timer` 一起运行。计时输出包含原始包引用、
候选参与者、解出的秒数，以及存在匹配时的复活包引用；它要求十名参与者的死亡总数、
同刻 Hero_Die 配对及复活时序都通过校验。未执行的旧版事件汇总计数为
`null`，不会把未解码误写成零事件。

`--events hero_respawn` 可单独查询已观察到的候选复活时点，也可与计时候选
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
  --events hero_minions_killed_snapshot,hero_experience_snapshot,hero_gold_earned_snapshot,hero_gold_spent_snapshot,hero_champion_kills_snapshot,hero_deaths_snapshot,hero_assists_snapshot `
  --out-dir "work\16-19-hero-stats-snapshots"
```

输出包含每名英雄的候选快照值与原始包引用，并在逐能力结果中列出最后快照到回放尾部的差额。
它不推导两次 keyframe 之间的补刀、经验、金币变动或英雄击杀时间，也不发布为确认事件。

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
