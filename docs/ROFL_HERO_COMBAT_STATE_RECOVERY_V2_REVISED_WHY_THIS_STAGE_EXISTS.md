# Why this stage exists

Stage ID: `ROFL_HERO_COMBAT_STATE_RECOVERY_V2_REVISED`
Owner: `ROFL_PARSER`
Date: `2026-08-20`

## User value

Recovering exact-build hero HP, maximum HP, armor, and magic resistance makes
Replay combat evidence substantially more useful and auditable. It enables later
consumers to compare recorded damage with observed state changes without copying
decoder logic or guessing missing values.

## North Star value

This stage strengthens the precise ROFL evidence tier used by Inference Lab for
validated features and DETAILS calibration. The Parser recovers protocol facts
only; map truth, behavioral interpretation, Replay acquisition, runtime product
orchestration, player profiles, and UI remain outside this project.

## Why now

The previous semantic-coverage stage already created exact-build manifests,
packet inventory, generic entity evidence, combat anchors, multi-build support,
and regression gates. The installed runtime and newest local Replay fixtures are
both exact build `16.16.805.0442`, so the research can move from structural
candidate ranking to runtime registration/deserializer recovery on the current
playable build.

## Scope

Primary scope is direct recovery and validation of `CURRENT_HP`, `MAX_HP`,
`ARMOR`, and `MAGIC_RESIST`, followed by other hero combat stats and initial
Damage/Defense/HP cross-validation when evidence permits. Work extends existing
runtime, inventory, profiler, semantic-schema, and regression assets. Version
migration is exact-build and low-cost where possible; dedicated expensive legacy
reverse engineering is not a project KPI.

## Non-goals

No map or tactical meaning, behavior conclusion, network acquisition, Collector
function, Akari runtime/UI, jungle/vision/objective expansion, or mechanics-based
substitution for direct protocol evidence is introduced. Missing or unverified
fields remain null/unknown.

Realtime value classification: `OFFLINE_RESEARCH_ONLY`, with downstream value
for future calibrated `PRE_GAME_AVAILABLE` and `EARLY_GAME_AVAILABLE` outputs.

