# Why this stage exists

Stage ID: `ROFL_SEMANTIC_COVERAGE_AND_COMBAT_STATE_V1`
Owner: `ROFL_PARSER`
Date: `2026-08-20`

## User value

Future combat, survivability, support, and patch-comparison research needs one
auditable Replay semantic layer instead of topic-specific decoder forks.

## North Star value

This stage strengthens the exact Replay evidence tier used by Inference Lab for
precise features and DETAILS calibration. It does not perform behavioral
inference, acquire Replay files, own map truth, or publish product UI.

## Why now

The repository already preserves verified 16.15 combat/protection semantics,
partial 16.16 semantics, disabled candidates, raw inventories, and new-build
compatibility tooling. Those assets need a machine-readable capability source
of truth and a common cross-build schema before more patch-specific research
accumulates.

## Scope

The first stage inventories and preserves existing capabilities, creates the
canonical capability manifest and compatibility foundation, audits packet and
entity coverage, performs bounded HP/combat-state candidate probing, and adds
regression gates. Unknown or unavailable fields remain explicit.

## Non-goals

No map/behavior meaning, mechanics-formula result, live acquisition, player
profile, Akari runtime/UI, or offline corpus ownership is introduced here. Raw
Replay inputs and historical decode outputs remain immutable.

Realtime value classification: `OFFLINE_RESEARCH_ONLY`, with downstream value
for future `PRE_GAME_AVAILABLE` and `EARLY_GAME_AVAILABLE` calibrated outputs.

