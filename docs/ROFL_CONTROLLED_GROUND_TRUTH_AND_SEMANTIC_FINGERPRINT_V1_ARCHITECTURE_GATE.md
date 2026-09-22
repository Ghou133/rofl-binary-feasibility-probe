# Architecture gate

Gate ID: `ROFL_CONTROLLED_GROUND_TRUTH_AND_SEMANTIC_FINGERPRINT_V1_ARCHITECTURE_GATE`  
Date: `2026-08-21`  
Stage / task: controlled semantic ground truth, semantic fingerprints, and automatic migration oracles  
Proposed owner project: `ROFL_PARSER`  
`PROJECT_CONTEXT_LOADED = YES`  
Related `WHY_THIS_STAGE_EXISTS.md`:
`docs/ROFL_CONTROLLED_GROUND_TRUTH_AND_SEMANTIC_FINGERPRINT_V1_WHY_THIS_STAGE_EXISTS.md`

## Search-before-build evidence

1. Partial implementations exist in `src/canonical_semantic_schema.js`,
   `src/semantic_state_engine.js`, `src/full_semantic_baseline.js`,
   `src/full_semantic_migration.js`, `src/details_combat_state_anchors.js`, and
   `src/deep_recovery_decision_ledger.js`. They already enforce canonical fields,
   exact Replay/build scope, provenance, state timelines, migration diffs,
   conservation, decisions, and negative evidence.
2. Older reusable evidence includes
   `artifacts/multi_build_rofl_support_v1/semantic_fingerprints.json`, the V2
   saturation/queue/decision artifacts, P0 DETAILS anchors, field profiles,
   runtime registration maps, exact-build capability profiles, and controlled
   Replay request specifications in the V2 report. The existing fingerprint
   artifact is capability-specific and does not yet provide the requested generic
   schema, oracle, decision engine, importer, or exception registry.
3. Map Knowledge is neither required nor copied. Protocol coordinates remain
   coordinates and are not promoted to regions, objectives, lanes, or strategy.
4. Existing capability/state/negative-evidence infrastructure approximates parts
   of the request and will be generalized, not rewritten.
5. Parser currently exposes canonical HeroState placeholders plus verified
   Damage, Death, Respawn, Level, Path, Ward, Buff/Cast/Protection, item-state,
   and gameplay-tail surfaces. P0 continuous HP/defense fields remain explicitly
   `UNAVAILABLE` for `16.16.805.0442`.
6. Akari/Collector acquisition is not duplicated. This stage only imports
   explicitly supplied lawful local Replay fixtures and independent truth records.

Decision: `EXTEND + VALIDATE + GENERALIZE`.

## Required questions

1. Final user value: prove a semantic once with high-quality independent truth,
   preserve its complete identity, and make ordinary future patch migration
   automatic rather than repeatedly manual.
2. North Star contribution: expand reliable exact Replay truth and make that truth
   reproducible across exact builds for later calibrated downstream use.
3. Owner: `ROFL_PARSER`.
4. Reason: protocol semantic identity, exact-build routes, evidence grades,
   semantic API publication, capability manifests, and decoder migration
   regression are Parser responsibilities.
5. No other project owns protocol truth. Inference Lab retains map knowledge,
   DETAILS/ROFL proxy calibration, mechanics/behavior inference, confidence, and
   feature packs; Collector/Akari retain their acquisition roles; Akari retains
   product runtime/UI.
6. Related capability entries: `SEMANTIC_API_AND_CAPABILITY_MANIFEST`,
   `ROFL_16_16_FULL_SEMANTIC_BASELINE`, `ROFL_16_16_HERO_DAMAGE`,
   `ROFL_16_16_HERO_DEATH`, `ROFL_16_16_HERO_RESPAWN`,
   `ROFL_16_16_SCOREBOARD_XP_LANE_CS`,
   `ROFL_16_16_CAST_BUFF_PROTECTION`, `ROFL_16_16_GAMEPLAY_TAIL`,
   `INVENTORY_TRANSACTION`, `INVENTORY_STATE`, `SWEEPER_HELD`, and
   `SWEEPER_ACTIVATION`. Existing capabilities are extended; none is silently
   replaced or promoted.
7. Existing `PARTIAL`/`CANDIDATE`/`UNAVAILABLE` research is the direct starting
   point: saturation artifacts, decision ledger, negative registry, current
   fingerprints, exact-build profiles, migration pipeline, state engine, and
   controlled-Replay specifications.
8. Inputs: Parser-owned exact-build semantic artifacts and lawful fixtures;
   Collector-owned paired DETAILS/Replay exports when explicitly supplied;
   machine/manual independent truth with source provenance. Current build is
   `16.16.805.0442`; every Replay is SHA-256 bound; runtime evidence is bound to
   its registered exact image. Map version is not applicable to protocol-field
   identity. No nearest-build evidence is accepted.
9. Consumers: Parser regression/migration tooling, capability manifest, and
   semantic API; Inference Lab may consume only published verified fields. No
   feature pack is published by this stage, and Akari receives no research-code
   dependency.
10. Frozen V1/V2 baselines are not modified or reinterpreted. New schemas,
    fingerprints, oracles, decisions, exceptions, and reports are additive and
    stage-versioned. The protected Holdout remains entirely inaccessible.
11. No map dependency, old route fallback, unbound runtime, or
    `NEEDS_REVALIDATION` result is treated as verified.
12. No decoder fork, map/behavior ownership drift, acquisition/network work, or
    research-to-product dependency is introduced.
13. The stage is `OFFLINE_RESEARCH_ONLY`; its value is exact semantic validation,
    durable regression, low-cost patch migration, and higher-quality future
    calibration for `PRE_GAME_AVAILABLE`/`EARLY_GAME_AVAILABLE` profiles.

## Evidence and failure policy

- Exact build, Replay SHA, timestamp/entity scope, field-level evidence, truth
  source, structural candidate, and source hashes are mandatory where applicable.
- Semantic truth and build route are stored separately.
- Missing/unverified fields remain null/unknown/unavailable, never false or zero.
- Structural names, value resemblance, frequency, formulas, and timestamp
  proximity cannot independently promote a semantic.
- Automatic promotion requires a unique structural candidate plus passing
  behavioral, cross-field, ground-truth, negative-control, exception, and
  regression gates.
- Manual validation is forbidden by default and may be generated only for a
  specific unresolved capability after automatic evidence is exhausted.
- No silent discard, nearest-build fallback, map/behavior inference, acquisition,
  or protected-Holdout access is permitted.

## Decision

Owner confirmation: `ROFL_PARSER`  
Reviewer: Codex startup architecture review  
Rationale: the task generalizes existing Parser-owned exact-build semantic,
provenance, negative-evidence, state, and migration infrastructure without moving
map, behavioral calibration, acquisition, runtime, or UI responsibilities.

```text
ARCHITECTURE_GATE = PASS
```
