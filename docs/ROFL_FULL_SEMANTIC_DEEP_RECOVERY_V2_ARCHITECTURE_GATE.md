# Architecture gate

Gate ID: `ROFL_FULL_SEMANTIC_DEEP_RECOVERY_V2_ARCHITECTURE_GATE`  
Date: `2026-08-20`  
Stage / task: exact-build deep semantic recovery and saturation  
Proposed owner project: `ROFL_PARSER`  
`PROJECT_CONTEXT_LOADED = YES`  
Related `WHY_THIS_STAGE_EXISTS.md`:
`docs/ROFL_FULL_SEMANTIC_DEEP_RECOVERY_V2_WHY_THIS_STAGE_EXISTS.md`

## Search-before-build evidence

1. Partial implementations exist: the V1 full baseline and A–Z report, 69-capability
   manifest, canonical API/state engine, runtime callback/factory/deserializer maps,
   field profiler, semantic migration queue, and domain-specific exact-build decoders.
2. Reusable experiments include HeroStats/Damage/HeroDeath validation, four safe P0
   paired DETAILS anchors, Buff/Spell/Inventory runtime candidates, item-route
   differential evidence, high-frequency raw profiles, and the negative registry.
3. Map Knowledge is not copied or used to create protocol semantics. Only
   protocol-observed identities, positions, state, and lifecycle are in scope.
4. Existing Damage/Death/Path/Level/Ward/scoreboard semantics are anchors and
   regressions, not rewrite targets.
5. Akari/Collector acquisition is not duplicated. Inputs are authorised local Replay
   fixtures, the pinned runtime image, generated artifacts, and explicit read-only safe
   paired evidence.

Decision: `EXTEND + VALIDATE + GENERALIZE`.

## Required questions

1. Final user value: recover substantially more objective Replay facts and leave every
   remaining high-value hypothesis with a reproducible decision and required evidence.
2. North Star contribution: expand high-precision ROFL truth and calibration coverage.
3. Owner: `ROFL_PARSER`.
4. Reason: binary routes, layouts, decoders, evidence grades, semantics, and manifests
   are Parser responsibilities.
5. No other project owns protocol truth. Inference Lab owns map/behavior/calibration;
   Collector and Akari own their respective acquisition paths; Akari owns product/UI.
6. Related registry entries: `ROFL_16_16_HERO_DAMAGE`,
   `ROFL_16_16_HERO_DEATH`, `ROFL_16_16_SCOREBOARD_XP_LANE_CS`,
   `ROFL_16_16_CAST_BUFF_PROTECTION`, `INVENTORY_STATE`, `SWEEPER_HELD`,
   `SWEEPER_ACTIVATION`, and `ORDINARY_MONSTER_CAMP_CLEAR`.
7. Existing PARTIAL/CANDIDATE/UNAVAILABLE research is the direct starting point; no
   baseline infrastructure is rebuilt.
8. Inputs: exact build `16.16.805.0442`; pinned runtime SHA-256
   `0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55`;
   explicit local Replay hashes and source-bound safe paired DETAILS. No map version is
   applicable to protocol recovery. 16.15 is low-cost side evidence only.
9. Consumers remain canonical Parser adapters and Inference Lab through published
   manifests. Candidate research grants no product permission.
10. Frozen baselines are preserved; V2 evidence is additive. Protected Holdout content
    remains entirely inaccessible.
11. No map dependency or nearest-build fallback is introduced.
12. No ownership drift, decoder fork, network dependency, behavior inference, or
    product dependency on research code is introduced.
13. This is `OFFLINE_RESEARCH_ONLY`, valuable for precise facts, regression, patch
    migration, and future calibration.

## Evidence and failure policy

- Exact-build, field-level evidence and provenance are mandatory.
- UNKNOWN/null is never coerced to false or zero.
- Names, structure, frequency, and near-time correlation remain candidate evidence.
- Promotion requires positive anchors, counterexamples, cross-Replay consistency, and
  regression proportional to the claim.
- No silent discard, nearest-build fallback, or protected-Holdout access is permitted.

## Decision

Owner confirmation: `ROFL_PARSER`  
Reviewer: Codex startup architecture review  
Rationale: the task extends existing Parser-owned exact-build research and preserves
all acquisition, map, inference, and product boundaries.

```text
ARCHITECTURE_GATE = PASS
```
