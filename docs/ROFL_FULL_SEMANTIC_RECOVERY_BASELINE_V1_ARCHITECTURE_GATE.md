# Architecture gate

Gate ID: `ROFL_FULL_SEMANTIC_RECOVERY_BASELINE_V1_ARCHITECTURE_GATE`  
Date: `2026-08-20`  
Stage / task: current-build full protocol-semantic baseline and migration framework  
Proposed owner project: `ROFL_PARSER`  
`PROJECT_CONTEXT_LOADED = YES`  
Related `WHY_THIS_STAGE_EXISTS.md`:
`docs/ROFL_FULL_SEMANTIC_RECOVERY_BASELINE_V1_WHY_THIS_STAGE_EXISTS.md`

## Search-before-build evidence

1. Partial implementations exist and will be extended: `src/semantic_api.js`,
   `src/semantic_pipeline.js`, `src/capability_manifest.js`,
   `src/build_registry.js`, `src/generic_entity_registry.js`,
   `scripts/build_packet_coverage_inventory.js`, exact-build decoder profiles, and
   the current field/runtime research tools.
2. Preserved experiments and evidence are directly reusable:
   `artifacts/semantic_coverage_v1`, `artifacts/multi_build_rofl_support_v1`,
   `artifacts/new_build_rofl_compatibility_gate_v1`, verified 16.15 combat and
   protection artifacts, 16.16 Ward/Path/Level artifacts, current Hero Combat State
   artifacts, and their negative evidence.
3. Map Knowledge is not copied. Parser scope is limited to protocol-observed
   coordinates, identities, lifecycle, and state. Strategic regions, geometry,
   topology, camp meaning, and behavior remain owned by Inference Lab.
4. Existing verified semantics and coarse DETAILS anchors may validate candidates
   but never substitute for absent ROFL fields or silently upgrade precision.
5. The Parser already exposes build-bound semantic interfaces and several verified
   capabilities. This work generalizes their manifests and coverage instead of
   creating a competing decoder or downstream truth.
6. Akari and Research Collector acquisition are not reimplemented. Only authorised
   local runtime images, Replay fixtures, and read-only paired evidence are inputs.

Decision: `EXTEND + VALIDATE + GENERALIZE`; preserve published interfaces, raw
evidence, partial research, and failures. Do not rewrite from scratch.

## Required questions

1. Final user value: one honest, machine-readable map of the gameplay facts the
   current Replay build can and cannot provide, plus canonical semantic output.
2. North Star contribution: broader exact ROFL truth and calibration coverage with
   lower future patch-migration cost.
3. Owner: `ROFL_PARSER`.
4. Reason: packet/component registration, binary layouts, exact-build decoding,
   semantic events, evidence grades, APIs, and capability manifests are Parser
   responsibilities.
5. No other project owns protocol truth. Collector/Akari own acquisition; Inference
   Lab owns map knowledge, multisource calibration, and behavior; Akari owns product
   runtime/UI.
6. Related registry entries include `ROFL_CONTAINER_INSPECTION`,
   `SEMANTIC_API_AND_CAPABILITY_MANIFEST`, `HERO_PATH`, `LEVEL_TRANSITION`,
   `WARD_SPAWN`, `ROFL_16_15_COMBAT_AND_PROTECTION`,
   `ROFL_16_16_HERO_DAMAGE`,
   `ROFL_16_16_HERO_DEATH_CAST_BUFF_PROTECTION`, `SWEEPER_HELD`,
   `SWEEPER_ACTIVATION`, `INVENTORY_STATE`, and
   `ORDINARY_MONSTER_CAMP_CLEAR`. The task extends or validates these; it does not
   duplicate an available downstream capability.
7. Existing PARTIAL/INCOMPLETE work is the primary input: current inventories,
   generic entity evidence, semantic coverage V1, Hero Combat State research, and
   exact-build migration/regression tooling.
8. Inputs and provenance:
   - Current runtime EXE `D:\\WeGameApps\\英雄联盟\\Game\\League of Legends.exe`,
     displayed version `16.16.805.442`, SHA-256
     `82edff100aaf5b73d519addd177bff61fd15860f44f46b79f441f35325cdbb4e`.
   - Preserved mapped runtime exact build `16.16.805.0442`, SHA-256
     `0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55`.
   - Authorised local 16.16 Replay fixtures and a read-only Collector-owned paired
     corpus with per-source hashes. DETAILS/Timeline remains a separate evidence
     tier. No Map Knowledge version is applicable to protocol recovery.
   - Legacy 16.15 evidence is secondary and reused only when inexpensive; no
     dedicated expensive legacy reverse engineering is authorized.
9. Consumers are Inference Lab and published Parser adapters via canonical semantic
   bundles and capability manifests. No feature pack is published by this gate.
10. Frozen baselines are not modified. New manifests, evidence, and profiles are
    additive. `JUNGLE_OBJECTIVE_HOLDOUT_V1` remains entirely inaccessible.
11. No map dependency is introduced, so no stale/unbound map is used.
12. No project drift, decoder fork, network dependency, behavior inference, or
    product dependency on research code is introduced.
13. The work is `OFFLINE_RESEARCH_ONLY`; it supplies precise features, regression
    truth, patch migration, and future DETAILS proxy calibration for progressive
    early profiles.

## Evidence and failure policy

- Every field and capability remains exact-build, source-specific, and graded.
- Missing/unverified data is null/unknown/unavailable, never false or zero.
- No observed packet, unknown entity, failed decoder, or counterexample is silently
  discarded.
- Runtime names, packet frequency, payload shapes, and correlations rank candidates
  only. Promotion requires layout proof, positive anchors, counterexamples, and
  regression evidence proportional to the claim.
- No nearest-build fallback or silent profile reuse is permitted.
- Research preservation is additive; protected Holdout content is excluded from all
  inventories and tests.

## Decision

Owner confirmation: `ROFL_PARSER`  
Reviewer: Codex startup architecture review  
Rationale and evidence links: the requested outputs are Parser-owned exact-build
protocol semantics; extensive partial implementations and evidence exist; the work
extends them without crossing acquisition, map, inference, or product boundaries.

```text
ARCHITECTURE_GATE = PASS
```
