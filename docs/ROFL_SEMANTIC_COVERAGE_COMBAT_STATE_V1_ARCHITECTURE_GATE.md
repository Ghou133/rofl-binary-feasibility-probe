# Architecture gate

Gate ID: `ROFL_SEMANTIC_COVERAGE_AND_COMBAT_STATE_V1_ARCHITECTURE_GATE`
Date: `2026-08-20`
Stage / task: semantic coverage, combat-state priority, and long-term exact-build compatibility
Proposed owner project: `ROFL_PARSER`
`PROJECT_CONTEXT_LOADED = YES`
Related stage rationale: `docs/ROFL_SEMANTIC_COVERAGE_COMBAT_STATE_V1_WHY_THIS_STAGE_EXISTS.md`

## Search-before-build evidence

1. Partial implementation exists: `src/semantic_api.js`,
   `src/semantic_pipeline.js`, `src/build_registry.js`, and the exact-build
   decoder profiles already expose build-gated semantic surfaces.
2. Older evidence is reusable: `docs/PROTECTION_V4_CAPABILITY_MATRIX.md`,
   `docs/PROTECTION_V4_ON_EVENT_RE_REPORT.md`,
   `research-v3/docs/COMBAT_RESEARCH_STATUS.md`, and preserved `artifacts/`
   record verified, candidate, rejected, and unavailable results.
3. Map Knowledge is not required. Region/geometry meaning remains owned by
   Inference Lab and is outside this gate.
4. Existing approximations are preserved but not promoted: combat attribution
   research, protection context, and candidate packet routes may guide probes;
   none becomes direct protocol truth without exact-build evidence.
5. Parser already exposes 16.15 Hero Death, Damage, CastSpell, Buff, Shield,
   reported Heal, Hero Path, Ward, LevelTransition, and participant semantics;
   16.16 has verified P0/Vision surfaces and disabled combat candidates.
6. Akari acquisition/enemy identification is unrelated to implementation here.
   Akari remains the owner of runtime acquisition and may consume only published
   interfaces.

Decision: `EXTEND + VALIDATE + GENERALIZE`; do not rewrite verified decoders.

## Required questions

1. Final user value: reusable, versioned Replay combat truth with honest gaps.
2. North Star contribution: improves precise ROFL evidence and calibration
   truth while preserving progressive downstream source separation.
3. Owner: `ROFL_PARSER`.
4. Reason: packet routes, state replication, field semantics, exact-build
   profiles, evidence grades, validation, and the semantic API are Parser-owned.
5. No other project owns these responsibilities. Inference Lab owns mechanics,
   maps, calibration, and behavior meaning; Collector and Akari own acquisition.
6. Related registry entries are `SEMANTIC_API_AND_CAPABILITY_MANIFEST`,
   `ROFL_16_15_COMBAT_AND_PROTECTION`, `ROFL_16_16_HERO_DAMAGE`,
   `ROFL_16_16_HERO_DEATH_CAST_BUFF_PROTECTION`, plus existing Hero Path,
   LevelTransition, Ward, Sweeper, inventory, and camp-clear boundaries.
7. Yes. Protection V4, combat V3, multi-build support, Ward recovery, and
   new-build compatibility work are explicitly continued.
8. Input owner/source: immutable `ROFL` containers acquired by Collector/Akari;
   local authorised fixtures are exact build `16.15.801.3452` and preserved
   evidence for `16.16.805.0442`, with Replay SHA, runtime/profile provenance,
   decoder version, and semantic schema version. No Map Knowledge input is used.
9. Output consumers: Inference Lab and published parser adapters through a
   stable semantic API/capability manifest. This stage does not publish an
   Inference feature pack or authorize Akari product use.
10. Frozen baselines are not modified or reinterpreted. New manifests and
    regression outputs are additive; raw Replay and prior decode outputs remain
    immutable.
11. No map dependency is introduced.
12. No responsibility drift, decoder copy, network dependency, or product-layer
    research dependency is introduced.
13. Work is `OFFLINE_RESEARCH_ONLY`; its value is exact feature evidence,
    cross-build reuse, regression safety, and future DETAILS calibration for
    early progressive profiles.

## Evidence and failure policy

- Capability and field status remains build-specific and source-specific.
- Missing/unverified values are `null`/unknown, never zero or false.
- Nearest-build and silent cross-build decoder fallback remain forbidden.
- Mechanics-derived mitigation is not labeled `VERIFIED_DIRECT`.
- Existing raw, verified, negative, candidate, and historical assets are
  preserved; any later destructive migration requires a preservation gate.

## Decision

Owner confirmation: `ROFL_PARSER`
Reviewer: Codex startup architecture review
Rationale: the requested work is an explicit extension of Parser-owned
protocol semantics and existing exact-build assets, with downstream ownership
and evidence boundaries preserved.

```text
ARCHITECTURE_GATE = PASS
```

