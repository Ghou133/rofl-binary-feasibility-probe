# Architecture gate

Gate ID: `ROFL_HERO_COMBAT_STATE_RECOVERY_V2_REVISED_ARCHITECTURE_GATE`
Date: `2026-08-20`
Stage / task: current-build Hero Combat State deep recovery and initial closure
Proposed owner project: `ROFL_PARSER`
`PROJECT_CONTEXT_LOADED = YES`
Related `WHY_THIS_STAGE_EXISTS.md`:
`docs/ROFL_HERO_COMBAT_STATE_RECOVERY_V2_REVISED_WHY_THIS_STAGE_EXISTS.md`

## Search-before-build evidence

1. A partial implementation already exists. `src/combat_state_candidate_probe.js`,
   `scripts/probe_combat_state_candidates.js`, `src/capability_manifest.js`,
   `src/build_registry.js`, and exact-build decoder profiles already preserve the
   candidate, manifest, build-binding, and regression foundations.
2. Older experiments contain directly useful evidence. `docs/defense_state_research.md`,
   `docs/combat_semantics_status.md`,
   `artifacts/semantic_coverage_v1/combat_candidate_report.json`, the preserved
   runtime images, 16.15 Damage/Death/Protection anchors, and multi-build artifacts
   provide positive, negative, and candidate evidence to extend.
3. Map Knowledge is not required. This task decodes protocol state only; no
   strategic region, geometry, or map interpretation is introduced.
4. Existing approximations are retained only as anchors. Damage, reported heal,
   shield generation/absorption, LevelTransition, structural packet ranking, and
   runtime class-name occurrences can rank or validate candidates but cannot
   substitute for direct HP/defense fields.
5. Parser currently exposes exact-build semantic APIs and manifests, verified
   16.15 combat/protection anchors, and partial 16.16 semantics. The registry marks
   16.16 Hero Damage as `CANDIDATE` and the remaining 16.16 combat surface as
   `UNAVAILABLE`; no downstream truth is being duplicated.
6. Akari acquisition and enemy identification are not implemented here. Local
   authorised Replay fixtures and runtime images are read-only research inputs;
   acquisition ownership remains with Research Collector/Akari.

Decision: `EXTEND + VALIDATE + GENERALIZE`; preserve verified decoders and prior
negative evidence instead of rewriting them.

## Required questions

1. Final user value: reliable exact-build hero HP/defense state and an auditable
   foundation for combat reconstruction.
2. North Star contribution: increases high-precision ROFL feature/calibration
   truth while keeping source uncertainty and ownership explicit.
3. Owner: `ROFL_PARSER`.
4. Reason: runtime registration tracing, packet/component routes, deserializers,
   field layouts, exact-build evidence grades, semantic APIs, and capability
   manifests are Parser-owned protocol semantics.
5. No other project owns this responsibility. Inference Lab owns mechanics,
   fusion, calibration, map knowledge, and behavior meaning; Collector/Akari own
   acquisition; Akari owns product runtime/UI.
6. Related registry entries are `ROFL_CONTAINER_INSPECTION`,
   `SEMANTIC_API_AND_CAPABILITY_MANIFEST`, `LEVEL_TRANSITION`,
   `ROFL_16_15_COMBAT_AND_PROTECTION`, `ROFL_16_16_HERO_DAMAGE`,
   `ROFL_16_16_HERO_DEATH_CAST_BUFF_PROTECTION`, and `INVENTORY_STATE`.
   The work extends missing Parser capability; it does not reimplement an
   available downstream capability.
7. Yes. The prior stage is explicitly `PARTIAL`: current/max HP, armor, and MR
   remain unavailable while structural candidates and name-only runtime evidence
   are preserved for continuation.
8. Input owner/source and provenance:
   - Current installed runtime: `D:\WeGameApps\英雄联盟\Game\League of Legends.exe`,
     file/product version `16.16.805.442`, SHA-256
     `82edff100aaf5b73d519addd177bff61fd15860f44f46b79f441f35325cdbb4e`.
   - Preserved read-only memory image: exact build `16.16.805.0442`, capture schema
     version 1, SHA-256
     `0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55`.
   - Newest four local Replay fixtures parse as exact build `16.16.805.0442` with
     source SHA-256 values recorded by the Parser. A larger Collector-owned 16.16
     corpus is available read-only. No Map Knowledge version is applicable.
   - Legacy 16.15 evidence remains `SECONDARY_MACHINE_EVIDENCE`; expensive
     dedicated legacy recovery is excluded.
9. Output consumers are Inference Lab and published parser adapters through the
   semantic API/capability manifest. This gate does not publish an Inference
   feature pack or authorize Akari product use.
10. No frozen baseline is modified. Raw Replay/runtime evidence, verified decoder
    mappings, prior reports, and negative evidence remain immutable; new evidence
    and profiles are additive.
11. No map dependency is introduced, so no outdated or unbound map is used.
12. No responsibility drift, decoder copy, network dependency, behavioral
    inference, or research-code product dependency is introduced.
13. The stage is `OFFLINE_RESEARCH_ONLY`; its value is exact feature truth,
    version migration evidence, regression safety, and future DETAILS proxy
    calibration supporting progressive early profiles.

## Evidence and failure policy

- Capability and fields remain exact-build and source-specific.
- Missing/unverified values remain null/unknown, never false or zero.
- Runtime names, packet frequency, payload shape, and correlations are candidate
  ranking evidence only.
- Promotion requires a recovered route/layout, reproducible positive and negative
  examples, counterexample search, and exact-build regression evidence.
- Nearest-build fallback and mechanics-derived substitution remain forbidden.
- Preserved evidence is never deleted or silently reinterpreted.

## Decision

Owner confirmation: `ROFL_PARSER`
Reviewer: Codex startup architecture review
Rationale and evidence links: current runtime and Replay inputs are exact-build;
the work directly extends registered Parser-owned partial capabilities using
preserved assets without crossing map, inference, acquisition, or product
boundaries.

```text
ARCHITECTURE_GATE = PASS
```

