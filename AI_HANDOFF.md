# AI / developer handoff

This file is the compact ground truth for a new developer or AI. Read it before
changing decoder semantics or trusting any saved `PASS` file.

## What this package is

The project is a patch-pinned League replay research toolkit. It parses `.rofl`
containers through one shared core and maintains exact semantic build profiles.
`16.15.801.3452` is the frozen full-platform profile;
`16.16.805.0442` has resolver support level `DEEP_SEMANTIC_READY` and manifest
release status `SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL`: independently verified
participant, HeroPath, LevelTransition/LevelAfter, WardSpawn, Damage, HeroDeath,
HeroRespawn, raw XP/lane-CS, bounded gameplay-tail and field-specific partial
Buff/Cast/Protection capabilities. Direct values, derived associations, candidate
fields and unavailable fields are intentionally separate.

The `ROFL_STAT_SEMANTIC_MAPPING_AND_DERIVED_COMBAT_STATE_V1` layer is also exact-build
and fail-closed. It exposes stable stat/inventory query entry points, but currently
publishes no MaxHP/Armor/MR values and no new public semantic capability.

The portable ZIP is a source-and-bounded-evidence package. It is not a complete
reproduction capsule: raw Replay files, the 16.15 runtime memory image, DuckDB,
full JSONL packet corpora, Match Details and player identifiers are excluded.

## Read in this order

1. `README.md` for features, commands, limits and current verification state.
2. `docs/ROFL_FORMAT.md` for container and block framing.
3. `src/rofl.js`, `src/build_registry.js`, `src/semantic_api.js`, then
   `src/semantic_pipeline.js` for execution and exact profile resolution.
4. The modules in `src/decoders/` for patch-pinned field contracts.
5. `src/stat_semantic_system.js`, `src/stat_modifier_dependency.js`,
   `src/derived_hero_stat_state.js`, `src/inventory_state_at.js`,
   `src/exact_combat_dataflow_probe.js`, then `src/stat_combat_semantic_layer.js`.
6. `docs/V2_WARD_STATUS.md` and `src/ward_pipeline_v2.js` / `src/path_pipeline_v2.js`.
7. `research-v3/README.md`, `schema.sql` and `core.py` for the database layer.
8. `docs/PROTECTION_V4_CAPABILITY_MATRIX.md`, `research-v4/README.md` and
   `research-v4/protection_layer.py` for protection telemetry.
9. `handoff-evidence/` only after understanding that it is historical bounded
   evidence, not a fresh raw re-decode.
10. `docs/ROFL_NEW_BUILD_PLAYBOOK.md` before registering another build.

## Architecture

```text
.rofl bytes
  -> src/rofl.js: header, metadata, chunks, Zstd, packet blocks
  -> src/analysis.js: raw inventory, samples and anchors
  -> src/build_registry.js: exact build selection; no nearest-version fallback
  -> src/semantic_api.js: stable build-agnostic capability interface
       -> 16.15 full semantic pipeline
       -> 16.16 exact runtime profiles (HeroPath / LevelTransition / Ward /
          Damage / HeroDeath / HeroRespawn / HeroStats / bounded gameplay-tail)
       -> stat_semantic_system + stat_modifier_dependency: selector/dependency evidence
       -> derived_hero_stat_state: field-by-field fail-closed statsAt query
       -> inventory_state_at: direct-slot / carried / ambiguous partial inventory
       -> exact_combat_dataflow_probe: bounded static combat dataflow evidence
       -> stat_combat_semantic_layer: A-Z + Q1-Q8 integration and stop condition
  -> optional V2 inputs
       -> ward_pipeline_v2.js: WardSpawn + lifecycle
       -> path_pipeline_v2.js: PathPacket -> one-second positions
  -> CLI JSON/JSONL/CSV outputs
  -> research-v3: DuckDB canonical facts and research views
  -> research-v4: additive protection tables and verifier
```

## Non-negotiable evidence rules

- Never apply a 16.15 profile to another version because an opcode or nearby
  patch looks similar.
- Preserve Replay SHA, raw packet offset/order and payload hash for direct rows.
- `VERIFIED_DIRECT` means decoded from an exact patch/client field.
- `VERIFIED_DERIVED` means a documented association, transform or aggregation.
- `UNAVAILABLE` stays `null`. Decoder failure, unsupported patch and a genuine
  zero-event replay are distinct states.
- Match Details is validation-only. Do not use it to create semantic events.
- CastSpell target coordinates are not WardSpawn coordinates.
- `0x00ed` is the canonical generated-shield route; paired `0x00ee` is a
  duplicate route in the observed corpus.
- Heal `reported_amount` is not raw/effective/overheal until HP-state evidence
  proves that interpretation.
- For build `16.15.801.3452`, `0x0017` absorption is a direct target-total amount.
  For build `16.16.805.0442`, the verified migrated route is `0x01e1` with 12/12
  published target-total rows. Neither build provides source, shield-instance,
  remaining-amount or lifecycle attribution.
- A stat selector becomes semantic only through an exact consumer chain. The only
  current mapping is static `selector 11 / lane 0 -> MANA_REGEN`; selector `194`
  is event-observed but STRUCTURAL only. Do not infer neighbouring selectors.
- `0x0412` adjustment records do not currently prove modifier causality: 660 strict
  before/after pairs have zero four-lane deltas and the promoted edge set is empty.
- `stats_at` is a real query, not a promise of values. MaxHP/Armor/MR remain null
  until exact champion base/growth, complete item/rune/buff/exception state and
  formula-order evidence are all supplied. Algorithm-conformance fixtures have no
  production promotion authority.
- `inventory_state_at` may publish a direct slot or carried partial state with
  per-slot provenance. A missing full snapshot, rune state or rune proc is
  UNAVAILABLE, never an empty inventory or numeric zero.
- `0x025a` transition occurrence, hero/network entity and Replay timestamp are
  `VERIFIED_DIRECT`; `field_10 -> level_after` is `VERIFIED_DERIVED` only for
  exact build `16.15.801.3452`.
- `0x0314` is the independently verified `16.16.805.0442` LevelTransition
  route; `0x01e8` is rejected. Its build-bound P0 mapping is `242→Lv2`,
  `194→Lv3`, `210→Lv4`.
- Never accept an empty exported packet file as runtime validation. Recompute
  each payload length/SHA-256, bind it to the exact Replay export manifest and
  runtime image, and distinguish `NO_MATCHING_PACKETS_IN_REPLAY` from decoder
  PASS.
- A 16.16 LevelTransition event mixes evidence grades: occurrence/entity/time
  and raw fields are direct, while `level_after` is build-bound derived.
  Preserve `field_confidence`; unmapped initialization rows keep
  `level_after=null` and mark that field unavailable.
- `16.16.805.0442` HeroPath is `0x00f6`, Ward is the evidence-gated `0x049a`
  subset, Damage is `0x017f`, HeroDeath is `0x0112`, and the cumulative
  scoreboard route is `0x010c`. Every field remains exact-build and graded.
- Damage publishes direct time/source/target/recorded amount/type; amount stage
  and spell/basic/item/rune/passive attribution remain unknown.
- HeroDeath publishes occurrence/time/victim/killer with exact-build participant
  mappings. Assists, kill credit and other death inner fields remain
  unavailable/unknown; do not infer respawn from death.
- HeroRespawn is a separate exact route `0x0265`: 282/282 latest-four rows are
  native full-consumed and directly publish occurrence/time and protocol position.
  The scalar role and all map/base/strategic interpretation remain unavailable.
- HeroStats publishes raw XP and lane CS snapshots; only `floor(raw XP)` is a
  verified derived integer. Total gold and jungle CS are candidate-only; current
  gold is unavailable. Item routes `0x0137`/`0x04b3` make buy/sell candidate-only
  and undo unavailable. Separate ItemState snapshots, ItemSwap, ItemSubstitutionMap
  and bounded SupportQuest stage have exact field contracts, but never prove a
  universal transaction cause.
- DETAILS `SKILL_LEVEL_UP` is not hero level time.
- Camp clear and ordinary-monster mapping remain unavailable. Null/UNKNOWN is
  never zero, and neither a runtime item layout nor RTTI name is an item semantic.
- The protected Jungle Objective Holdout is outside the current evidence inputs:
  do not read, enumerate, hash, decode, test or consume it.

## Source-of-truth boundary

This repository owns ROFL protocol facts. Downstream projects own behavioral
interpretation. A downstream discovery of a packet, decoder, field meaning,
version difference, or verification result must be submitted here first or at
the same time; verified protocol capability must not remain privately forked in
`lol-inference-lab`.

## Current verification truth

`MULTI_BUILD_ROFL_SUPPORT_V1` registers two exact builds. The current 16.16
resolver support level is `DEEP_SEMANTIC_READY`, manifest release status is
`SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL`, and downstream gate is
`RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`. In addition to the
18,001/18,001 HeroPath and 2,325/2,325 LevelTransition evidence, Damage has
266,332/266,332 latest-four full-consume rows, HeroDeath has 301/301 P0
victim+killer matches, HeroRespawn `0x0265` has 282/282 exact rows (Talon's
audited respawn is `250195 ms`), and HeroStats has 1,390/1,390 P0 full-consume
snapshots validating raw XP and lane CS. Six gameplay-tail routes are public only
for bounded direct protocol fields; partial Buff/Cast/Protection fields do not
authorize complete event semantics. Heal reported and Shield generated remain
direct fields; item buy/sell are candidate-only and item undo unavailable.

The Stat/Combat integration is `EVIDENCE_EXHAUSTED` with stop condition
`C_EVIDENCE_EXHAUSTED`: 130,490 unique `0x042f` rows, 714 `0x0412` rows, one
verified stat mapping, zero promoted modifier edges, 53 governed `0x006c`
special-slot rows, 79 classified capability records, and zero public semantic
changes. Damage stage/mitigation, CurrentHP, effective heal/overheal and shield
remaining/source/instance/lifecycle are unavailable. The machine A-Z/Q1-Q8 report
is under `.omo/evidence/stat_semantic_mapping_v1/integration/`.

The full semantic baseline conserves all 288 latest-four routes and 7,223,748
packets: 27 registered, 3 decoded, 79 classified and 179 unknown routes (packet
partition 1,531,741 / 2,332,337 / 1,135,531 / 2,224,139). Its 69-item A–Z
capability enumeration has zero missing records, including the required map domain;
the completeness gate is `READY` and stale route count is zero. Deep recovery then
closes 137 route rows and 56 capability rows at actionable 0/0 across 16 locally
exhausted domains; 7/7 checks yield `SEMANTIC_RECOVERY_SATURATED`, not
`FULLY_PARSED`. This remains accounting/evidence saturation, not universal semantic
availability. Consult
`artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json`
for the machine regression count and exact suite boundary.

The latest-four 288-route inventory does not contain `0x01e1`. Route consistency is
not waived generically: the baseline accepts only the pinned
`evidence/exact_build_route_attestations/` manifest/artifact pair, re-runs its 12
full-consume rows through the exact decoder, and only matches the PASS +
VERIFIED_DIRECT `SHIELD_ABSORBED` manifest record.

Historical release evidence reported full passes on 2026-08-11, including 59
Node tests, 38 V3 tests and 15 V4 tests. The cleaned checkout has since been
tested again; use `VALIDATION_STATUS.md` for the exact current commands, counts,
skips and packaging result instead of quoting only the historical report.

The local DuckDB differs from the frozen V3 publication hash because it contains
the recognized additive V4 tables. The current V3 verifier classifies this as
`EXPECTED_ADDITIVE_V4_CONTAINER_CHANGE` and passes after proving the frozen V3
tables against their Parquet publication. The old manifest does not bind the
whole V4-extended container, so a future unified V3/V4 distribution still needs
a newly generated atomic manifest.

The handoff package can run `npm run test:portable`, `npm run test:v3` and
`npm run test:v4`. `npm test` and raw decoder validators need excluded inputs.

## Input matrix

| Task | Extra input required |
| --- | --- |
| Read/modify source, portable tests | none beyond Node/Python dependencies |
| Inspect arbitrary compatible ROFL container | a `.rofl` file |
| Decode 16.15 semantic packets | patch-exact `.rofl`, pinned runtime image, Python + Unicorn |
| Decode verified 16.16 semantic packets | exact `.rofl`, exact 16.16 runtime image, Python + Unicorn |
| Query current Stat/Inventory boundary | no extra input; missing governed dependencies return field-level null/UNAVAILABLE |
| Produce MaxHP/Armor/MR values | exact champion base/growth mechanics plus complete time-indexed item/rune/buff/exception inputs and verified formula order |
| Revalidate LevelTransition | the 12 pinned Replay/DETAILS pairs plus the pinned runtime image |
| Attach V2 ward/path facts | verified same-replay WardSpawn/lifecycle/position JSONL |
| Rebuild V3 | canonical replay manifest plus per-replay event JSONL and V2 inputs |
| Rebuild V4 | V3 DB plus decoded `0x009e` and `0x0017` streams and attestation inputs |
| Reproduce historical all-corpus counts | the original authorised 10/14-replay corpus and pinned image |

## Safe first commands

```powershell
python -m pip install -r requirements.txt
npm run test:portable
npm run test:v3
npm run test:v4
npm run package:handoff
npm run verify:handoff
```

When private inputs are supplied separately, first hash and inventory them;
never copy them into the source handoff. Use a new output directory rather than
overwriting saved evidence.

## Where to make changes

- Container/framing bug: `src/rofl.js` plus `test/rofl.test.js`.
- CLI/output contract: `src/cli.js` plus portable and real-replay tests.
- 16.15 direct packet field: decoder profile and emulator scripts, with raw
  provenance and a new patch-gated test.
- New build: shared core first, then an exact entry in `src/build_registry.js`,
  a build decoder profile, bounded L1/L2/L3 evidence and semantic fingerprints.
- Level transition/query contract: `src/level_transition.js`, the exact-build
  decoder module, `src/semantic_pipeline.js`, and `test/level_transition.test.js`.
- Ward/path association: V2 pipeline; never alter direct source fields.
- Stat selector/dependency semantics: `src/stat_semantic_system.js` and
  `src/stat_modifier_dependency.js`; require exact consumer/dependency proof.
- Derived stat/inventory/combat boundary: `src/derived_hero_stat_state.js`,
  `src/inventory_state_at.js`, `src/exact_combat_dataflow_probe.js`, and
  `src/stat_combat_semantic_layer.js`; preserve per-field missing inputs and manifests.
- Database schema/materialization: V3 or additive V4 schema with migration and
  idempotence tests.
- Package contents: `scripts/package_handoff.py`; keep its exclusion and content
  scans strict.

## Before claiming completion

Report separately:

1. commands actually run now and their exit codes;
2. historical attested results merely inspected;
3. missing private inputs that prevented full re-decode;
4. fields still unavailable;
5. whether a blind holdout was actually untouched;
6. archive SHA-256 and whether its closed manifest/fresh extraction passed.

Do not turn a compact evidence package into a claim of full reproducibility.
