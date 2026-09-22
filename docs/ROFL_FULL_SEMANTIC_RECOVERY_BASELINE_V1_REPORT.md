# ROFL Full Semantic Recovery Baseline V1 — Final A–Z Report

Generated: 2026-08-20  
Project: `ROFL binary feasibility probe`  
Primary exact build: `16.16.805.0442`

This report closes the `ROFL_FULL_SEMANTIC_RECOVERY_BASELINE_V1` stage. `SEMANTIC_BASELINE_READY` means the exact-build protocol inventory, evidence ledger, capability enumeration, research statuses, unknown registry, regression, and migration workflow satisfy the stage gate. It does **not** mean every Replay semantic is recovered, and it must never be restated as `FULLY_PARSED`.

Evidence grades retain their strict meanings: `VERIFIED_DIRECT` is carried by the Replay protocol field itself; `VERIFIED_DERIVED` is a deterministic exact-build transform over verified inputs; `CANDIDATE` is not consumer permission; `UNAVAILABLE` records the current evidence boundary and does not assert protocol nonexistence.

## A. STATUS — COMPLETE

`SEMANTIC_BASELINE_READY`.

- Machine gate: `READY`, zero blockers.
- Requested fact-layer capability enumeration: 69/69, zero missing.
- All eight readiness conditions in §31 pass: exhaustive inventory, high-frequency analysis, explicit gameplay-candidate status, systematic high-value-domain research, actionable remaining UNKNOWN, passing regression, no silent discard, and no silent fallback.
- This is an accounting/research baseline with selectively published semantics, not universal semantic availability.

Primary evidence: [completeness_gate.json](../artifacts/full_semantic_baseline_v1/completeness_gate.json), [full_semantic_baseline.json](../artifacts/full_semantic_baseline_v1/full_semantic_baseline.json).

## B. PRIMARY BUILD — COMPLETE

- `PRIMARY_RESEARCH_BUILD`: exact `16.16.805.0442`.
- Runtime image SHA-256: `0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55`.
- Exact-build-only resolution is enforced; nearest-build fallback is `FORBIDDEN`.
- A client-visible public Replay, `HN1-11191203388.rofl`, passed the real semantic API smoke. Human client playback was not re-run as part of this final gate.
- Existing `16.15.801.3452` capabilities remain separate build-bound profiles. Binary routes and decoders are not reused silently across builds.

Evidence grade: build/container identity `VERIFIED_DIRECT`; runtime/profile binding exact-build verified.

## C. PACKET COVERAGE — COMPLETE

The latest-four exact-build corpus contains 288 observed routes and 7,223,748 packets. Every route and packet is conserved one-to-one across inventory, callback join, registry, and output.

| Partition | Routes | Route share | Packets | Packet share |
| --- | ---: | ---: | ---: | ---: |
| KNOWN | 6 | 2.0833% | 489,935 | 6.7823% |
| DECODED | 3 | 1.0417% | 2,332,337 | 32.2871% |
| CLASSIFIED | 95 | 32.9861% | 1,789,875 | 24.7777% |
| UNKNOWN | 184 | 63.8889% | 2,611,601 | 36.1530% |

`DECODED` includes exact structural decodes and explicit negative controls; it is not positive semantic coverage. All 29 routes with at least 50,000 packets have an allowed analysis-evidence tier. No route is silently discarded.

Evidence grade: exhaustive structural accounting `VERIFIED_DIRECT`; RTTI family classifications remain `CANDIDATE` unless independently validated.

## D. ENTITY COVERAGE — PARTIAL

- Champion participant mapping is exact-build verified and canonicalized.
- Confirmed player Wards are represented with direct entity identifiers and derived participant/team/type fields.
- `UNKNOWN_ENTITY` is a first-class canonical type, so unresolved entities are preserved rather than coerced or discarded.
- Lane Minion, Jungle Monster, Epic Monster, Trap, Pet, Summon, Missile, Structure, Plant, and Map Mechanic identity/lifecycle are `UNAVAILABLE` for this build.
- Runtime family names and numeric IDs do not independently prove entity taxonomy.

Evidence grade: Champion/Ward identifiers `VERIFIED_DIRECT` with explicitly marked exact-build derivations; remaining taxonomy `UNAVAILABLE`.

## E. HERO STATE — PARTIAL

- `LEVEL_TRANSITION` is published: occurrence/entity/time direct; `level_after` exact-build derived.
- HeroStats route `0x010c` provides cumulative raw XP and lane minions killed; see Economy for field grades.
- `CURRENT_HP`, `MAX_HP`, `CURRENT_MANA`, `MAX_MANA`, `ARMOR`, `MAGIC_RESIST`, `ATTACK_DAMAGE`, `ABILITY_POWER`, `ATTACK_SPEED`, persistent `MOVE_SPEED`, `TEMPORARY_HP`, and temporary stat state are not published from 16.16 ROFL.
- Four paired DETAILS P0 samples provide a coarse, roughly 60-second, source-bound oracle for HP/max HP/armor/MR. They validate research methods but do not promote those fields to ROFL semantics.
- Scoreboard and runtime-name evidence must not be mislabeled as live combat state.

Evidence grade: Level `VERIFIED_DIRECT`/`VERIFIED_DERIVED`; DETAILS anchors `GROUND_TRUTH_FRAME_SNAPSHOT`; remaining ROFL hero state `UNAVAILABLE`.

## F. COMBAT / DAMAGE — PARTIAL

- Damage route `0x017f`: 266,332/266,332 latest-four packets exact full-consume. Time, raw source, raw target, recorded amount, and physical/magic/true type are `VERIFIED_DIRECT`; Champion participant mapping is exact-build derived.
- HeroDeath route `0x0112`: 301/301 safe-P0 events align at 0–1 ms. Death occurrence/time and raw victim/killer storage are direct; victim/killer participant mappings are exact-build derived. The public smoke emitted 96 deaths with killer.
- The recorded damage amount is not proven to be pre-mitigation, post-mitigation, or effective HP loss.
- Critical/basic attack/spell/passive/item/rune/on-hit/DoT/execute attribution, kill-credit semantics, and assists are not published. In particular, 242 nonempty-assist counterexamples reject the tested scalar, bitmask, and fixed-triplet interpretations.

Evidence grade: bounded fields `VERIFIED_DIRECT`/`VERIFIED_DERIVED`; source-kind and amount-stage semantics `UNAVAILABLE`.

## G. DEFENSE / MITIGATION — UNAVAILABLE

There is no verified exact-timestamp 16.16 ROFL chain from armor/MR and pre-damage state through mitigation to HP loss. Therefore `pre_mitigation_damage`, `post_mitigation_damage`, `actual_hp_loss`, `mitigation`, and damage-stage classification remain unavailable. No game-formula reconstruction is published without verified inputs and an explicit `VERIFIED_DERIVED` contract.

## H. SHIELD / HEAL — UNAVAILABLE

No current-build route is published for shield create/update/absorb/remove, shield remaining, heal source/target, effective heal, or overheal. SUMMARY teammate heal/shield totals and DETAILS game frames are coarse anchors only; they do not provide exact Replay event timestamps. Older 16.15 protection semantics do not migrate to 16.16.

Evidence grade: 16.16 Replay semantics `UNAVAILABLE`.

## I. BUFF / DEBUFF — UNAVAILABLE

Runtime registration, constructors, vtables, deserializers, and bounded layouts were recovered for several BuffManagerClient routes, but no independent 16.16 semantic anchors establish `BUFF_ADD`, `BUFF_UPDATE`, stack, remove, identifier, source/target, duration, or control-effect meaning. Structural success is retained as candidate evidence only.

Evidence grade: exact structural layouts verified; gameplay semantics `UNAVAILABLE`.

## J. SPELL / MISSILE — UNAVAILABLE

No 16.16 `SpellCast`, channel/recast, or missile lifecycle event is published. Callback names and numeric fields do not prove cast semantics or a Cast → Missile → Hit → Damage causal chain. The decoded `0x04ca` route is an explicit negative control for summoner-spell name-vector ASCII, not a cast/state event.

Evidence grade: route-local structure/negative controls verified; gameplay semantics `UNAVAILABLE`.

## K. MOVEMENT — PARTIAL

- HeroPath route `0x00f6` is published for 16.16. Entity/time/path fields are direct; transformed/interpolated coordinates are derived and labeled accordingly.
- The real public smoke emitted 47,665 HeroPath events.
- Packet-local path speed is decoded, but persistent move speed, movement commands, dash, blink, knockback, teleport, and recall state are unavailable.
- Position is not a strategic map-region label.

Evidence grade: raw path `VERIFIED_DIRECT`; coordinate transforms/interpolation `VERIFIED_DERIVED`; special movement `UNAVAILABLE`.

## L. VISION — PARTIAL

- Ward spawn is published. Time, raw owner/entity/name/position are direct; participant/team/ward-type classification is derived.
- Conservative Ward lifecycle matching is `PARTIAL`; end reason remains `UNKNOWN` and estimated ends are never emitted.
- The public smoke emitted 154 Ward rows, including 147 confirmed player Wards.
- Sweeper held is unverified; activation, interval, owner, position, ward disable, reveal, true sight, fog visibility, and player visibility state are unavailable.
- Route `0x0302` is retained as a negative-control/full-entity selector candidate, not vision-state truth.

## M. ITEM — UNVERIFIED

- Route `0x0137` is 1,601/1,601 full-consume. Its bounded item-ID field matches 1,154/1,154 aligned purchase rows, but the route aligns only 1,154/1,168 purchases and contains 447 additional packets. It is therefore not published as `ITEM_BUY`.
- Route `0x04b3` is 1,013/1,013 full-consume. All 60 sales align, but 953 rows are not sales and the route carries no direct item ID. It is not published as `ITEM_SELL`.
- `ITEM_UNDO` matches 0/52 through this route pair and is `UNAVAILABLE`.
- Only 26/60 sold identities reconstruct; 71 rows have unknown prior slot state. `ITEM_STATE`, slots, stacks, charges, transform, destroy, and complete inventory transitions remain unpublished.
- No canonical `ItemEvent` is emitted.

Evidence grade: exact structural decode verified; bounded `item_id`/participant transforms `VERIFIED_DERIVED`; event/state semantics `CANDIDATE_ONLY` or `UNAVAILABLE`.

## N. RUNE / SUMMONER / PASSIVE — UNAVAILABLE

No exact-build event/state capability is published for Summoner Spell casts/cooldowns, Rune state/procs, or Passive state/procs. A numeric damage-source identifier is preserved but is not promoted to spell/basic/item/rune/passive attribution.

## O. ECONOMY — PARTIAL

- HeroStats `0x010c`: 1,390/1,390 decoded rows full-consume and align one-to-one with safe DETAILS at 0–1 ms.
- Raw cumulative XP is `VERIFIED_DIRECT`; integer XP is `VERIFIED_DERIVED` by floor, with 1,390/1,390 agreement.
- Cumulative lane minions killed is `VERIFIED_DIRECT`, 1,390/1,390.
- Total gold is `CANDIDATE` (floor agrees 1,389/1,390); jungle CS is `CANDIDATE` (1,375/1,390).
- Current gold, gold gain/spend, passive income, level progress, and exact economy-event timing are unavailable. The keyframe cadence is roughly 60 seconds.

## P. MINION — PARTIAL

Only the cumulative lane-minion-kill scoreboard field is verified. Minion identity/classification, spawn, position, damage, death, killer, wave identity, and gold/XP relationships are unavailable. The cumulative CS field must not be restated as an entity lifecycle or last-hit event.

## Q. JUNGLE / MONSTERS — UNAVAILABLE

No 16.16 ordinary-monster identity, spawn, damage, death, killer, despawn, reset, respawn, or `CAMP_STATE` semantic is published. Jungle CS is only a candidate scoreboard field. Downstream spatial camp contact is outside Parser truth and is not camp clear, intent, kill, or XP evidence. No protected Jungle Objective Holdout content was enumerated, read, hashed, decoded, tested, or consumed.

## R. OBJECTIVES — UNAVAILABLE

Dragon/type, Herald, Baron, other epic-objective identity, spawn, damage, death, killer/team, and consequence state are unavailable for this exact build. Objective-like RTTI classification is not semantic proof.

## S. STRUCTURES — UNAVAILABLE

Tower, plate, inhibitor, Nexus identity, ownership, HP/state, damage, and destruction are unavailable. Observed structure-family candidates remain raw/classified evidence only.

## T. MAP MECHANICS — UNAVAILABLE

`MAP_MECHANIC` is now an explicit required capability and exact-build `UNAVAILABLE` record, so it cannot disappear through a dashboard blind spot. No protocol route is published for version-specific map-mechanic events or state. Static Map Knowledge and strategic-region interpretation belong to the Inference Lab; Parser coordinates do not create map truth.

## U. COMBAT RECONSTRUCTION — PARTIAL

- A canonical opcode-free schema/API and deterministic `SemanticStateEngine` now support canonical timelines, combat timelines, explicit state updates, and `stateAt(t)`.
- State carry-forward preserves null versus zero, retains field-level evidence/provenance/raw references, separates direct updates from `VERIFIED_DERIVED_STATE`, and does not synthesize absent schema defaults.
- Published Damage, HeroDeath, HeroPath, Level, Ward, and scoreboard events can share the canonical timeline.
- The engine intentionally does not infer HP from damage, respawn from death, buff/shield expiry, aliases, or other missing truth.

Evidence grade: engine behavior and schema contracts verified by tests; reconstruction coverage limited to explicitly supplied verified fields.

## V. UNKNOWN SEMANTICS — COMPLETE

Unknown accounting is complete and actionable:

- Strict `UNKNOWN` partition: 184 routes / 2,611,601 packets.
- Full non-KNOWN registry: 282 routes / 6,733,813 packets, covering DECODED, CLASSIFIED, and UNKNOWN routes exactly once.
- Every observed route retains raw evidence, build binding, count/size distributions, status, and next required evidence.
- `UNKNOWN`, `UNAVAILABLE`, and `UNKNOWN_ENTITY` are preserved values, not coerced to null/zero or discarded.

This section is `COMPLETE` for inventory/accounting, not semantic interpretation.

## W. NEGATIVE EVIDENCE — COMPLETE

The machine-readable negative-evidence registry records failed hypotheses and counterexamples without turning absence into proof of protocol nonexistence. Material examples include:

- 0x0112 assist-layout hypotheses rejected by 242 nonempty-assist counterexamples.
- 0x0137/0x04b3 item-route event naming rejected by route extras, misses, non-sale rows, and 0/52 undo matches.
- 0x010c scoreboard fields rejected as live HP/combat state; gold and jungle CS remain candidates due residuals.
- 0x0302 rejected as a scalar HP/defense/resource route.
- 0x04ca retained as a semantic negative control, not a combat-state candidate.

Evidence: [negative_evidence_registry.json](../artifacts/full_semantic_baseline_v1/negative_evidence_registry.json).

## X. REGRESSION — COMPLETE

Exact-build attestation is `PASS`: 237 discovered tests/scenarios, 236 passed, 0 failed, 1 skipped.

- Repository Node regression: 181/181 passed.
- Research V3: 37/38 passed, 1 skipped solely because frozen Holdout artifacts were absent; protected artifacts were not opened or consumed.
- Protection V4: 17/17 passed.
- Strict real public Replay semantic API smoke: 1/1 passed; 47,665 path, 142 level, 154 Ward, 59,160 damage, 96 death-with-killer, and 300 scoreboard-state events.

Evidence: [regression_attestation_16_16.json](../artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json).

## Y. PATCH MIGRATION READINESS — COMPLETE

The one-command migration audit compares exact build profiles, inventories, runtime registrations, payload/layout evidence, semantic anchors, decoders, and field behavior without nearest-build reuse.

The 16.15 → 16.16 audit reports:

- Packet diff: 219 new, 69 payload-changed, 227 removed.
- Capability migration: 2 `UNCHANGED_VERIFIED`, 8 `ROUTE_MOVED`, 3 `FIELD_SHIFT`, 5 `NEEDS_REVALIDATION`, 51 `UNSUPPORTED`, 0 `UNKNOWN`, 0 `SEMANTIC_CHANGED`.
- Research queue: 581 explicit work items.

`UNSUPPORTED` and queued work remain explicit; migration readiness does not imply cross-build decoder compatibility.

Evidence: [migration_16_15_to_16_16.json](../artifacts/full_semantic_baseline_v1/migration/migration_16_15_to_16_16.json).

## Z. HARD BLOCKERS — COMPLETE

There is no hard external blocker to this stage's `SEMANTIC_BASELINE_READY` outcome.

Further semantic promotion is evidence-bound rather than silently assumed. The main next inputs are independently anchored exact-build routes/layouts for hero combat state, mitigation, heal/shield, buff/spell/missile, full inventory transitions and undo, NPC/minion/jungle/objective/structure/map-mechanic lifecycles, plus controlled high-information-density Replay samples or manual playback only where a hypothesis cannot be separated otherwise. Until those inputs exist, the affected capabilities remain explicitly `UNAVAILABLE`, `UNVERIFIED`, `CANDIDATE`, or `UNKNOWN`.

The protected Jungle Objective Holdout was outside this baseline: it was not enumerated, read, hashed, decoded, tested, modified, or consumed.

---

Final declaration: **`SEMANTIC_BASELINE_READY`**, exact build **`16.16.805.0442`**, with explicit semantic gaps and no claim of `FULLY_PARSED`.
