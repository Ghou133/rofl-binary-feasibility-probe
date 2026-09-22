# Combat semantic status

Status: `PARTIAL`. The first semantic-coverage round preserves every existing
exact-build decoder and promotes only the additional 16.15 damage fields that
already have direct or deterministic evidence. It does not yet provide a full
combat-state timeline.

## Canonical 16.15 surface

| Semantic | Status | Public behavior |
| --- | --- | --- |
| Damage time/source/target/amount | `VERIFIED_DIRECT` | Emitted from exact route `0x028a` with Replay, decoder-profile, and runtime-image provenance. |
| Damage type | `VERIFIED_DIRECT` | `field_21`: `0 physical`, `1 magic`, `2 true`; an unknown code is `null`. |
| Damage script key | `VERIFIED_DIRECT` | Numeric and padded hexadecimal `field_1c`; it is not automatically a spell name. |
| Critical, positive case | `VERIFIED_DERIVED` | `field_20 == 3` emits `is_critical=true`; all other codes remain `null`, never `false`. |
| Human spell/basic/item/rune/passive source | `UNAVAILABLE` in the base API | The V3 research layer has partial true-only/name enrichment, but it is not copied into the decoder. |
| Pre-/post-mitigation and effective HP loss | `UNAVAILABLE` | Canonical fields are present and `null`; the recorded amount has no promoted mitigation meaning. |
| Hero death | `VERIFIED_DIRECT` | Exact route `0x0160`, hero victim and precise Replay time; killer/combat reconstruction is not supplied. |
| CastSpell | direct fields plus derived dictionary fields | Exact route `0x0459`; no nearest-time attribution is allowed. |
| Buff | `VERIFIED_DIRECT` operations | Add `0x0406`, Remove `0x0031`, UpdateCount `0x0256`; unknown identifiers and unproved categories are retained. |
| Shield generation | `VERIFIED_DIRECT` | Canonical OnEvent `0x009e/0x00ed`; source, target, generated amount. |
| Shield absorption | `VERIFIED_DIRECT_TARGET_TOTAL` | Route `0x0017`; target and total amount only, no source or shield instance. |
| Reported heal | `VERIFIED_DIRECT` with unresolved amount meaning | Source, target, reported amount; effective heal and overheal are `null`. |
| Current/max HP, armor, MR | `UNAVAILABLE` | First-round structural candidates are recorded, but no field is emitted. |

Every `damage` event now has stable nullable slots for recorded amount,
pre-/post-mitigation amount, effective damage, type/code, direct script key,
source category, spell/item/rune/passive/on-hit/DoT/execute, basic attack, and
critical. Missing semantics stay `null`, not zero or guessed values.

## Buff and protection state-machine boundary

The parser can preserve Buff Add, Remove, and UpdateCount observations with
direct target/source/hash/slot/count/timing fields where present. This is a
usable partial lifecycle, but it does not yet prove every requested canonical
transition (`BUFF_UPDATE`, `BUFF_STACK`) for every Buff family, nor semantic
categories such as stun, stealth, item proc, or rune proc. Unknown Buffs remain
events.

Protection V4 supersedes the older V3 statement that numeric protection values
were unavailable. Generated shield, target-total absorbed shield, and reported
heal now have direct exact-build values. Remaining shield, expired/unused
shield, effective heal, overheal, temporary HP, and temporary max-HP remain
unavailable.

## Reconstruction readiness

A precise partial sequence can currently contain Damage, HeroDeath, CastSpell,
Buff, shield-generation, target-total shield-absorption, and reported-heal
events. It cannot truthfully answer “HP before/after”, effective damage,
remaining shield, effective healing, armor/MR mitigation, concurrent-regeneration
residuals, or a complete death-before-15-seconds combat state. Therefore a full
ADC death timeline is `BLOCKED_BY_MISSING_STATE_FIELDS`, while the event-only
combat timeline is `PARTIAL`.

The machine contracts are
`artifacts/semantic_coverage_v1/capability_manifest.json` and
`artifacts/semantic_coverage_v1/combat_candidate_report.json`.
