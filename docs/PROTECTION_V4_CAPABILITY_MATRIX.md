# Protection V4 capability matrix

Authoritative machine contract: `artifacts/protection_v4_probe/protection_v4_field_contract.json`.

The separate `on_event_protection_field_contract.json` is intentionally scoped only to `0x009e PKT_OnEvent_s`. Shield absorption is supplied by `0x0017 PKT_UnitApplyShieldDamage_s`, not by OnEvent.

## Observable protection fields

| Capability | Status | Replay-observed value | Attribution | Required output behavior |
|---|---|---|---|---|
| Current HP | `UNAVAILABLE` | No verified current-HP state packet or field | None | `NULL` |
| Max HP | `UNAVAILABLE` | No verified max-HP state or modification field | None | `NULL` |
| Shield generated | `VERIFIED_DIRECT` | `0x009e / 0x00ed`, `ShieldingParams +0x10 f32` | Source and target are direct at `+0x08` and `+0x0c` | Emit every canonical `0x00ed` row |
| Shield remaining | `UNAVAILABLE` | No verified remaining-shield field | None | `NULL` |
| Shield absorbed | `VERIFIED_DIRECT_TARGET_TOTAL` | `0x0017 +0x18 f32`; observed amounts `375.13690185546875` and `30.030563354492188` | Target direct; source and shield instance unavailable | Emit each verified `0x0017` row once as unattributed target-total absorption |
| Shield unused | `UNAVAILABLE` | No expiry/removal remainder amount | None | `NULL` |
| Heal reported amount | `VERIFIED_DIRECT_RAW_VS_EFFECTIVE_UNRESOLVED` | `0x009e / 0x004b`, `ParamsHeal +0x18 f32` | Source and target are direct at `+0x14` and `+0x04` | Preserve the direct reported amount in its own field |
| Raw heal | `UNAVAILABLE` | Reported heal has not been proven to be pre-overheal/raw | Source/target known, semantics unresolved | `NULL` |
| Effective heal | `UNAVAILABLE` | No verified HP-before/after state | None | `NULL` |
| Overheal | `UNAVAILABLE` | Cannot derive without raw/effective separation | None | `NULL` |
| Temporary HP | `UNAVAILABLE` | CastSpell/Buff lifecycle exists, but no amount or HP-state change field | Caster/target lifecycle only | Amount/start/end remain `NULL` |
| Temporary max-HP modification | `UNAVAILABLE` | No verified max-HP before/after telemetry | None | `NULL` |

## Source and instance attribution

| Measurement | Source attribution | Target attribution | Spell/instance attribution |
|---|---|---|---|
| Shield generated (`0x00ed`) | `VERIFIED_DIRECT` | `VERIFIED_DIRECT` | CastSpell/Buff correlation is supporting evidence; a stable shield-instance ID is unavailable |
| Heal reported (`0x004b`) | `VERIFIED_DIRECT` | `VERIFIED_DIRECT` | Exact CastSpell anchors exist, but simultaneous legitimate effect rows prohibit nearest-cast deduplication |
| Shield absorbed (`0x0017`) | `UNAVAILABLE` | `VERIFIED_DIRECT` | No source or shield-instance field; expose only total absorbed on the target |

The two current `0x0017` rows were both fully consumed, their duplicate target fields agreed, and both correlated to the first following `UnitApplyDamage` row with the same target and replay timestamp. That correlation is ordered-neighbor evidence; it does not identify which shield source or instance absorbed the damage.

## Canonicalization

- Shield generation: use all `0x00ed OnReceiveShield` rows. All 4,752 observed `0x00ee OnGrantShield` rows are exact immediately preceding duplicates; 328 additional receive-only rows prove that `0x00ee` cannot be the canonical route.
- Heal: preserve all 81,652 raw rows. Exact full-blob collapse to 77,415 rows is only a lower-bound candidate, not a silent deduplication rule.
- Shield absorption: use each verified `0x0017` row once as target-total absorption. Do not assign it to a support, spell, buff, or shield instance.

## Status and provenance meanings

| Status | Meaning |
|---|---|
| `VERIFIED_DIRECT` | Value comes directly from a replay packet decoded with the exact current-client constructor/deserializer and recovered field transform. |
| `VERIFIED_DIRECT_TARGET_TOTAL` | Direct amount and target are verified, but source/instance attribution is unavailable. |
| `VERIFIED_ORDERED_NEIGHBOR` | Separate direct packets share target and timestamp and have a verified raw order relationship. It is correlation evidence, not source attribution. |
| `DERIVED_SUM_OF_TWO_DIRECT_PACKET_AMOUNTS` | Arithmetic sum of the direct `0x0017` absorbed amount and its correlated direct damage amount. Preserve both inputs and mark the sum derived. |
| `UNAVAILABLE` | Telemetry was not recovered or semantics are not proven; the field must remain `NULL`. |
| `NO_PROTECTION_EVENT` | Decoder is supported and ran successfully, but no matching event occurred. |
| `DECODER_UNAVAILABLE` / `PROTECTION_PROFILE_UNSUPPORTED` | Patch/profile decoder is unavailable. Never reinterpret this as a game with zero protection. |

Every emitted direct or derived row must retain replay hash, chunk/block/payload offsets, replay timestamp, occurrence index, opcode, raw parameter, raw payload hash, decoder profile, runtime-image hash, and semantic status.

## Evidence artifacts

- Combined authoritative contract: `artifacts/protection_v4_probe/protection_v4_field_contract.json`
- OnEvent-only field/static contract: `artifacts/protection_v4_probe/on_event_protection_field_contract.json`
- OnEvent corpus summary: `artifacts/protection_v4_probe/on_event_protection_decoded_all14.summary.json`
- Ten CastSpell-linked raw anchors: `artifacts/protection_v4_probe/protection_raw_anchors.json`
- Shield-absorption decoded rows: `artifacts/protection_v4_probe/shield_damage_decoded_all14.jsonl`
- Shield-absorption validation summary: `artifacts/protection_v4_probe/shield_damage_decoded_all14.summary.json`
- Buff lifecycle validation: `artifacts/runtime_probe/buff_validation_summary.json`
- Frozen V3 runtime regression: `artifacts/protection_v4_probe/v3_regression_unit_apply_damage_runtime_validation.summary.json`
