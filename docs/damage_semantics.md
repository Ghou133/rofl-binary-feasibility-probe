# Damage semantics

The stable 16.15 damage event is exact-build and exact-runtime gated. A row is
accepted only when Replay SHA/version, packet ID `0x028a`, decoder profile,
pinned runtime-image SHA-256, decoded opcode, success result, and full payload
consumption all agree.

## Field contract

| Field | Evidence | Meaning |
| --- | --- | --- |
| `replay_time_ms` | `VERIFIED_DIRECT` | Packet time. |
| `source_network_id`, `target_network_id` | `VERIFIED_DIRECT` | Direct damage source and target entities. |
| participant/champion/team fields | `VERIFIED_DERIVED` when mapped | Exact champion network-ID range plus Replay-tail roster. Unknown entities stay unknown. |
| `amount` | `VERIFIED_DIRECT` | Recorded UnitApplyDamage float; mitigation/effective-HP-loss interpretation is unresolved. |
| `damage_type`, `damage_type_code` | `VERIFIED_DIRECT` | Exact-build `field_21`: physical/magic/true for codes 0/1/2. |
| `spell_key`, `spell_key_hex` | `VERIFIED_DIRECT` | Exact numeric `field_1c`; no human-readable category is implied. |
| `damage_result_code` | `VERIFIED_DIRECT` | Exact `field_20` value. |
| `is_critical=true` | `VERIFIED_DERIVED` | Positive-only mapping for result code 3. Other codes are `null`. |
| `is_basic_attack`, `source_type`, `spell`, `item`, `rune`, `passive`, `on_hit`, `damage_over_time`, `execute` | `UNAVAILABLE` | Nullable schema slots; base decoder does not infer them. |
| `pre_mitigation_amount`, `post_mitigation_amount`, `effective_damage` | `UNAVAILABLE` | No direct distinction is proven. |

Four public 16.15 Replays contain 220,244 fully consumed UnitApplyDamage rows;
10,911 are champion-to-champion. The exact-runtime comparison matched all fields
for 1,000/1,000 sampled rows. The published V3 corpus independently validates
27,625 champion rows across ten Replays: 11,423 physical, 12,799 magic, and
3,403 true damage rows.

The V3 attribution layer may resolve a unique fixed-build script identity or an
exact replay/time/source/target/key CastSpell match, and it has a true-only basic
attack classifier. Those are partial enrichments. A direct key alone never
authorizes spell/basic/item/rune/passive classification in the base parser.

16.16 Damage route `0x017f` remains a disabled `CANDIDATE`; no 16.15 decoder or
field mapping is used as fallback. Consequently 16.15 and 16.16 Damage cannot
yet be pooled as the same verified semantic capability.
