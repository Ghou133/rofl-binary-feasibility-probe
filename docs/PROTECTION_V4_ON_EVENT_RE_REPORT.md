# Protection V4 current-client OnEvent reverse-engineering report

## Result

The current `16.15.801.3452` client provides direct replay-observed protection amounts through `PKT_OnEvent_s` (`0x009e`):

- `0x004b OnCastHeal / ParamsHeal` provides target, source, and a direct reported heal amount.
- `0x00ed OnReceiveShield / ShieldingParams` provides source, target, and the direct shield application/generated amount.
- `0x00ee OnGrantShield` carries the same `ShieldingParams` payload on a duplicate source-side route.
- No `0x00ef OnDamageShielded` row occurs in the 14-replay corpus, so its layout is not claimed.

This is a current-client Route A + Route B protocol breakthrough. It does not provide HP state, heal raw/effective/overheal separation, shield remaining/absorbed/unused, or temporary HP.

A later full-corpus packet scan additionally recovered direct target-level shield
absorption from `PKT_UnitApplyShieldDamage_s` (`0x0017`). That separate result is
documented in `docs/PROTECTION_V4_SHIELD_DAMAGE_RE_REPORT.md`; it does not change
the OnEvent field contracts below.

## Frozen V1/V2/V3 boundary

The shared decoder was restored byte-for-byte to the accepted V3 review copy:

```text
scripts/emulate_exact_packet_decoder.py
SHA-256 c3959b3163c391a97ee0d6fc63641ad1f4507fbbe6dab87cd647e9a174fca6e7
size 31912 bytes
```

Historical stage/extract copies that once carried the same hash were removed as
duplicate package output. The retained root script is now the only source copy;
the hash above remains the frozen comparison value.

All V4-specific behavior, including the semantic CRT `memset` stub needed because Unicorn cannot execute the client AVX implementation, is isolated in:

```text
scripts/decode_on_event_protection_v4.py
```

## Static current-client chain

### PKT_OnEvent_s (`0x009e`)

```text
callback registration       0x004a7358..0x004a73c1
captured consumer           0x004d1120
generic registration        0x007004b0
factory                     0x00eddb80
factory jump table          0x00eedfa8
opcode case                 0x00edfcb6
allocation                  0x28 bytes
constructor                 0x00e827e0
final vtable                0x01b14f80
deserializer                0x00fe12f0
```

Object layout:

```text
+0x10 encoded event enum
+0x14 encoded schema ID
+0x18 parameter blob pointer
+0x20 parameter blob length
+0x24 parameter blob capacity
```

### PKT_UnitApplyShieldDamage_s (`0x0017`)

The correct registration is the block preceding the `0x0313` registration:

```text
registration                0x0025294b..0x002529c2
opcode load                 0x002529a7 = 0x0017
std::function vtable        0x01a2ecd0
vtable type getter          0x002ca9c0
callback / consumer         0x0029edd0
descriptor                  PKT_UnitApplyShieldDamage_s
```

The following block at `0x00252a01`, vtable `0x01a2ed00`, is `PKT_NPC_InstantStop_Attack_s` with opcode `0x0313`; it is not the shield-damage packet. A complete 14-Replay opcode scan later found two genuine `0x0017` packets in `HN1-11184800649`; both decode to direct target-level shield absorption and are published separately from this OnEvent stream.

## Field contract

| Event | Schema / size | Field | Meaning | Confidence |
|---|---:|---:|---|---|
| `0x004b OnCastHeal` | `0x7c044fe1` / `0x34` | `+0x04 u32` | target network ID | `VERIFIED_DIRECT` |
| | | `+0x14 u32` | source/caster network ID | `VERIFIED_DIRECT` |
| | | `+0x18 f32` | direct reported heal amount | `VERIFIED_DIRECT`; raw vs effective unresolved |
| `0x00ed OnReceiveShield` | `0x8f7f3f4e` / `0x14` | `+0x08 u32` | source/caster network ID | `VERIFIED_DIRECT` |
| | | `+0x0c u32` | target network ID | `VERIFIED_DIRECT` |
| | | `+0x10 f32` | shield application/generated amount | `VERIFIED_DIRECT` |
| `0x00ee OnGrantShield` | same | same | duplicate source route | exact duplicate in this corpus; non-canonical |

Heal consumer `0x00315530` independently supports the layout: `0x003155c2` converts `+0x18` to integer, `0x003155e8` compares `+0x04` with the entity ID, `0x0031577f` resolves the source from `+0x14`, and `0x003157ba` forwards `+0x18`. Shield callbacks are `0x00329100` (`0xed`) and `0x0031bb90` (`0xee`).

## Full-corpus decode

Input: 103,249 `0x009e` packets across 14 replays.

```text
deserialize success         103249 / 103249
fully consumed              103249 / 103249
OnCastHeal                  81652
OnReceiveShield              5080
OnGrantShield                4752
OnDamageShielded                0
schema mismatches               0
size mismatches                 0
```

Every one of the 4,752 grant rows is followed by an identical receive row at raw occurrence delta `+1`. There are 328 receive-only rows. Therefore the canonical shield rule is to emit every `0xed` row and not also emit `0xee`.

Heal rows must be preserved. Exact `(replay, timestamp, full parameter blob)` collapse would yield 77,415 rows versus 81,652 raw rows, but this is only a lower-bound candidate. Soraka W at `HN1-11177593199`, `821714 ms` produces two legitimate same-source/same-target direct amounts (`32.8087158203125` and `132.22900390625`) at the same cast timestamp, demonstrating that nearest-cast or same-time collapsing is unsafe.

## Compact RAW anchors

`artifacts/protection_v4_probe/protection_raw_anchors.json` contains ten full raw anchors. Each preserves the OnEvent raw packet, decoded parameter blob, chunk/block/payload order, exact same-time CastSpell packet, and exact same-time Buff packet where one is available.

| Replay / time | Spell | Target | Event | Amount | Route |
|---|---|---|---|---:|---|
| `HN1-11154791609 / 160140` | Lulu E | Nilah | shield | `78.2249984741211` | paired grant+receive |
| `HN1-11154791609 / 172248` | Karma E | Tristana | shield | `90.80000305175781` | paired grant+receive |
| `HN1-11158276256 / 318761` | Janna E | Caitlyn | shield | `84.94999694824219` | paired grant+receive |
| `HN1-11172852368 / 615141` | Yuumi E | Yuumi | shield | `101.5999984741211` | paired grant+receive |
| `HN1-11177593199 / 615939` | Seraphine W | Seraphine | shield | `75.80000305175781` | receive-only |
| `HN1-11181975536 / 131958` | Milio E | Xerath | shield | `49.04999923706055` | paired grant+receive |
| `HN1-11177593199 / 821714` | Soraka W | Senna | heal | `132.22900390625` | raw row preserved with same-time sibling |
| `HN1-11177593199 / 522316` | Soraka R | Senna | heal | `284.9962463378906` | raw row |
| `HN1-11181975536 / 214067` | Milio W | Xerath | heal | `3.0` | raw row |
| `HN1-11181975536 / 602107` | Milio R | Xerath | heal | `177.0` | raw row |

All ten anchors have exact replay timestamps, exact caster IDs, and the decoded protection target in the CastSpell target list. The Lulu E parameter blob is:

```text
d201000000000000b7000040b600004033739c42
```

which decodes to source `0x400000b7`, target `0x400000b6`, amount `78.2249984741211`.

## Buff-path result

The Buff path supports lifecycle, caster/target, stack count, elapsed time, and remaining time. It does not contain heal/shield magnitude, remaining shield, absorbed shield, or temporary-HP amount. The audit covered 312,813 Buff packets, including 109,104 Add rows and 981 protection-skill anchors.

```text
Add callback                0x0091e450
Add consumer chain          0x0091cee0 -> 0x0091aeb0
UpdateCount chain           0x0091e930 -> 0x0091da20
Remove chain                0x0091e790 -> 0x0091d4e0
```

## Tests and artifacts

```text
V3 runtime regression       PASS, 1000 / 1000 full matches
V4 transform self-tests     PASS, heal/shield event and schema transforms
V4 smoke                    PASS, 100 / 100
V4 full batch               PASS, 103249 / 103249
RAW-anchor validation       PASS, 10 / 10 exact cast/caster/target matches
```

Primary files:

```text
scripts/decode_on_event_protection_v4.py
scripts/build_protection_v4_raw_anchors.py
artifacts/protection_v4_probe/on_event_protection_decoded_all14.summary.json
artifacts/protection_v4_probe/on_event_protection_field_contract.json
artifacts/protection_v4_probe/protection_raw_anchors.json
artifacts/protection_v4_probe/v3_regression_unit_apply_damage_runtime_validation.summary.json
```

The exhaustive decoded JSONL was deliberately removed after its compact
summary, contracts and raw anchors were retained. Reproducing the 103,249-row
scan requires the separately supplied Replay corpus and pinned runtime image.

## Explicit limitations

- `direct_reported_amount` must not be relabeled as raw heal, effective heal, or overheal without HP-state validation.
- Shield `0x00ed +0x10` is application/generated amount, not remaining or absorbed shield.
- Target-level `shield_absorbed` is available only from the separate `0x0017` packet. It cannot be attributed to a specific caster or shield instance.
- `shield_remaining`, `shield_unused`, current/max HP, temporary HP, and max-HP modification remain unavailable.
- `DamageShieldedParams` layout is not claimed because the corpus contains no `0xef` row.
- Buff correlation is supporting lifecycle evidence only; it is not an amount source.
