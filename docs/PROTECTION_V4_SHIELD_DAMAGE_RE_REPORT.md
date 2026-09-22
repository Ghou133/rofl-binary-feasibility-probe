# Protection V4 shield-depletion reverse-engineering report

## Result

The current `16.15.801.3452` client exposes direct shield depletion through
packet opcode `0x0017`, RTTI descriptor `PKT_UnitApplyShieldDamage_s`.

The complete 14-Replay scan found exactly two packets, both in
`HN1-11184800649`; all other scanned Replays had zero. Both packets deserialize
successfully, consume the full payload, expose the same target in both decoded
network-ID fields, and match the packet header target.

## Frozen boundary

The decoder is isolated in `scripts/decode_shield_damage_v4.py`. It subclasses
no production pipeline and does not modify the frozen shared emulator:

```text
scripts/emulate_exact_packet_decoder.py
SHA-256 c3959b3163c391a97ee0d6fc63641ad1f4507fbbe6dab87cd647e9a174fca6e7
```

## Current-client chain

```text
registration range                 0x0025294b..0x002529c2
opcode load                        0x002529a7 = 0x0017
factory inline construction        0x00ede2f8
factory opcode write               0x00ede31b
packet vtable                      0x01b108a8
deserializer                       0x00f1db80
callback                           0x0029edd0
RTTI getter                        0x002ca9c0
RTTI descriptor                   0x01e7be40
descriptor                         PKT_UnitApplyShieldDamage_s
object size                        0x20
```

The emulator uses the `RET` at `0x002cd334` as a deterministic V4-local no-op
constructor entry. The packet's inline factory constructor depends on runtime
state, while the deserializer independently writes every payload field used by
the callback. This substitution is guarded by exact image hash and transform
self-tests.

## Callback-decoded field contract

| Offset | Type | Meaning | Status |
|---:|---|---|---|
| `+0x10` | `u32` | unresolved protocol field; zero in both samples | `UNRESOLVED` |
| `+0x14` | `u32` | target/entity network ID | `VERIFIED_DIRECT` |
| `+0x18` | `f32` | shield damage / absorbed amount | `VERIFIED_DIRECT` |
| `+0x1c` | `u32` | target/entity network ID | `VERIFIED_DIRECT` |

In both rows, `+0x14 == +0x1c == raw_param`. No source or shield-instance ID is
available from this packet, so absorption is published only as a target-level
total and is not assigned to Lulu, Janna, or another shield source.

## Complete scan and ordered damage correlation

```text
Replays scanned                    14
parser errors                       0
0x0017 packets                      2
deserialize success                 2 / 2
fully consumed                      2 / 2
target-field agreement              2 / 2
same-target same-time damage link   2 / 2
```

| Replay time | Target | Direct shield absorbed | First following same-target `UnitApplyDamage` | Block delta | Derived sum |
|---:|---|---:|---:|---:|---:|
| `2280009 ms` | Samira `0x400000b6` | `375.13690185546875` | `134.57955932617188` | `+192` | `509.7164611816406` |
| `2288778 ms` | Gnar `0x400000b3` | `30.030563354492188` | `102.86150360107422` | `+269` | `132.8920669555664` |

The neighbor relation is strict: same Replay, same timestamp, same chunk, same
target, and the first following `UnitApplyDamage` in decompressed block order.
The two packet amounts remain separate direct observations. Their sum is marked
`VERIFIED_DERIVED_SUM`; it is not relabeled as a separately observed field.

## Artifacts

```text
scripts/decode_shield_damage_v4.py
artifacts/protection_v4_probe/packet_0017_all14.jsonl
artifacts/protection_v4_probe/packet_0017_all14.jsonl.manifest.json
artifacts/protection_v4_probe/shield_damage_decoded_all14.jsonl
artifacts/protection_v4_probe/shield_damage_decoded_all14.summary.json
artifacts/protection_v4_probe/shield_damage_deserializer_f1db80.json
artifacts/protection_v4_probe/shield_damage_callback_29ed80.json
artifacts/protection_v4_probe/shield_damage_factory_case_ede280.json
```

## Limitations

- Shield remaining and unused/expiry amount are not present.
- Absorption cannot be attributed to a specific active shield instance or caster.
- Consumption order between simultaneous shields is unavailable.
- Only two positive samples exist, so the packet/profile is patch-specific and
  must not be generalized to another client image without a new static audit.
