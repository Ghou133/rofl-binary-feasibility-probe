# Ward Spawn Upstream Reverse Engineering Baseline

## Scope and status

This document records an audited historical baseline for the upstream ROFL project and its 5.5 patch archive. It is deliberately not a decoder profile for League 16.15.801.3452. Current-build facts must come from current-build static or dynamic evidence, not from these historical values.

The retained machine-readable records are `artifacts/v2_ward_spawn/upstream_reference_manifest.json` and `artifacts/v2_ward_spawn/old_build_ward_spawn_signature.json`.

## Fixed material

The historical audit inspected `https://github.com/Mowokuma/ROFL.git` at commit `7181c9a745881cad9e14b79653c48af0d2fcd824`; `git fsck --no-reflogs --full` completed successfully and the clone was clean at that time.

The audited release archive had SHA-256 `8ff64b70f1f962ca3dccd0b29a363605a8b2ca19fee09c8a12a34e1d90cfbd4f`; its selected `patch/5-5.patch` had SHA-256 `954d9056286770de294ab3e0b5e75f24a3d5f099661ab673bf041feb5a875fe5`.

The clone, release archive and extracted binaries are no longer distributed in
this cleaned workspace because the upstream snapshot did not include a licence
file. The hashes below remain historical provenance only; they cannot be
recomputed from the handoff package without obtaining the source separately.

The `5-5.patch` archive entries were streamed through SHA-256 and compared with `artifacts/v2_ward_spawn/old_build_5-5`. All four entries matched byte-for-byte:

| Entry | Bytes | SHA-256 |
| --- | ---: | --- |
| `data.bin` | 1,265,664 | `c8cd50d27caa1fc5c1e975f50e43155413c47676cfb9192120c0c90c28fbbb43` |
| `rdata.bin` | 3,993,600 | `4f087a1e0527f8e9da3134cf8ea7565bff2559f8305da07c0eb6469263895bb5` |
| `result.json` | 934 | `794939b3d60958530d397b6f0091bb43cdd10529f857d2c8d4d2a0a76a2e715a` |
| `text.bin` | 23,699,456 | `85646feec1731121f280624bec4f8fca5eb1e64fce8d5e2402126570ae9a74b4` |

This validates the local provenance chain. It does not prove that the retained upstream source commit built the retained release binary; that relationship is intentionally not asserted.

## Source data flow

The fixed source parses replay chunks and blocks, where a block exposes a u16 `packet_id`, a timestamp, and payload. `get_blocks_with_id` filters those parsed blocks by the configured packet ID. `get_replay_info` in `src/main.rs` then feeds ward blocks to the configured WardSpawn range and path blocks to the configured Path range.

`Config::parse` in `src/emulator/config.rs` reads `result.json` from the patch archive. `StubEmulator::setup_args` in `src/emulator/stub_emulator.rs` allocates an emulated object of `0x90` bytes, passes it in RCX, and passes a replay-payload pointer chain in RDX/R8. The ward call installs an object-range write hook. It uses the first observed writes for owner and ID; it selects x/y based on the configured zero-based pre-increment write count; then reads a pointer and length for the name after emulation.

The source does not treat a CastSpell target as a WardSpawn coordinate. It obtains its historical ward position only from writes produced while emulating the selected WardSpawn block. Any current pipeline must preserve that distinction.

## Historical 5.5 profile

`old_build_5-5/result.json` specifies the following historical values:

| Item | Historical 5.5 value |
| --- | --- |
| Ward replay packet ID | 571 (`0x023b`) |
| Ward deserialize range | `0x00e3d7b0` to exclusive `0x00e3fd61` |
| Ward emulated allocation | `0x90` bytes in fixed source |
| Ward owner ID | object offset `0x18`, first write |
| Ward x | object offset `0x20`, configured count 4 |
| Ward y | object offset `0x28`, configured count 4 |
| Ward network ID | object offset `0x48`, first write |
| Ward name | pointer `0x60`, u32 length `0x68` |
| Path replay packet ID | 980 (`0x03d4`) |
| Path deserialize range | `0x00e45710` to exclusive `0x00e45b35` |
| Path decoded payload pointer / size | `0x18` / `0x20` |

The Ward function range lies inside the verified `text.bin` section. Its precise 9,649-byte slice has SHA-256 `a3bfcb430d396412513418f5e8849ec36d32ebfad2e4b275c9a37eaa07bb9ff9`.

The x/y count needs careful interpretation. Source initializes every field count at zero, reads the count before incrementing it, and captures when `count == 4`. Therefore the value written in `result.json` is zero-based count 4, which is the fifth observed write at that offset. The historical shorthand "write #4" is retained only as that configuration value, never as an ambiguous ordinal claim.

The path payload decoder reads `u16 parsing_type`, `u32 entity_id`, then `f32 speed`, with subsequent compressed waypoints. In this old implementation, the coordinate reconstruction is `encoded * 2 + 7358` for x and `encoded * 2 + 7412` for y after 16-bit sign extension. This is historical parser behavior, not a portable map transform.

The ward application layer accepts `YellowTrinket`, `SightWard`, and `JammerDevice`; a decoded name containing `Corpse` removes a stored ward at the matching decoded integer coordinate. That is an upstream lifecycle policy, not a protocol guarantee.

## Retained checks

The two compact manifests can still be parsed and inspected. Re-running the
old-source hash chain requires separately obtaining the upstream commit and
release archive; it is not a supported handoff workflow.

## Current-build guardrails

- No old packet ID, RVA, object size, offset, write count, field interpretation, Path transform, or lifecycle heuristic in this document establishes a League 16.15 fact.
- A current WardSpawn result must arise from independently identified current replay packet data and successful current decoder execution.
- A CastSpell target remains an action target. It cannot be relabeled or substituted as an independently verified ward spawn position.
- Matching old and new code shape is a migration lead only. It is not field-level verification.
