# ROFL container and semantic decoder notes

Scope: container/framing facts observed in real Replay files and semantic
profiles pinned to exact replay version `16.15.801.3452`. Similar names, old
patch offsets and Match Details values do not promote a field to verified.

## File layout

```text
RIOT header
variable-length replay version
chunk region
256-byte signature region
UTF-8 metadata JSON
u32 little-endian metadata length
```

Header:

| Offset | Size | Field | Status |
| ---: | ---: | --- | --- |
| `0x00` | 4 | ASCII `RIOT` | `VERIFIED_DIRECT` |
| `0x04` | 2 | format version, LE | `VERIFIED_DIRECT` |
| `0x06` | 2 | unnamed raw field | `VERIFIED_DIRECT` |
| `0x08` | 6 | unnamed raw bytes | `VERIFIED_DIRECT` |
| `0x0e` | 1 | version-string length | `VERIFIED_DIRECT` |
| `0x0f` | variable | UTF-8 replay version | `VERIFIED_DIRECT` |

The final four bytes store `metadata_length`:

```text
metadata_end    = file_size - 4
metadata_start  = metadata_end - metadata_length
signature_start = metadata_start - 256
```

`statsJson` is aggregate metadata. It is not converted into individual replay
events. If game ID is absent from the verified container fields, a value taken
from a filename remains `INFERRED_FROM_FILENAME`.

## Chunk records

Each chunk header is 17 bytes:

| Relative offset | Size | Field |
| ---: | ---: | --- |
| `0x00` | 4 | `chunk_id` |
| `0x04` | 1 | `chunk_type` |
| `0x05` | 4 | `chunk_id_2` / stream identifier |
| `0x09` | 4 | `uncompressed_length` |
| `0x0d` | 4 | `compressed_length` |

When `compressed_length > 0`, the body uses Zstandard. The parser checks all
header/body bounds, declared sizes, safety limits, decompressed size and exact
consumption of the chunk region.

| Stream tag | Name |
| ---: | --- |
| `0x01` | `game_chunk` |
| `0x02` | `keyframe` |
| `0x03` | `start_keyframe` |
| `0x04` | `start_sentinel` |

## Decompressed block framing

| Marker bit | Set | Clear |
| ---: | --- | --- |
| `0x80` | `u8` relative timestamp delta in milliseconds | `f32 LE` absolute seconds |
| `0x40` | reuse previous packet ID | `u16 LE` packet ID |
| `0x20` | `u8` relative parameter delta | `u32 LE` absolute parameter |
| `0x10` | `u8` payload length | `u32 LE` payload length |

Direct and derived events retain replay SHA-256, chunk file offset,
decompressed block/payload offsets, packet ID, payload length and payload
SHA-256 where the route supports them.

## Exact runtime decoder

The supported Tencent client executable was packed. The historical research
captured a read-only runtime image and pinned its SHA-256:

```text
7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb
```

The portable handoff does not distribute that image. When authorised input is
provided separately, `scripts/emulate_exact_packet_decoder.py` uses Unicorn to
map it, construct the packet object and execute the exact constructor and
deserializer. A profile is accepted only when replay version, packet ID,
stream, runtime-image hash and object bounds match, deserialization succeeds,
and the payload is fully consumed.

## Patch-pinned semantic families

| Family | Packet/opcode | Direct surface |
| --- | ---: | --- |
| Hero Death | `0x0160` | victim participant/network identity from the verified signature |
| NPC LevelUp | `0x025a` | transition occurrence, raw hero/network entity, Replay timestamp, and raw `field_10/field_11`; level-after is separately derived and build-bound |
| UnitApplyDamage | `0x028a` | source, target and `f32` amount; V3 additionally maps the direct damage-type byte |
| CastSpell | `0x0459` | caster, spell key, targets, positions and internal cast time; dictionary names are derived |
| Buff Add | `0x0406` | target/caster/slot/hash/type/count and timing fields |
| Buff Remove | `0x0031` | removal and lifecycle fields |
| Buff UpdateCount | `0x0256` | count/timing updates associated conservatively to active Buff state |
| WardSpawn | `0x0353` | owner/entity/name and direct planar x/y fields |
| Hero Path | `0x02d1` | entity, speed and compressed waypoints; game-plane coordinates are calibrated |
| OnEvent protection | `0x009e` | direct reported heal and generated-shield event parameters |
| Shield damage | `0x0017` | direct target-total absorbed amount, without source/instance attribution |

Exact RVAs, object offsets and corpus validation counts are documented in
`docs/V2_WARD_STATUS.md`, `docs/PROTECTION_V4_ON_EVENT_RE_REPORT.md` and
`docs/PROTECTION_V4_SHIELD_DAMAGE_RE_REPORT.md`. LevelUp evidence and the
version gate are documented in `docs/ROFL_UPSTREAM_CAPABILITY_SYNC_V1.md` and
`docs/PROTOCOL_VERSION_MATRIX.md`.

## Negative and candidate packet registry

| Packet/name | Status | Guardrail |
| --- | --- | --- |
| `0x0160 / PKT_NPC_Hero_Die_s` | `VERIFIED_DIRECT_HERO_ONLY` | Never widen to ordinary-monster death. |
| `0x0313 / PKT_NPC_Die_MapView_s` association | `CANDIDATE` | 27,524 packets decoded in the bounded probe, but no verified victim identity; `NOT_USABLE_FOR_CAMP_CLEAR`. |
| `0x02eb / PKT_NPC_Die_Broadcast_s` association | `REJECTED_FOR_CAMP_CLEAR` | Decodes, but does not match verified Hero Death anchors and does not prove ordinary-monster death. |
| `PKT_S2C_NeutralCampLeashStateChanged_s` | `NAME_ONLY_CANDIDATE` | Registration name without a verified Replay route. |
| `PKT_S2C_DestroyUnit_s` | `NAME_ONLY_CANDIDATE` | Registration name without a verified Replay route. |
| `NeutralCampCleared`, `OnNeutralMinionKill`, `OnNeutralMinionCampCleared` | `SCRIPT_EVENT_STRING_ONLY` | Client strings are not packet-emission evidence. |

`UnitApplyDamage` supplies a direct combat amount. It cannot represent camp
clear without verified ordinary-monster identity, remaining HP, death,
reset/despawn distinction, and camp lifecycle.

## Derived ADC timeline

The ADC death window scans backward from a verified death through verified
champion damage. A gap larger than 2,500 ms opens a new segment; fixed 5/10/15
second windows are also retained. Killer/attacker, Ward/position and protection
context are derived facts and must carry derived status.

## Unsupported versions

Semantic profiles are bound to exact version `16.15.801.3452`. A mismatch
returns `UNSUPPORTED_REPLAY_VERSION`; it never reuses a nearby patch's offsets.
Container/raw inventory may still work through `inspect` when the framing is
compatible.

## Current reproduction boundary

The cleaned workspace retains source and selected local research inputs, while
the portable handoff deliberately excludes raw Replay files, runtime image,
DuckDB and exhaustive decoder JSONL. Historical corpus counts therefore remain
bounded evidence rather than a clean-machine re-decode result.
