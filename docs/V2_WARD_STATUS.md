# V2 Ward and Position Status

## Current Status

`RESEARCH_READY_V2_COMPLETE` for replay version `16.15.801.3452`.
For exact build `16.16.805.0442`, WardSpawn is `VISION_SPAWN_READY`; Ward
lifecycle is `PARTIAL` because removal reason remains unavailable.

V2 is additive. It does not alter V1 Death, Damage, CastSpell, Buff,
participant mapping, or ADC-timeline claims.

## 16.15 WardSpawn Decoder

WardSpawn is `VERIFIED_DIRECT` from replay packet `851` (`0x0353`):

| Profile item | Current-build value |
| --- | --- |
| vtable | `0x01b141b0` |
| constructor | `0x00eb0640` |
| deserialize range | `0x0103b1c0..0x0103d737` |
| object size | `0x90` |
| direct position writes | planar x `+0x18`, height `+0x1c`, planar y `+0x20` |
| direct owner / entity ID | `+0x30` / `+0x44` |
| decoded names | generic pointer/length `+0x50/+0x58`; entity pointer/length `+0x78/+0x80` |

`current_registration_analysis.json` proves that the constructor stores opcode
`0x0353`, the packet factory's entry 851 invokes that constructor, and generic
replay dispatch invokes vtable `+0x08`. `current_full_decode/summary.json`
records exact runtime Unicorn execution of all selected packets, with fields
read only from the current object-write trace.

The full decode selected 17,406 `0x0353` blocks across ten replays. All 17,406
were accepted with zero infrastructure failures. It emitted 1,357 WardSpawn
records and 2,320 corpse records.

## 16.16 WardSpawn Decoder

The independently recovered route is `0x049a`. It is a broad entity route, so
public player Ward rows are gated by direct current-build names, a champion
owner and plausible direct coordinates rather than by packet occurrence alone.

| Profile item | `16.16.805.0442` value |
| --- | --- |
| factory / case | `0x00ed97b0` / `0x00ee9116` |
| constructor / opcode store | `0x00eabb20` / `0x00eabb29` (`0x049a`) |
| final vtable / deserialize | `0x01b14570` / `0x01025d50` |
| rejected old candidate | `0x00fc7770` |
| object size | `0x90` |
| direct position writes | x `+0x10`, height `+0x14`, y `+0x18` |
| direct owner / entity ID | `+0x1c` / `+0x70` |
| decoded names | generic `+0x48/+0x50`; entity `+0x78/+0x80` |

Twenty exact-build replays produced 31,862/31,862 successful full-consume
route rows and 2,252 confirmed player WardSpawn rows. Type counts are 1,732
Yellow/Sight, 350 Control and 170 Farsight. Owner-to-participant/team coverage
is 100% with zero conflicts; 197/200 participant-game rows equal Replay-tail
`WARD_PLACED` exactly and three differ by one. Special/map entities and 22
unknown player-Ward candidates remain in separate public evidence streams.

The 16.16 corpus has 4,269 direct corpse signals and 1,128 conservative
spawn-to-corpse matches. These rows use `OBSERVED_END` because the corpse event
itself is direct, but the association is explicitly derived. Removal reason is
`UNKNOWN`; no game-rule estimated end is emitted.

The direct WardSpawn planar axes are output `position.x` from object offset
`+0x10` and output `position.y` from `+0x18`; height is the separate
`+0x14` field. This x/y convention is distinct from the calibrated hero-path
x/z convention below.

## Direct, Derived, and Unavailable Fields

| Field / capability | Status | Boundary |
| --- | --- | --- |
| Spawn timestamp, planar x/y, owner network ID, entity network ID, decoded name | `VERIFIED_DIRECT` | recovered only from current-build object writes (`x +0x10`, `height +0x14`, `y +0x18`, owner `+0x1c`, entity ID `+0x70`) |
| Ward classification | `VERIFIED_DERIVED` | deterministic classification of the direct entity name |
| Participant and team | `VERIFIED_DERIVED_BUILD_BOUND` | exact-build owner-network-ID formula plus Replay-tail participant/team map |
| Lifecycle duration | `VERIFIED_DERIVED` | conservative direct spawn/corpse association; removal time minus spawn time |
| Removal reason, killer | `UNAVAILABLE` | no verified field or unique semantic delete reason |

## Frozen 16.15 Validation Detail

The statistics below belong only to the frozen `16.15.801.3452` V2 corpus.
They remain as regression context and must not be interpreted as 16.16 counts,
fields, or acceptance evidence.

Type coverage is: 923 `YELLOW_OR_SIGHT_WARD`, 174 `CONTROL_WARD`, 98
`FARSIGHT_WARD`, and 162 `OTHER_WARD`. These are entity-name-derived types,
not a CastSpell dictionary restriction.

## Frozen 16.15 Yellow Ward Validation

All 464 decoded `TrinketTotemLvl1` casts associate with a direct WardSpawn;
there are zero unmatched casts. Timestamp delta is exactly `0 ms` at mean,
p50, p90, p95, and max. The 893 unmatched decoded spawns remain visible in
the corpus rather than being discarded.

Both CastSpell coordinate vectors are retained and compared; neither feeds the
WardSpawn decoder.

| Spawn comparison | Mean | p50 | p90 | p95 | Max | <= 10 units |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `target_position` (start-like) | 529.85 | 575.75 | 622.91 | 627.05 | 844.08 | 0 / 464 |
| `target_position_end` (end-like) | 6.75 | 1.66 | 2.45 | 31.09 | 246.52 | 430 / 464 |

`CAST_TARGET_POSITION_END_AS_WARD_POSITION_PROXY` is
`VERIFIED_DERIVED_WITH_REPORTED_ERROR_PROFILE`. It is validation-only and
cannot replace the direct decoded WardSpawn x/y axes for Ward heatmaps or
analysis.

## Frozen 16.15 Lifecycle

There are 637 conservative WardSpawn-to-corpse lifecycle matches. The derived
duration distribution has mean `115157.88 ms`, p50 `103560 ms`, p90
`150177 ms`, p95 `150262 ms`, and max `558023 ms`. The rule prefers same
network ID; otherwise it accepts a unique same-replay, time-ordered, same-owner
match within five coordinate units. Ambiguous fallback candidates are rejected.

## Hero Path and Position

Path packet `721` (`0x02d1`) is `VERIFIED_DIRECT` for entity ID, speed, and
compressed waypoints. Its current profile is constructor `0x00eb1b90`,
deserialize `0x0103f810..0x0103fbc9`, object size `0x28`, payload pointer
`+0x18`, and payload size `+0x20`. Dynamic execution accepted 1,249 of 1,249
representative `0x02d1` samples and decoded 11,953 records with zero emulator
failures.

The position transform is separately `VERIFIED_CURRENT_CALIBRATION`:
`x = signed(encoded_x) * 2 + 7358`, `z = signed(encoded_y) * 2 + 7412`.
Across 27,452 calibration matches its p50/p95 error is `1.98/80.60` units;
the swapped-axis p50 is `6846.24` units. The all-replay extraction reports
374,368 path packets, 1,385,189 path records, 459,906 hero-path events, and
159,765 one-second position samples.

## Remaining Boundaries

Damage type, basic-attack and critical flags, per-hit spell attribution,
shield generated/absorbed, healing received, and temporary-HP amount remain
`UNAVAILABLE`. Current ward and path work does not infer any of these values.

## Evidence and Reproduction

```powershell
npm test
npm run validate-ward-spawn-current
npm run verify-v2
```

- `artifacts/v2_ward_spawn/current_full_decode/summary.json`
- `artifacts/v2_ward_spawn/current_full_decode/validation.json`
- `artifacts/v2_ward_spawn/current_registration_analysis.json`
- `artifacts/v2_ward_spawn/current_path_packet_analysis.json`
- `artifacts/v2_ward_spawn/current_path_summary.json`
- `artifacts/v2_ward_spawn/path_packet_profile_16_15.json`
