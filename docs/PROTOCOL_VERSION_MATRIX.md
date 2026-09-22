# Protocol version matrix

Container compatibility, structural packet compatibility and semantic
compatibility are separate gates. Framing a packet does not prove that its
route, runtime object layout or field meaning is unchanged.

| Replay version/build | L1 format | L2 packet structure | L3 semantics | Release level |
| --- | --- | --- | --- | --- |
| `15.23` | not currently regression verified | `UNSUPPORTED_VERSION` | `UNSUPPORTED_VERSION` | `BLOCKED` |
| `16.14` | not currently regression verified | `UNSUPPORTED_VERSION` | `UNSUPPORTED_VERSION` | `BLOCKED` |
| `16.15.801.3452` | `FORMAT_VERIFIED` | exact runtime profiles verified | P0/P1 platform semantics verified as documented | `FULL_PLATFORM_READY` |
| `16.16.805.0442` | `FORMAT_VERIFIED` | HeroPath `0x00f6`, LevelTransition `0x0314`, entity/Ward `0x049a`, Damage `0x017f`, HeroDeath `0x0112`, HeroRespawn `0x0265`, HeroStats `0x010c`, and six bounded gameplay-tail routes exact profiles verified | Deep semantic surface with field-specific direct/derived/candidate grades; Buff/Cast/Protection partial; Ward lifecycle partial | resolver `DEEP_SEMANTIC_READY` / manifest `SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL` |
| Other `16.15.*` / `16.16.*` builds | raw inspect only | `UNSUPPORTED_VERSION` | `UNSUPPORTED_VERSION` | `BLOCKED` |
| Any other build | raw inspect may be attempted | `UNSUPPORTED_VERSION` | `UNSUPPORTED_VERSION` | `BLOCKED` |

The exact registry is `src/build_registry.js`. It keeps a rolling window of up
to three explicit build profiles; it never selects the nearest version. The
public build-agnostic entry point is `src/semantic_api.js`. Every semantic event
continues to carry `game_version`, `patch` and `build_profile`.

## Exact route matrix

| Capability | `16.15.801.3452` | `16.16.805.0442` | 16.16 status |
| --- | ---: | ---: | --- |
| HeroPath | `0x02d1` | `0x00f6` | structure direct; coordinates `SEMANTIC_VERIFIED_DERIVED` |
| LevelTransition | `0x025a` | `0x0314` | occurrence/entity/time direct; LevelAfter build-bound derived |
| WardSpawn | `0x0353` | `0x049a` | `SEMANTIC_VERIFIED_DERIVED`; direct time/owner/entity/name/position; lifecycle partial |
| HeroDamage | `0x028a` | `0x017f` | `VERIFIED_DIRECT` time/source/target/recorded amount/type; amount stage and source-kind attribution unresolved |
| HeroDeath | `0x0160` | `0x0112` | `VERIFIED_DIRECT` occurrence/time/raw victim+killer fields; participant mappings exact-build derived; assists unavailable |
| HeroRespawn | unresolved | `0x0265` | `VERIFIED_DIRECT` occurrence/time/protocol position; 282/282 exact full-consume; scalar role and map/base semantics unavailable |
| HeroStats scoreboard | unresolved | `0x010c` keyframe | raw XP and lane CS verified; XP integer floor-derived; total gold/jungle CS candidate-only |
| Item transaction candidates | unresolved | `0x0137` / `0x04b3` | exact structural decode and bounded anchor differentials only; buy/sell `CANDIDATE`, undo `UNAVAILABLE`, no universal ItemEvent publication |
| Item state / swap / substitution / support quest | unresolved | `0x0311` / `0x02ea` / `0x006c` / `0x01e8` / `0x005a` / `0x0064` | field-specific direct/partial snapshots, direct swap/substitution, and constrained derived stage; never transaction-cause semantics |
| CastSpell | `0x0459` | exact-build partial surface | field-specific `PARTIAL`; full event/target attribution unavailable |
| Buff | `0x0406` / `0x0031` / `0x0256` | exact-build partial surface | field-specific `PARTIAL`; unnamed fields unavailable |
| Protection | `0x009e` / `0x0017` | exact-build partial surface | field-specific `PARTIAL`; source/instance/full lifecycle unavailable |
| Gameplay tail | unresolved | `0x00b8` / `0x03d4` / `0x01ab` / `0x00e4` / `0x01b5` / `0x0298` | bounded direct protocol fields only; no cooldown/spell/attack/map semantic promotion |
| Sweeper held / trinket state | no 16.16 inference | no verified 16.16 route | `UNVERIFIED`, exact-build contract only |
| Sweeper activation / interval / owner / position | no 16.16 inference | CastSpell and Buff/state unresolved | `UNAVAILABLE`, exact-build contract only |

`0x01e8`, the initial 16.16 LevelTransition shape candidate, is explicitly
rejected. The verified route is `0x0314`.

The Sweeper V1 capability contract is version-pinned to `16.16.805.0442` and
does not import 16.15 item, CastSpell, or Buff semantics. Its empty event arrays
are capability metadata, not a behavior count; see `docs/SWEEPER_CAPABILITY_V1.md`.

## 16.16 format and root-cause evidence

The corpus contains 100 unique exact-build files; 40 were selected
deterministically for strict validation. Header, metadata, chunks, native Zstd,
55,552,224 framed blocks and timestamp order passed with zero framing errors.
All eleven old semantic IDs were genuinely absent.

The exact read-only runtime image is 35,213,312 bytes with SHA-256
`0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55`.
Every checked 16.15 RVA moved. The 16.16 base serializer, decode wrapper and
base vtable are `0x0124c2e0`, `0x0122e820` and `0x01a23ab0` respectively.

The supported root-cause conclusion is a build-specific Replay route and
runtime-registration migration. It is not a container detector failure: strict
framing remained healthy while P0 semantics reappeared under new routes. The
evidence does not support applying a single global opcode permutation to the
unresolved capabilities.

## 16.16 P0 semantic evidence

HeroPath executed the exact constructor/deserializer on 18,001 bounded packets
from eight replays: 18,001/18,001 runtime full-consume and 18,001/18,001 shared
plaintext-grammar full-consume. It produced 24,314 hero records with all ten
participants in all eight replays. Against 240 DETAILS position anchors, the
direct coordinate transform had p50 2.24 and p95 173.26 game units; swapped
axes had p50 2,667.94. Five ten-participant trajectory plots passed manual
review.

LevelTransition executed 2,325 champion-param packets from twenty replays:
2,325/2,325 exact full-consume. It matched 2,295 unique events among 2,356
DETAILS `LEVEL_UP` anchors within ±2 ms, with 180 participant sequences and no
mapping conflict. Required build-bound mappings are `242→Lv2`, `194→Lv3` and
`210→Lv4`.

Match Details remains validation-only; Replay packets remain the emitted fact
source. The 16.16 P0 gate remains historical evidence. The current downstream
gate is `RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`. WardSpawn, Damage, HeroDeath,
HeroRespawn, XP/lane CS and bounded gameplay-tail fields have their respective
field-specific gates. Ward lifecycle remains partial, Ward removal reason and
HeroDeath assists are unavailable, and total gold/jungle CS remain candidate-only.

The 2,295 LevelTransition matches are one-to-one (duplicate packet-to-anchor
reuse is rejected), a 97.41% unique-anchor coverage ratio across 18
anchor-bearing replays. Lv2/Lv3/Lv4 have 180/179/180 independent observations.
Both P0 validators require nonempty input, recompute payload length/SHA-256,
bind rows to an exact-build strict-export manifest and exact runtime image, and
report zero input-provenance and infrastructure failures. A replay with no
matching capability packet is reported as an observation state, not as a
zero-row decoder PASS.

This semantic release supersedes the earlier format-only
`NEW_BUILD_CORE_COMPATIBILITY_BLOCKED` result; that older artifact remains as
historical L1-stage evidence and is not the current downstream gate.

## 16.16 combat and scoreboard semantic evidence

Damage `0x017f` executed the exact constructor/deserializer for every observed
latest-four row: 266,332/266,332 successful full-consume. Packet time,
source/target IDs, recorded amount, and damage type are direct exact-build
fields. Independent type anchors cover physical/magic/true at 2/2/2 with zero
mismatches. The amount's pre-/post-mitigation/effective-HP-loss stage and
spell/basic/item/rune/passive attribution remain unknown.

HeroDeath `0x0112` produced 301/301 successful full-consume P0 packets and
matched independent DETAILS victim and killer at 0–1 ms. Victim/killer raw
storage is retained and participant mappings are exact-build derived. Assists,
kill credit and all remaining death inner fields are unavailable or unknown; 242
nonempty-assist counterexamples reject the tested scalar, bitmask, and fixed-triplet
interpretations. HeroRespawn `0x0265` is independently published: 282/282 exact
rows uniquely follow one of those deaths (19 terminal deaths have no row);
occurrence/time/protocol position are direct, while the resource-like scalar and
map/base semantics remain unpromoted. Talon's audited example respawns at `250195 ms`.

HeroStats `0x010c` is a cumulative keyframe scoreboard snapshot, not a live
combat-state route. Across 1,390/1,390 full-consume P0 rows, raw XP at blob
`+0x28` has an exact `floor` projection to DETAILS and lane CS at `+0x3c`
matches exactly. Total gold at `+0x38` remains `CANDIDATE` because one of 1,390
floor comparisons fails; jungle CS at `+0x40` remains `CANDIDATE` with 15 floor
mismatches. No current-gold, item transaction, or exact XP/CS event-time
semantic is claimed from HeroStats.

The item-route differential fully consumes 1,601/1,601 `0x0137` and 1,013/1,013
`0x04b3` packets. `0x0137` has a bounded item-id field and aligns 1,154/1,168
purchase anchors, but 447 route extras and 14 misses prevent route-level buy
semantics. All 60 sale anchors align to `0x04b3`, but another 953 rows are not
sales and the packet carries no direct item ID. The tested pair matches 0/52
undo anchors and reconstructs only 26/60 sold item identities. These facts are
registered as candidate/negative evidence; the public API emits no ItemEvent.

## 16.16 full semantic baseline gate

The current exact-build latest-four inventory conserves 288 routes and
7,223,748 packets with no fallback or silent discard. The route partition is
27 `registered`, 3 `decoded`, 79 `classified`, and 179 `unknown`; the packet
partition is 1,531,741, 2,332,337, 1,135,531, and 2,224,139, with stale-route
count zero. `FULL_SEMANTIC_COMPLETENESS_GATE_V1` is `READY`
only after all 69 requested A–Z fact-layer capabilities have an explicit exact-
build record, `map` is included in the required domains, and a passing nonzero
machine regression attestation is present; consult that generated attestation
for the current test count. `READY` is completeness of
inventory/research accounting, not universal positive semantic verification. The
deep-recovery queue then reaches actionable route/capability 0/0 (137/57 rows),
16 locally exhausted domains and 7/7 saturation checks PASS:
`SEMANTIC_RECOVERY_SATURATED`, never `FULLY_PARSED`.
The protected Jungle Objective Holdout was not read, enumerated, hashed,
decoded, tested, or consumed.

The low-cost 16.15→16.16 structural migration remains an exact-build boundary,
not a semantic transfer: `MIGRATION_ANALYSIS_COMPLETE`, SHA-256
`bd91c59d8272649016ff855a01a6cfdfdfa41957d2b81fa77ecf30ee28a5f3f5`, reports
container/inventory/route/layout/registration deltas and requires fresh
exact-build decoder replay plus field-behavior regression before any promotion.

## 16.16 Ward semantic evidence

Packet `0x049a` is a broad entity route, not one Ward per packet. Its exact
factory case allocates `0x90`, calls constructor `0x00eabb20`, installs final
vtable `0x01b14570`, and dispatches deserializer `0x01025d50`. The earlier
`0x00fc7770` candidate is rejected because it is not that vtable slot.

Across twenty exact-build replays, 31,862/31,862 route rows returned success and
fully consumed. Direct object writes recover x/height/y at `+0x10/+0x14/+0x18`,
owner at `+0x1c`, generic name at `+0x48/+0x50`, entity ID at `+0x70`, and entity
name at `+0x78/+0x80`. Current-build names plus champion owner and plausible
direct coordinates yield 2,252 confirmed player wards: 1,732 Yellow/Sight, 350
Control and 170 Farsight. All map to participant/team with zero conflicts.
Special/map/unknown vision rows remain visible and are not counted as player
wards. Direct corpse rows support 1,128 conservative observed-end matches, but
destroy reason is unknown; therefore `VISION_SPAWN_READY=YES`,
`VISION_LIFECYCLE_READY=NO`, and `VISION_DOWNSTREAM_READY=YES` for spawn-based
timelines only.
