# ROFL capability matrix

This is the protocol-level capability source of truth. It describes what the
current parser and evidence corpus can establish; it does not claim that an
unavailable signal can never exist in any ROFL version.

Evidence grades used by public outputs are `VERIFIED_DIRECT`,
`VERIFIED_DERIVED`, `CANDIDATE`, `UNAVAILABLE`, and `UNSUPPORTED_VERSION`.
The build registry additionally records the layer gates `FORMAT_VERIFIED`,
`STRUCTURE_VERIFIED`, `SEMANTIC_VERIFIED_DIRECT` and
`SEMANTIC_VERIFIED_DERIVED`.
Older surfaces that use `VERIFIED`, `DERIVED`, or `PARTIAL` retain those names
until migrated deliberately.

## Per-build compatibility gate

The 2026-08-13 gate found 100 unique Replay files whose binary header is exact
build `16.16.805.0442`. Forty were selected deterministically for strict block
validation. Subsequent exact-runtime validation promoted the P0 participant,
HeroPath and LevelTransition profiles. The 16.16 Ward recovery then promoted
the `0x049a` entity route's evidence-gated player WardSpawn subset. Current
exact-build validation also promotes Damage `0x017f`, HeroDeath `0x0112`, and
the XP/lane-CS fields of HeroStats `0x010c`. The build release is now
resolver support level `DEEP_SEMANTIC_READY`, manifest release status
`SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL`, and downstream gate
`RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS`. Ward removal reason and HeroDeath
assists remain unavailable; Ward lifecycle is partial; total gold and jungle CS
remain candidate-only. Inventory routes `0x0137`/`0x04b3` are structurally decoded
and anchor-tested, but remain candidate subsets rather than published ItemEvents.

| Capability | `16.15.801.3452` | `16.16.805.0442` |
| --- | --- | --- |
| Container/header | `VERIFIED_DIRECT` | `VERIFIED_DIRECT` (40/40) |
| Chunk/Zstd/block framing | `VERIFIED_DIRECT` | `VERIFIED_DIRECT` (55,552,224 blocks; 0 errors) |
| Metadata roster | `VERIFIED_DIRECT` | `VERIFIED_DIRECT` (10/10 in 40/40) |
| Packet participant/entity mapping | `VERIFIED_DIRECT` | `SEMANTIC_VERIFIED_DIRECT`; 10/10 participants in 8/8 Path replays |
| Hero Path | `VERIFIED_DIRECT` / coordinates `VERIFIED_DERIVED` | route `0x00f6`; direct path fields / coordinates `SEMANTIC_VERIFIED_DERIVED` |
| LevelTransition occurrence | `VERIFIED_DIRECT` | route `0x0314`; `SEMANTIC_VERIFIED_DIRECT` (`0x01e8` rejected) |
| LevelAfter | `VERIFIED_DERIVED`, build-bound | `SEMANTIC_VERIFIED_DERIVED`, build-bound; `242→2`, `194→3`, `210→4` |
| Hero Death | `VERIFIED_DIRECT` | route `0x0112`; occurrence/time and raw victim/killer storage direct, victim/killer participant mappings exact-build derived; assists unavailable |
| Hero Respawn | `UNAVAILABLE` | route `0x0265`; 282/282 exact full-consume direct occurrence/time/protocol position; scalar role and map/base interpretation unavailable |
| Hero Damage | `VERIFIED_DIRECT` | route `0x017f`; time/source/target/recorded amount/type `VERIFIED_DIRECT`, amount stage and source-kind attribution unresolved |
| WardSpawn | `VERIFIED_DIRECT` | route `0x049a`; direct time/position/owner/entity/name, derived participant/team/type; `SEMANTIC_VERIFIED_DERIVED` |
| Ward lifecycle | conservative corpse-derived matching | 4,269 direct corpse signals; 1,128 conservative observed-end matches; `SEMANTIC_PARTIAL_DERIVED`, reason unknown |
| CastSpell | `VERIFIED_DIRECT` | exact-build field-specific `PARTIAL`; no complete spell target/attribution semantic |
| Buff | `VERIFIED_DIRECT` | exact-build field-specific `PARTIAL`; unnamed fields remain null/UNKNOWN |
| Shield | `VERIFIED_DIRECT` / target-total variant | `UNAVAILABLE` |
| Heal | `VERIFIED_DIRECT` reported amount | `UNAVAILABLE` |
| Protection | field-specific V4 contract | exact-build field-specific `PARTIAL`; do not infer source/instance/full protection lifecycle |
| Sweeper held | not a 16.16 inference source | `UNVERIFIED`; no verified item/trinket state or swap route |
| Sweeper activation | not a 16.16 inference source | `UNAVAILABLE`; CastSpell and Buff/state routes are unresolved |
| Item buy / sell | `UNAVAILABLE` | `CANDIDATE`; `0x0137` and `0x04b3` contain aligned subsets but have decisive extra/missing rows, so no ItemEvent is emitted |
| Item undo / transform / destroy | `UNAVAILABLE` | `UNAVAILABLE`; 52 undo anchors have no direct match on the tested pair and component removals lack an independent recipe graph |
| Inventory state | `UNAVAILABLE` | `VERIFIED_DIRECT` / `PARTIAL`; separate `0x0311` / `0x02ea` snapshots and `0x006c` special-slot fields publish only successful exact rows; they do not identify buy/sell/undo/transform/use causes |
| Item swap / substitution / support quest stage | `UNAVAILABLE` | `VERIFIED_DIRECT` / `VERIFIED_DERIVED`; `0x01e8` swap and `0x005a` substitution map are bounded direct fields, `0x0064` stage is a constrained derived map; none establishes a universal item transaction |
| Camp Clear | `CAMP_CLEAR_DIRECT_UNAVAILABLE` | `UNAVAILABLE` |
| XP | `UNAVAILABLE` | route `0x010c` keyframe; raw cumulative XP `VERIFIED_DIRECT`, `floor(raw)` integer `VERIFIED_DERIVED`; not exact XP-event timing |
| Lane CS | `UNAVAILABLE` | route `0x010c` keyframe; cumulative lane minions killed `VERIFIED_DIRECT` (1,390/1,390 exact oracle matches) |
| Jungle CS | `UNAVAILABLE` | route `0x010c` field candidate only (1,375/1,390 floor matches); no promoted semantic |
| Current gold | `UNAVAILABLE` | `UNAVAILABLE`; no verified current-gold, spend, income, or transaction-delta field |
| Total gold | `UNAVAILABLE` | route `0x010c` field `CANDIDATE` only (1,389/1,390 floor matches with one retained anomaly); public value remains null/CANDIDATE |

## 16.16 full semantic baseline readiness

The exact-build latest-four inventory conserves all 288 observed routes and all
7,223,748 packets. Its exhaustive partition is 27 `registered`, 3 `decoded`, 79
`classified`, and 179 `unknown` routes; packet counts are 1,531,741, 2,332,337,
1,135,531, and 2,224,139 respectively. Manifest/inventory stale-route count is
zero. These labels
are accounting states: `decoded` and RTTI-derived `classified` do not establish
positive semantics, and explicit `unknown` is allowed.

`FULL_SEMANTIC_COMPLETENESS_GATE_V1` reports `READY`: route/packet conservation,
required high-frequency analysis tiers, systematic high-value-domain records, an
explicit 69-capability A–Z enumeration with zero missing entries (including the
`map` domain), and a passing exact-build machine regression attestation all pass.
The subsequent deep-recovery queue has 137 route rows / 57 capability rows, with
actionable 0 / 0 across 16 locally exhausted domains and 7/7 saturation checks
PASS: `SEMANTIC_RECOVERY_SATURATED`, explicitly not `FULLY_PARSED`. Readiness and
saturation mean no silent discard/fallback and no remaining local-safe action; they
do not mean every route is decoded or every capability is available. The protected Jungle Objective
Holdout was not an input and was not read, enumerated, hashed, decoded, tested,
or consumed.

All eleven old semantic Replay block IDs (`0x02d1`, `0x025a`, `0x0353`,
`0x028a`, `0x0160`, `0x0459`, `0x0406`, `0x0031`, `0x0256`, `0x009e`,
`0x0017`) occurred zero times in the 40-Replay 16.16 strict scan. The exact
16.15 profiles and mapping remain frozen. The verified P0 route migrations are
`0x02d1→0x00f6` and `0x025a→0x0314`; constructor immediates or similar shapes
do not bypass the exact-build gate for any other capability. WardSpawn migrated
independently as `0x0353→0x049a`; its old ID remains absent and no layout is
shared implicitly.

## 16.16 Sweeper capability boundary

The formal `rofl-16.16.805.0442-sweeper-capability-v1` export is exact-build
bound. It reports `TRINKET_STATE`, `TRINKET_SLOT_STATE`, `TRINKET_SWAP`,
`TRINKET_PURCHASE_OR_SWAP`, and `SWEEPER_HELD` as `UNVERIFIED`; it reports
`SWEEPER_ACTIVATION`, active interval, position, and owner as `UNAVAILABLE`.
The distinction is intentional: `SWEEPER_HELD != SWEEPER_ACTIVATION`. Empty
Sweeper arrays state an absence of emitted verified events, never a zero-player
or zero-activation claim. A bounded scan of 31,862 non-Holdout exact-build
`0x049a` entity rows found no Oracle/Sweeper/Lens/Scanner name token; it is not
a protocol-nonexistence proof. See `docs/SWEEPER_CAPABILITY_V1.md`.

| Capability | Status | Timing | Entity | Version | Notes |
| --- | --- | --- | --- | --- | --- |
| Replay metadata | `VERIFIED_DIRECT` | aggregate | match/participant | structural | Tail JSON; not an event stream. |
| Packet timestamp | `VERIFIED_DIRECT` | precise | packet | structural | Parsed from block framing. |
| Hero Death (`0x0160`) | `VERIFIED_DIRECT` | precise | hero | `16.15.801.3452` | **Hero only**; does not establish ordinary-monster death. |
| Hero Death (`0x0112`) | `VERIFIED_DIRECT` fields / exact-build derived participant mappings | precise | victim/killer hero | **build-bound `16.16.805.0442`** | 301/301 exact runtime full-consume packets matched independent DETAILS victim and killer at 0–1 ms. Assists, kill credit and remaining death inner fields are unavailable/unknown; respawn is separately published by `0x0265`. |
| Hero Respawn (`0x0265`) | `VERIFIED_DIRECT` occurrence/time/protocol position | precise | respawning hero | **build-bound `16.16.805.0442`** | 282/282 exact native full-consume rows uniquely follow 301 P0 deaths; 19 unmatched deaths are terminal. Protocol coordinates do not establish map/base semantics; scalar role remains candidate. |
| Hero damage source/target/amount (`0x028a`) | `VERIFIED_DIRECT` | precise | source/target | `16.15.801.3452` | Direct combat amount is available. |
| Damage type | `VERIFIED_DIRECT` | precise | source/target | `16.15.801.3452` | Stable API maps direct `field_21`: `0 physical`, `1 magic`, `2 true`; unknown codes remain null. |
| Hero damage source/target/amount (`0x017f`) | `VERIFIED_DIRECT` | precise | source/target | **build-bound `16.16.805.0442`** | 266,332/266,332 latest-four rows full-consume. Recorded amount is direct, but pre-/post-mitigation/effective-HP-loss meaning is unresolved. |
| Damage type (`0x017f`) | `VERIFIED_DIRECT` | precise | source/target | **build-bound `16.16.805.0442`** | Direct `+0x28`: `0 physical`, `1 magic`, `2 true`, independently anchored with 2/2/2 examples and zero mismatches; unknown codes remain null/UNKNOWN. |
| BuyItemAns (`0x0137`) | `CANDIDATE` route / bounded `item_id` field only | precise packet time | participant candidate | **build-bound `16.16.805.0442`** | 1,601/1,601 full-consume; 1,154/1,168 purchases align by time/subject/item, but 447 route extras and 14 DETAILS misses forbid `ITEM_BUY` publication. |
| RemoveItemAns (`0x04b3`) | `CANDIDATE` generic removal | precise packet time | participant candidate | **build-bound `16.16.805.0442`** | 1,013/1,013 full-consume; all 60 sales align, but 953 rows are non-sale and no direct item ID is carried, so `ITEM_SELL` is not published. |
| Item undo from `0x0137`/`0x04b3` | `UNAVAILABLE` | — | participant | **build-bound `16.16.805.0442`** | 0/52 direct matches. This is route-pair negative evidence, not protocol-nonexistence proof. |
| Damage script key | `VERIFIED_DIRECT` | precise | source/target | `16.15.801.3452` | Direct `field_1c` is exposed as numeric/hex key; it is not by itself a human-readable spell/basic/item/rune/passive attribution. |
| Critical damage, positive-only | `VERIFIED_DERIVED` | precise | source/target | `16.15.801.3452` | `field_20 == 3` emits `is_critical=true`; every other result code remains null, never false. |
| Basic attack, V1 semantic surface | `UNAVAILABLE` | — | source/target | `16.15.801.3452` | V3 has a partial true-only derived classifier; it does not rewrite the V1 surface. |
| CastSpell (`0x0459`) | `VERIFIED_DIRECT` | precise | caster/targets | `16.15.801.3452` | Dictionary names and slots are derived. |
| WardSpawn (`0x0353`) | `VERIFIED_DIRECT` | precise | owner/ward | `16.15.801.3452` | Spawn identity and coordinates direct; type/team/lifecycle derived. |
| WardSpawn (`0x049a`) | `VERIFIED_DIRECT` fields / `VERIFIED_DERIVED` event | precise | owner/ward | **build-bound `16.16.805.0442`** | 31,862/31,862 full-consume across 20 replays; 2,252 confirmed player wards. Time, owner/entity, names and x/y direct; participant/team/type derived. Special/map/unknown rows retained separately. |
| Ward observed end (`0x049a` corpse subset) | `VERIFIED_DERIVED` match | precise direct timestamps | ward/corpse | **build-bound `16.16.805.0442`** | 1,128 conservative matches from 4,269 direct corpse signals. End reason is `UNKNOWN`; no estimated ends are emitted. |
| Hero Path (`0x02d1`) | `VERIFIED_DIRECT` | precise | hero | `16.15.801.3452` | Entity, speed and compressed waypoints direct. |
| Hero Path game coordinates | `VERIFIED_DERIVED` | precise/interpolated | hero | current calibration | Coordinate transform and one-second positions are derived. |
| LevelTransition occurrence (`0x025a`) | `VERIFIED_DIRECT` | precise | hero/network entity | `16.15.801.3452` | Entity and Replay timestamp direct; two timestamp-zero rows are pre-game initialization. |
| LevelAfter from `field_10` | `VERIFIED_DERIVED` | precise | hero | **build-bound `16.15.801.3452`** | `224→2`, `207→3`, `197→4`, `198→5`, `204→6`, `199→7`. Other builds and unknown bytes do not inherit this map. |
| Hero Path (`0x00f6`) | `VERIFIED_DIRECT` | precise | hero | `16.16.805.0442` | Exact runtime full-consume 18,001/18,001; shared path plaintext grammar; entity, speed and waypoints direct. |
| Hero Path game coordinates | `VERIFIED_DERIVED` | precise/interpolated | hero | **build-bound `16.16.805.0442`** | 240 DETAILS anchors across eight replays; direct p95 173.26, swapped p50 2,667.94; five trajectory plots reviewed. |
| LevelTransition occurrence (`0x0314`) | `VERIFIED_DIRECT` | precise | hero/network entity | `16.16.805.0442` | Exact runtime full-consume 2,325/2,325; 2,295 unique matches among 2,356 DETAILS anchors within ±2 ms. |
| LevelAfter from `field_10` | `VERIFIED_DERIVED` | precise | hero | **build-bound `16.16.805.0442`** | Re-derived independently with zero conflicts: `242→2`, `194→3`, `210→4`; complete observed map is in `artifacts/multi_build_rofl_support_v1/level_mapping_16_16.json`. |
| DETAILS `SKILL_LEVEL_UP` as hero level time | `UNAVAILABLE` | delayed | participant | observed corpus | Rejected proxy: p50 1103 ms, p90 6179.6 ms, max 34286 ms. |
| Generated shield amount | `VERIFIED_DIRECT` | precise | source/target | `16.15.801.3452` | Canonical `0x00ed`; paired `0x00ee` is duplicate-route evidence. |
| Shield absorbed amount | `VERIFIED_DIRECT_TARGET_TOTAL` | precise | target only | `16.15.801.3452` | No source or shield-instance attribution. |
| Direct reported heal amount | `VERIFIED_DIRECT` | precise | source/target | `16.15.801.3452` | Raw/effective/overheal meaning remains unavailable. |
| UnitApplyDamage as camp clear | `UNAVAILABLE` | — | ordinary monster | current corpus | Damage amount alone lacks monster identity, remaining HP, death, reset, despawn and camp lifecycle. |
| Camp contact | `NOT_PROTOCOL_CAPABILITY` | — | — | — | Hero Path entering a camp polygon is a downstream spatial derivation. |
| Ordinary-monster/camp clear | `CAMP_CLEAR_DIRECT_UNAVAILABLE` | — | camp/monster | current corpus | Evidence grade remains `UNAVAILABLE`; no direct clear event is exposed. |
| `0x0313` for camp clear | `CANDIDATE` | — | unresolved | `16.15.801.3452` | `PKT_NPC_Die_MapView_s` association; 27,524 bounded decodes but no victim identity; `NOT_USABLE_FOR_CAMP_CLEAR`. |
| `0x02eb` for camp clear | `REJECTED_FOR_CAMP_CLEAR` | — | unresolved | `16.15.801.3452` | 477 bounded decodes did not match verified death anchors; evidence grade is `UNAVAILABLE`. |
| `PKT_S2C_NeutralCampLeashStateChanged_s` | `NAME_ONLY_CANDIDATE` | — | unresolved | unresolved | Static registration name without a verified Replay route. |
| `PKT_S2C_DestroyUnit_s` | `NAME_ONLY_CANDIDATE` | — | unresolved | unresolved | Static registration name without a verified Replay route or camp-clear semantics. |
| `NeutralCampCleared` family | `SCRIPT_EVENT_STRING_ONLY` | — | unresolved | unresolved | Client strings are not packet-emission or camp-clear evidence. |
| Ordinary-monster entity mapping | `UNAVAILABLE` | — | RED/BLUE/GROMP/WOLVES/RAPTORS/KRUGS | current corpus | No verified main/small monster identity, death, killer, reset/despawn distinction or lifecycle. |
| XP snapshot (`0x010c`) | raw `VERIFIED_DIRECT`; integer `VERIFIED_DERIVED` | approximately 60-second keyframes | participant | **build-bound `16.16.805.0442`** | Raw f32 at blob `+0x28`; `floor(raw)` matched DETAILS 1,390/1,390. This is cumulative scoreboard state, not exact XP-event timing. |
| Lane CS snapshot (`0x010c`) | `VERIFIED_DIRECT` | approximately 60-second keyframes | participant | **build-bound `16.16.805.0442`** | Cumulative f32 at blob `+0x3c` matched DETAILS `minionsKilled` exactly 1,390/1,390. |
| Jungle CS snapshot (`0x010c`) | `CANDIDATE` | approximately 60-second keyframes | participant | **build-bound `16.16.805.0442`** | Blob `+0x40` has 1,375/1,390 floor matches; 15 retained mismatches forbid promotion and combined CS remains unavailable. |
| Current gold | `UNAVAILABLE` | — | participant | current corpus | No verified current-gold, spend, passive-income, or transaction-delta field; unavailable is not zero. |
| Total gold snapshot (`0x010c`) | `CANDIDATE` | approximately 60-second keyframes | participant | **build-bound `16.16.805.0442`** | Blob `+0x38` has 1,389/1,390 floor matches. The unique 2.97265625 residual is retained; no correction/fallback or public semantic is allowed. |

## Camp-clear semantic guard

`UnitApplyDamage` remains a direct combat-amount capability only. No API or
documentation may promote it, Hero Path camp contact, `0x0313`, `0x02eb`, or
static NeutralCamp strings into a direct camp-clear event without new verified
identity and lifecycle evidence.

## Multi-build P0 publication safeguards

The 16.16 runtime publication rejects empty validator inputs and validates each
packet row against an exact-build strict-export manifest, Replay SHA-256,
payload length/SHA-256 and pinned runtime image. HeroPath passed nonempty exact
full-consume with all ten participants in every selected replay, per-replay
coordinate/map gates and 240/240 position anchors. LevelTransition passed
2,325/2,325 exact full-consume and 2,295/2,356 one-to-one unique anchor matches
(97.41%) across 18 anchor-bearing replays; independent Lv2/Lv3/Lv4 counts are
180/179/180.

Public 16.16 LevelTransition events expose direct occurrence/entity/timestamp
and raw-field confidence separately from build-bound derived `level_after`.
Unmapped initialization rows retain `level_after=null` and mark that field
`UNAVAILABLE`; a genuine replay with no LevelTransition packet reports
`NO_MATCHING_PACKETS_IN_REPLAY`, not a zero-row decoder PASS.

Damage `0x017f` executes the exact constructor/deserializer and fully consumes
all 266,332 latest-four rows. Direct packet time, source/target IDs, recorded
amount, and type code are published with field-specific provenance; amount
stage and spell/basic/item/rune/passive attribution stay unknown. HeroDeath
`0x0112` fully consumes and independently validates 301/301 P0 packets for
occurrence/time/victim/killer. Assists remain unavailable after 242 nonempty-
assist counterexamples rejected the tested scalar/bitmask/fixed-triplet
interpretations.

HeroStats `0x010c` is a cumulative scoreboard keyframe route, not a live combat-
state route. Its 1,390/1,390 strict rows validate raw XP and cumulative lane CS;
only `floor(raw XP)` is an allowed derived integer. Total gold and jungle CS are
retained candidates. The separately decoded `0x0137`/`0x04b3` item routes retain
bounded field and subset evidence, but their counterexamples prohibit canonical
buy/sell/undo/state events.

The six additional public gameplay-tail routes are exact-build bounded capabilities:
Cooldown Broadcast `0x00b8`, Missile movement-complete count `0x03d4`, Face Direction
`0x01ab`, Instant Stop Attack `0x00e4`, Basic Attack Position Minion `0x01b5`, and
Wall Tracking cache keyframe `0x0298`. Their direct packet fields do not name a
cooldown interval, spell/attack attribution, target semantic, or map truth.

The 16.16 Ward release uses the exact factory chain `0x00ed97b0` → constructor
`0x00eabb20` → final vtable `0x01b14570` → deserializer `0x01025d50`; the prior
`0x00fc7770` candidate is rejected. Twenty exact-build replays produced
31,862/31,862 successful full-consume rows and 2,252 confirmed player wards.
All confirmed rows map owner→participant/team with zero conflicts; 197/200
participant-game rows equal Replay-tail `WARD_PLACED` exactly and three differ
by one. Direct Ward coordinates are nonconstant and map-range; CastSpell target
coordinates are not used. Public selectors are `queryWardEvents()`,
`queryWardSpawns()` and `queryWardLifecycles()`.
