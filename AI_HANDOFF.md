# AI / developer handoff

The published semantic baseline remains the historical 2026-08-21
`SOURCE_FROZEN_DURING_MIGRATION` snapshot. As recorded in `AGENTS.md`, the user
has authorized continued 16.19 development, CLI/API integration and field research.
Development candidates do not promote published semantics, delete evidence, or
create a second protocol authority.

## Start here

The next Oct-7 increment adds [saved packet/window comparison queries](docs/DAMAGE_WINDOW_QUERY_16_19_821.md),
recomputing the complete native packet and sampled-interval dependencies. A real
Replay's 64,824 native packets and 320 windows passed complete source reproduction.
Static interval queries also accept PROVIDED_NOT_USED annotations from combined
decodes; only this unused-image annotation is normalized during static source comparison.

The follow-on Oct-7 milestone connects saved `hero_damage_keyframe_interval_candidates`
queries, participant/full-header/endpoint filters and complete static source re-decode.
All 3,160 intervals across 11 Replays passed. [Query scope](docs/DAMAGE_INTERVAL_QUERY_16_19_821.md)
keeps cumulative sampled differences separate from effective damage or event times.
No new process/heap capture was performed. This is independent of missing receiver state.

2026-10-07 continuation adds opt-in `cooldownPacketProfile: 'v2'` /
`--cooldown-packet-v2`: original packet-only native code recovers four f32 request
arguments and one control byte without a receiver object. All 182,482 requests
across 11 KR Replays passed decode and complete native source-query verification.
Read [the code roles and remaining inputs](docs/COOLDOWN_REQUEST_FIELDS_16_19_821.md).
Q/W/E/R default input labels and a SpellLevel formatting accessor were inspected
but did not establish the packet-to-live-slot binding. Preserve that negative
boundary; request exact-build offline receiver/slot/state/clock evidence before
claiming applied level or cooldown. No new capture authority is implied.

Read [README](README.md), [public maintenance](docs/PUBLIC_DEVELOPMENT.md),
[AGENTS](AGENTS.md), then only the relevant source/tests. Ownership and state are
in [PROJECT_CHARTER](PROJECT_CHARTER.md) and `project_contract.json`.

The legacy CLI calls `src/semantic_pipeline.js` for **16.15.801.3452**. For
**16.19.820.7193** and **16.19.821.7343**, `decode`/`batch` dispatch explicit
`--events` selections through `src/semantic_api.js`; candidate output remains
separate from confirmed semantics. Read [the 16.19 quick start](docs/QUICK_START_16_19.md)
for runnable CLI/API examples and saved-query verification. `capabilities --events`
preflights selected names and reports unregistered names with exit code 2.
The library's 16.16 surfaces are still not dispatched by the CLI. Preserve full
build gates and do not feed one build into another decoder.

The exact-821 `anonymous_049c_packet` V2 surface retains its raw vectors and adds
packet-only native callback requests: slot index, name-change bytes/hash or
`+0x2f` byte-write intent. Read [its receive-dataflow evidence](docs/NATIVE_049C_CALLBACK_16_19_821.md)
before extending it. Actual receiver/entity and application are unobserved;
neither callback return success nor static writes prove a Replay effect.
The adjacent `spell_slot_change_request` capability covers the regular route
plus exact `0x028e` Summoner and `0x0375` OwnerOnly variants. OwnerOnly words are
native-copied raw bit presentations with unknown type/units; its observed data
is keyframe-only. Preserve separate route/class identities and request/effect
boundaries when extending this family.
`spell_slot_change_roster_key_pair` associates complete fresh requests with the
same Replay's ten-way candidate roster using only full-u32 header equality.
It retains both source references and request intent; it does not promote packet
actor, live receiver, application or Q/W/E/R identity. Read
[the association and remaining-input assessment](docs/SLOT_CHANGE_ROSTER_KEY_PAIR_16_19_821.md)
before continuing this branch. The current module image has no receiver heap;
do not repeat that missing-state research or require old-client reruns.
Saved slot request/association queries now validate complete sources and support
internal index/operation filters. `src/slot_change_event_query.js` owns that query
validation; it reuses the decoder's output constructor and observed-shape gate.
`--verify-source` requires the exact image and freshly re-decodes all source rows,
including unmatched requests. Saved-only consistency is explicitly unverified;
do not describe its hashes as native-output authentication.
The source package has also passed independent-extraction CLI acceptance of
decode, static/native source verification, limits and error handling. `--list-events`
rejects both slot filters; it must not silently ignore them. Dependency checks and
interpreter selection are documented in the quick start. This delivery is usable
without a running game. With the available module-only image, further application
or gameplay identity claims require lawful exact-build packet-to-receiver/slot
bindings and before/after object-state evidence; preserve the current candidate
boundary and wait for those inputs rather than repeating missing-heap research.

Container fixes belong in `src/rofl.js`; raw analysis in `src/analysis.js`; command
orchestration in `src/cli.js`; execution-scoped reports in `src/cli_report.js`;
packaging in `scripts/package_handoff.py`. Preserve research-v3/v4 and existing
Node/Python test directories. A filename containing an old stage is not proof
that its code is unused.

## Evidence rules

Preserve exact versions, source SHA, packet offsets, payload hashes and field
confidence. Direct, derived, partial, candidate and unavailable are different.
Decoder failure, a missing input, an unsupported build and a valid zero-event
result must remain distinct. `UNAVAILABLE` stays null, not zero.

Match Details is validation-only. Ward cast targets are not spawn coordinates.
Reported healing is not effective healing or overheal. Target-total shield
absorption is not source/instance attribution. MaxHP/Armor/MR remain unpublished
when governed inputs are missing. Do not promote fields merely to make tests pass.

Do not read, enumerate, hash, decode, test or consume the protected Jungle
Objective Holdout. Do not overwrite original evidence, negative results or
historical source hashes. Use a separate output directory for reruns.

## Verify without overstating

`npm test` runs the public suite; `npm run test:maintenance` isolates maintenance
regressions. `npm run test:all` and CLI `validate` retain the full Node suite.
V3/V4 and entity/item Python suites have separate commands and input requirements.
`package:source` needs public source; `package:handoff` explicitly requires the
bounded-evidence inputs. Neither package is a raw re-decoding capsule.

Report commands actually executed, pass/fail/skip counts, missing private inputs,
untested platforms and remaining capabilities separately. Never count a missing
fixture as an ordinary pass or label old attestations as a fresh reproduction.

Historical field notes and results remain in
[VALIDATION_STATUS](VALIDATION_STATUS.md), the capability/version matrices and
[the archived handoff](docs/history/AI_HANDOFF-20260923.md). That archive is not a
current task list or current command guide.
