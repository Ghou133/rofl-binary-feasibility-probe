# Exact-821 slot-change request dataflow

This opt-in candidate extends `anonymous_049c_packet`; its CLI/API name and raw
vector output remain available. The V2 profile adds `callback_request_candidate`.
It is gated to KR `16.19.821.7343` and runtime image SHA-256
`35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`.

## What the code establishes

The exact-image registration chain connects numeric route `0x049c` to a typed
`AIBaseClient` member callback for `PKT_ChangeSlotSpellData_s`:

| Link | Exact image RVA |
| --- | --- |
| Callback address supplied to MakeFunction | `0x26324d` -> `0x2bbe30` |
| Typed closure constructor / vtable | `0x24f200` / `0x1ac2c30` |
| Closure type function / RTTI descriptor | `0x303820` / `0x1f28680` |
| Registration wrapper writes route `0x049c` | `0x252252` |
| Callback thunk / body | `0x2bbe30` -> `0x24ebb0` |
| Operation selector / jump table | packet `+0x1c` / `0x24edf4` |
| Encoded slot byte / conversion | packet `+0x18` / `0x24ebbf..0x24ebf3` |

The constructor/deserializer binding from V1 remains pinned. Additional complete
bounded code spans, the closure type entry and receiver/packet type names are
checked before producing the V2 witness. The regular, Summoner and OwnerOnly
closures are distinct; the regular class is selected through registration,
not a nearby string match.

Only selectors 1 and 2 occur on regular route `0x049c` in the supplied 11-Replay
corpus. Their dataflow is:

| Selector | Request output | Downstream path |
| --- | --- | --- |
| 1 | `SLOT_BYTE_FIELD_WRITE_REQUEST`; `slot_index`, `requested_u8`, receiver field `+0x2f` | Lookup in receiver component `+0x3110`, then setter `0x8f2f70` writes the vector's first byte to slot-object `+0x2f` and invokes a virtual method. |
| 2 | `SLOT_NAME_CHANGE_REQUEST`; `slot_index`, exact name bytes/ASCII, native comparison hash, three anonymous control bytes | `0x287350` compares the supplied C string with the current entry using native hash `0x1168ba0`; if its gates permit, it passes that string through `0x97f7a0` to the slot object's update method. |

The name comparison folds ASCII uppercase letters; the hash can collide and is
not a unique spell identifier. The byte field's gameplay meaning and the three
control bytes' semantic roles remain unknown. Internal slot indices include
values above 5; no Q/W/E/R, item, summoner, champion or owner mapping is assigned.
The simple selector-1 lookup defaults indices above 63 to entry zero, which is
reported as `native_lookup_index`; this is code behavior, not a corpus finding
that such an out-of-range request occurred.

## Per-packet native execution and its limit

After full native deserialization, the decoder executes only the packet-reading
prefix of the actual callback. Execution stops before the first receiver lookup
or downstream call: `0x24ec26` for selector 1 or `0x24ecdf` for selector 2.
There is no receiver object supplied and no receiver/callback result stubbed.
Selector 2 also executes the pinned pure native string-comparison hash.

Every emitted request therefore records:

- `value_decode_witness: NATIVE_PACKET_ONLY_CALLBACK_PREFIX`
- `receiver_entity_status: UNKNOWN`
- `application_status: NOT_OBSERVED`

The static registered receiver class is known; its actual Replay entity is not.
Name-change gates can skip updates, and the callback returns success even when
it performs no mutation. Native packet acceptance, callback branch selection,
repeated names and hash equality must not be interpreted as successful change,
cast, availability, damage or another gameplay effect. Game packets and keyframe
packets retain their distinct stream tags and original source references.

## Exercised scope

Fresh native CLI decoding of all 11 existing KR Replays yielded 107,059 requests:
106,071 selector-2 name-change requests (95,956 game, 10,115 keyframe) and 988
selector-1 byte-write requests (836 game, 152 keyframe). There were zero framing
errors; all outputs remain `CANDIDATE`. The three native control bytes were
`[0,0,0]` in every observed name-change request.

Tests compare all 256 encoded indices for both observed branches and all 256
values of each of the three control bytes against independent instruction-level
formulas. Synthetic native setter checks verify the exact `+0x2f` write and
surrounding sentinels; those generated objects are not real receiver observations.
The original 142 packet representatives and malformed native consumption controls
remain exercised. Portable guards reject field/source disagreement, wrong class,
hash disagreement and claimed actor/effect promotion. Optional native tests skip
explicitly if their authorized exact image and representative inputs are absent.

## Evidence still needed

Actual application requires a lawful, exact-build offline receive trace linking
one original packet to its resolved receiver and selected slot, with the callee
result and before/after field or name state. For the byte field's gameplay label,
an independently anchored accessor/type or controlled observation is required.
The existing module-only image and replay files do not supply these observations;
no new live capture or old client is required by the runnable candidate decoder.
Regular-route selectors 3 through 9 have no original packets in this corpus.
The sibling coverage below independently adds observed OwnerOnly selectors 6/7.

## Unified regular / Summoner / OwnerOnly entry

`spell_slot_change_request` selects all three independently pinned routes;
`anonymous_049c_packet` continues to select only regular `0x049c`.

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events spell_slot_change_request --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --event-jsonl-only --out-dir "work\slot-requests"
```

Read `spell_slot_change_request_candidates.jsonl`, or select
`capabilities: ['spell_slot_change_request']` through `decodeSemanticReplay`.
Each record retains its `native_packet_id`, registered class, stream tag and
complete original source reference. No saved `query-events` support is claimed.

| Route / registered class suffix | Factory / constructor / deserializer | Observed operations |
| --- | --- | --- |
| `0x049c` / regular | `0xf0cfeb` / `0xe9a6c0` / `0x10d0d30` | 1 byte field `+0x2f`; 2 name change |
| `0x028e` / Summoner | `0xf06391` / `0xe9a670` / `0x10d0bd0` | 2 name change |
| `0x0375` / OwnerOnly | `0xf0945a` / `0xe9a620` / `0x10d0a70` | 6 gated byte field `+0xe8`; 7 counted four-byte vector |

Summoner registration `0x2521e2`, closure `0x1ac2c90`, type descriptor
`0x1f28460`, and OwnerOnly registration `0x252172`, closure `0x1ac2c60`,
descriptor `0x1f28570` bind the same callback. Their distinct native factory,
vtable and deserializer are checked; the regular decoder is not substituted.
Class names alone do not establish Replay delivery audience or actor identity.

Selector 6 stops at `0x24ed5e` before entering gated callee `0x97f8b0`.
Selector 7 stops at `0x24ed7b`; its packet-only callee `0x2875b0` also runs
through actual native vector construction, stopping at `0x287633` before
receiver lookup. Native copied words must equal the count-prefixed source
vector. The downstream path copies into a nested holder's vector `+0x40` if its
state/object gates permit. `requested_words_u32` is a reversible integer bit
presentation; integer/float type, units and gameplay meaning remain unknown.
All 935 observed selector-7 requests have exactly one word; zero/two-word
requests are outside this candidate's observed scope.

Fresh unified CLI processing of the same 11 Replays accepted 115,290 native
packets with zero framing errors: 107,059 regular, 6,790 Summoner and 1,441
OwnerOnly. Output includes 112,861 name-change requests, 988 regular byte-write
requests, 506 gated byte-write requests and 935 word-vector requests. OwnerOnly
packets in this corpus occur only in keyframes. All remain candidate and
`NOT_OBSERVED` for application; keyframe requests are not cast/action events.
The additional 66 original sibling representatives and native truncation/append
controls pass. Current focused tests: 19 Node and 6 actual-image Python methods,
zero failures/skips. The sibling method explicitly skips without its optional
`ROFL_821_SLOT_SIBLING_SAMPLES` input.
