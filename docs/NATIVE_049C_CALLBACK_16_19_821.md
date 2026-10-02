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

Only selectors 1 and 2 occur in the supplied 11-Replay corpus. Their dataflow is:

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
Selectors 3 through 9 have static branches but no original packets in this corpus;
their requests are not emitted as supported decoded operations.
