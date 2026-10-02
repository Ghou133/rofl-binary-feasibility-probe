# Exact-821 slot-change request / roster-key association

This opt-in development candidate places named slot requests and field-write
requests beside candidate participant, champion, team and role records. It uses
only complete **16.19.821.7343 KR** native request outcomes and a unique ten-way
same-Replay K/D/A roster bridge. It does not change confirmed semantic output.

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events spell_slot_change_roster_key_pair --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --event-jsonl-only --out-dir "work\slot-roster"
```

Through `decodeSemanticReplay`, select
`capabilities: ['spell_slot_change_roster_key_pair']` and supply
`runtimeImagePath`. Both request and roster dependencies execute automatically;
no precomputed private output is required. See [environment setup](QUICK_START_16_19.md).
The required image SHA-256 remains
`35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`.
No image or Replay is included in the source package.

Read `spell_slot_change_roster_key_pair_candidates.jsonl`. Each record contains
the original route, time and internal slot index, the complete callback request
subrecord, candidate participant/champion/team/role, the original request source
reference and the roster keyframe source reference. Name requests retain the
exact name bytes, printable ASCII, native comparison hash and three anonymous
control bytes. Gated byte and counted-word requests retain their existing bounds.

`spell_slot_change_request_candidates.jsonl` retains **all** input requests,
including unmatched keys. `hero_roster_metadata_bridge_candidates.jsonl`
retains the ten candidate roster records. Direct JSONL/API use is supported;
the saved-query entry is described below.

## Query saved requests and associations

```powershell
node src/cli.js query-events "work\slot-roster" --event spell_slot_change_roster_key_pair_candidates --participant 1 --from-ms 0 --to-ms 300000 --slot-change-index 4 --slot-change-operation 2 --limit 10 --output "work\slot-preview.jsonl"
node src/cli.js query-events "work\slot-roster" --event spell_slot_change_roster_key_pair_candidates --verify-source --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --limit 10 --output "work\slot-verified.jsonl"
```

Single Replay artifact directories and complete decode/batch output roots work.
Queries also accept `spell_slot_change_request_candidates` and the original
regular-only `anonymous_049c_packet_candidates`. Time, full `--raw-param`,
`--slot-change-index` (0..255) and `--slot-change-operation` (1/2/6/7) filters
apply to all three streams. `--participant` applies only to the roster association
and means its candidate participant, not a confirmed actor. Use the distinct
slot-change index option; inventory `--slot` is unrelated. Selector 1 is a byte
request, 2 a name request, 6 a gated byte request, and 7 a counted-word request.

Every query checks manifest hashes, complete row counts, native profile binding,
request field consistency and candidate boundaries. Association queries also
check the entire request stream, the ten-way roster and excluded-key counts.
`--limit` restricts output only; all later rows and Replays are still checked.
Library API calls stage output until validation completes; the CLI removes its
new output on failure and does not publish partial stdout. Original JSONL rows
are returned without changing confidence, references or field order.

Ordinary queries need only the saved output and report `SAVED_ONLY_UNVERIFIED`.
Manifest hashes and coherent field checks do not authenticate native values
against original packets. `--verify-source` additionally requires the original
Replay and exact runtime image, re-decodes all selected native packets and roster
dependencies, and compares every saved result/row before filtering. It reports
`FRESH_EXACT_IMAGE_REDECODE`; this verifies reproduction of the candidate decoder,
not live receiver state or confirmed gameplay semantics. A single Replay query
can use `--source-replay` to relocate an unchanged original file. Batch queries
use each recorded source path. Missing/wrong inputs fail explicitly.

## Join and evidence boundary

The join compares the whole unsigned 32-bit packet header parameter with the
roster key. Low-byte equality and `+0x100` aliases cannot match. Original source
geometry, payload hashes, physical Replay metadata, complete source counts,
native image binding and callback request checks must pass for every input row,
including unmatched rows; a late failure emits no association rows.

The calculation consumes fresh decoder outcomes. It does not authenticate
arbitrary saved JSON or independently prove the native meaning of the header
parameter. Champion/team/role are metadata facts, while the roster alignment
and header association remain candidates. The named class and receiver callback
registration do not independently identify the live packet actor or receiver.

Every association keeps `packet_actor_status`, `owner_status` and
`live_receiver_status` as `UNKNOWN`, and `actual_application_status` as
`NOT_OBSERVED`. A requested name is not an observed spell/cast/effect. Internal
indices are not mapped to Q/W/E/R. Keyframe requests remain keyframe observations;
the latest roster keyframe reference is a join witness, not state at request time.
Private player IDs, Riot IDs and PUUIDs are not copied into these records.

## Current validation

Fresh CLI processing of all 11 existing exact-821 Replays accepted 115,290 native
requests with zero framing errors. Full header equality associates **94,390**;
the other **20,900** remain unmatched in the complete dependency stream.

| Matched request kind | Count |
| --- | ---: |
| Name change, regular | 85,218 |
| Name change, Summoner | 6,787 |
| Regular byte write | 944 |
| OwnerOnly gated byte write | 506 |
| OwnerOnly counted-word change | 935 |

The all-row guard compares the complete request dependency with the previous
native family output and checks each association against its same-run request
and roster sources. The focused Node suite has 37 passes, zero failures/skips.
New synthetic fixtures test full-key exclusion, source/metadata substitution,
late unmatched-row failure, missing inputs and pair-only API expansion. They are
framing/output-schema fixtures, not native packet or identity evidence. The
native field decoder is unchanged in this stage; native tests from the preceding
family stage and this stage's fresh real-image CLI execution retain that scope.

## Remaining work and smallest useful additional input

The available Replay plus exact module image support native request values,
protocol-key comparisons and metadata association. This stage implements that
useful association; it does not add anonymous counters to compensate for missing
semantics. Other request-to-request comparisons would still describe intent,
not independently observed application.

The next semantic step needs a lawful **offline exact-build** witness linking an
original packet to its resolved receiver and selected slot, with callee result
and before/after state. A byte/word gameplay label also needs an independently
anchored accessor/type or controlled observation. That would resolve receiver
identity, conditional gates, actual name/field change and possibly slot meaning.
The existing module-only capture contains no receiver heap; more disassembly
does not replace those missing observations. Effective per-hit damage and HP
similarly need independently anchored object/state inputs and remain separate.

Unobserved regular selectors 3/4/5/8/9 additionally need original exact-build
packet examples before their output scope can be validated. No old 16.15/16.16
client is a prerequisite. Do not access protected holdout, acquire live state,
change security settings, or upload private inputs to obtain this evidence.
Until such inputs are available, keep these semantic promotions pending and
preserve the current runnable candidate release.
