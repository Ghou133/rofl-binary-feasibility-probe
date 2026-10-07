# Exact KR 821 cooldown request arguments

2026-10-07. This opt-in extension supports only `16.19.821.7343` and the mapped
module SHA-256 `35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325`.
It adds usable packet arguments, not an observed cooldown or cast timeline.

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events cooldown_broadcast_packet --cooldown-packet-v2 --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --event-jsonl-only --out-dir "work\cooldown"
node src/cli.js query-events "work\cooldown" --event cooldown_broadcast_packet_candidates --opaque-u32 0 --limit 10 --output "work\cooldown-preview.jsonl"
node src/cli.js query-events "work\cooldown" --event cooldown_broadcast_packet_candidates --verify-source --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --limit 10 --output "work\cooldown-verified.jsonl"
```

The API selects the same implementation with `cooldownPacketProfile: 'v2'` in
`decodeSemanticReplay` options. Omitting it keeps the existing V1 lookup-only
profile and ordered output digest. `--cooldown-packet-v2` is valid only for
`decode`/`batch` selecting `cooldown_broadcast_packet`. Preflight remains the
registered capability check, not proof that the image or receiver was validated.

## What the native code establishes

The original reader fully consumes each `0x039d` packet. Its original callback
prefix at `0x2bbc90` witnesses the protected `+0x10` lookup key and stops before
`0x98a840`; V2 supplies no receiver object. Three further **independent pure
packet-code regions** run against that decoded packet and scratch stack:
`0x2bbcca..0x2bbda0`, `0x2bbda5..0x2bbddf`, and `0x2bbde4..0x2bbe23`.
They stop before the receiver call or store. The fourth-field region is given
only the scratch pointer computed by the excluded preceding instruction.
No lookup return value, receiver gate, clock or receiver state is synthesized.

`native_callback_request` retains protected bytes, transformed f32 bits and
numeric presentations. The four `argument_f32` entries have this exact order:

| Index | Packet object | Original consumer | Established role; remaining limit |
| --- | --- | --- | --- |
| 0 | `+0x20` | XMM1 at call `0x94d3b0` | Additive time-source argument on one receiver branch. Units and actual branch outcome unresolved. |
| 1 | `+0x14` | XMM2 at the same call | Comparison/store argument for receiver `+0x74`; can contain native default `-1`. No applied duration inferred. |
| 2 | `+0x1c` | Proposed f32 store to receiver `+0x78` | Write intent only; all current observations are zero, which does not establish the field's gameplay role. |
| 3 | `+0x24` | Proposed f32 store to receiver `+0x7c` | Write intent only; field meaning remains unknown. |

The `+0x18` control byte is transformed into R9B. One branch of `0x94d3b0`
writes it to receiver `+0xe9`; a preceding conditional alternative can bypass
that branch. The helper never executes either receiver branch. Nonfinite f32
and unobserved control values outside 0/1 fail closed. Protected field bytes are
ordered `+0x14[4], +0x18[1], +0x1c[4], +0x20[4], +0x24[4]`; f32 bits are
little-endian in the table's output order. The output digest extends V1 with
these 17 protected bytes, 16 transformed bytes and one control byte per row.

Pure packet arguments have `VERIFIED_EXACT_NATIVE_PACKET_ARGUMENTS` confidence.
The overall row remains `CANDIDATE`; actual lookup, slot identity, actor, target,
cooldown state and effect stay unobserved/unknown. Native constructor defaults
are part of the decoded request, not invented state or a successful zero effect.

Pinned callback `0x2bbc90..0x2bbe2e` SHA-256:
`3069f2c707768f8f2727f33da0f313b1cfa93ea1a78c41f0e3e3bbc54116740e`.
Static receiver span `0x94d3b0..0x94d520` SHA-256:
`5499c8c4aecff546563f7b3c505ed136bf853adae151019c8b35e16c90dcadd6`.
The lookup table at `0x1ab62d0` has the same bytes as the existing exact-821
table (`328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b`);
this equality was checked in the pinned image, not borrowed from another build.

## Saved queries and verification

Saved-only queries check complete schema, constants, native field transforms,
source references and ordered input/output counts/digests, even after the output
limit. They remain `SAVED_ONLY_UNVERIFIED`: coherent substitutions with rewritten
digests can pass consistency checks. CLI and library callbacks stage V2 output
until all selected rows/Replays pass, including in saved-only mode.

For V2, `--verify-source` requires the image and re-decodes **every** original
packet using the native reader and packet-code slices. Complete result metadata
and every saved row must equal that fresh output, before any filter or output
limit can hide a later difference. `FRESH_EXACT_IMAGE_REDECODE` reproduces the
candidate request, not a real receiver or effect. Missing/wrong images or native
decoder failures emit no partial output. V1's existing source check remains a
packet-provenance check and is not upgraded by these V2 claims.

## Fresh validation and remaining evidence

All 11 existing authorized KR Replays decoded successfully: **182,482** native
requests, 97,977 keyframe and 84,505 game packets, zero framing errors. JavaScript
field arithmetic agreed with original native packet-code outputs for every row.
The control counts are 162,715 zero and 19,767 one. Argument-0 observations span
`-2.607177734375..390`; negative requests are preserved, not clamped by the parser.
All 11 streams were freshly re-decoded and fully queried under a global limit of
one output row. Candidate markers stayed unchanged. Original inputs and complete
JSONL remain local and excluded from source packages.

Focused Node tests passed 31/31 without skips, covering V1/V2, CLI selection,
complete native verification, late effect/schema forgeries, coherent protected
field plus digest forgery, empty output on failure, and adjacent SetSpellLevel
source-query regression. Three actual-image Python tests passed, including
independently deriving 256-byte native transform inverses to reject Infinity and
an unobserved control. Generated containers/mutations are protocol tests, not
receiver-state observations. No full test graph or older-client regression was
repeated for this extension.

To reproduce the focused native checks, set the image explicitly:

```powershell
$env:ROFL_821_RUNTIME_IMAGE = "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin"
npm run test:16-19-cooldown-broadcast
python -B test/python/test_cooldown_request_fields_16_19_821.py
```

Without that image, the native test cases skip; a skipped test does not validate
the new native argument path.

Adjacent bounded exact-module analysis found default `[Q]/[W]/[E]/[R]` input
registrations (`0xe0fc09` onward) and action labels selecting 0..3 in
`0x5ec150`. This does **not** bridge those input indices to each Replay packet's
receiver component slot. The named `SpellLevel` formatting accessor at `0x4c5970`
reads a different context's `+0x49 & 7`; it does not anchor SetSpellLevel's live
slot-object `+0x28`. No Q/W/E/R or actual rank field was promoted from these names.
The time-source getter at `0x1277b60` reads a heap-backed selected integer tick;
`0x8db060` also uses that clock and live slot state. Their actual values and
branch results are absent from the module capture. More synthetic receiver tests
cannot provide the missing observations.

The smallest decisive new input is a lawful **offline witness for this exact
build** tying one original Replay SHA/packet position to the dispatch registry's
bound receiver (`this+0xbc`), selected component/slot, relevant native callee
outcome and before/after slot state. Cooldown needs the corresponding time-source
value and its anchored units; level needs slot `+0x28` before/after; Q/W/E/R needs
an independently anchored input-index-to-slot binding. Heal/shield/damage effect
promotion likewise needs identified affected objects and observed state, not key
co-occurrence. The capture must identify its Replay/session and address ranges;
the existing module-only image does neither for receiver heap. There is no
permission to acquire a new process/heap capture in this parser task. Old
16.16/16.15 clients are not prerequisites.
