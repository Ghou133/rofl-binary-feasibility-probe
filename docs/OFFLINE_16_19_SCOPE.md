# Useful offline scope with the existing 16.19 inputs

**Historical scope; active development stopped on 2026-10-07.** The decisions
below describe completed work and its then-current gaps, not authorization to
continue. [Final scope](PROJECT_STOPPED_20261007.md) supersedes acquisition and
continuation suggestions. Existing candidates and original evidence are retained.

The continuation focused on protocol coverage and correct observation timelines, not
more query flags. Existing exact module/Replay evidence supports the following
choices; missing independent state is not silently replaced by nearby-build code.

| Work | Existing evidence / missing input | Decision |
| --- | --- | --- |
| HN 820 cumulative-counter observation timeline | Its own `0x0276` route, fingerprint, byte transform and existing four snapshot candidates; three local original HN Replays | Implemented this increment; adds exact-build coverage without heap or a new damage label |
| More packet-only native argument decoding | Original bytes/native packet slices can support anonymous fields; useful meanings still need receiver/typed-field links | Continue only for a concrete missing field with a defensible anchor, not to grow candidate counts |
| Additional build adaptation | Each complete build needs its own available route/transform evidence and original input | No adjacent-build aliases; HN 820 and KR 821 are now independently supported for the sampled-counter timeline |
| Objective/OnEvent typed child fields | Existing blob does not equal the callback's typed argument; indirect conversion/listener link is unresolved | Blocked at that link; repeating blob-count or timing joins does not recover typed semantics |
| Ordinary hero paths / visibility | Existing path scouts lack a position-field link; 821 visibility native decoding reaches omitted heap | Need a lawful exact-build field/position/state witness; do not reuse old paths or infer map coordinates |
| Real combat roles, HP/effective damage, skill slot/rank/cooldown application, transactions | Existing module/packets provide requests and sampled candidates, not successful receiver lookup plus independently observed before/after state | Needs independent exact-build state/role/action anchors; heap is one possible input, not an authorized current action |

This does **not** establish that every remaining protocol field needs heap. It
does establish that the current role/effect claims cannot be promoted from the
existing packet-only evidence. No equally strong, unimplemented named gameplay
semantic was found in the scoped existing evidence after this adaptation.

## Exact-build sampled timelines

`hero_damage_keyframe_intervals` now selects an independent profile for:

| Profile | Route / accepted observation streams | Embedded transform |
| --- | --- | --- |
| HN `16.19.820.7193` | `0x0276`, keyframe and start-keyframe | HN image `7e6804…76d`, lookup table `328528…04b` |
| KR `16.19.821.7343` | `0x0089`, keyframe | KR image `35b495…325`, lookup table from its existing snapshot profile |

Both profiles reuse their original snapshot decoders and a single internal
endpoint-arithmetic builder. Protocol byte transforms stay in the exact-build
decoders; query validation uses the selected build's shared transform. HN's
start-keyframe origin, multiple observation epochs in one chunk and nonzero
initial observations are accepted when its existing snapshot decoder validates
them. Its tail gaps retain protected field bytes, including for a checked
single-epoch empty interval set. KR's existing profile/output stays unchanged.
Foreign-route inputs or missing tails remain unavailable, not zero intervals.

```powershell
node src/cli.js capabilities "D:\Replays\example.rofl" --events hero_damage_keyframe_intervals --json
node src/cli.js decode "D:\Replays\example.rofl" --events hero_damage_keyframe_intervals --event-jsonl-only --out-dir "work\sampled-counters"
node src/cli.js query-events "work\sampled-counters" --event hero_damage_keyframe_interval_candidates --verify-source --participant 1 --limit 10
```

No client, runtime image, Python or heap is required for this static path.
Default batch execution is serial and accepts multiple explicit input files;
the optional `--jobs` worker mode remains KR 821-only. A mixed input must report
each build/capability's own availability rather than borrow a profile.

Three existing HN Replays passed fresh decoding and complete original-source
reproduction: **880** intervals, zero framing errors. The query emitted only
one row under a global limit while checking every interval in all three Replays.
This is exact-build compatibility and observation arithmetic, not a semantic
breakthrough in effective damage or participant combat roles.

The adjacent window-query defect is fixed: a partially available batch now
reports `PARTIAL_SAVED_DEPENDENCY_RECONCILIATION`, rather than a complete witness.
All-unavailable batches still fail explicitly without output.

## Deliverable minimal offline analysis tool

The existing parser can serve as a local CLI/API analysis tool for supported
exact builds: container/build and framing diagnostics; candidate deaths, timers
and observed returns where registered; sampled progress/counter/item observations;
raw/native packet arguments and their exact provenance when an existing matching
image is supplied; and saved or full-original-source queries. Structured JSONL,
summary availability and unobserved tail gaps are usable deliverables today.

It cannot yet provide a faithful visual replay, player-position map, combat
attribution/effective-damage log or a successful cast/cooldown timeline. Candidate
death/return labels also retain their own profile limitations. Map/behavior/UI
truth remains outside this parser's ownership. New process/heap acquisition is
not part of the stopped project. Existing missing state remains unknown; no new
process or heap capture was performed during this continuation.
