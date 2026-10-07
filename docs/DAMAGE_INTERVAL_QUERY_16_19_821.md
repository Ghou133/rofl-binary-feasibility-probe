# Query sampled damage counter intervals (exact KR 821)

The existing `hero_damage_keyframe_intervals` decoder outputs differences of four
cumulative counter candidates between adjacent complete keyframes. Its saved
stream now supports CLI/API queries, without a game client, Python or runtime
image. Only `16.19.821.7343` is accepted.

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events hero_damage_keyframe_intervals --event-jsonl-only --out-dir "work\damage-windows"
node src/cli.js query-events "work\damage-windows" --list-events
node src/cli.js query-events "work\damage-windows" --event hero_damage_keyframe_interval_candidates --participant 1 --from-ms 60000 --to-ms 180000 --limit 10 --output "work\damage-preview.jsonl"
node src/cli.js query-events "work\damage-windows" --event hero_damage_keyframe_interval_candidates --verify-source --participant 1 --limit 10 --output "work\damage-verified.jsonl"
```

Both single-Replay artifact directories and decode/batch roots work. Source
verification at a batch root uses each saved source path. A single artifact can
use `--source-replay` to point to the same original bytes elsewhere; saved source
paths remain unchanged in output. Full SHA and build must match. This path uses
the existing static exact-build decoder; `--runtime-image` is unnecessary and
rejected for this stream.

The query filters inclusive `--from-ms`/`--to-ms` by the **current keyframe
endpoint**, not an invented change time or window-overlap rule. `--participant`
selects the candidate participant; `--raw-param` compares the complete observed
hero header u32. It accepts `--limit`, `--output` and `--verify-source`.
Combat-role, native packet, inventory and slot-change filters are unsupported.

```javascript
const {prepareEventQuery, streamEventQuery} = require('./src/event_query');
const prepared = prepareEventQuery(replayArtifactDirectory,
  'hero_damage_keyframe_interval_candidates');
const summary = await streamEventQuery(prepared,
  {participant: 1, fromMs: 60000, limit: 10, verifySource: true},
  line => consumeJsonl(line));
```

Saved-only validation checks the exact profile/dependencies and mirrored
metadata; complete ten-participant windows; protected endpoint bytes using the
shared decoder transform; both f32 differences and differences of endpoint
floors; complete endpoint chains/packet identity; changed/unchanged counts; and
unobserved final-tail gaps. Embedded and JSONL rows must agree when both were
saved. All rows and tail gaps are checked after filters and limits. CLI/API stage
all selected output until all selected Replays pass, including saved-only mode.
A late failure emits no earlier rows; missing/invalid/unavailable inputs are
distinct from a checked one-keyframe empty interval set.

Saved-only results are `SAVED_ONLY_UNVERIFIED`. Coherent substitutions that also
rewrite saved metadata/digests can pass internal consistency; they do not prove
correspondence to the original Replay. `--verify-source` re-runs the existing
decoder against the complete original source and compares all capability
metadata and every row before emitting any output. A source override normalizes
only source paths, never SHA/build/packet references or numeric values.

Rows are returned unchanged as `CANDIDATE`,
`KEYFRAME_ENDPOINT_DIFFERENCE_ONLY`, with
`UNRESOLVED_WITHIN_INTERVAL` change time. The counter labels and participant
mapping inherit the existing exact-build candidate evidence. This is no new
claim about individual attacks, attackers/targets, effective damage, health
loss, mitigation, lethal damage or precise event times. Unchanged cumulative
endpoints do not prove no activity. Final tails are reported as unobserved gaps,
not fabricated intervals. The optional native packet/window comparison stream
remains decode/API output and is not part of this saved interval query.

Fresh Oct-7 verification: 11 authorized existing KR Replays, **3,160** intervals,
all complete-source queries passed under a global limit of one output row; zero
framing errors. Focused decoder/query/snapshot tests passed 22/22 without skips,
including coherent byte/tail/count forgery, late multi-Replay failure, source
path override and checked zero intervals. Generated fixtures are protocol tests,
not actual gameplay-state witnesses. No heap was acquired and the preceding
182,482 cooldown requests were not rerun. Another 86 shared CLI and focused
cooldown-V2 query regression tests passed without failures/skips.

```powershell
npm run test:16-19-damage-intervals
```
