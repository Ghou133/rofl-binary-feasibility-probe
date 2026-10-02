# Run the 16.19 parser locally

Use Node >=22.15.0 (native Zstd required). Container inspection and the
death/assist/respawn candidate path need no game client or Python installation.
Native packet candidates additionally need a legally obtained matching runtime
image, Python, and Unicorn (`requirements.txt`). Inputs remain local.

## Inspect the build and selected inputs

```powershell
node src/cli.js capabilities "D:\Replays\example.rofl" --events hero_death,hero_assist,hero_respawn --json
```

The full build comes from the file. `--events` limits preflight to those names,
in request order. Unknown names appear in `unregistered_requested_capabilities`
and return exit code 2. Omitting `--events` lists the complete registered build.
Preflight reads the container and tail, without packet decoding or creating
output. It does not verify the runtime image hash or prove event semantics.

## Decode death episodes and candidate roster labels (exact KR 821)

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events hero_death,hero_assist,hero_death_timer,hero_respawn,hero_roster_metadata_bridge --event-jsonl-only --out-dir "work\episodes"
node src/cli.js query-events "work\episodes" --list-events
node src/cli.js query-events "work\episodes" --event hero_death_episode_candidates --verify-source --limit 10 --output "work\episodes-preview.jsonl"
```

For `16.19.820.7193`, start with `--events hero_death`. Capabilities are bound to
the complete build; 821-only names are not borrowed for 820 or unknown builds.
The 821 example preserves matched deaths, assist lists, timer fields, observed
returns or end-of-Replay nonreturns, plus a separately gated roster bridge.
It never predicts respawn from a timer. All these results remain candidates.

The exact-821 `hero_death_candidates`, `hero_assist_candidates`,
`hero_death_timer_candidates`, `hero_respawn_candidates`, and joined episode
streams support `--verify-source`. This independently checks the original ROFL
identity, re-decodes every row and checks the complete capability metadata before
emitting filtered or limited output. It requires no runtime image for static
candidate observations. If assist child identities were natively witnessed
during decode, provide the matching `--runtime-image` again; missing or mismatched
images fail the query without emitting partial output. Source verification does
not promote these observations to confirmed gameplay semantics.

Outputs include `acceptance_summary.json`, `manifest.json`, and per-Replay
`semantic_run.json` and candidate JSONL files under `replays/`.
`CANDIDATE` and `PARTIAL` do not mean confirmed semantics. Missing inputs and
unavailable routes remain explicit; they are not zero-event results.

## Sampled damage counter windows (exact KR 821)

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events hero_damage_keyframe_intervals --event-jsonl-only --out-dir "work\damage-windows"
```

The selected capability needs no runtime image. Its
`hero_damage_keyframe_interval_candidates.jsonl` contains one row for each
candidate participant and adjacent pair of complete keyframes. `counters`
contains the previous/current decoded f32 values and their differences for
`TOTAL_DAMAGE_DEALT_TO_CHAMPIONS`, `TOTAL_DAMAGE_DEALT`, `TOTAL_DAMAGE_TAKEN`
and `TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS`. The field labels and participant
mapping inherit the existing exact-build candidate evidence.

Both endpoint times, protected field bytes and original packet references are
retained. `replay_time_ms` is the current observation endpoint; intervening
change times are unresolved. Zero differences are emitted as sampled unchanged
endpoints. Final-tail gaps are reported in `semantic_run.json` and never filled
with invented intervals. These windows are useful for a sampled damage timeline
and packet-field comparisons; they establish no attack, actor, health effect or
effective damage. `endpoint_floor_difference_candidate` subtracts the two
integer endpoint floors; it is different from flooring the f32 delta.

```javascript
const decoded = decodeSemanticReplay(parseReplayFile(replayPath), {
  capabilities: ['hero_damage_keyframe_intervals'],
});
const windows = decoded.events?.hero_damage_keyframe_interval_candidates;
console.log(decoded.capability_results.hero_damage_keyframe_intervals, windows);
```

Consume the decode JSONL or API rows directly. This stream is not yet registered
with the saved `query-events` command.

To compare the windows with native anonymous packet fields, select both inputs:

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events hero_damage_keyframe_intervals,unit_apply_damage_packet --damage-packet-v6 --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --event-jsonl-only --out-dir "work\damage-packet-windows"
```

This additionally produces `hero_damage_packet_keyframe_window_candidates.jsonl`
and `candidate_associations.hero_damage_packet_keyframe_windows` in the API and
`semantic_run.json`. Each native lookup key (`+0x24` and `+0x2c`) is grouped
independently by full equality with the candidate participant key. The output
compares anonymous `+0x20` sums with all four counter deltas and a rotated-key
control, retaining packet counts and first/last refs. It uses strict open
intervals and reports packets at exact endpoints or beyond the last keyframe
separately. Small discrepancies are measured; no combat role or effective
damage is assigned. A missing native image leaves the static windows available
and marks this additional comparison unavailable.

## Native heal and missile key observations (exact KR 821)

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events params_heal_roster_key_pair,missile_key_cooccurrence --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --event-jsonl-only --out-dir "work\native-pairs"
node src/cli.js query-events "work\native-pairs" --event params_heal_roster_key_pair_candidates --verify-source --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --limit 10 --output "work\heal-preview.jsonl"
node src/cli.js query-events "work\native-pairs" --event missile_key_cooccurrence_candidates --verify-source --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --limit 10 --output "work\missile-preview.jsonl"
```

Source verification checks every saved row and re-decodes the original source
before applying the output limit. `SOURCE_REPLAY_VERIFIED` establishes source
correspondence; healing effectiveness, actor roles, missile identity, target
change, and gameplay effects remain unknown. A Replay without the needed missile
route reports `PROFILE_UNAVAILABLE`, including in a mixed `PARTIAL` batch.

## API and batches

```javascript
const { parseReplayFile } = require('./src/rofl');
const { decodeSemanticReplay } = require('./src/semantic_api');
const result = decodeSemanticReplay(parseReplayFile(replayPath), {
  capabilities: ['hero_death', 'hero_assist', 'hero_death_timer', 'hero_respawn'],
});
console.log(result.status, result.capability_results);
// Read result.events.hero_death_episode_candidates only as candidate observations.
```

Replace `decode FILE` with `batch DIRECTORY` to process an existing local corpus.
Use separate output directories for reruns. Default batch execution is serial;
`--jobs 2` is available for exact-821 JSONL-only batches. A saved query without
`--verify-source` reports `SAVED_ONLY_UNVERIFIED`.

## Source archive

```powershell
npm run package:source
npm run verify:source
```

`dist/rofl-analyzer-source.zip` contains code, tests, and documentation with a
closed file/hash manifest. Replays, runtime images, and fresh research outputs
are excluded. Extract it, run the commands above against your local inputs, and
keep generated event artifacts private. See [development progress](DEVELOPMENT_16_19.md)
for prior evidence and the remaining field-specific limitations.
