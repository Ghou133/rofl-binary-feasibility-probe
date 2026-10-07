# Query native packet / sampled damage window comparisons

Exact `16.19.821.7343` comparison output now supports saved CLI/API queries.
Select both existing capabilities during decode; the comparison remains an
association, not a separately published gameplay event.

```powershell
node src/cli.js decode "D:\Replays\example.rofl" --events hero_damage_keyframe_intervals,unit_apply_damage_packet --damage-packet-v6 --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --event-jsonl-only --out-dir "work\damage-comparison"
node src/cli.js query-events "work\damage-comparison" --event hero_damage_packet_keyframe_window_candidates --participant 1 --limit 10
node src/cli.js query-events "work\damage-comparison" --event hero_damage_packet_keyframe_window_candidates --verify-source --runtime-image "D:\Capture\LeagueOfLegends_16.19.821.7343.memory.bin" --limit 10 --output "work\damage-comparison-verified.jsonl"
```

Saved queries need the complete native packet and interval JSONL plus their
metadata. They work without the image/Python. Original-source verification
requires the exact image and Python/Unicorn, re-runs both original decoders and
compares every dependency row, all metadata and all derived comparison rows.
The source's V5/V6 native profile is recovered from saved metadata. Filtering or
limits do not hide excluded native packets, interval rows, later windows or
other Replays. Native candidates and unknown effects stay unchanged.

Each saved query first validates the complete dependency streams and recomputes
the association with the existing shared calculator. This checks independent
`lookup_0x24`/`lookup_0x2c` grouping, anonymous `+0x20` sums, first/last
packet refs, counter differences, rotated-key negative control, 0.1-error-screen
metadata and exact-endpoint/outside-window exclusions. These are parser-owned
candidate comparisons; no decoder algorithm is copied into a consumer.

Both source and saved-only modes stage CLI/API output until every selected
Replay passes. Saved-only is `SAVED_ONLY_UNVERIFIED` with
`COMPLETE_SAVED_DEPENDENCY_RECONCILIATION`: a coherent substitution across all
saved dependencies can still pass. Source verification is
`FRESH_EXACT_IMAGE_REDECODE`, reproducing native anonymous packet arguments,
not a successful live receiver call or health effect. Missing/wrong images,
incomplete dependencies, stale manifest hashes, false role/effect fields or
late row corruption cannot produce partial output.

Supported filters are candidate `--participant`, complete candidate
hero key `--raw-param`, inclusive current-endpoint `--from-ms`/`--to-ms`,
and `--limit`. Source path overrides work on a single Replay artifact and only
normalize paths; full SHA/build/positions/values remain checked. A supplied but
unused image annotation on the static interval capability is accepted; its
source query normalizes only that annotation, retaining all numeric/provenance
comparisons. It still never executes an image for static counter intervals.

Rows keep `CANDIDATE`, `STRICT_OPEN_ENDPOINTS`, key-role `UNKNOWN` and
semantic-effect `UNKNOWN`. Packets exactly at sampled endpoints stay excluded:
game/keyframe ordering is unresolved. No tail window, attack time, source/target
role, effective damage, health loss or fatal hit is inferred. The rotated-key
control and 0.1 screen are evidence comparisons, not acceptance criteria.

Fresh validation: one existing real KR Replay's **64,824** native damage packets
and **320** sampled intervals passed complete-source reproduction. **20** exact
endpoint packets and **2,073** outside-window packets remained excluded.
Final saved-query reconciliation additionally checks every protected native field,
input digest, profile-specific source count and effect marker. Native packet queries
perform this full validation by default, including queries without native filters;
they retain all rows instead of selecting only the legacy available-f32 shape.
Both single and batch queries stage output until the complete validation passes.
The historical summary's `damage_callback_f32_available_count` still describes
the narrow legacy saved-f32 shape; it does not count availability of the native
V2+ anonymous f32 field. On the real Replay this is 684 legacy-shape rows and
64,140 other shapes, while all 64,824 native packets passed complete validation.
Focused interval/window query tests cover V5/V6, source overrides, missing image/dependencies,
coherent position/reference substitution, full-stream late falsification and
checked one-keyframe zero comparisons. Fixtures around existing observed packet
bodies are generated protocol tests, not live-state evidence. Prior 182,482
cooldown requests and the full old-client graph were not rerun.

```powershell
npm run test:16-19-damage-windows
```

Counter and anonymous-sum screens are now available on unchanged candidate rows:

```powershell
node src/cli.js query-events "work\damage-comparison" --event hero_damage_packet_keyframe_window_candidates --damage-counter TOTAL_DAMAGE_TAKEN --damage-min-delta 5.25 --limit 10
node src/cli.js query-events "work\damage-comparison" --event hero_damage_packet_keyframe_window_candidates --damage-counter TOTAL_DAMAGE_TAKEN --window-key lookup_0x24 --window-max-error 0.1 --limit 10
```

`--damage-changed` selects any positive delta among the four cumulative counters.
`--damage-counter` selects a positive delta of the named counter; adding
`--damage-min-delta` changes this to an inclusive threshold (explicit zero is valid).
Names are `TOTAL_DAMAGE_DEALT_TO_CHAMPIONS`, `TOTAL_DAMAGE_DEALT`,
`TOTAL_DAMAGE_TAKEN`, and `TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS`.
`--window-key` requires a nonempty anonymous group for `lookup_0x24` or `lookup_0x2c`.
`--window-max-error` also requires a counter and keeps inclusive absolute differences
between the anonymous sum and that counter delta. Decimal thresholds retain normal
double precision; they are not rounded to on-wire f32 values. All requested screens
combine with AND and run after complete validation, even if no rows match.
API options are `damageChanged`, `damageCounter`, `damageMinDelta`, `windowKey`,
and `windowMaxError`; summaries report their values. The real Replay has 292 windows
passing the positive `TOTAL_DAMAGE_TAKEN` / `lookup_0x24` / 0.1 screen. A small
difference does not identify a target or validate effective damage; rotated controls
and unknown roles remain in each returned row.
