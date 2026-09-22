# ROFL new-build playbook

Use this procedure for every exact client build. The rolling window retains up
to three independently validated profiles; it never treats a nearby version as
compatible by default.

## Evidence layers

- `L1 FORMAT`: header, metadata, chunks, native Zstd, block framing and
  timestamp order.
- `L2 STRUCTURE`: exact build route, constructor/runtime image, deserialize
  success and full payload consumption.
- `L3 SEMANTICS`: entity meaning, fields, coordinates or build-bound mapping
  proved with independent anchors.

L1 does not imply L2. L2 does not imply L3. Match Details can validate L3 but
must not create the emitted Replay fact.

## Frozen migration policy — AUTO FIRST, MANUAL LAST

For a future exact build, the migration engine traverses **all public canonical
capabilities**. It runs the versioned `SemanticFingerprint`,
`GroundTruthOracle`, deterministic matcher, `RegressionIntegration`,
`MigrationOracle`, and exception registry before a human task can exist. The
deterministic matcher records structural, behavioral, cross-field,
ground-truth-derived, and negative-control results for every capability.

```text
unique candidate + all required automatic evidence passes = AUTO_MIGRATION_VERIFIED
failed / ambiguous / conflicting automatic evidence = targeted manual escalation allowed
```

Passing capabilities are never manually revalidated merely because the build is
new. There is no nearest-build fallback, wildcard compatibility, or semantic
promotion from route/offset similarity. The migration must still enumerate and
retain diffs for every new packet, component, runtime type, callback, and
entity family; those diffs feed the research queue even when no existing
capability needs manual validation.

## Step 1 — collect bounded inputs

Collect 20–40 exact-build `.rofl` files for the gate and retain up to 100 for
candidate distributions. Record hashes, byte sizes, selection order and the
exact binary `header.version`. Capture the matching runtime module image and
its SHA-256. Keep Replay and Match Details outside the source handoff.

Start `migration_time_log.csv` before discovery. Use separate rows for
automatic scan, candidate discovery, static analysis, dynamic validation,
regression and manual inspection. Unknown historical duration stays blank with
`UNMEASURED_HISTORICAL`; do not invent it later.

## Step 2 — L1 format gate

Run the bounded strict validator:

```powershell
node scripts/validate_new_build_compatibility.js `
  --new-replay-dir <new-build-replays> `
  --old-replay-dir <old-build-replays> `
  --runtime-image <exact-runtime-image> `
  --sample-size 40 `
  --output <new-gate-output>
```

Stop if header/build selection, Zstd, block framing or timestamp order fails.
Do not start semantic migration from a damaged L1 sample.

## Step 3 — route diff, semantic fingerprints, and automatic oracle regression

Compare the previous verified routes with every new Replay ID using:

- packet frequency and replay coverage;
- payload-length and raw-param distributions;
- stream and timestamp onset/spacing;
- constructor opcode stores, vtables and deserializer slots;
- exact-runtime full-consume behavior;
- existing semantic fingerprints.

For every public canonical capability, run the deterministic matcher and
`RegressionIntegration` against the versioned `GroundTruthOracle` and exception
registry. Feed the resulting evidence to `MigrationOracle`; preserve
unmatched/ambiguous rows and residuals without auto-promoting a semantic. A
unique candidate must pass the applicable structural, behavioral, cross-field,
ground-truth, negative-control, and exception gates before automatic migration.

Generate `route_migration_<old>_to_<new>.csv`. A shape match is `CANDIDATE`,
never a decoder authorization. Reject candidates explicitly when semantic
anchors disagree; keep the rejected route in the evidence trail.

## Step 4 — recover the shared runtime environment

Recover the exact build's base packet vtable, serializer, decode wrapper,
allocator boundary and any runtime leaf that Unicorn cannot execute. Put these
values in the build runtime profile. Do not hand-write a different base-header
parser per packet.

For a target route, prove the constructor writes the route, locate the actual
object vtable and deserializer, and record the object extent and field offsets.
Hash-gate the runtime image before every dynamic decode.

## Step 5 — P0 semantic gate

Validate, in order:

1. participant / champion entity mapping;
2. HeroPath exact/full consume, fields, ten participants, chronology,
   coordinates, map sanity and 3–5 ten-participant trajectory plots;
3. LevelTransition occurrence/entity/timestamp;
4. LevelAfter mapping re-derived for this build, including `raw_value`,
   transition/anchor level, `n` and `conflict_n`.

The runtime validator must reject an empty selected packet stream. It must
recompute every raw-payload length and SHA-256, bind each row to the exact
Replay SHA in the strict-export manifest, require exact runtime-image SHA-256,
and retain zero infrastructure failures. A genuine replay with no packet of a
supported capability is reported separately as `NO_MATCHING_PACKETS_IN_REPLAY`;
it is not a successful zero-row decoder validation.

For HeroPath, require all ten participants in every selected replay, at least
one emitted path event per participant, per-participant DETAILS coverage,
chronological order, >=95% position-anchor coverage, bounded source age,
aggregate and per-replay coordinate-error gates, and aggregate and per-replay
map sanity. For LevelTransition, match packets to DETAILS anchors one-to-one;
require >=100 anchors, >=10 anchor-bearing replays, >=95% unique-anchor
coverage, >=100 participant sequences, zero mapping conflicts/non-monotonic
sequences, and at least 100 independent observations for Lv2, Lv3 and Lv4.

Export selected packets with an exact version gate:

```powershell
node scripts/export_selected_packets.js `
  --replay-version <exact-build> `
  --packet-id <route> `
  --output <packets.jsonl> `
  <replay-files>
```

If the payload grammar is unchanged, reuse the shared semantic decoder with a
new build route/runtime adapter. If it changed, add the smallest build adapter;
do not copy the container parser.

## Step 6 — P1 gates

After P0, independently validate WardSpawn, HeroDamage and HeroDeath. Ward
requires full consume, coordinates, owner, ward entity/type, participant/team
and timing. Damage requires direct source, target and amount. Death requires a
unique Replay route and hero-only identity proof.

Vision and combat facts remain unavailable until these gates pass. Their
failure does not block an already proven `INFERENCE_READY` P0 release.

## Step 7 — regression and exact registration

Run the full Node suite, portable suite, frozen 16.15 V2 validators and bounded
V3/V4 tests. Verify that old profile constants, artifact hashes and semantic
outputs did not change unintentionally.

Only then add the exact build to `src/build_registry.js` with:

- `game_version`, `patch` and runtime profile;
- packet routes and decoder profiles;
- field semantics and semantic mappings;
- verified, candidate and unsupported capabilities;
- validation artifacts and regression fixture set;
- release support level.

Unknown versions must return `UNSUPPORTED_VERSION`. Never add wildcard or
nearest-build fallback.

## Step 7a — manual validation only for unresolved capabilities

Do not request manual review for any capability that already passes the frozen
automatic migration gates. When, and only when, a single capability remains
failed or ambiguous after the matcher, `RegressionIntegration`,
`MigrationOracle`, and exception registry have completed, generate a small
targeted batch with `ManualValidationCaseGenerator`. It ranks information gain
and emits at most 20 concrete replay tasks (normally 5–20; fewer only when
fewer cases are unresolved), each naming the Replay, exact build, timestamp,
champion/entity, variable, before/after recording points, competing hypotheses,
and expected observation fields. Incorporate the returned truth as a versioned
`GroundTruthOracle` regression input for future automatic migrations.

## Step 8 — publication and downstream release

Run:

```powershell
node scripts/build_multi_build_artifacts.js
```

Publish the route map, shared decoder matrix, fingerprints, capability
validation tables, mapping, time log, regression and summary. All public events
must carry `game_version`, `patch` and `build_profile`; downstream code calls
`decodeSemanticReplay()`, `getHeroPaths()`, `getLevelTransitions()`,
`getWardSpawns()` or `getHeroDamage()` and never build opcodes.

Field-level confidence is mandatory when one event mixes evidence grades. In
particular, a LevelTransition packet's occurrence/entity/timestamp/raw fields
may be `VERIFIED_DIRECT` while `level_after` is
`VERIFIED_DERIVED_BUILD_BOUND`; an unmapped initialization row keeps
`level_after=null` and marks that field `UNAVAILABLE`.

Release levels are cumulative:

- `CORE_READY`: L1 + participant mapping + HeroPath + LevelTransition.
- `INFERENCE_READY`: `CORE_READY` + verified build-bound Lv2/Lv3/Lv4.
- `VISION_READY`: `INFERENCE_READY` + WardSpawn.
- `COMBAT_READY`: `INFERENCE_READY` + HeroDamage + HeroDeath.
- `FULL_PLATFORM_READY`: the main previously supported capabilities pass.

At `INFERENCE_READY`, release to `lol-inference-lab` for a new calibration and
blind holdout. Behavior-regime pooling across builds remains a downstream
decision; protocol compatibility does not assert game-content equivalence.
