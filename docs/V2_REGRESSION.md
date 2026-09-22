# V2 Regression Evidence

V2 is additive to the frozen V1 decoder. The accepted completion state is
`RESEARCH_READY_V2_COMPLETE`; V1 continues to report
`RESEARCH_READY_COMPLETE` through its existing decoder status.

Run the full cross-platform test suite:

```powershell
npm test
```

The focused Ward/Path surface is:

```powershell
node --test test/ward_v2.test.js test/path_v2.test.js test/ward_analysis_v2.test.js
```

Re-hash and validate the exhaustive current-build Ward decode:

```powershell
npm run validate-ward-spawn-current
```

This checks the runtime image, selected packet file, ten CastSpell inputs, all
decoded outputs, 17,406 packet rows, 1,357 Ward spawns, 464 cast-to-spawn
matches, and 637 lifecycle rows.

Regenerate the integrated Ward research dataset using direct spawn coordinates
and corpse-derived lifecycles:

```powershell
npm run validate-ward-v2
```

The command must report `RESEARCH_READY_V2_COMPLETE`, 464 direct spawn matches,
and 637 lifecycle rows. `NO_V2_BLIND_HOLDOUT_NON_BLOCKING` remains a disclosure,
not a decoder gate.

Run the combined source/test/evidence gate and refresh its compact manifest:

```powershell
npm run verify-v2 -- --write-manifest
```

The checker reruns both Ward validators, re-hashes every source declared by the
integrated Ward report, verifies the enriched Path-position provenance manifest
and its source/output hashes, checks the Ward/Path summaries and calibration,
and runs both focused and complete repository test suites. It requires the
local exhaustive Ward/Path inputs and is not expected to run in the portable
handoff package.

The main CLI consumes verified decoder artifacts explicitly:

```powershell
node src/cli.js analyze replay/HN1-11154791609.rofl `
  --out-dir artifacts/v2_research/cli-v2-complete `
  --ward-spawns artifacts/v2_ward_spawn/current_full_decode/ward_spawns.jsonl `
  --ward-lifecycles artifacts/v2_ward_spawn/current_full_decode/ward_lifecycle.jsonl `
  --hero-positions artifacts/v2_ward_spawn/current_path_hero_positions_1s_all10_enriched.jsonl
```

The per-replay output must contain `ENTITY_SPAWN_DIRECT` Ward rows and nonempty
`position_events.jsonl`. CastSpell coordinates remain separate validation
fields and are never substituted for decoded spawn coordinates.

Build the portable AI handoff package with Python 3.10+:

```powershell
npm run package:handoff
```

The package includes source, tests, protocol documents and path-free bounded
summaries. It deliberately excludes raw Replays, the runtime image, DuckDB,
Match Details, player identifiers and exhaustive Ward/Path traces. Run
`npm run test:portable` after extraction; full V2 reproduction requires the
excluded inputs.
