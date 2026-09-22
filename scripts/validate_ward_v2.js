'use strict';

// Build a compact, replay-only Ward research surface from already verified
// CastSpell JSONL. Match Details is accepted only as a validation oracle here;
// its rows never supply coordinates or replay facts.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  buildWardOutputs,
  WARD_P0_PROFILE,
} = require('../src/ward_pipeline_v2');
const { parseReplayFile } = require('../src/rofl');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_EVENTS_ROOT = path.join(ROOT, 'artifacts', 'final_run', 'replays');
const DEFAULT_TIMELINE = path.join(ROOT, 'artifacts', 'holdout_timeline.json');
const DEFAULT_OUTPUT = path.join(ROOT, 'artifacts', 'v2_research', 'ward_dataset');
const DEFAULT_WARD_SPAWNS = path.join(
  ROOT, 'artifacts', 'v2_ward_spawn', 'current_full_decode', 'ward_spawns.jsonl',
);
const DEFAULT_WARD_LIFECYCLES = path.join(
  ROOT, 'artifacts', 'v2_ward_spawn', 'current_full_decode', 'ward_lifecycle.jsonl',
);
const DEFAULT_WARD_SUMMARY = path.join(
  ROOT, 'artifacts', 'v2_ward_spawn', 'current_full_decode', 'summary.json',
);

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJsonl(filePath) {
  const bytes = fs.readFileSync(filePath);
  return {
    rows: bytes.toString('utf8').split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line)),
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  };
}

function parseArgs(argv) {
  const options = {
    eventsRoot: DEFAULT_EVENTS_ROOT,
    timeline: DEFAULT_TIMELINE,
    output: DEFAULT_OUTPUT,
    manifest: path.join(ROOT, 'artifacts', 'replay_manifest.json'),
    wardSpawns: DEFAULT_WARD_SPAWNS,
    wardLifecycles: DEFAULT_WARD_LIFECYCLES,
    wardSummary: DEFAULT_WARD_SUMMARY,
  };
  const args = [...argv];
  while (args.length > 0) {
    const token = args.shift();
    const value = args.shift();
    if (!value) throw new Error(`missing value for ${token}`);
    if (token === '--events-root') options.eventsRoot = path.resolve(value);
    else if (token === '--timeline') options.timeline = path.resolve(value);
    else if (token === '--output') options.output = path.resolve(value);
    else if (token === '--manifest') options.manifest = path.resolve(value);
    else if (token === '--ward-spawns') options.wardSpawns = path.resolve(value);
    else if (token === '--ward-lifecycles') options.wardLifecycles = path.resolve(value);
    else if (token === '--ward-summary') options.wardSummary = path.resolve(value);
    else throw new Error(`unknown option: ${token}`);
  }
  return options;
}

function gameIdFromPath(filePath) {
  return /(?:^|[-_])(\d+)\.rofl$/i.exec(path.basename(filePath ?? ''))?.[1] ?? null;
}

function finite(value) { return Number.isFinite(value); }

function flattenTimeline(document) {
  return (document?.frames ?? []).flatMap((frame) => frame.events ?? [])
    .filter((event) => typeof event?.type === 'string' && event.type.startsWith('WARD_'));
}

function ownerId(event) {
  return event?.creatorId ?? event?.participantId ?? null;
}

function percentile(values, fraction) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index];
}

function matchTimelineOracle(candidates, timelineEvents, options = {}) {
  const placed = timelineEvents.filter((event) => (
    event.type === 'WARD_PLACED'
      && event.wardType === 'YELLOW_TRINKET'
  ));
  const maxDeltaMs = options.maxDeltaMs ?? 10;
  const used = new Set();
  const matches = [];
  for (const candidate of candidates) {
    const choices = placed
      .map((event, index) => ({ event, index, delta: event.timestamp - candidate.timestamp_ms }))
      .filter((item) => ownerId(item.event) === candidate.caster_participant_id
        && Math.abs(item.delta) <= maxDeltaMs
        && !used.has(item.index))
      .sort((left, right) => Math.abs(left.delta) - Math.abs(right.delta));
    const selected = choices[0] ?? null;
    if (selected) used.add(selected.index);
    matches.push({
      schema_version: 2,
      match_kind: 'CAST_TO_TIMELINE_ORACLE',
      oracle_only: true,
      replay_sha256: candidate.replay_sha256,
      game_id: candidate.game_id,
      cast_timestamp_ms: candidate.timestamp_ms,
      spawn_timestamp_ms: null,
      timeline_timestamp_ms: selected?.event.timestamp ?? null,
      delta_ms: selected?.delta ?? null,
      caster_participant_id: candidate.caster_participant_id,
      owner_participant_id: ownerId(selected?.event),
      ward_type: candidate.ward_type,
      cast_target_x: candidate.cast_target_x,
      cast_target_y: candidate.cast_target_y,
      cast_target_z: candidate.cast_target_z,
      spawn_x: null,
      spawn_y: null,
      spawn_z: null,
      position_delta: null,
      match_confidence: selected ? 'ORACLE_TIME_OWNER_TYPE_ONLY' : 'UNMATCHED',
      position_source: 'TIMELINE_POSITION_UNAVAILABLE',
      raw_packet_ref: candidate.raw_packet_ref,
    });
  }
  return matches;
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeJsonl(filePath, rows) {
  fs.writeFileSync(filePath,
    rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''),
    'utf8');
}

function csvCell(value) {
  if (value === null || value === undefined) return '';
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeHeatmapCsv(filePath, rows) {
  const columns = [
    'game_id', 'timestamp', 'minute', 'team', 'participant', 'champion',
    'ward_type', 'x', 'y', 'cast_target_y', 'position_source',
    'coordinate_system', 'map_id', 'map_name', 'patch', 'normalized_x',
    'normalized_y', 'perspective_team', 'perspective_participant', 'role',
    'side', 'confidence', 'is_spawn_position',
  ];
  fs.writeFileSync(filePath, [
    columns.join(','),
    ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(',')),
  ].join('\n') + '\n', 'utf8');
}

function writeWardEventsCsv(filePath, rows) {
  const columns = [
    'game_id', 'timestamp_ms', 'owner_participant', 'owner_champion',
    'owner_team', 'ward_type', 'cast_target_x', 'cast_target_y',
    'cast_target_z', 'actual_x', 'actual_y', 'actual_z',
    'position_source', 'confidence', 'event_status', 'lifecycle_status',
    'coordinate_system', 'map_id', 'patch',
  ];
  fs.writeFileSync(filePath, [
    columns.join(','),
    ...rows.map((row) => columns.map((column) => csvCell(row[column])).join(',')),
  ].join('\n') + '\n', 'utf8');
}

function discoverEventFiles(eventsRoot) {
  if (!fs.existsSync(eventsRoot)) throw new Error(`events root does not exist: ${eventsRoot}`);
  return fs.readdirSync(eventsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(eventsRoot, entry.name, 'spell_events.jsonl'))
    .filter((filePath) => fs.existsSync(filePath))
    .sort((left, right) => left.localeCompare(right));
}

function buildSpellInventory(allSpellRows, sourceFiles, wardTypeCounts = {}) {
  const count = (identifier) => allSpellRows.filter(
    (row) => row.spell_identifier === identifier,
  ).length;
  return {
    schema_version: 2,
    replay_version: WARD_P0_PROFILE.replay_version,
    source: 'PINNED_REPLAY_CASTSPELL_SEMANTIC_OUTPUT',
    source_files: sourceFiles.map((filePath) => ({
      path: filePath,
      sha256: sha256File(filePath),
    })),
    identifiers: [
      {
        spell_identifier: 'TrinketTotemLvl1',
        spell_key_hex: '0x0fb93891',
        ward_type: 'YELLOW_TRINKET',
        observed_count: count('TrinketTotemLvl1'),
        status: 'VERIFIED_REPLAY_OBSERVED',
        placement_role: 'INCLUDED',
      },
      {
        spell_identifier: 'TrinketTotemLvl2',
        spell_key_hex: '0x0fb93892',
        ward_type: 'YELLOW_TRINKET_LVL2',
        observed_count: count('TrinketTotemLvl2'),
        status: 'KNOWN_DICTIONARY_NOT_OBSERVED',
        placement_role: 'NOT_EMITTED',
      },
      {
        spell_identifier: 'TrinketSweeperLvl3',
        spell_key_hex: '0x0dcce223',
        ward_type: null,
        observed_count: count('TrinketSweeperLvl3'),
        status: 'VERIFIED_ACTION_BUT_NOT_WARD_PLACEMENT',
        placement_role: 'EXCLUDED',
      },
      {
        spell_identifier: 'Farsight / blue trinket',
        spell_key_hex: null,
        ward_type: 'BLUE_TRINKET',
        observed_count: wardTypeCounts.FARSIGHT_WARD ?? 0,
        status: 'VERIFIED_BY_WARDSPAWN_ENTITY_TYPE',
        placement_role: 'ENTITY_SPAWN_DIRECT',
      },
      {
        spell_identifier: 'Control Ward',
        spell_key_hex: null,
        ward_type: 'CONTROL_WARD',
        observed_count: wardTypeCounts.CONTROL_WARD ?? 0,
        status: 'VERIFIED_BY_WARDSPAWN_ENTITY_TYPE',
        placement_role: 'ENTITY_SPAWN_DIRECT',
      },
      {
        spell_identifier: 'Support/champion-created vision',
        spell_key_hex: null,
        ward_type: 'OTHER_WARD',
        observed_count: wardTypeCounts.OTHER_WARD ?? 0,
        status: 'VERIFIED_ENTITY_SPAWN; SUBTYPE_NOT_FULLY_CLASSIFIED',
        placement_role: 'ENTITY_SPAWN_DIRECT',
      },
    ],
  };
}

function holdoutStatus(manifest, sourceFiles) {
  const holdout = (manifest?.replays ?? []).find(
    (replay) => replay.sample_role === 'FROZEN_BLIND_HOLDOUT',
  );
  const rawPresent = Boolean(holdout?.replay_path && fs.existsSync(holdout.replay_path));
  const external = (manifest?.replays ?? []).filter(
    (replay) => replay.sample_role === 'EXTENDED_EXTERNAL_VALIDATION',
  );
  const externalRawPresent = external.filter((replay) => fs.existsSync(replay.replay_path));
  return {
    schema_version: 2,
    status: 'NO_V2_BLIND_HOLDOUT_NON_BLOCKING',
    blocking: false,
    reason: 'All physically available 16.15.801.3452 replays are already listed in the V1/preprocessed corpus; none can honestly be called an untouched V2 blind holdout after the existing semantic outputs were generated.',
    v1_holdout_reused_for_regression_only: true,
    holdout_game_id: holdout?.game_id ?? null,
    holdout_sha256: holdout?.replay_sha256 ?? null,
    holdout_raw_path_recorded: holdout?.replay_path ?? null,
    holdout_raw_present_at_run: rawPresent,
    extended_external_validation_count: external.length,
    extended_external_raw_present_count: externalRawPresent.length,
    available_patch_exact_raw_replay_count: (manifest?.replays ?? []).filter(
      (replay) => replay.patch === WARD_P0_PROFILE.replay_version
        && fs.existsSync(replay.replay_path),
    ).length,
    untouched_v2_candidate_count: 0,
    external_replays_are_preprocessed: true,
    semantic_source_files: sourceFiles,
    optional_follow_up: 'A future raw replay may be frozen as an additional blind holdout; it is not a decoder or completion prerequisite.',
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  for (const [label, filePath] of Object.entries({
    wardSpawns: options.wardSpawns,
    wardLifecycles: options.wardLifecycles,
    wardSummary: options.wardSummary,
  })) {
    if (!fs.existsSync(filePath)) throw new Error(`${label} input does not exist: ${filePath}`);
  }
  const wardSpawnInput = readJsonl(options.wardSpawns);
  const wardLifecycleInput = readJsonl(options.wardLifecycles);
  const wardDecodeSummary = JSON.parse(fs.readFileSync(options.wardSummary, 'utf8'));
  if (wardDecodeSummary.status !== 'PASS') throw new Error('WardSpawn full-decode summary is not PASS');
  const replayShaFor = (row) => row?.replay_sha256
    ?? row?.raw_packet_ref?.replay_sha256
    ?? row?.spawn_raw_packet_ref?.replay_sha256
    ?? null;
  const groupByReplay = (rows) => {
    const result = new Map();
    for (const row of rows) {
      const replaySha256 = replayShaFor(row);
      if (!replaySha256) continue;
      const group = result.get(replaySha256) ?? [];
      group.push(row);
      result.set(replaySha256, group);
    }
    return result;
  };
  const wardSpawnsByReplay = groupByReplay(wardSpawnInput.rows);
  const wardLifecyclesByReplay = groupByReplay(wardLifecycleInput.rows);
  const eventFiles = discoverEventFiles(options.eventsRoot);
  const sourceFiles = [];
  const byReplay = new Map();
  for (const filePath of eventFiles) {
    const input = readJsonl(filePath);
    sourceFiles.push(filePath);
    for (const row of input.rows) {
      const replaySha256 = row.raw_packet_ref?.replay_sha256 ?? row.replay_sha256 ?? null;
      if (!replaySha256) continue;
      let group = byReplay.get(replaySha256);
      if (!group) {
        group = {
          source_path: row.raw_packet_ref?.source_path ?? row.replay_path ?? null,
          source_sha256: replaySha256,
          header: { version: row.replay_version ?? WARD_P0_PROFILE.replay_version },
          spell_events: [],
        };
        byReplay.set(replaySha256, group);
      }
      group.spell_events.push(row);
    }
  }

  const candidates = [];
  const events = [];
  const lifecycles = [];
  const spawnMatches = [];
  const heatmap = [];
  const perReplay = [];
  for (const replay of byReplay.values()) {
    const parsedReplay = parseReplayFile(replay.source_path);
    if (parsedReplay.source_sha256 !== replay.source_sha256) {
      throw new Error(`Replay hash mismatch: ${replay.source_path}`);
    }
    const output = buildWardOutputs(parsedReplay, {
      spell_events: replay.spell_events,
      ward_spawn_events: wardSpawnsByReplay.get(replay.source_sha256) ?? [],
      ward_lifecycles: wardLifecyclesByReplay.get(replay.source_sha256) ?? [],
      ward_spawn_input_sha256: wardSpawnInput.sha256,
      ward_lifecycle_input_sha256: wardLifecycleInput.sha256,
    });
    candidates.push(...output.ward_cast_candidates);
    events.push(...output.ward_events);
    lifecycles.push(...output.ward_lifecycles);
    spawnMatches.push(...output.ward_cast_spawn_matches);
    heatmap.push(...output.ward_heatmap_input);
    perReplay.push({
      game_id: gameIdFromPath(replay.source_path),
      replay_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      source_spell_event_count: replay.spell_events.length,
      ward_cast_candidate_count: output.ward_cast_candidates.length,
      ward_event_count: output.ward_events.length,
      heatmap_count: output.ward_heatmap_input.length,
      lifecycle_count: output.ward_lifecycles.length,
      spawn_match_count: output.ward_cast_spawn_matches.length,
      direct_spawn_event_count: output.ward_events.filter(
        (row) => row.position_source === 'ENTITY_SPAWN_DIRECT',
      ).length,
      status: output.status,
    });
  }
  candidates.sort((a, b) => (a.replay_sha256 || '').localeCompare(b.replay_sha256 || '')
    || (a.timestamp_ms ?? 0) - (b.timestamp_ms ?? 0));
  events.sort((a, b) => (a.replay_sha256 || '').localeCompare(b.replay_sha256 || '')
    || (a.timestamp_ms ?? 0) - (b.timestamp_ms ?? 0));
  heatmap.sort((a, b) => (a.replay_sha256 || '').localeCompare(b.replay_sha256 || '')
    || (a.timestamp ?? 0) - (b.timestamp ?? 0));

  const timelineDocument = fs.existsSync(options.timeline)
    ? JSON.parse(fs.readFileSync(options.timeline, 'utf8')) : null;
  const timelineEvents = flattenTimeline(timelineDocument);
  const holdoutSha = (JSON.parse(fs.readFileSync(options.manifest, 'utf8')).replays ?? [])
    .find((row) => row.sample_role === 'FROZEN_BLIND_HOLDOUT')?.replay_sha256;
  const holdoutCandidates = candidates.filter((candidate) => candidate.replay_sha256 === holdoutSha);
  const oracleMatches = matchTimelineOracle(holdoutCandidates, timelineEvents);
  const matchedDeltas = oracleMatches.filter((row) => row.delta_ms !== null).map((row) => row.delta_ms);
  const coordinateValidationCount = timelineEvents.filter(
    (event) => event.type === 'WARD_PLACED' && event.position
      && Number.isFinite(event.position.x) && Number.isFinite(event.position.y),
  ).length;
  const manifest = JSON.parse(fs.readFileSync(options.manifest, 'utf8'));
  const directSpawnEvents = events.filter(
    (event) => event.position_source === 'ENTITY_SPAWN_DIRECT',
  );
  const expected = wardDecodeSummary.counts;
  if (directSpawnEvents.length !== expected.cast_spawn_matches
      || spawnMatches.length !== expected.cast_spawn_matches
      || lifecycles.length !== expected.lifecycle_matches) {
    throw new Error(
      `integrated Ward counts disagree with full decode: events=${directSpawnEvents.length}, `
      + `matches=${spawnMatches.length}, lifecycles=${lifecycles.length}`,
    );
  }
  const reportSourceFiles = [
    ...sourceFiles.map((filePath) => ({ path: filePath, sha256: sha256File(filePath) })),
    { path: options.wardSpawns, sha256: wardSpawnInput.sha256 },
    { path: options.wardLifecycles, sha256: wardLifecycleInput.sha256 },
    { path: options.wardSummary, sha256: sha256File(options.wardSummary) },
  ];
  const report = {
    schema_version: 2,
    status: 'RESEARCH_READY_V2_COMPLETE',
    pipeline_status: 'WARD_SPAWN_POSITION_VERIFIED_DIRECT',
    generated_at_utc: new Date().toISOString(),
    replay_version: WARD_P0_PROFILE.replay_version,
    spell_event_source_file_count: sourceFiles.length,
    source_file_count: reportSourceFiles.length,
    replay_count: byReplay.size,
    counts: {
      ward_cast_candidates: candidates.length,
      ward_events: events.length,
      ward_events_entity_spawn_direct: directSpawnEvents.length,
      decoded_ward_spawns_all_types: expected.ward_spawns,
      ward_lifecycles: lifecycles.length,
      ward_cast_spawn_matches: spawnMatches.length,
      ward_heatmap_input: heatmap.length,
    },
    decoder_profile: wardDecodeSummary.profile,
    ward_type_counts: wardDecodeSummary.ward_type_counts,
    coordinate_policy: {
      cast_target_position: 'DIRECT_REPLAY_FIELD',
      cast_target_position_end: 'DIRECT_REPLAY_FIELD_VALIDATED_AS_PROXY_ONLY',
      actual_spawn_position: 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
      spawn_coordinate_source: 'packet 0x0353 object writes +0x18/+0x20 only',
      castspell_coordinates_are_decoder_inputs: false,
      coordinate_system: {
        map_name: 'SUMMONERS_RIFT',
        map_id: null,
        patch: WARD_P0_PROFILE.replay_version,
        raw_axis_mapping: {
          x: 'WardSpawn.object.position_x (+0x18)',
          y: 'WardSpawn.object.position_y (+0x20)',
          vertical: 'WardSpawn.object.position_height (+0x1c)',
        },
        castspell_validation_axis_mapping: {
          target_position_planar: 'CastSpell.target_position.x/z',
          target_position_end_planar: 'CastSpell.target_position_end.x/z',
          vertical: 'CastSpell target vector .y',
        },
        castspell_coordinates_are_decoder_inputs: false,
        transform: 'NONE_RAW_REPLAY_ORIENTATION',
        bounds_status: 'CANONICAL_BOUNDS_UNVERIFIED',
        normalized_coordinates: 'NOT_EMITTED',
      },
      timeline_position_rows: coordinateValidationCount,
      cast_to_spawn_validation_count: spawnMatches.length,
      timestamp_delta_ms: wardDecodeSummary.timestamp_delta_ms,
      error_to_target_position: wardDecodeSummary
        .coordinate_euclidean_error_start_like_target_position,
      error_to_target_position_end: wardDecodeSummary
        .coordinate_euclidean_error_end_like_target_position_end,
      proxy_decision: wardDecodeSummary.proxy_decision,
      position_source_allowed: ['CAST_TARGET_DIRECT', 'ENTITY_SPAWN_DIRECT', 'DERIVED_MATCHED'],
    },
    holdout_oracle: {
      holdout_sha256: holdoutSha ?? null,
      yellow_cast_count: holdoutCandidates.length,
      timeline_yellow_placed_count: timelineEvents.filter(
        (event) => event.type === 'WARD_PLACED' && event.wardType === 'YELLOW_TRINKET',
      ).length,
      cast_timeline_owner_type_matches: matchedDeltas.length,
      unmatched_cast_count: oracleMatches.filter((row) => row.delta_ms === null).length,
      delta_ms: {
        min: matchedDeltas.length ? Math.min(...matchedDeltas) : null,
        max: matchedDeltas.length ? Math.max(...matchedDeltas) : null,
        p50: percentile(matchedDeltas, 0.5),
        p95: percentile(matchedDeltas, 0.95),
      },
      use: 'VALIDATION_ORACLE_ONLY; timeline did not provide coordinates and was not used to populate event positions.',
    },
    per_replay: perReplay,
    source_files: reportSourceFiles,
    field_boundaries: {
      spawn_timestamp_owner_entity_id_name_position: 'VERIFIED_DIRECT',
      owner_participant_and_team: 'VERIFIED_DERIVED_FROM_MATCHED_CASTSPELL',
      lifecycle_remove_time_and_duration: 'VERIFIED_DERIVED_FROM_CORPSE_ASSOCIATION',
      removal_reason_and_killer: 'UNAVAILABLE_BEYOND_CORPSE_PACKET_DERIVED',
    },
  };
  const outputDir = options.output;
  fs.mkdirSync(outputDir, { recursive: true });
  writeJsonl(path.join(outputDir, 'ward_cast_candidates.jsonl'), candidates);
  writeJsonl(path.join(outputDir, 'ward_events.jsonl'), events);
  writeWardEventsCsv(path.join(outputDir, 'ward_events.csv'), events);
  writeJsonl(path.join(outputDir, 'ward_lifecycles.jsonl'), lifecycles);
  writeJsonl(path.join(outputDir, 'ward_cast_spawn_matches.jsonl'), spawnMatches);
  writeJsonl(path.join(outputDir, 'ward_heatmap_input.jsonl'), heatmap);
  writeHeatmapCsv(path.join(outputDir, 'ward_heatmap_input.csv'), heatmap);
  writeJsonl(path.join(outputDir, 'ward_timeline_oracle_matches.jsonl'), oracleMatches);
  writeJson(path.join(outputDir, 'ward_spell_inventory.json'), buildSpellInventory(
    [...byReplay.values()].flatMap((replay) => replay.spell_events),
    sourceFiles,
    wardDecodeSummary.ward_type_counts,
  ));
  writeJson(path.join(outputDir, 'V2_HOLDOUT_STATUS.json'), holdoutStatus(manifest, sourceFiles));
  writeJson(path.join(outputDir, 'ward_validation_report.json'), report);
  process.stdout.write(`${JSON.stringify({
    output_dir: outputDir,
    replay_count: byReplay.size,
    ward_cast_candidates: candidates.length,
    holdout_oracle_matches: matchedDeltas.length,
    cast_to_spawn_validation_count: spawnMatches.length,
    lifecycle_count: lifecycles.length,
    status: report.status,
  }, null, 2)}\n`);
  return report;
}

if (require.main === module) main();

module.exports = {
  parseArgs,
  matchTimelineOracle,
  buildSpellInventory,
  holdoutStatus,
  main,
};
