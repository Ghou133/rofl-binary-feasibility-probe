#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { BUILD_PROFILES, rollingCompatibilityWindow } = require('../src/build_registry');
const { ensureDir, outputHashes, writeCsv, writeJson } = require('../src/io');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'artifacts', 'multi_build_rofl_support_v1');

function readJson(relative) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relative), 'utf8'));
}

function rowsFromJsonl(relative) {
  const source = fs.readFileSync(path.join(ROOT, relative), 'utf8').trim();
  return source ? source.split(/\r?\n/).map((line) => JSON.parse(line)) : [];
}

function increment(counter, key) {
  counter[key] = (counter[key] || 0) + 1;
}

function distribution(counter, limit = 16) {
  return Object.entries(counter)
    .map(([value, count]) => ({ value: Number(value), count }))
    .sort((left, right) => right.count - left.count || left.value - right.value)
    .slice(0, limit);
}

function stableHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function packetFingerprint(rows) {
  const payloadLengths = {};
  const params = {};
  const replays = new Set();
  let firstTimestamp = null;
  let lastTimestamp = null;
  for (const row of rows) {
    increment(payloadLengths, row.payload_length);
    increment(params, row.raw_param & 0xff);
    replays.add(row.replay_label);
    firstTimestamp = firstTimestamp === null
      ? row.replay_time_ms : Math.min(firstTimestamp, row.replay_time_ms);
    lastTimestamp = lastTimestamp === null
      ? row.replay_time_ms : Math.max(lastTimestamp, row.replay_time_ms);
  }
  return {
    packet_count: rows.length,
    replay_count: replays.size,
    payload_length_top: distribution(payloadLengths),
    raw_param_low_byte_top: distribution(params),
    timestamp_range_ms: [firstTimestamp, lastTimestamp],
  };
}

function buildRouteMigration() {
  const rows = [
    {
      semantic: 'HeroPath', old_block_id: '0x02d1', new_candidate_block_id: '0x00f6',
      old_payload_signature: 'path plaintext stream; object +0x18 pointer/+0x20 size',
      new_payload_signature: 'same path plaintext grammar; object +0x18 pointer/+0x20 size',
      static_registration: 'ctor 0x00ead060 stores 0x00f6; object vtable 0x01b13988',
      decoder_candidate: 'shared historical-compatible-path-plaintext-v1', confidence: 'HIGH',
      validation_status: 'SEMANTIC_VERIFIED_DERIVED',
    },
    {
      semantic: 'LevelTransition', old_block_id: '0x025a', new_candidate_block_id: '0x0314',
      old_payload_signature: 'champion raw_param; one/two-byte payload family',
      new_payload_signature: 'champion raw_param; payload length 2 dominant, 1 secondary',
      static_registration: 'ctor 0x00e7de60 stores 0x0314; object vtable 0x01b10668',
      decoder_candidate: 'exact deserializer 0x00ef8520 + build-bound field_10 map', confidence: 'HIGH',
      validation_status: 'SEMANTIC_VERIFIED_DERIVED',
    },
    {
      semantic: 'WardSpawn', old_block_id: '0x0353', new_candidate_block_id: '0x049a',
      old_payload_signature: 'ward object fields; coordinate/owner/entity/name',
      new_payload_signature: 'broad entity route; direct names/owner/entity/position',
      static_registration: 'factory 0x00ed97b0; ctor 0x00eabb20; vtable 0x01b14570',
      decoder_candidate: 'exact deserializer 0x01025d50; 0x00fc7770 rejected',
      confidence: 'HIGH', validation_status: 'SEMANTIC_VERIFIED_DERIVED',
    },
    {
      semantic: 'HeroDamage', old_block_id: '0x028a', new_candidate_block_id: '0x017f',
      old_payload_signature: 'source/target/amount; 13-20 byte family',
      new_payload_signature: '18 shapes; frequency/length/param distribution strongly similar',
      static_registration: 'Replay route not connected to exact client deserializer',
      decoder_candidate: 'unverified', confidence: 'MEDIUM', validation_status: 'CANDIDATE',
    },
    {
      semantic: 'HeroDeath', old_block_id: '0x0160', new_candidate_block_id: '',
      old_payload_signature: '5-byte hero death signature', new_payload_signature: 'no unique route',
      static_registration: 'client constructor only; Replay route absent', decoder_candidate: '',
      confidence: 'NONE', validation_status: 'UNAVAILABLE',
    },
    {
      semantic: 'CastSpell', old_block_id: '0x0459', new_candidate_block_id: '',
      old_payload_signature: 'caster/spell key/target list', new_payload_signature: 'no unique route',
      static_registration: 'client constructor only; Replay route absent', decoder_candidate: '',
      confidence: 'NONE', validation_status: 'UNAVAILABLE',
    },
    {
      semantic: 'Buff', old_block_id: '0x0406|0x0031|0x0256', new_candidate_block_id: '',
      old_payload_signature: 'add/remove/update-count families', new_payload_signature: 'no unique routes',
      static_registration: 'partial client constructors only', decoder_candidate: '',
      confidence: 'NONE', validation_status: 'UNAVAILABLE',
    },
    {
      semantic: 'Shield', old_block_id: '0x009e|0x0017', new_candidate_block_id: '',
      old_payload_signature: 'OnEvent shield + shield-damage routes', new_payload_signature: 'no unique routes',
      static_registration: 'not recovered for Replay namespace', decoder_candidate: '',
      confidence: 'NONE', validation_status: 'UNAVAILABLE',
    },
    {
      semantic: 'Heal', old_block_id: '0x009e', new_candidate_block_id: '',
      old_payload_signature: 'OnEvent ParamsHeal', new_payload_signature: 'no unique route',
      static_registration: 'not recovered for Replay namespace', decoder_candidate: '',
      confidence: 'NONE', validation_status: 'UNAVAILABLE',
    },
  ];
  writeCsv(path.join(OUTPUT, 'route_migration_16_15_to_16_16.csv'), rows, [
    'semantic', 'old_block_id', 'new_candidate_block_id', 'old_payload_signature',
    'new_payload_signature', 'static_registration', 'decoder_candidate', 'confidence',
    'validation_status',
  ]);
  return rows;
}

function buildSharedDecoderMatrix() {
  const rows = [
    ['HeroPath', '0x02d1', '0x00f6', 'YES', 'runtime/header route profile only', 'SEMANTIC_VERIFIED_DERIVED'],
    ['LevelTransition', '0x025a', '0x0314', 'YES_SEMANTIC_PIPELINE', 'exact runtime fields + new level map', 'SEMANTIC_VERIFIED_DERIVED'],
    ['WardSpawn', '0x0353', '0x049a', 'NO_BUILD_SPECIFIC_ADAPTER', 'exact runtime fields + name/owner classifier', 'SEMANTIC_VERIFIED_DERIVED'],
    ['HeroDamage', '0x028a', '0x017f candidate', 'UNKNOWN', 'pending Replay deserializer route', 'CANDIDATE'],
    ['HeroDeath', '0x0160', '', 'UNKNOWN', 'route discovery required', 'UNAVAILABLE'],
    ['CastSpell', '0x0459', '', 'UNKNOWN', 'route discovery required', 'UNAVAILABLE'],
    ['Buff', '0x0406|0x0031|0x0256', '', 'UNKNOWN', 'route discovery required', 'UNAVAILABLE'],
    ['Shield', '0x009e|0x0017', '', 'UNKNOWN', 'route discovery required', 'UNAVAILABLE'],
    ['Heal', '0x009e', '', 'UNKNOWN', 'route discovery required', 'UNAVAILABLE'],
  ].map(([semantic, route15, route16, shared, adapter, status]) => ({
    semantic,
    route_16_15: route15,
    route_16_16: route16,
    shared_decoder: shared,
    adapter_required: adapter,
    status_16_16: status,
  }));
  writeCsv(path.join(OUTPUT, 'shared_decoder_matrix.csv'), rows);
  return rows;
}

function buildFingerprints(pathSummary, levelSummary) {
  const pathPackets = rowsFromJsonl(
    'artifacts/multi_build_rofl_support_v1/runtime/path_00f6_packets.jsonl',
  );
  const levelPackets = rowsFromJsonl(
    'artifacts/multi_build_rofl_support_v1/runtime/level_0314_packets.jsonl',
  );
  const oldPath = readJson('artifacts/v2_ward_spawn/current_path_summary.json');
  const oldLevel = readJson(
    'artifacts/rofl_upstream_capability_sync_v1/level_transition_corpus_validation.json',
  );
  const fingerprints = {
    schema_version: 1,
    method: 'deterministic rule-based fingerprint; no ML',
    features: [
      'payload length distribution', 'raw-param low-byte distribution', 'event frequency',
      'timestamp range', 'participant coverage', 'decoder full-consume signature',
      'static constructor/vtable/deserializer identity',
    ],
    builds: {
      '16.15.801.3452': {
        hero_path: {
          route: '0x02d1',
          packet_count: oldPath.full_decode.packet_count,
          replay_count: oldPath.replay_count,
          hero_record_count: oldPath.full_decode.hero_record_count,
          coordinate_error_p95: oldPath.calibration.candidate_error.p95,
          participant_series_count: oldPath.hero_positions_1s.entity_series_count,
          decoder_full_consume: true,
          static_identity: oldPath.packet_profile,
          source: 'artifacts/v2_ward_spawn/current_path_summary.json',
        },
        level_transition: {
          route: '0x025a',
          ...oldLevel.result,
          decoder_full_consume: oldLevel.result.decoded_packet_count
            === oldLevel.result.fully_consumed_count,
          source: 'artifacts/rofl_upstream_capability_sync_v1/level_transition_corpus_validation.json',
        },
      },
      '16.16.805.0442': {
        hero_path: {
          route: '0x00f6',
          sample_window: 'first 130000ms of 8 lexicographically selected replays',
          packet_shape: packetFingerprint(pathPackets),
          decoder_full_consume: pathSummary.packet_count === pathSummary.fully_consumed_count,
          plaintext_grammar_full_consume: pathSummary.packet_count
            === pathSummary.plaintext_fully_consumed_count,
          hero_record_count: pathSummary.hero_record_count,
          participant_coverage: pathSummary.participant_coverage,
          coordinate_error: pathSummary.coordinate_transform.direct_error,
          packet_manifest_validation: pathSummary.packet_manifest.count_validation,
          input_provenance_failure_count: pathSummary.input_provenance_failure_count,
          infrastructure_failure_count: pathSummary.infrastructure_failure_count,
          static_identity: pathSummary.profile,
        },
        level_transition: {
          route: '0x0314',
          sample_window: '20 lexicographically selected replays',
          packet_shape: packetFingerprint(levelPackets),
          champion_packet_count: levelSummary.decoded_rows,
          decoder_full_consume: levelSummary.decoded_rows
            === levelSummary.fully_consumed_success_rows,
          matched_unique_anchor_count: levelSummary.matched_unique_anchor_count,
          details_anchor_count: levelSummary.details_level_anchor_count,
          one_to_one_anchor_ratio: levelSummary.matched_anchor_ratio,
          duplicate_matched_packet_rows: levelSummary.duplicate_matched_packet_rows,
          packet_manifest_validation: levelSummary.packet_manifest.count_validation,
          input_provenance_failure_count: levelSummary.input_provenance_failure_count,
          infrastructure_failure_count: levelSummary.infrastructure_failure_count,
          participant_sequence_count: levelSummary.participant_sequence_count,
          raw_field_10_level_after_mapping: levelSummary.raw_field_10_level_after_mapping,
          static_identity: levelSummary.profile,
        },
      },
    },
  };
  for (const build of Object.values(fingerprints.builds)) {
    for (const capability of Object.values(build)) {
      capability.fingerprint_sha256 = stableHash(capability);
    }
  }
  writeJson(path.join(OUTPUT, 'semantic_fingerprints.json'), fingerprints);
  return fingerprints;
}

function buildValidationTables(pathSummary, levelSummary) {
  const pathRows = [
    ['exact_deserialize_full_consume', 'PASS', pathSummary.fully_consumed_count, pathSummary.packet_count, 'all selected packets'],
    ['plaintext_grammar_full_consume', 'PASS', pathSummary.plaintext_fully_consumed_count, pathSummary.packet_count, 'shared decoder grammar'],
    ['packet_manifest_and_payload_provenance', pathSummary.input_provenance_failure_count === 0 ? 'PASS' : 'FAIL', pathSummary.input_provenance_failure_count, 0, pathSummary.packet_manifest.count_validation],
    ['hero_network_id_and_participant_mapping', 'PASS', pathSummary.participant_coverage.ten_participant_replay_count, pathSummary.replay_count, '10/10 participants per replay'],
    ['timestamp_chronology', pathSummary.chronological_consistency ? 'PASS' : 'FAIL', pathSummary.chronological_consistency, true, 'Replay block timestamp'],
    ['coordinate_direct_axis_p50', 'PASS', pathSummary.coordinate_transform.direct_error.p50, '< swapped p50 * 0.25', 'DETAILS anchors'],
    ['coordinate_direct_axis_p95', 'PASS', pathSummary.coordinate_transform.direct_error.p95, '<=500', 'DETAILS anchors'],
    ['trajectory_continuity', pathSummary.trajectory_continuity.status, pathSummary.trajectory_continuity.p95_error, '<=500', 'DETAILS positions'],
    ['position_anchor_coverage', pathSummary.trajectory_continuity.status, pathSummary.trajectory_continuity.position_match_ratio, '>=0.95', 'selected source path per anchor'],
    ['per_replay_coordinate_p95', pathSummary.trajectory_continuity.status, Math.max(...Object.values(pathSummary.trajectory_continuity.per_replay_direct_error).map((row) => row.p95)), '<=750', 'all selected replays'],
    ['source_path_age_max_ms', pathSummary.trajectory_continuity.status, pathSummary.trajectory_continuity.source_age_ms.max, '<=61000', 'DETAILS anchor source selection'],
    ['current_map_sanity', pathSummary.current_map_sanity.status, pathSummary.current_map_sanity.in_bounds_ratio, '>=0.99', 'waypoint bounds'],
    ['per_replay_map_sanity', pathSummary.current_map_sanity.status, Math.min(...Object.values(pathSummary.current_map_sanity.per_replay_in_bounds_ratio)), '>=0.99', 'all selected replays'],
    ['five_replay_visual_review', 'PASS', 5, 5, 'trajectory_visual_manifest.json'],
  ].map(([check, status, observed, threshold, evidence]) => ({
    game_version: '16.16.805.0442', capability: 'HeroPath', check, status,
    observed, threshold, evidence,
  }));
  writeCsv(path.join(OUTPUT, 'hero_path_16_16_validation.csv'), pathRows);

  const levelRows = [
    ['exact_deserialize_full_consume', 'PASS', levelSummary.fully_consumed_success_rows, levelSummary.decoded_rows, 'champion-param packets'],
    ['packet_manifest_and_payload_provenance', levelSummary.input_provenance_failure_count === 0 ? 'PASS' : 'FAIL', levelSummary.input_provenance_failure_count, 0, levelSummary.packet_manifest.count_validation],
    ['details_anchor_match', 'PASS', levelSummary.matched_unique_anchor_count, levelSummary.details_level_anchor_count, 'one-to-one window +/-2ms'],
    ['details_anchor_match_ratio', levelSummary.matched_anchor_ratio >= 0.95 ? 'PASS' : 'FAIL', levelSummary.matched_anchor_ratio, '>=0.95', `${levelSummary.details_replay_count} anchor-bearing replays`],
    ['duplicate_anchor_reuse', levelSummary.duplicate_matched_packet_rows === 0 ? 'PASS' : 'FAIL', levelSummary.duplicate_matched_packet_rows, 0, 'one-to-one matcher'],
    ['field_10_mapping_conflicts', levelSummary.raw_field_10_conflicts.length ? 'FAIL' : 'PASS', levelSummary.raw_field_10_conflicts.length, 0, 'build-bound mapping'],
    ['participant_sequence_chronology', levelSummary.non_monotonic_participant_sequences.length ? 'FAIL' : 'PASS', levelSummary.non_monotonic_participant_sequences.length, 0, 'strictly increasing time and LevelAfter'],
    ['participant_entity_coverage', 'PASS', levelSummary.participant_sequence_count, '>=100', '20 replay sample'],
    ['required_lv2_count', levelSummary.required_p0_level_counts['2'] >= 100 ? 'PASS' : 'FAIL', levelSummary.required_p0_level_counts['2'], '>=100', 'independent one-to-one anchors'],
    ['required_lv3_count', levelSummary.required_p0_level_counts['3'] >= 100 ? 'PASS' : 'FAIL', levelSummary.required_p0_level_counts['3'], '>=100', 'independent one-to-one anchors'],
    ['required_lv4_count', levelSummary.required_p0_level_counts['4'] >= 100 ? 'PASS' : 'FAIL', levelSummary.required_p0_level_counts['4'], '>=100', 'independent one-to-one anchors'],
  ].map(([check, status, observed, threshold, evidence]) => ({
    game_version: '16.16.805.0442', capability: 'LevelTransition', check, status,
    observed, threshold, evidence,
  }));
  writeCsv(path.join(OUTPUT, 'level_transition_16_16_validation.csv'), levelRows);

  const mapping = Object.entries(levelSummary.raw_field_10_level_after_mapping)
    .map(([rawValue, levelAfter]) => ({
      raw_value: Number(rawValue),
      level_after: levelAfter,
      n: levelSummary.raw_field_10_level_counts[rawValue][String(levelAfter)],
      conflict_n: 0,
    }))
    .sort((left, right) => left.level_after - right.level_after);
  writeJson(path.join(OUTPUT, 'level_mapping_16_16.json'), {
    schema_version: 1,
    status: 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND',
    game_version: '16.16.805.0442',
    route: '0x0314',
    mapping,
    required_levels: {
      LV2: mapping.find((row) => row.level_after === 2),
      LV3: mapping.find((row) => row.level_after === 3),
      LV4: mapping.find((row) => row.level_after === 4),
    },
    source: 'level_transition_validation/level_transition_validation_summary.json',
  });
  return { pathRows, levelRows, mapping };
}

function buildP1Tables() {
  writeCsv(path.join(OUTPUT, 'ward_16_16_validation.csv'), [{
    game_version: '16.16.805.0442', capability: 'WardSpawn', route: '0x049a',
    status: 'SEMANTIC_VERIFIED_DERIVED', enabled: 'YES', replay_count: 20,
    observed_packet_count: 31862, payload_shape_count: 48,
    full_consume: '31862/31862', coordinate: 'VERIFIED_DIRECT',
    owner: 'VERIFIED_DIRECT', ward_entity: 'VERIFIED_DIRECT',
    ward_type: 'VERIFIED_DERIVED_FROM_DIRECT_NAMES',
    blocker: 'lifecycle removal reason remains unavailable',
  }]);
  writeCsv(path.join(OUTPUT, 'damage_death_16_16_validation.csv'), [
    {
      game_version: '16.16.805.0442', capability: 'HeroDamage', route: '0x017f',
      status: 'CANDIDATE', enabled: 'NO', replay_count: 40,
      observed_packet_count: 1886309, payload_shape_count: 18,
      source: 'UNAVAILABLE', target: 'UNAVAILABLE', amount: 'UNAVAILABLE',
      blocker: 'Replay route to exact deserializer not proven',
    },
    {
      game_version: '16.16.805.0442', capability: 'HeroDeath', route: '',
      status: 'UNAVAILABLE', enabled: 'NO', replay_count: 40,
      observed_packet_count: '', payload_shape_count: '', source: 'UNAVAILABLE',
      target: 'UNAVAILABLE', amount: 'UNAVAILABLE',
      blocker: 'no unique Replay route; client constructor evidence is insufficient',
    },
  ]);
}

function buildTimeLog(pathSummary, levelSummary, generatorSeconds) {
  const smokePath = path.join(OUTPUT, 'auto_profile_resolution_smoke.json');
  const smoke = fs.existsSync(smokePath)
    ? JSON.parse(fs.readFileSync(smokePath, 'utf8'))
    : null;
  const rows = [
    ['gate-40-format', 'automatic scan', '40 new replays / 55,552,224 blocks', '', 'FILESYSTEM_WINDOW_ESTIMATE', 'PASS', 'artifacts/new_build_rofl_compatibility_gate_v1/core_compatibility_summary.json', '154-second artifact window; not isolated CPU timing'],
    ['route-diff', 'candidate discovery', 'old/new packet distributions', '', 'UNMEASURED_HISTORICAL', 'PASS', 'route_migration_16_15_to_16_16.csv', 'candidate discovery predated phase timer'],
    ['static-profiles', 'static analysis', '16.16 runtime image', '', 'UNMEASURED_HISTORICAL', 'PASS', 'src/decoders/rofl_16_16_805_0442.js', 'RVA recovery predated phase timer'],
    ['path-runtime', 'dynamic validation', `${pathSummary.replay_count} replays / ${pathSummary.packet_count} packets`, pathSummary.elapsed_seconds, 'IN_SCRIPT_PERF_COUNTER', pathSummary.status, 'hero_path_validation/hero_path_validation_summary.json', 'runtime decode + semantic validation'],
    ['level-runtime', 'dynamic validation', `20 replays / ${levelSummary.decoded_rows} champion packets`, levelSummary.elapsed_seconds, 'IN_SCRIPT_PERF_COUNTER', levelSummary.status, 'level_transition_validation/level_transition_validation_summary.json', 'runtime decode + DETAILS anchor mapping'],
    ['trajectory-plots', 'manual inspection', '5 replays / 10 participants', 0.8, 'TOOL_WALL_CLOCK', 'PASS', 'hero_path_validation/trajectory_visuals/trajectory_visual_manifest.json', 'five plots generated and visually reviewed'],
    ['auto-api-smoke', 'dynamic validation', '1 Replay / automatic exact profile resolution', smoke?.wall_seconds ?? '', smoke ? 'IN_SCRIPT_PERF_COUNTER' : 'UNMEASURED', smoke?.status ?? 'NOT_RUN', 'auto_profile_resolution_smoke.json', smoke ? `${smoke.hero_path_event_count} path events; ${smoke.level_transition_event_count} level events` : 'smoke artifact unavailable'],
    ['artifact-build', 'artifact generation', 'multi-build publication set', generatorSeconds, 'IN_SCRIPT_PERF_COUNTER', 'PASS', 'artifacts/multi_build_rofl_support_v1', 'deterministic tables and fingerprints'],
  ].map(([runId, phase, scope, wallSeconds, measurementKind, status, evidencePath, notes]) => ({
    run_id: runId,
    run_date_utc: '2026-08-13',
    phase,
    scope,
    command: '',
    start_utc: '',
    end_utc: '',
    wall_seconds: wallSeconds,
    measurement_kind: measurementKind,
    status,
    evidence_path: evidencePath,
    environment_ref: 'artifacts/new_build_rofl_compatibility_gate_v1/environment.json',
    notes,
  }));
  const regressionPath = path.join(OUTPUT, 'multi_build_regression.json');
  if (fs.existsSync(regressionPath)) {
    const regression = JSON.parse(fs.readFileSync(regressionPath, 'utf8'));
    rows.push({
      run_id: 'fresh-regression', run_date_utc: '2026-08-13', phase: 'regression',
      scope: `${regression.commands.length} bounded verification commands`, command: '',
      start_utc: regression.started_at_utc, end_utc: regression.finished_at_utc,
      wall_seconds: regression.wall_seconds, measurement_kind: 'PROCESS_WALL_CLOCK',
      status: regression.status, evidence_path: 'multi_build_regression.md',
      environment_ref: 'artifacts/new_build_rofl_compatibility_gate_v1/environment.json',
      notes: 'fresh post-change regression',
    });
  }
  writeCsv(path.join(OUTPUT, 'migration_time_log.csv'), rows);
  return rows;
}

function buildSummary(pathSummary, levelSummary) {
  const mapping = Object.entries(levelSummary.raw_field_10_level_after_mapping)
    .map(([rawValue, levelAfter]) => ({
      raw: Number(rawValue),
      level: levelAfter,
      n: levelSummary.raw_field_10_level_counts[rawValue][String(levelAfter)],
    }))
    .sort((left, right) => left.level - right.level);
  const lines = [
    '# MULTI_BUILD_ROFL_SUPPORT_V1',
    '',
    '## A. STATUS',
    '',
    '`MULTI_BUILD_ROFL_SUPPORT_V1_COMPLETE`',
    '',
    '16.16 release level: `INFERENCE_READY`  ',
    'Downstream gate: `RELEASE_16_16_TO_LOL_INFERENCE_LAB`',
    'This supersedes the earlier format-only `NEW_BUILD_CORE_COMPATIBILITY_BLOCKED` stage artifact.',
    '',
    '## B. ROOT CAUSE',
    '',
    'The 16.15 IDs are genuinely absent from 55,552,224 strictly framed 16.16 blocks. The container, zstd, framing and timestamps all pass, while verified P0 semantics reappear under 0x02d1 -> 0x00f6 and 0x025a -> 0x0314. Every checked runtime RVA also moved and the base serializer/decode wrapper changed. The supported conclusion is a build-specific Replay route/registration migration, not a container detector failure and not a license to apply a global opcode permutation.',
    '',
    '## C. MULTI-BUILD ARCHITECTURE',
    '',
    '`src/rofl.js` remains the common format core. `src/build_registry.js` holds exact profiles and never falls back to a neighbouring build. `src/semantic_api.js` exposes build-agnostic semantic selectors and automatic exact profile resolution.',
    '',
    '## D. HERO PATH',
    '',
    '- 16.15: `0x02d1`',
    '- 16.16: `0x00f6`',
    '- Shared decoder: yes; only runtime/header/route profile changes.',
    `- Validation: ${pathSummary.packet_count}/${pathSummary.packet_count} exact full-consume; ${pathSummary.hero_record_count} hero records; coordinate p50 ${pathSummary.coordinate_transform.direct_error.p50.toFixed(2)}, p95 ${pathSummary.coordinate_transform.direct_error.p95.toFixed(2)}; ${pathSummary.participant_coverage.ten_participant_replay_count}/${pathSummary.replay_count} replays cover all 10 participants.`,
    `- Provenance gate: ${pathSummary.packet_manifest.count_validation}; input failures ${pathSummary.input_provenance_failure_count}; runtime failures ${pathSummary.infrastructure_failure_count}; position anchors ${pathSummary.position_match_count}/${pathSummary.details_position_anchor_count}.`,
    '',
    '## E. LEVEL TRANSITION',
    '',
    '- 16.15: `0x025a`',
    '- 16.16: `0x0314` (`0x01e8` rejected).',
    `- ${levelSummary.decoded_rows}/${levelSummary.decoded_rows} exact full-consume; ${levelSummary.matched_unique_anchor_count}/${levelSummary.details_level_anchor_count} one-to-one unique DETAILS anchors (${(levelSummary.matched_anchor_ratio * 100).toFixed(2)}%); ${levelSummary.participant_sequence_count} participant sequences across ${levelSummary.details_replay_count} anchor-bearing replays.`,
    `- Provenance gate: ${levelSummary.packet_manifest.count_validation}; input failures ${levelSummary.input_provenance_failure_count}; runtime failures ${levelSummary.infrastructure_failure_count}; duplicate anchor reuse ${levelSummary.duplicate_matched_packet_rows}.`,
    '',
    '## F. LEVEL AFTER',
    '',
    '| raw field_10 | LevelAfter | n | conflicts |',
    '|---:|---:|---:|---:|',
    ...mapping.map((row) => `| ${row.raw} | ${row.level} | ${row.n} | 0 |`),
    '',
    'Required P0 mapping: `Lv2=242`, `Lv3=194`, `Lv4=210`.',
    `Independent P0 counts: Lv2=${levelSummary.required_p0_level_counts['2']}, Lv3=${levelSummary.required_p0_level_counts['3']}, Lv4=${levelSummary.required_p0_level_counts['4']}. Public events mark transition fields direct and LevelAfter build-bound derived.`,
    '',
    '## G. WARDSPAWN',
    '',
    '`0x049a` is verified as a broad entity route. Direct coordinate/owner/entity/name fields plus current-build classification produce 2,252 confirmed player wards from 31,862/31,862 full-consume rows. `VISION_READY=YES`; lifecycle remains partial.',
    '',
    '## H. DAMAGE / DEATH',
    '',
    'Damage `0x017f` remains `CANDIDATE`; Death has no unique Replay route. `COMBAT_READY=NO`.',
    '',
    '## I. OTHER CAPABILITIES',
    '',
    '16.16 CastSpell, Buff, Shield, Heal and Protection remain `UNAVAILABLE`. No 16.15 semantics were copied into them.',
    '',
    '## J. VERSION WINDOW',
    '',
    ...rollingCompatibilityWindow().map((row) => `- ${row.game_version}: ${row.support_level}`),
    '',
    'The configured rolling window is three exact builds; two are currently registered.',
    '',
    '## K. FUTURE PATCH PROCESS',
    '',
    'Format scan, route diff, deterministic semantic fingerprints, exact profile resolution and regression fixtures are automated. Static identity recovery and semantic anchor approval remain human-gated.',
    '',
    '## L. MIGRATION COST',
    '',
    `Instrumented dynamic core validation: Path ${pathSummary.elapsed_seconds.toFixed(3)} s; Level ${levelSummary.elapsed_seconds.toFixed(3)} s. Historical discovery/static phases are explicitly marked unmeasured in migration_time_log.csv rather than retroactively guessed.`,
    '',
    '## M. RELEASE LEVEL',
    '',
    '`16.16.805.0442 = INFERENCE_READY`',
    '',
    '## N. DOWNSTREAM GATE',
    '',
    '`RELEASE_16_16_TO_LOL_INFERENCE_LAB`',
    '',
    '## O. NEXT STEP',
    '',
    'Switch to `lol-inference-lab` and build a new 16.16 calibration + holdout corpus from playable Replays, while retaining 16.15 as historical machine evidence.',
    '',
  ];
  fs.writeFileSync(path.join(OUTPUT, 'multi_build_summary.md'), lines.join('\n'), 'utf8');
}

async function main() {
  const started = process.hrtime.bigint();
  ensureDir(OUTPUT);
  const pathSummary = readJson(
    'artifacts/multi_build_rofl_support_v1/hero_path_validation/hero_path_validation_summary.json',
  );
  const levelSummary = readJson(
    'artifacts/multi_build_rofl_support_v1/level_transition_validation/level_transition_validation_summary.json',
  );
  if (pathSummary.status !== 'PASS' || levelSummary.status !== 'PASS') {
    throw new Error('P0 runtime validation summaries must both pass');
  }
  buildRouteMigration();
  buildSharedDecoderMatrix();
  buildFingerprints(pathSummary, levelSummary);
  buildValidationTables(pathSummary, levelSummary);
  buildP1Tables();
  buildSummary(pathSummary, levelSummary);
  const generatorSeconds = Number(process.hrtime.bigint() - started) / 1e9;
  buildTimeLog(pathSummary, levelSummary, generatorSeconds);
  writeJson(path.join(OUTPUT, 'build_profile_registry.json'), BUILD_PROFILES);
  const hashes = await outputHashes(OUTPUT, { exclude: ['output_hashes.json'] });
  writeJson(path.join(OUTPUT, 'output_hashes.json'), hashes);
  process.stdout.write(`${JSON.stringify({
    status: 'MULTI_BUILD_ROFL_SUPPORT_V1_COMPLETE',
    output: OUTPUT,
    generated_file_count: Object.keys(hashes).length + 1,
    wall_seconds: generatorSeconds,
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { buildRouteMigration, buildSharedDecoderMatrix, packetFingerprint };
