'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { importControlledCalibrationBatch } = require('./controlled_calibration');
const { alignControlledActions, expectedEntityNetworkId } = require('./controlled_action_alignment');
const { writeJson } = require('./io');
const { parseReplayFile, normalizePlayers } = require('./rofl');
const { decodeSemanticReplay } = require('./semantic_api');

const PROCESS_SCHEMA = 'CONTROLLED_REPLAY_CALIBRATION_RUN_V1';
const EXACT_BUILD_PATTERN = /^\d+\.\d+\.\d+\.\d+$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const P0_SEMANTICS = Object.freeze(['CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST']);

const ACTION_DEFINITIONS = Object.freeze({
  TAKE_ISOLATED_DAMAGE: { semantics: ['CURRENT_HP'], covers: ['TAKE_ISOLATED_DAMAGE'] },
  NATURAL_REGEN: { semantics: ['CURRENT_HP'], covers: ['NATURAL_REGEN'] },
  TAKE_ISOLATED_DAMAGE_THEN_NATURAL_REGEN: {
    semantics: ['CURRENT_HP'], covers: ['TAKE_ISOLATED_DAMAGE', 'NATURAL_REGEN'],
  },
  HEAL: { semantics: ['CURRENT_HP'], covers: ['HEAL'] },
  SHIELD: { semantics: ['CURRENT_HP'], covers: ['SHIELD'] },
  SHIELD_THEN_TAKE_ISOLATED_DAMAGE: {
    semantics: ['CURRENT_HP'], covers: ['SHIELD', 'TAKE_ISOLATED_DAMAGE'],
  },
  DEATH: { semantics: ['CURRENT_HP'], covers: ['DEATH'] },
  RESPAWN: { semantics: ['CURRENT_HP', 'MAX_HP'], covers: ['RESPAWN'] },
  LEVEL_UP: { semantics: [...P0_SEMANTICS], covers: ['LEVEL_UP'] },
  BUY_HP_ITEM: { semantics: ['CURRENT_HP', 'MAX_HP'], covers: ['BUY_HP_ITEM'], item_family: 'HP' },
  SELL_HP_ITEM: { semantics: ['CURRENT_HP', 'MAX_HP'], covers: ['SELL_HP_ITEM'], item_family: 'HP' },
  UNDO_HP_ITEM: { semantics: ['CURRENT_HP', 'MAX_HP'], covers: ['UNDO_HP_ITEM'], item_family: 'HP' },
  BUY_ARMOR_ITEM: { semantics: ['ARMOR'], covers: ['BUY_ARMOR_ITEM'], item_family: 'ARMOR' },
  SELL_ARMOR_ITEM: { semantics: ['ARMOR'], covers: ['SELL_ARMOR_ITEM'], item_family: 'ARMOR' },
  UNDO_ARMOR_ITEM: { semantics: ['ARMOR'], covers: ['UNDO_ARMOR_ITEM'], item_family: 'ARMOR' },
  BUY_MAGIC_RESIST_ITEM: { semantics: ['MAGIC_RESIST'], covers: ['BUY_MAGIC_RESIST_ITEM'], item_family: 'MAGIC_RESIST' },
  SELL_MAGIC_RESIST_ITEM: { semantics: ['MAGIC_RESIST'], covers: ['SELL_MAGIC_RESIST_ITEM'], item_family: 'MAGIC_RESIST' },
  UNDO_MAGIC_RESIST_ITEM: { semantics: ['MAGIC_RESIST'], covers: ['UNDO_MAGIC_RESIST_ITEM'], item_family: 'MAGIC_RESIST' },
});

const REQUIRED_ACTION_COVERAGE = Object.freeze([
  'TAKE_ISOLATED_DAMAGE', 'NATURAL_REGEN', 'HEAL', 'SHIELD', 'DEATH', 'RESPAWN', 'LEVEL_UP',
  'BUY_HP_ITEM', 'SELL_HP_ITEM', 'UNDO_HP_ITEM',
  'BUY_ARMOR_ITEM', 'SELL_ARMOR_ITEM', 'UNDO_ARMOR_ITEM',
  'BUY_MAGIC_RESIST_ITEM', 'SELL_MAGIC_RESIST_ITEM', 'UNDO_MAGIC_RESIST_ITEM',
]);

function fail(message) {
  throw new Error(`controlled replay calibration: ${message}`);
}

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function string(value, label) {
  if (typeof value !== 'string' || value.trim() === '') fail(`${label} must be a non-empty string`);
  return value.trim();
}

function assertNoProtectedReference(value, label = 'input') {
  const seen = new Set();
  function visit(candidate, location) {
    if (candidate == null) return;
    if (typeof candidate === 'string') {
      if (/jungle[_ -]?objective[_ -]?holdout|protected[_ -]?holdout|holdout/i.test(candidate)) {
        fail(`${location} references protected Holdout`);
      }
      return;
    }
    if (typeof candidate !== 'object' || seen.has(candidate)) return;
    seen.add(candidate);
    for (const [key, child] of Object.entries(candidate)) visit(child, `${location}.${key}`);
  }
  visit(value, label);
}

function exactBuild(value, label) {
  const result = string(value, label);
  if (!EXACT_BUILD_PATTERN.test(result)) fail(`${label} must be an exact build in N.N.N.N form`);
  return result;
}

function sha256(value, label) {
  const result = string(value, label).toLowerCase();
  if (!SHA256_PATTERN.test(result)) fail(`${label} must be a SHA-256 hex digest`);
  return result;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function contentHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

function parseTimestamp(value, label) {
  if (Number.isSafeInteger(value) && value >= 0) return value;
  const timestamp = string(value, label);
  const match = /^(\d{2,3}):([0-5]\d)$/.exec(timestamp);
  if (!match) fail(`${label} must be MM:SS or a non-negative integer timestamp_ms`);
  return (Number(match[1]) * 60 + Number(match[2])) * 1000;
}

function formatTimestamp(timestampMs) {
  const seconds = Math.floor(timestampMs / 1000);
  return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

function normalizeActionLog(rows, durationMs) {
  if (!Array.isArray(rows) || rows.length === 0) fail('action_log must contain explicit structured actions');
  let previous = -1;
  return rows.map((input, index) => {
    const row = object(input, `action_log[${index}]`);
    const action = string(row.action, `action_log[${index}].action`).toUpperCase();
    const definition = ACTION_DEFINITIONS[action];
    if (!definition) fail(`action_log[${index}].action is unknown: ${action}`);
    const timestampMs = parseTimestamp(
      row.timestamp_ms ?? row.time ?? row.timestamp,
      `action_log[${index}].time`,
    );
    if (timestampMs <= previous) fail(`action_log[${index}] is out of order or duplicates a timestamp`);
    if (timestampMs > durationMs) fail(`action_log[${index}] is outside Replay duration`);
    previous = timestampMs;
    const itemName = row.item_name == null ? null : string(row.item_name, `action_log[${index}].item_name`);
    if (definition.item_family && !itemName) fail(`action_log[${index}].item_name is required for ${action}`);
    return {
      schema_version: 'CONTROLLED_ACTION_ANCHOR_V1',
      anchor_id: `ACTION_${String(index + 1).padStart(3, '0')}_${action}`,
      ordinal: index + 1,
      timestamp_ms: timestampMs,
      timestamp_mm_ss: formatTimestamp(timestampMs),
      action,
      causal_control_only: true,
      scalar_ground_truth: false,
      covered_request_actions: definition.covers,
      expected_semantics_for_candidate_search: definition.semantics,
      item_family: definition.item_family ?? null,
      item_name: itemName,
      note: row.note == null ? null : string(row.note, `action_log[${index}].note`),
    };
  });
}

function replayDurationMs(replay) {
  const value = Number(replay?.tail?.metadata?.gameLength);
  if (!Number.isFinite(value) || value <= 0) fail('Replay metadata lacks a finite positive gameLength');
  return Math.round(value);
}

function validateChampion(replay, expectedChampion) {
  if (replay?.tail?.stats_parse_error) fail(`Replay stats metadata parse failed: ${replay.tail.stats_parse_error}`);
  const players = normalizePlayers(replay);
  const matches = players.filter((player) => String(player.champion ?? '').toLowerCase()
    === expectedChampion.toLowerCase());
  if (matches.length !== 1) {
    fail(`expected exactly one ${expectedChampion} champion metadata row; found ${matches.length}`);
  }
  return {
    expected_champion: expectedChampion,
    matched: true,
    metadata_index: matches[0].metadata_index,
    team_id: matches[0].team_id,
    role: matches[0].role,
    provenance: matches[0].provenance,
  };
}

function validateIndependentScalars(rows) {
  if (rows == null) return [];
  if (!Array.isArray(rows)) fail('independently_observed_scalar_values must be an array');
  return rows.map((input, index) => {
    const row = object(input, `independently_observed_scalar_values[${index}]`);
    const semantic = string(row.semantic, `independently_observed_scalar_values[${index}].semantic`).toUpperCase();
    if (!P0_SEMANTICS.includes(semantic)) fail(`independently_observed_scalar_values[${index}].semantic is not P0`);
    const observedValue = Number(row.observed_value);
    if (!Number.isFinite(observedValue)) fail(`independently_observed_scalar_values[${index}].observed_value must be finite`);
    return {
      semantic,
      observed_value: observedValue,
      timestamp_ms: parseTimestamp(row.timestamp_ms ?? row.time ?? row.timestamp,
        `independently_observed_scalar_values[${index}].time`),
      source: string(row.source, `independently_observed_scalar_values[${index}].source`),
      independently_observed: true,
    };
  });
}

function machineCases(anchors, replaySha, build, champion, windowMs) {
  const cases = [];
  for (const anchor of anchors) {
    for (const semantic of anchor.expected_semantics_for_candidate_search) {
      cases.push({
        schema_version: 'MACHINE_CALIBRATION_CASE_V1',
        case_id: `${anchor.anchor_id}:${semantic}`,
        replay_sha256: replaySha,
        exact_build: build,
        champion,
        action_anchor_id: anchor.anchor_id,
        action: anchor.action,
        semantic_candidate_target: semantic,
        before_timestamp_ms: Math.max(0, anchor.timestamp_ms - windowMs),
        action_timestamp_ms: anchor.timestamp_ms,
        after_timestamp_ms: anchor.timestamp_ms + windowMs,
        observed_value: null,
        ground_truth_status: 'NOT_INDEPENDENTLY_OBSERVED',
        automatic_promotion: 'FORBIDDEN',
      });
    }
  }
  return cases;
}

function summarizeDecode(decoded, build) {
  object(decoded, 'semantic decode result');
  const status = string(decoded.status, 'semantic decode result.status');
  if (/UNSUPPORTED|FALLBACK|BLOCKED|ERROR|FAIL/i.test(status)) fail(`semantic decode failed closed with status ${status}`);
  if (decoded.fallback_used === true || decoded.exact_build_match === false) fail('semantic decode reported fallback/non-exact build');
  const decodedBuild = decoded.game_version ?? decoded.profile?.game_version;
  if (decodedBuild !== build || (decoded.profile?.game_version && decoded.profile.game_version !== build)) {
    fail('semantic decode did not bind to the requested exact build');
  }
  const events = decoded.events && typeof decoded.events === 'object' ? decoded.events : {};
  const eventGroups = Object.fromEntries(Object.entries(events)
    .filter(([, value]) => Array.isArray(value))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, rows]) => [name, rows.length]));
  const eventCount = Object.values(eventGroups).reduce((sum, count) => sum + count, 0);
  return {
    schema_version: 'CONTROLLED_REPLAY_DECODE_SUMMARY_V1',
    status,
    exact_build: build,
    profile_exact_build_match: true,
    fallback_used: false,
    decoded_packet_count: Number(decoded.decoded_packet_count ?? 0),
    event_groups: eventGroups,
    event_group_count: Object.keys(eventGroups).length,
    event_count: eventCount,
    conservation: {
      event_group_sum: eventCount,
      event_count: eventCount,
      event_group_accounting_pass: true,
      decoded_packet_count_reported_separately: true,
    },
  };
}

function artifactRecord(filePath, runDirectory) {
  return {
    path: path.relative(runDirectory, filePath).replaceAll(path.sep, '/'),
    sha256: sha256File(filePath),
    byte_size: fs.statSync(filePath).size,
  };
}

function processControlledReplayCalibration(input, options = {}) {
  const spec = object(input, 'spec');
  assertNoProtectedReference(spec, 'spec');
  if (spec.allow_fallback === true || spec.directory_discovery === true) fail('fallback and directory discovery are forbidden');
  const replaySpec = object(spec.replay, 'spec.replay');
  const replayPath = path.resolve(string(replaySpec.path, 'spec.replay.path'));
  const expectedSha = sha256(replaySpec.expected_sha256, 'spec.replay.expected_sha256');
  const build = exactBuild(replaySpec.exact_build, 'spec.replay.exact_build');
  const champion = string(replaySpec.champion, 'spec.replay.champion');
  const outputDirectory = path.resolve(string(spec.output_directory, 'spec.output_directory'));
  assertNoProtectedReference([replayPath, outputDirectory], 'resolved paths');

  const deps = {
    parseReplayFile: options.parseReplayFile ?? parseReplayFile,
    importControlledCalibrationBatch: options.importControlledCalibrationBatch ?? importControlledCalibrationBatch,
    decodeSemanticReplay: options.decodeSemanticReplay ?? decodeSemanticReplay,
    sha256File: options.sha256File ?? sha256File,
  };
  const beforeSha = deps.sha256File(replayPath);
  if (beforeSha !== expectedSha) fail('Replay SHA-256 mismatch before processing');
  const replay = deps.parseReplayFile(replayPath);
  if (replay?.header?.version !== build) fail(`Replay build ${replay?.header?.version ?? 'missing'} does not equal ${build}`);
  if (replay.source_sha256 && replay.source_sha256 !== expectedSha) fail('parser Replay SHA-256 disagrees with expected hash');
  const championVerification = validateChampion(replay, champion);
  const durationMs = replayDurationMs(replay);
  const anchors = normalizeActionLog(spec.action_log, durationMs);
  const windowMs = Number(spec.machine_case_window_ms ?? 1000);
  if (!Number.isSafeInteger(windowMs) || windowMs <= 0) fail('machine_case_window_ms must be a positive integer');
  const requestId = string(spec.request_id ?? 'CALIBRATION_SET_A_HP_DEFENSE_V1', 'spec.request_id');
  const independentScalars = validateIndependentScalars(spec.independently_observed_scalar_values);
  for (const row of independentScalars) {
    if (row.timestamp_ms > durationMs) fail('independently observed scalar timestamp is outside Replay duration');
  }

  const actionLogObject = { schema_version: 'CONTROLLED_ACTION_LOG_V1', champion, exact_build: build, actions: anchors };
  const batch = deps.importControlledCalibrationBatch({
    files: [{ id: 'controlled_replay', kind: 'REPLAY', path: replayPath, expected_sha256: expectedSha,
      exact_build: build, source: { kind: 'USER_EXPLICIT_REPLAY_PATH' } }],
    objects: [{ id: 'controlled_action_log', kind: 'ACTION_LOG', object: actionLogObject,
      exact_build: build, source: { kind: 'USER_EXPLICIT_STRUCTURED_ACTION_LOG' }, hash: true }],
  });
  const decoded = options.decoded ?? deps.decodeSemanticReplay(replay, { allowFallback: false });
  const decodeSummary = summarizeDecode(decoded, build);
  const afterSha = deps.sha256File(replayPath);
  if (afterSha !== beforeSha) fail('Replay SHA-256 changed during processing');

  const runIdentity = {
    schema_version: PROCESS_SCHEMA, replay_sha256: expectedSha, exact_build: build,
    champion: champion.toLowerCase(), actions: anchors, independently_observed_scalar_values: independentScalars,
    machine_case_window_ms: windowMs, request_id: requestId,
  };
  const runId = `controlled-replay-${contentHash(runIdentity).slice(0, 24)}`;
  const runDirectory = path.join(outputDirectory, runId);
  const cases = machineCases(anchors, expectedSha, build, champion, windowMs)
    .map((row) => ({ ...row, after_timestamp_ms: Math.min(durationMs, row.after_timestamp_ms) }));
  const covered = [...new Set(anchors.flatMap((row) => row.covered_request_actions))].sort();
  const missing = REQUIRED_ACTION_COVERAGE.filter((action) => !covered.includes(action));
  const requestFulfillment = {
    schema_version: 'CONTROLLED_REPLAY_REQUEST_FULFILLMENT_V1',
    request_id: requestId,
    replay_and_action_log_status: missing.length === 0 ? 'FULFILLED' : 'PARTIAL',
    covered_actions: covered,
    missing_actions: missing,
    independently_observed_scalar_value_count: independentScalars.length,
    p0_promotion_status: independentScalars.length === 0
      ? 'BLOCKED_NO_INDEPENDENT_SCALAR_GROUND_TRUTH'
      : 'BLOCKED_PENDING_ORACLE_ALIGNMENT_AND_REGRESSION',
    next_step: independentScalars.length === 0
      ? 'TARGETED_MANUAL_UI_SCALAR_OBSERVATION_ONLY_AFTER_MACHINE_CANDIDATE_REVIEW'
      : 'ALIGN_INDEPENDENT_SCALARS_WITH_MACHINE_CANDIDATES_THEN_RUN_REGRESSION',
    action_labels_are_causal_controls_not_scalar_ground_truth: true,
    automatic_promotion: 'FORBIDDEN',
  };
  const intakeManifest = {
    schema_version: 'CONTROLLED_REPLAY_INTAKE_MANIFEST_V1', run_id: runId,
    directory_discovery: 'FORBIDDEN', fallback: 'FORBIDDEN', exact_build: build,
    replay: { path: replayPath, expected_sha256: expectedSha, before_sha256: beforeSha,
      after_sha256: afterSha, byte_size: fs.statSync(replayPath).size, duration_ms: durationMs },
    champion_verification: championVerification,
    controlled_batch: batch,
    conservation: {
      input_action_count: spec.action_log.length,
      normalized_action_anchor_count: anchors.length,
      action_count_conserved: spec.action_log.length === anchors.length,
      machine_case_count: cases.length,
      expected_machine_case_count: anchors.reduce((sum, row) => sum + row.expected_semantics_for_candidate_search.length, 0),
      machine_case_count_conserved: cases.length === anchors.reduce((sum, row) => sum + row.expected_semantics_for_candidate_search.length, 0),
    },
    protected_boundary: { enumerated: false, read: false, hashed: false, decoded: false, consumed: false },
  };
  const participantId = championVerification.metadata_index + 1;
  const actionSemanticAlignment = alignControlledActions(anchors, decoded, {
    window_ms: windowMs,
    participant_id: participantId,
    entity_network_id: expectedEntityNetworkId(participantId),
    champion,
    replay_sha256: expectedSha,
    exact_build: build,
  });

  fs.mkdirSync(runDirectory, { recursive: true });
  const outputValues = [
    ['intake_manifest.json', intakeManifest],
    ['action_anchors.json', { schema_version: 'CONTROLLED_ACTION_ANCHORS_V1', run_id: runId, anchors }],
    ['machine_calibration_cases.json', { schema_version: 'MACHINE_CALIBRATION_CASES_V1', run_id: runId, case_count: cases.length, cases }],
    ['decode_summary.json', { ...decodeSummary, run_id: runId }],
    ['action_semantic_alignment.json', { ...actionSemanticAlignment, run_id: runId }],
    ['request_fulfillment.json', { ...requestFulfillment, run_id: runId }],
  ];
  const paths = outputValues.map(([name, value]) => {
    const filePath = path.join(runDirectory, name);
    writeJson(filePath, value);
    return filePath;
  });
  const artifactManifest = {
    schema_version: 'CONTROLLED_REPLAY_ARTIFACT_MANIFEST_V1', run_id: runId,
    generated_at_omitted_for_reproducibility: true,
    artifacts: paths.map((filePath) => artifactRecord(filePath, runDirectory)),
  };
  const artifactManifestPath = path.join(runDirectory, 'artifact_manifest.json');
  writeJson(artifactManifestPath, artifactManifest);
  return {
    schema_version: PROCESS_SCHEMA, run_id: runId, status: 'PROCESSED_EXACT_BUILD', exact_build: build,
    replay_sha256: expectedSha, output_directory: runDirectory, artifact_manifest: artifactManifestPath,
    action_anchor_count: anchors.length, machine_calibration_case_count: cases.length,
    action_semantic_alignment_status: actionSemanticAlignment.alignment_status,
    matched_direct_typed_action_step_count: actionSemanticAlignment.matched_direct_typed_step_count,
    unresolved_action_step_count: actionSemanticAlignment.unresolved_step_count,
    request_fulfillment_status: requestFulfillment.replay_and_action_log_status,
    p0_promotion_status: requestFulfillment.p0_promotion_status,
  };
}

module.exports = {
  ACTION_DEFINITIONS,
  PROCESS_SCHEMA,
  REQUIRED_ACTION_COVERAGE,
  normalizeActionLog,
  processControlledReplayCalibration,
  summarizeDecode,
};
