'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXPECTED_BUILD,
  EXPECTED_REPLAY_SHA,
  loadGroundTruthOracle,
  buildOracleTransitions,
  scanNumericLanes,
  candidateKey,
  nearestPair,
  scoreCandidate,
  runOracleGuidedP0Recovery,
} = require('../src/oracle_guided_p0_recovery');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const ORACLE_PATH = path.join(
  REPOSITORY_ROOT,
  'artifacts', 'controlled_calibration_replays', 'HN1-11212942693',
  'p0_anchor_scan', 'manual_ground_truth_import_v1', 'manual_ground_truth_oracle.json',
);
function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function makeTemporaryRoot(t, name) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `${name}-`));
  t.after(() => {
    if (path.resolve(root).startsWith(path.resolve(os.tmpdir()) + path.sep)) {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
  return root;
}

function normalizeOutputPaths(value, key = '') {
  if (Array.isArray(value)) return value.map((entry) => normalizeOutputPaths(entry, key));
  if (!value || typeof value !== 'object') {
    return /(?:path|directory|manifest)$/i.test(key) ? null : value;
  }
  return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [
    childKey,
    /(?:path|directory|manifest)$/i.test(childKey)
      ? null
      : normalizeOutputPaths(childValue, childKey),
  ]));
}

const CONTROLLED_REPLAY_PATH = process.env.ROFL_CONTROLLED_REPLAY_PATH
  || path.join(REPOSITORY_ROOT, 'replay', 'HN1-11212942693.rofl');
const HAS_ORACLE = fs.existsSync(ORACLE_PATH);
const HAS_CONTROLLED_REPLAY = fs.existsSync(CONTROLLED_REPLAY_PATH);

test('loads the imported manual oracle with 50 records, 11 completed cases, and Level-Up HOLD', { skip: !HAS_ORACLE && 'private oracle input unavailable' }, () => {
  const loaded = loadGroundTruthOracle({
    oracle_path: ORACLE_PATH,
    expected_build: EXPECTED_BUILD,
    expected_replay_sha: EXPECTED_REPLAY_SHA,
  });
  assert.equal(EXPECTED_BUILD, '16.16.805.0442');
  assert.equal(EXPECTED_REPLAY_SHA, '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff');
  assert.equal(loaded.records.length, 50);
  assert.equal(loaded.completed_case_count, 11);
  assert.equal(loaded.held_case_count, 1);
  assert.deepEqual(loaded.held_cases.map((row) => row.case_id), ['P0-STATS-06-LEVEL-UP']);
  assert.equal(loaded.automatic_promotion, 'FORBIDDEN');
  assert.ok(loaded.records.every((row) => row.manual_or_machine === 'MANUAL'));
  assert.ok(loaded.records.every((row) => row.exact_build === EXPECTED_BUILD));
  assert.ok(loaded.records.every((row) => row.replay_sha === EXPECTED_REPLAY_SHA));
});

test('constructs event-relative transitions and does not turn Level-Up HOLD into a global blocker', { skip: !HAS_ORACLE && 'private oracle input unavailable' }, () => {
  const oracle = loadGroundTruthOracle({ oracle_path: ORACLE_PATH });
  const transitions = buildOracleTransitions(oracle.records);
  assert.ok(Array.isArray(transitions));
  assert.ok(transitions.length >= 13);
  assert.equal(transitions.filter((row) => row.manual_case_id === 'P0-STATS-06-LEVEL-UP').length, 0);
  for (const semantic of ['CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST']) {
    assert.ok(transitions.some((row) => row.semantic === semantic), semantic);
  }
  const changed = (semantic, beforeValue, afterValue) => transitions.some((row) => row.semantic === semantic
    && row.before_value === beforeValue && row.after_value === afterValue);
  for (const pair of [[730, 880], [880, 730]]) {
    assert.equal(changed('MAX_HP', ...pair), true, `MAX_HP ${pair.join('->')}`);
  }
  for (const pair of [[41, 56], [56, 41]]) {
    assert.equal(changed('ARMOR', ...pair), true, `ARMOR ${pair.join('->')}`);
  }
  for (const pair of [[33, 53], [53, 33]]) {
    assert.equal(changed('MAGIC_RESIST', ...pair), true, `MAGIC_RESIST ${pair.join('->')}`);
  }
  for (const pair of [[655, 512], [549, 629], [655, 602], [630, 0], [0, 655]]) {
    assert.equal(changed('CURRENT_HP', ...pair), true, `CURRENT_HP ${pair.join('->')}`);
  }
});

test('numeric lane scanner includes unaligned integer, float, and scaled views', () => {
  const payload = Buffer.alloc(24, 0);
  payload.writeUInt16LE(730, 1);
  payload.writeFloatLE(73, 5);
  payload.writeUInt32LE(5600, 10);
  payload.writeUInt16LE(53, 17);
  const lanes = scanNumericLanes(payload, {
    include_unaligned: true,
    scales: [1, 0.1, 0.01],
  });
  assert.ok(lanes.some((row) => row.offset === 1 && row.type === 'u16le' && row.value === 730));
  assert.ok(lanes.some((row) => row.offset === 5 && row.type === 'f32le' && row.value === 73));
  assert.ok(lanes.some((row) => row.offset === 10 && row.type === 'u32le' && row.value === 5600));
  assert.ok(lanes.some((row) => row.offset === 10 && row.scale === 0.01 && row.value === 56));
  assert.ok(lanes.some((row) => row.offset === 17 && row.type === 'u16le' && row.value === 53));
});

test('exact build and replay SHA guards fail closed before scanning', { skip: !HAS_ORACLE && 'private oracle input unavailable' }, (t) => {
  const root = makeTemporaryRoot(t, 'oracle-guard');
  const badBuild = path.join(root, 'bad-build.json');
  const badSha = path.join(root, 'bad-sha.json');
  const source = readJson(ORACLE_PATH);
  const withBadBuild = structuredClone(source);
  withBadBuild.records[0].exact_build = '16.16.805.0443';
  fs.writeFileSync(badBuild, `${JSON.stringify(withBadBuild)}\n`);
  assert.throws(() => loadGroundTruthOracle({
    oracle_path: badBuild,
    expected_build: EXPECTED_BUILD,
    expected_replay_sha: EXPECTED_REPLAY_SHA,
  }), /build|exact/i);
  const withBadSha = structuredClone(source);
  withBadSha.records[0].replay_sha = '0'.repeat(64);
  fs.writeFileSync(badSha, `${JSON.stringify(withBadSha)}\n`);
  assert.throws(() => loadGroundTruthOracle({
    oracle_path: badSha,
    expected_build: EXPECTED_BUILD,
    expected_replay_sha: EXPECTED_REPLAY_SHA,
  }), /sha|replay/i);
});

test('nearest pairing is bounded by adjacent oracle anchors and exact-event delta remains attributable', () => {
  const shieldAnchorBounds = { lowerExclusive: 58198, upperExclusive: 61484.5 };
  const beforeOnly = [
    { timestamp_ms: 61000, value: 655 },
    // This is the next oracle anchor; it must not become the after-side of 61184.
    { timestamp_ms: 61785, value: 602 },
  ];
  assert.equal(nearestPair(beforeOnly, 61184, 3000, shieldAnchorBounds), null);

  const sameEvent = [
    { timestamp_ms: 61000, value: 655 },
    { timestamp_ms: 61200, value: 655 },
    { timestamp_ms: 61770, value: 655 },
    { timestamp_ms: 61790, value: 602 },
  ];
  const sameEventPair = nearestPair(sameEvent, 61184, 3000, shieldAnchorBounds);
  assert.deepEqual([sameEventPair.before.timestamp_ms, sameEventPair.after.timestamp_ms], [61000, 61200]);

  const key = candidateKey('0x017f', 'game_chunk', 'payload', 'u16le', 1, 'KAYN_PARAM');
  const scored = scoreCandidate(key, sameEvent, [
    { id: 'shield_apply', timestamp_ms: 61184, semantic: 'CURRENT_HP', before: 655, after: 655, delta: 0 },
    { id: 'shielded_damage', timestamp_ms: 61785, semantic: 'CURRENT_HP', before: 655, after: 602, delta: -53 },
  ], 1, 3_000);
  assert.equal(scored.responses.length, 2);
  assert.equal(scored.responses[0].candidate_delta, 0);
  assert.equal(scored.responses[1].candidate_delta, -53);
  assert.equal(scored.responses.every((row) => row.delta_match), true);
});

test('controlled run is deterministic, reports cross-stat negative controls, and preserves protected holdout boundary', { timeout: 180_000, skip: !(HAS_ORACLE && HAS_CONTROLLED_REPLAY) && 'private controlled inputs unavailable' }, (t) => {
  const root = makeTemporaryRoot(t, 'oracle-guided-p0');
  const outputA = path.join(root, 'run-a');
  const outputB = path.join(root, 'run-b');
  const resultA = runOracleGuidedP0Recovery({
    repository_root: REPOSITORY_ROOT,
    oracle_path: ORACLE_PATH,
    replay_path: CONTROLLED_REPLAY_PATH,
    output_directory: outputA,
  });
  const resultB = runOracleGuidedP0Recovery({
    repository_root: REPOSITORY_ROOT,
    oracle_path: ORACLE_PATH,
    replay_path: CONTROLLED_REPLAY_PATH,
    output_directory: outputB,
  });
  assert.equal(resultA.status, 'PASS');
  assert.equal(resultB.status, 'PASS');
  assert.equal(resultA.exact_build, EXPECTED_BUILD);
  assert.equal(resultA.replay_sha, EXPECTED_REPLAY_SHA);
  assert.equal(resultA.oracle_record_count, 50);
  assert.equal(resultA.completed_case_count, 11);
  assert.equal(resultA.held_case_count, 1);
  assert.ok(resultA.transition_count >= 13);
  assert.equal(path.isAbsolute(CONTROLLED_REPLAY_PATH), true);
  assert.deepEqual(normalizeOutputPaths(resultA), normalizeOutputPaths(resultB));

  const reportA = readJson(resultA.report_path);
  const reportB = readJson(resultB.report_path);
  assert.deepEqual(reportA, reportB);
  assert.ok(reportA.scan.raw_unaligned_identity_count >= reportA.scan.anchor_observed_identity_count);
  assert.equal(reportA.protected_boundary.enumerated, false);
  assert.equal(reportA.protected_boundary.read, false);
  assert.equal(reportA.protected_boundary.hashed, false);
  assert.equal(reportA.protected_boundary.decoded, false);
  assert.equal(reportA.protected_boundary.tested, false);
  assert.equal(reportA.protected_boundary.consumed, false);

  for (const semantic of ['CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST']) {
    const row = reportA.semantic_summary[semantic];
    assert.ok(row, semantic);
    assert.ok(row.candidate_count_before >= row.candidate_count_after, semantic);
    assert.equal(row.cross_stat_negative_control_failures, 0, semantic);
  }
  assert.equal(reportA.level_up.status, 'HOLD');
  assert.equal(reportA.level_up.global_blocker, false);

  const manifest = readJson(resultA.artifact_manifest);
  assert.equal(fs.existsSync(resultA.artifact_manifest), true);
  assert.ok(manifest.outputs.length > 0);
  for (const output of manifest.outputs) {
    const filePath = path.join(outputA, output.path);
    assert.equal(fs.statSync(filePath).size, output.byte_size, output.path);
    assert.equal(sha256File(filePath), output.sha256, output.path);
  }
});
