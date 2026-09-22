'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  floatDeltaTolerance,
  representationDeltaTolerance,
  displayInterval,
  deltaInterval,
  intervalContains,
  fractionalResidue,
  auditCandidate,
  buildQuantizedOracleInterpretation,
  runQuantizationAwareP0Recovery,
  EXPECTED_PARTIAL_COUNTS,
} = require('../src/quantization_aware_p0_recovery');
const { loadGroundTruthOracle } = require('../src/oracle_guided_p0_recovery');

const ROOT = path.resolve(__dirname, '..');
const ORACLE = path.join(ROOT, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'p0_anchor_scan', 'manual_ground_truth_import_v1', 'manual_ground_truth_oracle.json');
const CONTROLLED_REPLAY = process.env.ROFL_CONTROLLED_REPLAY_PATH
  || path.join(ROOT, 'replay', 'HN1-11212942693.rofl');
const PRIOR_REPORT = path.join(ROOT, '.omo', 'evidence', 'oracle_guided_p0_recovery_core', 'oracle_guided_p0_recovery_report.json');

function hash(filePath) { return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex'); }

test('HUD projection hypotheses produce explicit intervals without preselecting one', () => {
  assert.deepEqual(displayInterval(41, 'FLOOR'), { lower: 41, upper: 42, lower_inclusive: true, upper_inclusive: false });
  assert.deepEqual(displayInterval(41, 'ROUND_HALF_AWAY_FROM_ZERO'), { lower: 40.5, upper: 41.5, lower_inclusive: true, upper_inclusive: false });
  assert.deepEqual(displayInterval(41, 'TRUNCATE_TOWARD_ZERO'), { lower: 41, upper: 42, lower_inclusive: true, upper_inclusive: false });
  assert.equal(intervalContains(deltaInterval(41, 56, 'FLOOR'), 15.25), true);
  assert.equal(intervalContains(deltaInterval(41, 56, 'ROUND_HALF_AWAY_FROM_ZERO'), 15.25), true);
  const open = deltaInterval(41, 56, 'FLOOR');
  assert.deepEqual(open, { lower: 14, upper: 16, lower_inclusive: false, upper_inclusive: false });
  assert.equal(intervalContains(open, 14), false);
  assert.equal(intervalContains(open, 16), false);
  assert.equal(intervalContains(open, 14, 1), false, 'tolerance must not turn an open endpoint into a member');
});

test('tolerance derives from actual endpoint ULPs and scale, and flat steps preserve residue', () => {
  const f32 = representationDeltaTolerance('f32le', 0.5, 1000, 1030);
  const f64 = representationDeltaTolerance('f64le', 0.5, 1000, 1030);
  const smallF32 = representationDeltaTolerance('f32le', 0.5, 10, 40);
  assert.ok(f32 > f64);
  assert.ok(f32 > smallF32);
  assert.equal(floatDeltaTolerance('f32le', 150), representationDeltaTolerance('f32le', 1, 0, 150));
  assert.ok(Math.abs(fractionalResidue(41.375) - fractionalResidue(56.375)) < 1e-12);
  assert.ok(Math.abs(fractionalResidue(-2.625) - fractionalResidue(12.375)) < 1e-12);
});

test('derived oracle interpretation is additive and leaves all 50 manual observations immutable', { skip: !fs.existsSync(ORACLE) && 'private oracle input unavailable' }, () => {
  const before = hash(ORACLE);
  const oracle = loadGroundTruthOracle({ oracle_path: ORACLE });
  const derived = buildQuantizedOracleInterpretation(oracle, ORACLE);
  assert.equal(derived.records.length, 50);
  assert.equal(derived.raw_observation_mutated, false);
  assert.ok(derived.records.every((row) => row.observation_type === 'HUD_QUANTIZED_SCALAR'));
  assert.ok(derived.records.every((row) => row.hypotheses.length === 3));
  assert.equal(derived.hypotheses_are_non_exhaustive, true);
  assert.equal(hash(ORACLE), before);
});

test('item negative-control matrix excludes the target item and requires the other two items', () => {
  const transition = (id, semantic, before, after) => ({ id, semantic, before, after, delta: after - before });
  const transitions = [
    transition('CLOTH-BUY-UNDO-a', 'ARMOR', 41, 56), transition('CLOTH-BUY-UNDO-b', 'ARMOR', 56, 41),
    transition('CLOTH-BUY-SELL-a', 'ARMOR', 41, 56), transition('CLOTH-BUY-SELL-b', 'ARMOR', 56, 41),
    transition('RUBY-control', 'MAX_HP', 730, 880), transition('MANTLE-MR-control', 'MAGIC_RESIST', 33, 53),
  ];
  const response = (row, internalBefore, internalAfter) => ({
    transition_id: row.id, semantic: row.semantic, oracle_before: row.before, oracle_after: row.after,
    oracle_delta: row.delta, candidate_before: internalBefore, candidate_after: internalAfter,
    candidate_delta: internalAfter - internalBefore, absolute_snapshot_match: false,
  });
  const responses = [
    response(transitions[0], 41.375, 56.375), response(transitions[1], 56.375, 41.375),
    response(transitions[2], 41.375, 56.375), response(transitions[3], 56.375, 41.375),
    response(transitions[4], 41.375, 41.375), response(transitions[5], 41.375, 41.375),
  ];
  const audited = auditCandidate('ARMOR', {
    route: 'synthetic', source: 'payload', binding_scope: 'KAYN', view: 'f32le', offset: 4,
    scale: 1, stream: 'game_chunk', target_delta_match_count: 4, target_observed_pair_count: 4, responses,
  }, transitions);
  assert.equal(audited.cross_stat_negative_control_policy.own_experiment_excluded, 'CLOTH');
  assert.deepEqual(audited.cross_stat_negative_control_policy.required_negative_experiments, ['RUBY', 'MANTLE']);
  assert.equal(audited.cross_stat_negative_control_policy.pass, true);
  assert.equal(audited.promoted, true);

  const current = auditCandidate('CURRENT_HP', {
    route: 'synthetic', source: 'payload', binding_scope: 'KAYN', view: 'f32le', offset: 8,
    scale: 1, stream: 'game_chunk', target_delta_match_count: 1, target_observed_pair_count: 1,
    responses: [response(transition('HP-DAMAGE', 'CURRENT_HP', 655, 602), 655.25, 602.25)],
  }, [transition('HP-DAMAGE', 'CURRENT_HP', 655, 602)]);
  assert.equal(current.cross_stat_negative_control_policy.pass, false);
  assert.equal(current.cross_stat_negative_control_policy.strategy, 'UNAVAILABLE_NO_CURRENT_HP_OBSERVATIONS_AT_ITEM_TRANSITION_ANCHORS');
});

test('controlled audit reconstructs every prior partial and records each failed gate', { timeout: 180_000, skip: ![ORACLE, CONTROLLED_REPLAY, PRIOR_REPORT].every((file) => fs.existsSync(file)) && 'private controlled inputs unavailable' }, (t) => {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'quant-p0-'));
  t.after(() => fs.rmSync(output, { recursive: true, force: true }));
  const result = runQuantizationAwareP0Recovery({ repository_root: ROOT, output_directory: output, replay_path: CONTROLLED_REPLAY });
  assert.equal(result.status, 'PASS');
  assert.equal(result.report.question_1_old_exact_equality_rejection.answer, 'NO');
  for (const [semantic, expected] of Object.entries(EXPECTED_PARTIAL_COUNTS)) {
    const counts = result.report.p0_candidate_counts[semantic];
    assert.equal(counts.before_quantization_aware_audit, expected);
    assert.equal(counts.reconstructed_partial_count, expected);
    assert.equal(counts.all_required_transitions_quantized_compatible, 0);
    assert.equal(counts.after_quantization_aware_audit, 0);
    assert.equal(result.report.rejection_gate_audit[semantic].length, expected);
      for (const candidate of result.report.rejection_gate_audit[semantic]) {
      for (const key of ['semantic', 'route', 'component', 'field', 'representation', 'failure_gate', 'failure_reason', 'responses']) assert.ok(key in candidate, `${semantic}:${key}`);
      for (const response of candidate.responses) {
        for (const key of ['raw_before', 'raw_after', 'observed_HUD_before', 'observed_HUD_after', 'internal_delta', 'HUD_delta']) assert.ok(key in response, `${semantic}:${key}`);
      }
      assert.deepEqual(Object.keys(candidate.cross_stat_negative_control_matrix), ['RUBY', 'CLOTH', 'MANTLE']);
    }
  }
  assert.deepEqual(Object.fromEntries(Object.entries(result.report.p0_candidate_counts).map(([semantic, row]) => [semantic, row.at_least_one_quantized_compatible])), {
    MAX_HP: 10, ARMOR: 105, MAGIC_RESIST: 23, CURRENT_HP: 5,
  });
  assert.equal(result.report.quantized_hud_model.hypotheses_are_non_exhaustive, true);
  assert.deepEqual(result.report.protected_holdout_access, { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false });
  const manifest = JSON.parse(fs.readFileSync(result.artifact_manifest, 'utf8'));
  assert.equal(fs.existsSync(result.evidence_path), true);
  for (const artifact of manifest.outputs) {
    const artifactPath = path.join(output, artifact.path);
    assert.equal(fs.statSync(artifactPath).size, artifact.byte_size);
    assert.equal(hash(artifactPath), artifact.sha256);
  }
});
