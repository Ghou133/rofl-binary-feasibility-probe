'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const semanticApi = require('../src/semantic_api');
const { assertTruthIsSemanticOnly } = require('../src/controlled_calibration');
const {
  CURRENT_BUILD,
  DEFAULT_INPUT_PATHS,
  STAGE_SCHEMA,
  buildControlledGroundTruthStage,
  resolveSafeInputs,
} = require('../src/controlled_ground_truth_stage');
const { DECISION_STATUSES } = require('../src/semantic_migration_oracle');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const P0_SEMANTICS = ['CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST'];
const REPORT_SECTIONS = [
  'A_STATUS', 'B_CURRENT_BUILD', 'C_CALIBRATION_INFRASTRUCTURE',
  'D_SEMANTIC_FINGERPRINT_SYSTEM', 'E_GROUND_TRUTH_ORACLE', 'F_MIGRATION_ORACLE',
  'G_CURRENT_HP', 'H_MAX_HP', 'I_ARMOR', 'J_MAGIC_RESIST', 'K_OTHER_HERO_STATE',
  'L_DAMAGE_STAGE', 'M_DAMAGE_MITIGATION', 'N_SHIELD', 'O_HEAL', 'P_SPELL_MISSILE',
  'Q_ENTITY_CALIBRATION', 'R_ITEM_CALIBRATION', 'S_VISION_CALIBRATION',
  'T_EXCEPTION_REGISTRY', 'U_AUTOMATIC_MIGRATION_TEST', 'V_MANUAL_VALIDATION_REQUIRED',
  'W_NEW_REPLAY_REQUIRED', 'X_REGRESSION', 'Y_NEXT_BUILD_READINESS', 'Z_HARD_BLOCKER',
];

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('real controlled stage deterministically conserves all current-build evidence without false P0 promotion', { timeout: 120_000 }, (t) => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-controlled-stage-v1-'));
  const resolvedTemporaryRoot = path.resolve(temporaryRoot);
  assert.ok(resolvedTemporaryRoot.startsWith(`${path.resolve(os.tmpdir())}${path.sep}`));
  t.after(() => {
    if (path.resolve(temporaryRoot).startsWith(`${path.resolve(os.tmpdir())}${path.sep}`)) {
      fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
  });

  const outputA = path.join(temporaryRoot, 'run-a');
  const outputB = path.join(temporaryRoot, 'run-b');
  const resultA = buildControlledGroundTruthStage({
    repository_root: REPOSITORY_ROOT,
    output_directory: outputA,
  });
  const resultB = buildControlledGroundTruthStage({
    repository_root: REPOSITORY_ROOT,
    output_directory: outputB,
  });

  assert.equal(resultA.schema, STAGE_SCHEMA);
  assert.equal(resultA.status, 'EXTERNAL_INPUT_REQUIRED');
  assert.equal(resultA.exact_build, CURRENT_BUILD);
  assert.equal(resultA.ground_truth_oracle_record_count, 5720);
  assert.equal(resultA.semantic_fingerprint_count, 79);
  assert.equal(resultA.machine_calibration_case_count, 4);
  assert.equal(resultA.manual_validation_task_count, 0);
  assert.equal(resultA.p0_promotion_count, 0);
  assert.equal(resultA.need_calibration_replay, true);
  assert.deepEqual({ ...resultA, output_directory: null, artifact_manifest: null },
    { ...resultB, output_directory: null, artifact_manifest: null });

  const artifactManifestA = readJson(resultA.artifact_manifest);
  const artifactManifestB = readJson(resultB.artifact_manifest);
  assert.deepEqual(artifactManifestA, artifactManifestB);
  assert.equal(artifactManifestA.input_count, Object.keys(DEFAULT_INPUT_PATHS).length + 1);
  assert.equal(artifactManifestA.output_count, artifactManifestA.outputs.length);
  assert.deepEqual(artifactManifestA.protected_boundary, {
    enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false,
  });
  for (const output of artifactManifestA.outputs) {
    const filePath = path.join(outputA, output.path);
    assert.equal(fs.statSync(filePath).size, output.byte_size, output.path);
    assert.equal(sha256File(filePath), output.sha256, output.path);
  }

  const oracle = readJson(path.join(outputA, 'ground_truth_oracle.json'));
  assert.equal(oracle.records.length, 5720);
  assertTruthIsSemanticOnly(oracle);
  for (const semantic of P0_SEMANTICS) {
    assert.equal(oracle.records.filter((row) => row.semantic === semantic).length, 1430);
  }

  const fingerprints = readJson(path.join(outputA, 'semantic_fingerprints.json'));
  assert.deepEqual(fingerprints.availability_counts, { VERIFIED: 30, UNKNOWN: 4, UNAVAILABLE: 45 });
  assert.equal(fingerprints.record_count, fingerprints.capability_count);
  assert.equal(fingerprints.promotion_eligible_count, 0);
  assert.equal(fingerprints.verified_incomplete_revalidation_count, 30);
  assert.equal(fingerprints.non_promotion_eligible_count, 79);
  for (const row of fingerprints.records.filter((entry) => entry.fingerprint.availability === 'VERIFIED')) {
    assert.equal(row.fingerprint.promotion_eligible, false, row.fingerprint.semantic_name);
    assert.equal(row.fingerprint.migration_policy, 'REVALIDATE_IF_AMBIGUOUS');
    assert.equal(row.fingerprint.completeness.status, 'INCOMPLETE');
    assert.ok(row.fingerprint.completeness.incomplete_dimensions.length > 0);
  }
  for (const semantic of P0_SEMANTICS) {
    const row = fingerprints.records.find((entry) => entry.fingerprint.semantic_name === semantic);
    assert.equal(row.fingerprint.availability, 'UNAVAILABLE', semantic);
    assert.equal(row.fingerprint.promotion_eligible, false, semantic);
  }

  const report = readJson(path.join(outputA, 'stage_report.json'));
  assert.deepEqual(Object.keys(report).filter((key) => /^[A-Z]_/.test(key)), REPORT_SECTIONS);
  assert.equal(report.A_STATUS.infrastructure_success, true);
  assert.equal(report.A_STATUS.p0_semantic_breakthrough, false);
  assert.equal(report.D_SEMANTIC_FINGERPRINT_SYSTEM.promotion_eligible_count, 0);
  assert.equal(report.D_SEMANTIC_FINGERPRINT_SYSTEM.verified_incomplete_revalidation_count, 30);
  assert.equal(report.D_SEMANTIC_FINGERPRINT_SYSTEM.non_promotion_eligible_count, 79);
  for (const key of ['G_CURRENT_HP', 'H_MAX_HP', 'I_ARMOR', 'J_MAGIC_RESIST']) {
    assert.equal(report[key].deep_recovery_availability, 'UNAVAILABLE');
    assert.equal(report[key].deep_recovery_decision, 'REJECT');
    assert.equal(report[key].evidence_exhausted, true);
    assert.equal(report[key].promotion, 'NOT_PROMOTED');
    assert.ok(report[key].next_required_evidence.length > 0);
  }
  assert.equal(report.L_DAMAGE_STAGE.matched_anchor_count, 6);
  assert.equal(report.L_DAMAGE_STAGE.amount_semantic_stage, 'RECORDED_COMPONENT_STAGE_UNKNOWN');
  assert.equal(report.M_DAMAGE_MITIGATION.post_mitigation_stage_test.status, 'UNDERDETERMINED');
  assert.equal(report.C_CALIBRATION_INFRASTRUCTURE.source_evidence.decision_ledger.route_decision_count, 176);
  assert.equal(report.Z_HARD_BLOCKER.exhausted_search_space.length, 15);
  assert.equal(report.Z_HARD_BLOCKER.all_independent_local_work_complete, true);

  const alignment = readJson(path.join(outputA, 'p0_alignment_baseline.json'));
  assert.equal(alignment.oracle_record_count, 5720);
  assert.equal(alignment.unmatched_oracle_count, 5720);
  assert.equal(alignment.promotion_count, 0);
  const manualTasks = readJson(path.join(outputA, 'manual_ground_truth_tasks.json'));
  assert.equal(manualTasks.task_count, 0);
  assert.equal(manualTasks.manual_validation_default,
    'FORBIDDEN_UNLESS_AUTOMATIC_EVIDENCE_IS_UNRESOLVED');
  const replayRequest = readJson(path.join(outputA, 'controlled_replay_request.json'));
  assert.equal(replayRequest.recommended_replay_count, 1);
  assert.equal(replayRequest.maximum_replay_count_only_if_first_is_ambiguous, 3);
  assert.equal(replayRequest.exact_build_handling.nearest_build_fallback, 'FORBIDDEN');
  assert.equal(replayRequest.experimental_sequence.length, 9);
  const migrationContract = readJson(path.join(outputA, 'migration_oracle_contract_test.json'));
  assert.deepEqual([...migrationContract.status_coverage].sort(), [...DECISION_STATUSES].sort());
  assert.equal(migrationContract.result, 'PASS');
  const readiness = readJson(path.join(outputA, 'next_build_readiness.json'));
  assert.equal(readiness.new_build_detected, false);
  assert.equal(readiness.all_public_capabilities_traversed, true);
  assert.equal(readiness.public_capability_count, 79);
});

test('semantic API publishes the complete calibration/fingerprint/oracle surface', () => {
  const calibration = semanticApi.semanticCalibration;
  assert.equal(typeof calibration.semanticFingerprint.SemanticFingerprint, 'function');
  assert.equal(typeof calibration.controlledCalibration.createGroundTruthOracle, 'function');
  assert.equal(typeof calibration.controlledCalibration.generateManualValidationCases, 'function');
  assert.equal(typeof calibration.controlledCalibration.importControlledCalibrationBatch, 'function');
  assert.equal(typeof calibration.semanticFingerprint.ExceptionRegistry, 'function');
  assert.equal(typeof calibration.semanticFingerprintMatcher.matchSemanticFingerprint, 'function');
  assert.equal(typeof calibration.semanticMigrationOracle.createMigrationDecision, 'function');
  assert.equal(typeof calibration.semanticRegressionOracle.runRegressionIntegration, 'function');
  assert.equal(typeof calibration.controlledGroundTruthStage.buildControlledGroundTruthStage, 'function');
});

test('stage rejects undeclared input overrides and non-pinned exact builds before research work', () => {
  assert.throws(() => resolveSafeInputs(REPOSITORY_ROOT, { undeclared_input: 'package.json' }),
    /unknown input override/);
  assert.throws(() => buildControlledGroundTruthStage({
    repository_root: REPOSITORY_ROOT,
    current_build: '16.16.805.4420',
  }), /pinned to 16\.16\.805\.0442/);
});
