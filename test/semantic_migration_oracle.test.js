'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DECISION_STATUSES,
  DECISION_SCHEMA_DOCUMENT,
  createMigrationDecision,
  createDecisionSchemaDocument,
  decideFullSemanticMigration,
  rejectProtectedHoldout,
} = require('../src/semantic_migration_oracle');

const SOURCE_BUILD = '16.16.805.0442';
const TARGET_BUILD = '16.17.900.0001';
const SOURCE_FINGERPRINT_SHA = 'a'.repeat(64);

function provenance(overrides = {}) {
  return {
    source_build: SOURCE_BUILD,
    target_build: TARGET_BUILD,
    run_id: 'machine-run-1',
    source_fingerprint_sha256: SOURCE_FINGERPRINT_SHA,
    ...overrides,
  };
}

function candidate(id, overrides = {}) {
  return {
    candidate_id: id,
    exact_build: TARGET_BUILD,
    structural_match_score: 1,
    behavioral_match_score: 1,
    cross_field_match_score: 1,
    ground_truth_oracle_score: 1,
    invariant_gate: 'PASS',
    regression_gate: 'PASS',
    negative_control_gate: 'PASS',
    exception_audit: { status: 'PASS', exceptions: [] },
    provenance: provenance(),
    ...overrides,
  };
}

function decision(overrides = {}) {
  return createMigrationDecision({
    semantic_name: 'CURRENT_HP',
    source_build: SOURCE_BUILD,
    target_build: TARGET_BUILD,
    provenance: provenance(),
    candidates: [candidate('one')],
    ...overrides,
  });
}

test('automatic statuses require exactly one complete passing candidate', () => {
  assert.equal(decision().status, 'REVALIDATED_MACHINE_ONLY');
  assert.equal(decision({ candidates: [candidate('one', { migration_class: 'UNCHANGED' })] }).status,
    'AUTO_VERIFIED');
  assert.equal(decision({ candidates: [candidate('one', { migration_class: 'ROUTE_MOVED' })] }).status,
    'AUTO_VERIFIED_WITH_ROUTE_MOVE');
  assert.equal(decision({ candidates: [candidate('one', { migration_class: 'FIELD_SHIFT' })] }).status,
    'AUTO_VERIFIED_WITH_FIELD_SHIFT');
});

test('ambiguous, failed, explicit semantic change, and unavailable inputs fail closed', () => {
  assert.equal(decision({ candidates: [candidate('one'), candidate('two')] }).status,
    'MANUAL_VALIDATION_REQUIRED');
  assert.equal(decision({ candidates: [candidate('one', { regression_gate: 'FAIL' })] }).status,
    'MANUAL_VALIDATION_REQUIRED');
  assert.equal(decision({ candidates: [candidate('one', {
    behavioral_match_score: 0.1,
    semantic_change_evidence: { kind: 'controlled-ground-truth-disagreement', evidence_ids: ['gt-42'] },
  })] }).status, 'SEMANTIC_CHANGED');
  assert.equal(decision({ availability: 'UNAVAILABLE', candidates: [] }).status, 'UNSUPPORTED');
  assert.deepEqual(new Set(DECISION_STATUSES), new Set([
    'AUTO_VERIFIED', 'AUTO_VERIFIED_WITH_ROUTE_MOVE', 'AUTO_VERIFIED_WITH_FIELD_SHIFT',
    'REVALIDATED_MACHINE_ONLY', 'MANUAL_VALIDATION_REQUIRED', 'SEMANTIC_CHANGED', 'UNSUPPORTED',
  ]));
});

test('explicit semantic-change evidence preempts an otherwise automatic passing candidate', () => {
  const result = decision({ candidates: [candidate('contradiction', {
    migration_class: 'UNCHANGED',
    semantic_change_evidence: { kind: 'controlled-ground-truth-contradiction', evidence_ids: ['gt-change-1'] },
  })] });
  assert.equal(result.status, 'SEMANTIC_CHANGED');
  assert.equal(result.selected_candidate_id, null);
  assert.equal(result.candidates.length, 1);
  assert.ok(result.candidates[0].reasons.includes('EXPLICIT_SEMANTIC_CHANGE_EVIDENCE'));
});

test('one eligible candidate promotes automatically while rejected lookalikes remain conserved', () => {
  const result = decision({
    candidates: [
      candidate('accepted', { migration_class: 'UNCHANGED' }),
      candidate('negative-control-rejected', { negative_control_gate: 'FAIL' }),
    ],
  });
  assert.equal(result.status, 'AUTO_VERIFIED');
  assert.equal(result.eligible_candidate_count, 1);
  assert.equal(result.selected_candidate_id, 'accepted');
  assert.equal(result.candidates.length, 2);
  assert.deepEqual(result.candidates[1].reasons, ['GATE_FAILED:negative_control_gate']);
  assert.equal(decision({ candidates: [candidate('one'), candidate('two')] }).status,
    'MANUAL_VALIDATION_REQUIRED');
});

test('decisions conserve every candidate and reject missing fields, build fallback, and Holdout references', () => {
  const result = decision({ candidates: [candidate('one'), candidate('two')] });
  assert.equal(result.candidate_count, 2);
  assert.equal(result.candidates.length, 2);
  assert.equal(result.conservation.preserved_candidates, 'PASS');
  assert.equal(result.conservation.silent_discard, 'FORBIDDEN');
  assert.throws(() => decision({ candidates: [candidate('wrong-build', { exact_build: '16.16.805.0442' })] }),
    /does not match target build/);
  assert.throws(() => decision({ candidates: [candidate('missing-score', { ground_truth_oracle_score: null })] }),
    /ground_truth_oracle_score/);
  assert.throws(() => rejectProtectedHoldout({ provenance: { input: 'Jungle Objective Holdout/x.json' } }),
    /protected Holdout references/);
  assert.throws(() => decision({
    provenance: { source_build: SOURCE_BUILD, target_build: TARGET_BUILD, run_id: 'arbitrary' },
    candidates: [candidate('arbitrary', { migration_class: 'UNCHANGED', provenance: {
      source_build: SOURCE_BUILD, target_build: TARGET_BUILD, run_id: 'arbitrary',
    } })],
  }), /requires source_fingerprint_sha256 or/);
});

test('source and target builds require strict N.N.N.N form and the schema document is versioned', () => {
  assert.throws(() => decision({ source_build: '16.16' }), /strict N\.N\.N\.N exact-build form/);
  assert.throws(() => decision({ target_build: 'v16.17.900.0001' }), /strict N\.N\.N\.N exact-build form/);
  assert.throws(() => decision({ target_build: '16.17.900.0001', exact_build: '16.17.900.0002' }),
    /compatibility alias/);
  assert.throws(() => decision({ candidates: [candidate('bad-format', { exact_build: '16.17' })] }),
    /strict N\.N\.N\.N exact-build form/);
  const schema = createDecisionSchemaDocument();
  assert.equal(schema.schema, DECISION_SCHEMA_DOCUMENT);
  assert.equal(schema.exact_build_format, 'N.N.N.N');
  assert.deepEqual(schema.statuses, DECISION_STATUSES);
  assert.ok(schema.required_input_fields.includes('source_build'));
  assert.ok(schema.required_input_fields.includes('target_build'));
  assert.deepEqual(schema.provenance_required_fields, ['source_build', 'target_build', 'run_id']);
  assert.ok(schema.provenance_evidence_binding.some((row) => row.includes('source_fingerprint_sha256')));
});

test('full_semantic_migration capability rows integrate without changing their producer', () => {
  const output = decideFullSemanticMigration({
    capabilities: [
      { capability: 'CURRENT_HP', status: 'ROUTE_MOVED', reasons: ['0x1 -> 0x2'] },
      { capability: 'SOMETHING_UNAVAILABLE', status: 'UNSUPPORTED', reasons: ['no decoder'] },
    ],
  }, {
    source_build: SOURCE_BUILD,
    target_build: TARGET_BUILD,
    provenance: provenance(),
    evidence_by_capability: {
      CURRENT_HP: { candidates: [candidate('current-hp')] },
    },
  });
  assert.deepEqual(output.decisions.map((row) => row.status), [
    'AUTO_VERIFIED_WITH_ROUTE_MOVE', 'UNSUPPORTED',
  ]);
  assert.equal(output.conservation.input_capability_rows, 2);
  assert.equal(output.conservation.decision_rows, 2);
  assert.equal(output.conservation.preserved_rows, 'PASS');
  assert.equal(output.decisions[0].candidates[0].candidate.provenance.full_semantic_migration.status,
    'ROUTE_MOVED');
});
