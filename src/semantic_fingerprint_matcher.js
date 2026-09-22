'use strict';

const {
  SEMANTIC_FINGERPRINT_SCHEMA,
  SEMANTIC_FINGERPRINT_SCHEMA_VERSION,
  assertNoProtectedSemantics,
  stableHash,
  validateSemanticFingerprint,
} = require('./semantic_fingerprint');

const MATCHER_SCHEMA = 'ROFL_SEMANTIC_FINGERPRINT_MATCHER_V1';
const MATCHER_SCHEMA_VERSION = 1;
const CANDIDATE_EVIDENCE_SCHEMA = 'ROFL_SEMANTIC_FINGERPRINT_CANDIDATE_EVIDENCE_V1';
const CANDIDATE_EVIDENCE_SCHEMA_VERSION = 1;
const MATCH_RESULT_SCHEMA = 'ROFL_SEMANTIC_FINGERPRINT_MATCH_RESULT_V1';
const EVIDENCE_STATUS = Object.freeze(['VERIFIED', 'UNKNOWN', 'UNAVAILABLE']);
const CHECK_STATUS = Object.freeze(['PASS', 'FAIL', 'UNKNOWN', 'UNAVAILABLE']);
const DIMENSIONS = Object.freeze(['structural', 'behavioral', 'cross_field', 'ground_truth_oracle']);
const STRUCTURAL_FIELDS = Object.freeze([
  'runtime_type', 'registration', 'callback', 'constructor', 'vtable', 'deserializer', 'serializer',
  'component', 'field_type', 'field_position', 'payload_shape', 'surrounding_fields', 'entity_relationship',
]);
const BEHAVIORAL_FIELDS = Object.freeze([
  'value_range', 'temporal_behavior', 'update_frequency', 'event_correlations', 'reset_behavior', 'persistence_behavior',
]);
const SHA256 = /^[a-f0-9]{64}$/i;
const BUILD = /^\d+\.\d+\.\d+\.\d+$/;
const FORBIDDEN_SEMANTIC = /^(?:MAP_|STRATEGIC_|PLAYER_PROFILE|BEHAVIOR_)/;

function isObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function requiredString(value, label) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${label} must be a non-empty string`);
  return value;
}
function exactBuild(value, label) {
  requiredString(value, label);
  if (!BUILD.test(value)) throw new TypeError(`${label} must be a four-component exact build`);
  return value;
}
function sha(value, label) {
  requiredString(value, label);
  if (!SHA256.test(value)) throw new TypeError(`${label} must be a 64-character SHA-256`);
  return value.toLowerCase();
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function equal(left, right) { return stableHash(left) === stableHash(right); }
function containsUnknownOrUnavailable(value, seen = new WeakSet()) {
  if (!isObject(value) && !Array.isArray(value)) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (isObject(value) && ['UNKNOWN', 'UNAVAILABLE'].includes(value.status)) return true;
  return Object.values(value).some((child) => containsUnknownOrUnavailable(child, seen));
}

function validateProvenance(provenance, label) {
  if (!isObject(provenance)) throw new TypeError(`${label} must be an object`);
  exactBuild(provenance.exact_build, `${label}.exact_build`);
  const hasReplay = provenance.replay_sha256 !== null && provenance.replay_sha256 !== undefined;
  const hasSet = provenance.replay_set_manifest_sha256 !== null && provenance.replay_set_manifest_sha256 !== undefined;
  if (hasReplay === hasSet) throw new Error(`${label} requires exactly one replay_sha256 or replay_set_manifest_sha256`);
  sha(hasReplay ? provenance.replay_sha256 : provenance.replay_set_manifest_sha256,
    `${label}.${hasReplay ? 'replay_sha256' : 'replay_set_manifest_sha256'}`);
  sha(provenance.source_sha256, `${label}.source_sha256`);
  requiredString(provenance.source_kind, `${label}.source_kind`);
  assertNoProtectedSemantics(provenance, label, true);
}
function exactKeys(value, expected, label) {
  if (!isObject(value)) throw new TypeError(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(sortedExpected)) {
    throw new Error(`${label} must contain exactly the required fields; observed=${actual.join(',')}`);
  }
}
function validateDimensionEvidence(value, fields, label) {
  if (!isObject(value)) throw new TypeError(`${label} must be an object`);
  if (!EVIDENCE_STATUS.includes(value.evidence_status)) throw new TypeError(`${label}.evidence_status is invalid`);
  if (value.evidence_status === 'VERIFIED') {
    exactKeys(value.observations, fields, `${label}.observations`);
    for (const field of fields) if (value.observations[field] === null || value.observations[field] === undefined) {
      throw new Error(`${label}.observations.${field} must be explicit`);
    }
  } else if (value.observations !== null && value.observations !== undefined) {
    throw new Error(`${label} ${value.evidence_status} must not supply observations`);
  }
}
function referenceMap(references, label) {
  const map = new Map();
  for (const reference of references) {
    if (map.has(reference.reference_id)) throw new Error(`source fingerprint duplicate ${label} ${reference.reference_id}`);
    map.set(reference.reference_id, reference);
  }
  return map;
}
function validateReferenceEvidence(value, expectedReferences, label) {
  if (!isObject(value)) throw new TypeError(`${label} must be an object`);
  if (!EVIDENCE_STATUS.includes(value.evidence_status)) throw new TypeError(`${label}.evidence_status is invalid`);
  if (value.evidence_status !== 'VERIFIED') {
    if (value.results !== null && value.results !== undefined) throw new Error(`${label} ${value.evidence_status} must not supply results`);
    return;
  }
  if (!Array.isArray(value.results)) throw new TypeError(`${label}.results must be an array`);
  const expected = new Set(expectedReferences.map((item) => item.reference_id));
  const seen = new Set();
  for (const [index, result] of value.results.entries()) {
    if (!isObject(result)) throw new TypeError(`${label}.results[${index}] must be an object`);
    requiredString(result.reference_id, `${label}.results[${index}].reference_id`);
    if (!expected.has(result.reference_id)) throw new Error(`${label} has an unknown result ${result.reference_id}`);
    if (seen.has(result.reference_id)) throw new Error(`${label} duplicate result ${result.reference_id}`);
    seen.add(result.reference_id);
    if (!CHECK_STATUS.includes(result.status)) throw new TypeError(`${label} result ${result.reference_id} has invalid status`);
    requiredString(result.reason, `${label} result ${result.reference_id}.reason`);
    assertNoProtectedSemantics(result, `${label}.results[${index}]`, true);
  }
  if (seen.size !== expected.size) {
    const missing = [...expected].filter((id) => !seen.has(id));
    throw new Error(`${label} is missing required results: ${missing.join(',')}`);
  }
}

function validateCandidateEvidence(candidate, fingerprint) {
  if (!isObject(candidate)) throw new TypeError('candidate evidence must be an object');
  if (candidate.schema !== CANDIDATE_EVIDENCE_SCHEMA) throw new Error('invalid candidate evidence schema');
  if (candidate.schema_version !== CANDIDATE_EVIDENCE_SCHEMA_VERSION) throw new Error('invalid candidate evidence schema_version');
  requiredString(candidate.candidate_id, 'candidate_id');
  exactBuild(candidate.source_build, 'candidate source_build');
  if (candidate.source_build !== fingerprint.provenance.exact_build) {
    throw new Error('candidate source_build does not match fingerprint provenance exact build');
  }
  requiredString(candidate.run_id, 'candidate run_id');
  requiredString(candidate.semantic_name, 'candidate semantic_name');
  if (FORBIDDEN_SEMANTIC.test(candidate.semantic_name)) throw new Error('candidate semantic_name violates Parser ownership boundary');
  if (candidate.semantic_name !== fingerprint.semantic_name) throw new Error('candidate semantic_name does not match fingerprint');
  if (candidate.exact_build_only !== true || candidate.nearest_build_fallback !== 'FORBIDDEN') {
    throw new Error('candidate must forbid nearest-build fallback');
  }
  if (candidate.promotion_eligible !== false || candidate.candidate_role !== 'MIGRATION_EVIDENCE_ONLY') {
    throw new Error('candidate must be explicit migration evidence only and never promotion eligible');
  }
  exactBuild(candidate.exact_build, 'candidate exact_build');
  validateProvenance(candidate.provenance, 'candidate provenance');
  if (candidate.provenance.exact_build !== candidate.exact_build) throw new Error('candidate exact build provenance mismatch');
  if (!isObject(candidate.build_binding) || Object.keys(candidate.build_binding).length === 0) throw new TypeError('candidate build_binding must be non-empty');
  assertNoProtectedSemantics(candidate, '$candidate', true);
  validateDimensionEvidence(candidate.structural, STRUCTURAL_FIELDS, 'candidate structural');
  validateDimensionEvidence(candidate.behavioral, BEHAVIORAL_FIELDS, 'candidate behavioral');
  const invariants = fingerprint.cross_field_invariants.map((item) => ({ reference_id: item.invariant_id }));
  validateReferenceEvidence(candidate.cross_field, invariants, 'candidate cross_field');
  validateReferenceEvidence(candidate.ground_truth_oracle, fingerprint.ground_truth_oracles, 'candidate ground_truth_oracle');
  validateReferenceEvidence(candidate.negative_controls, fingerprint.negative_controls, 'candidate negative_controls');
  return [];
}

function unavailableScore(dimension, evidenceStatus, expectedCount, reason) {
  return {
    dimension, score: 0, status: 'UNKNOWN', expected_count: expectedCount, observed_count: 0,
    matched_count: 0, mismatched_count: 0, reasons: [`${dimension} evidence is ${evidenceStatus}`, reason], mismatches: [],
  };
}
function compareFields(dimension, source, candidate, fields) {
  const sourceUnknown = fields.filter((field) => containsUnknownOrUnavailable(source[field]));
  if (sourceUnknown.length) {
    return {
      dimension, score: 0, status: 'UNKNOWN', expected_count: fields.length,
      observed_count: candidate.evidence_status === 'VERIFIED' ? fields.length : 0,
      matched_count: 0, mismatched_count: sourceUnknown.length,
      reasons: ['source fingerprint contains explicit UNKNOWN or UNAVAILABLE evidence; no credit awarded'],
      mismatches: sourceUnknown.map((field) => ({ field, status: 'SOURCE_UNKNOWN_OR_UNAVAILABLE' })),
    };
  }
  if (candidate.evidence_status !== 'VERIFIED') return unavailableScore(dimension, candidate.evidence_status, fields.length, 'no credit awarded');
  const mismatches = fields.filter((field) => !equal(source[field], candidate.observations[field]))
    .map((field) => ({ field, expected: clone(source[field]), observed: clone(candidate.observations[field]) }));
  const matched = fields.length - mismatches.length;
  return {
    dimension, score: matched / fields.length, status: mismatches.length === 0 ? 'PASS' : 'FAIL',
    expected_count: fields.length, observed_count: fields.length, matched_count: matched, mismatched_count: mismatches.length,
    reasons: mismatches.length ? ['one or more required observations mismatched'] : ['all required observations matched'], mismatches,
  };
}
function compareResults(dimension, candidate, expectedReferences) {
  if (candidate.evidence_status !== 'VERIFIED') return unavailableScore(dimension, candidate.evidence_status, expectedReferences.length, 'no credit awarded');
  const resultById = new Map(candidate.results.map((result) => [result.reference_id, result]));
  const mismatches = [];
  let matched = 0;
  let unknown = 0;
  for (const reference of expectedReferences) {
    const result = resultById.get(reference.reference_id);
    if (result.status === 'PASS') matched += 1;
    else if (result.status === 'UNKNOWN' || result.status === 'UNAVAILABLE') {
      unknown += 1;
      mismatches.push({ reference_id: reference.reference_id, status: result.status, reason: result.reason });
    } else mismatches.push({ reference_id: reference.reference_id, status: result.status, reason: result.reason });
  }
  if (unknown) return {
    dimension, score: 0, status: 'UNKNOWN', expected_count: expectedReferences.length, observed_count: candidate.results.length,
    matched_count: matched, mismatched_count: mismatches.length, reasons: ['unknown or unavailable result received; no credit awarded'], mismatches,
  };
  return {
    dimension, score: matched / expectedReferences.length, status: mismatches.length === 0 ? 'PASS' : 'FAIL',
    expected_count: expectedReferences.length, observed_count: candidate.results.length, matched_count: matched,
    mismatched_count: mismatches.length, reasons: mismatches.length ? ['one or more required checks failed'] : ['all required checks passed'], mismatches,
  };
}
function gateFrom(score, gate) {
  return { gate, status: score.status, reasons: [...score.reasons], failed_or_unknown: clone(score.mismatches) };
}

function matchSemanticFingerprint(fingerprint, candidate) {
  validateSemanticFingerprint(fingerprint);
  if (fingerprint.availability !== 'VERIFIED') throw new Error('matcher accepts only a VERIFIED semantic fingerprint');
  validateCandidateEvidence(candidate, fingerprint);
  const structural = compareFields('structural', fingerprint.structural_fingerprint, candidate.structural, STRUCTURAL_FIELDS);
  const behavioral = compareFields('behavioral', fingerprint.behavioral_fingerprint, candidate.behavioral, BEHAVIORAL_FIELDS);
  const crossField = compareResults('cross_field', candidate.cross_field,
    fingerprint.cross_field_invariants.map((item) => ({ reference_id: item.invariant_id })));
  const groundTruth = compareResults('ground_truth_oracle', candidate.ground_truth_oracle, fingerprint.ground_truth_oracles);
  const negative = compareResults('negative_control', candidate.negative_controls, fingerprint.negative_controls);
  const scores = { structural, behavioral, cross_field: crossField, ground_truth_oracle: groundTruth };
  const candidateConservation = Object.fromEntries([
    ['structural', structural], ['behavioral', behavioral], ['cross_field', crossField],
    ['ground_truth_oracle', groundTruth], ['negative_control', negative],
  ].map(([key, score]) => [key, {
    expected_count: score.expected_count, observed_count: score.observed_count,
    matched_count: score.matched_count, mismatched_count: score.mismatched_count,
  }]));
  const gates = {
    invariant_gate: gateFrom(crossField, 'CROSS_FIELD_INVARIANTS'),
    regression_gate: gateFrom(groundTruth, 'GROUND_TRUTH_ORACLE_REGRESSION'),
    negative_control_gate: gateFrom(negative, 'NEGATIVE_CONTROLS'),
  };
  const allPass = [...Object.values(scores), negative].every((score) => score.status === 'PASS');
  const sourceBuild = fingerprint.provenance.exact_build;
  const targetBuild = candidate.exact_build;
  const matcherProvenance = {
    source_build: sourceBuild,
    target_build: targetBuild,
    run_id: candidate.run_id,
    source_fingerprint_sha256: stableHash(fingerprint),
    candidate_evidence_provenance: clone(candidate.provenance),
  };
  const migrationDecisionScores = {
    structural_match_score: structural.score,
    behavioral_match_score: behavioral.score,
    cross_field_match_score: crossField.score,
    ground_truth_oracle_score: groundTruth.score,
  };
  const migrationDecisionCandidate = {
    candidate_id: candidate.candidate_id,
    exact_build: targetBuild,
    migration_class: candidate.migration_class ?? 'REVALIDATED_MACHINE_ONLY',
    provenance: clone(matcherProvenance),
    ...migrationDecisionScores,
  };
  const regressionMatcherScoreReport = {
    schema: 'SEMANTIC_MATCHER_SCORE_REPORT_V1', schema_version: 1,
    semantic_name: fingerprint.semantic_name,
    status: allPass ? 'PASS' : 'FAIL',
    source_build: sourceBuild,
    target_build: targetBuild,
    provenance: clone(matcherProvenance),
    ...migrationDecisionScores,
  };
  return {
    schema: MATCH_RESULT_SCHEMA,
    schema_version: MATCHER_SCHEMA_VERSION,
    matcher_schema: MATCHER_SCHEMA,
    matcher_schema_version: MATCHER_SCHEMA_VERSION,
    semantic_name: fingerprint.semantic_name,
    source_fingerprint: { schema: SEMANTIC_FINGERPRINT_SCHEMA, schema_version: SEMANTIC_FINGERPRINT_SCHEMA_VERSION, hash: matcherProvenance.source_fingerprint_sha256 },
    candidate: { candidate_id: candidate.candidate_id, exact_build: candidate.exact_build, provenance: clone(candidate.provenance), build_binding: clone(candidate.build_binding) },
    source_build: sourceBuild,
    target_build: targetBuild,
    provenance: matcherProvenance,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    migration_oracle_scores: scores,
    migration_decision_scores: migrationDecisionScores,
    migration_decision_candidate: migrationDecisionCandidate,
    regression_matcher_score_report: regressionMatcherScoreReport,
    gates,
    candidate_conservation: candidateConservation,
    decision: {
      status: allPass ? 'MATCH_COMPLETE_NO_PROMOTION' : 'MATCH_INCOMPLETE_OR_FAILED_NO_PROMOTION',
      promotion: 'FORBIDDEN',
      reasons: allPass ? ['all automated dimensions passed; downstream promotion remains a separate authority'] : ['one or more dimensions failed or remain unknown/unavailable'],
    },
  };
}

function matcherSchemaDocument() {
  return {
    schema: 'ROFL_SEMANTIC_FINGERPRINT_MATCHER_SCHEMA_DOCUMENT_V1', schema_version: MATCHER_SCHEMA_VERSION,
    matcher_schema: MATCHER_SCHEMA, candidate_evidence_schema: CANDIDATE_EVIDENCE_SCHEMA,
    result_schema: MATCH_RESULT_SCHEMA, dimensions: DIMENSIONS, evidence_status: EVIDENCE_STATUS,
    check_status: CHECK_STATUS,
    rules: {
      exact_build_only: true, nearest_build_fallback: 'FORBIDDEN', unknown_or_unavailable_credit: 'FORBIDDEN',
      silent_mismatch_drop: 'FORBIDDEN', automatic_promotion: 'FORBIDDEN', protected_holdout_access: 'FORBIDDEN',
      parser_map_behavior_profile_ownership: 'FORBIDDEN',
      migration_decision_score_range: '[0,1]', regression_score_report_emitted: true,
      incomplete_verified_source_matching: 'ZERO_SCORE_NO_PROMOTION',
    },
  };
}
function validateMatcherSchemaDocument(document) {
  if (!isObject(document)) throw new TypeError('matcher schema document must be an object');
  if (document.schema !== 'ROFL_SEMANTIC_FINGERPRINT_MATCHER_SCHEMA_DOCUMENT_V1' || document.schema_version !== MATCHER_SCHEMA_VERSION
      || document.matcher_schema !== MATCHER_SCHEMA || document.candidate_evidence_schema !== CANDIDATE_EVIDENCE_SCHEMA
      || document.result_schema !== MATCH_RESULT_SCHEMA) throw new Error('invalid matcher schema document identity');
  for (const [key, expected] of Object.entries({ dimensions: DIMENSIONS, evidence_status: EVIDENCE_STATUS, check_status: CHECK_STATUS })) {
    if (JSON.stringify(document[key]) !== JSON.stringify(expected)) throw new Error(`invalid matcher schema document ${key}`);
  }
  const rules = document.rules;
  if (!isObject(rules) || rules.exact_build_only !== true || rules.nearest_build_fallback !== 'FORBIDDEN'
      || rules.unknown_or_unavailable_credit !== 'FORBIDDEN' || rules.silent_mismatch_drop !== 'FORBIDDEN'
      || rules.automatic_promotion !== 'FORBIDDEN' || rules.protected_holdout_access !== 'FORBIDDEN'
      || rules.parser_map_behavior_profile_ownership !== 'FORBIDDEN'
      || rules.migration_decision_score_range !== '[0,1]' || rules.regression_score_report_emitted !== true
      || rules.incomplete_verified_source_matching !== 'ZERO_SCORE_NO_PROMOTION') throw new Error('invalid matcher schema document rules');
  return [];
}

module.exports = {
  CANDIDATE_EVIDENCE_SCHEMA,
  CANDIDATE_EVIDENCE_SCHEMA_VERSION,
  CHECK_STATUS,
  DIMENSIONS,
  EVIDENCE_STATUS,
  MATCHER_SCHEMA,
  MATCHER_SCHEMA_VERSION,
  MATCH_RESULT_SCHEMA,
  matcherSchemaDocument,
  matchSemanticFingerprint,
  validateCandidateEvidence,
  validateMatcherSchemaDocument,
};
