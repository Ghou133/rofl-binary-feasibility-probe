'use strict';

const { ExceptionRegistry, validateSemanticFingerprint } = require('./semantic_fingerprint');
const REGRESSION_INTEGRATION_SCHEMA = 'SEMANTIC_REGRESSION_INTEGRATION_V1';
const REGRESSION_REPORT_SCHEMA = 'SEMANTIC_REGRESSION_ORACLE_REPORT_V1';
const REGRESSION_SCHEMA_DOCUMENT = 'SEMANTIC_REGRESSION_ORACLE_SCHEMA_DOCUMENT_V1';
const MATCH_RESULT_SCHEMA = 'ROFL_SEMANTIC_FINGERPRINT_MATCH_RESULT_V1';
const ALIGNMENT_SCHEMA = 'GROUND_TRUTH_ALIGNMENT_V1';
const BUILD = /^\d+\.\d+\.\d+\.\d+$/;
const SHA256 = /^[a-f0-9]{64}$/i;
const SCORE_FIELDS = Object.freeze(['structural_match_score', 'behavioral_match_score', 'cross_field_match_score', 'ground_truth_oracle_score']);
const GATE_FIELDS = Object.freeze(['invariant_gate', 'regression_gate', 'negative_control_gate']);

function assert(ok, message) { if (!ok) throw new Error(message); }
function object(value, label) { assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`); return value; }
function string(value, label) { assert(typeof value === 'string' && value.length > 0, `${label} is required`); return value; }
function build(value, label) { assert(typeof value === 'string' && BUILD.test(value), `${label} must use strict N.N.N.N exact-build form`); return value; }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function protectedReference(value, seen = new Set()) {
  if (typeof value === 'string') return /holdout|jungle[ _-]*objective/i.test(value);
  if (!value || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  return Object.entries(value).some(([key, child]) => /holdout|jungle[ _-]*objective/i.test(key) || protectedReference(child, seen));
}
function rejectProtectedHoldout(value) { assert(!protectedReference(value), 'protected Holdout references are forbidden before regression evaluation'); }
function validateProvenance(provenance, sourceBuild, targetBuild) {
  object(provenance, 'provenance'); build(provenance.source_build, 'provenance.source_build'); build(provenance.target_build, 'provenance.target_build');
  assert(provenance.source_build === sourceBuild && provenance.target_build === targetBuild, 'provenance build mismatch'); string(provenance.run_id, 'provenance.run_id');
}

function normalizedScores(matcher) {
  if (matcher.migration_decision_scores !== undefined) {
    object(matcher.migration_decision_scores, 'matcher migration_decision_scores');
    return Object.fromEntries(SCORE_FIELDS.map((field) => {
      const value = matcher.migration_decision_scores[field];
      assert(typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1, `matcher migration_decision_scores.${field} must be normalized from 0 to 1`);
      return [field, value];
    }));
  }
  object(matcher.migration_oracle_scores, 'matcher migration_oracle_scores');
  const names = { structural_match_score: 'structural', behavioral_match_score: 'behavioral', cross_field_match_score: 'cross_field', ground_truth_oracle_score: 'ground_truth_oracle' };
  return Object.fromEntries(Object.entries(names).map(([field, name]) => {
    const value = matcher.migration_oracle_scores[name]?.score;
    assert(typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100, `matcher migration_oracle_scores.${name}.score must be numeric`);
    return [field, value <= 1 ? value : value / 100];
  }));
}
function matcherGate(matcher, name) {
  const status = matcher.gates?.[name]?.status;
  assert(['PASS', 'FAIL', 'UNKNOWN', 'UNAVAILABLE'].includes(status), `matcher gate ${name} has invalid status`);
  return status === 'PASS' ? 'PASS' : 'FAIL';
}
function validateMatcher(matcher, fingerprint, sourceBuild, targetBuild) {
  object(matcher, 'matcher_score_report');
  assert(matcher.schema === MATCH_RESULT_SCHEMA && matcher.schema_version === 1, 'invalid matcher_score_report schema');
  assert(matcher.semantic_name === fingerprint.semantic_name, 'matcher_score_report semantic mismatch');
  assert(matcher.exact_build_only === true && matcher.nearest_build_fallback === 'FORBIDDEN', 'matcher exact-build policy mismatch');
  build(matcher.candidate?.exact_build, 'matcher candidate exact_build');
  assert(matcher.candidate.exact_build === targetBuild && matcher.candidate.provenance?.exact_build === targetBuild, 'matcher target-build provenance mismatch');
  if (matcher.source_build !== undefined) { build(matcher.source_build, 'matcher source_build'); assert(matcher.source_build === sourceBuild, 'matcher source-build mismatch'); }
  if (matcher.target_build !== undefined) { build(matcher.target_build, 'matcher target_build'); assert(matcher.target_build === targetBuild, 'matcher target-build mismatch'); }
  if (matcher.provenance !== undefined) validateProvenance(matcher.provenance, sourceBuild, targetBuild);
  const sourceFingerprintSha = matcher.source_fingerprint?.hash;
  assert(typeof sourceFingerprintSha === 'string' && SHA256.test(sourceFingerprintSha), 'matcher source_fingerprint.hash must be a SHA-256');
  return { source_fingerprint_sha256: sourceFingerprintSha, scores: normalizedScores(matcher), gates: Object.fromEntries(GATE_FIELDS.map((name) => [name, matcherGate(matcher, name)])) };
}

function candidateValue(row) { return row?.observed_value ?? row?.value ?? row?.decoded_value; }
function same(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
function validateCrossBuildAdapter(adapter, sourceBuild, targetBuild) {
  object(adapter, 'cross_build_alignment_adapter');
  assert(adapter.schema === 'GROUND_TRUTH_CROSS_BUILD_ALIGNMENT_ADAPTER_V1' && adapter.schema_version === 1, 'invalid cross_build_alignment_adapter schema');
  build(adapter.source_build, 'cross_build_alignment_adapter.source_build'); build(adapter.target_build, 'cross_build_alignment_adapter.target_build');
  assert(adapter.source_build === sourceBuild && adapter.target_build === targetBuild && adapter.status === 'PASS', 'cross_build_alignment_adapter build/status mismatch');
  validateProvenance(adapter.provenance, sourceBuild, targetBuild);
}
function alignmentGate(alignment, sourceBuild, targetBuild, tolerance, adapter) {
  object(alignment, 'ground_truth_alignment');
  assert(alignment.schema_version === ALIGNMENT_SCHEMA && alignment.exact_build_only === true, 'invalid ground_truth_alignment contract');
  assert(Array.isArray(alignment.results), 'ground_truth_alignment.results must be an array'); object(alignment.counts, 'ground_truth_alignment.counts');
  const counts = { matched: 0, unmatched: 0, ambiguous: 0 };
  for (const row of alignment.results) { object(row, 'ground_truth_alignment result'); if (row.status === 'MATCHED') counts.matched += 1; else if (row.status === 'UNMATCHED') counts.unmatched += 1; else if (row.status === 'AMBIGUOUS') counts.ambiguous += 1; else throw new Error(`ground_truth_alignment has unknown result status ${row.status}`); }
  for (const key of Object.keys(counts)) assert(alignment.counts[key] === counts[key], `ground_truth_alignment counts.${key} mismatch`);
  if (sourceBuild !== targetBuild) validateCrossBuildAdapter(adapter, sourceBuild, targetBuild);
  const failures = alignment.results.filter((row) => {
    if (row.status !== 'MATCHED') return true;
    if (typeof row.residual === 'number') return !Number.isFinite(row.residual) || Math.abs(row.residual) > tolerance;
    return !same(candidateValue(row.candidate), row.oracle?.observed_value);
  });
  return { gate: failures.length ? 'FAIL' : 'PASS', failures, conservation: { oracle_cases: alignment.results.length, preserved_results: alignment.results.length, status: 'PASS', silent_discard: 'FORBIDDEN' } };
}
function validateExceptionAudit(audit, registry, semanticName, targetBuild) {
  const value = audit ?? { status: 'PASS', exceptions: [] }; object(value, 'exception_audit');
  assert(['PASS', 'EXCEPTION_ACCOUNTED'].includes(value.status) && Array.isArray(value.exceptions), 'invalid exception_audit');
  for (const reference of value.exceptions) {
    object(reference, 'exception_audit reference'); string(reference.exception_id, 'exception_audit exception_id');
    const entry = registry.get(reference.exception_id); assert(entry, `unknown exception reference ${reference.exception_id}`);
    assert(entry.semantic_name === semanticName && entry.exact_builds.includes(targetBuild) && entry.scope === reference.scope, `exception ${reference.exception_id} scope mismatch`);
    if (entry.scope === 'CHAMPION') assert(entry.champion === reference.champion, `exception ${reference.exception_id} champion mismatch`);
    if (entry.scope === 'MECHANIC') assert(entry.mechanic === reference.mechanic, `exception ${reference.exception_id} mechanic mismatch`);
  }
  if (value.status === 'EXCEPTION_ACCOUNTED') assert(value.exceptions.length > 0, 'EXCEPTION_ACCOUNTED requires referenced exceptions');
  return clone(value);
}
function validateMachineAttestations(attestations, sourceBuild, targetBuild) {
  assert(Array.isArray(attestations) && attestations.length > 0, 'machine_suite_attestations must be a non-empty array');
  const ids = new Set();
  for (const row of attestations) {
    object(row, 'machine suite attestation'); string(row.suite_id, 'machine suite attestation suite_id');
    assert(!ids.has(row.suite_id), `duplicate machine suite ${row.suite_id}`); ids.add(row.suite_id);
    build(row.target_build, 'machine suite attestation target_build'); assert(row.target_build === targetBuild, 'machine suite target-build mismatch');
    assert(['PASS', 'FAIL'].includes(row.status), 'machine suite status must be PASS or FAIL');
    validateProvenance(row.provenance, sourceBuild, targetBuild);
  }
  return attestations.filter((row) => row.status === 'FAIL');
}
function regressionIntegrationSchemaDocument() { return { schema: REGRESSION_SCHEMA_DOCUMENT, schema_version: 1, report_schema: REGRESSION_REPORT_SCHEMA, matcher_result_schema: MATCH_RESULT_SCHEMA, alignment_schema_version: ALIGNMENT_SCHEMA, required_inputs: ['semantic_fingerprint', 'source_build', 'target_build', 'ground_truth_alignment', 'matcher_score_report', 'exception_registry', 'machine_suite_attestations', 'provenance'], emitted_gates: [...GATE_FIELDS], rules: { exact_build_only: true, cross_build_adapter_required: true, alignment_conservation_required: true, protected_holdout_access: 'FORBIDDEN', promotion_authority: 'NONE', silent_discard: 'FORBIDDEN' } }; }

function runRegressionIntegration(input) {
  rejectProtectedHoldout(input); object(input, 'regression integration input');
  assert(input.schema === REGRESSION_INTEGRATION_SCHEMA && input.schema_version === 1, 'invalid regression integration input schema');
  build(input.source_build, 'source_build'); build(input.target_build, 'target_build'); string(input.semantic_name, 'semantic_name'); validateProvenance(input.provenance, input.source_build, input.target_build);
  assert(input.exception_registry instanceof ExceptionRegistry, 'exception_registry must be an ExceptionRegistry'); validateSemanticFingerprint(input.semantic_fingerprint, { exceptionRegistry: input.exception_registry });
  const fingerprint = input.semantic_fingerprint;
  assert(fingerprint.semantic_name === input.semantic_name && fingerprint.availability === 'VERIFIED' && fingerprint.provenance.exact_build === input.source_build, 'semantic fingerprint mismatch, unavailable, or source-build provenance mismatch');
  const matcher = validateMatcher(input.matcher_score_report, fingerprint, input.source_build, input.target_build);
  const tolerance = input.residual_tolerance ?? 0; assert(typeof tolerance === 'number' && Number.isFinite(tolerance) && tolerance >= 0, 'residual_tolerance must be non-negative');
  const aligned = alignmentGate(input.ground_truth_alignment, input.source_build, input.target_build, tolerance, input.cross_build_alignment_adapter);
  const exceptionAudit = validateExceptionAudit(input.exception_audit, input.exception_registry, fingerprint.semantic_name, input.target_build);
  const failedMachineSuites = validateMachineAttestations(input.machine_suite_attestations, input.source_build, input.target_build);
  const gates = { invariant_gate: matcher.gates.invariant_gate, regression_gate: matcher.gates.regression_gate === 'PASS' && aligned.gate === 'PASS' ? 'PASS' : 'FAIL', negative_control_gate: matcher.gates.negative_control_gate };
  if (failedMachineSuites.length) gates.regression_gate = 'FAIL';
  const reportProvenance = { ...input.provenance, source_fingerprint_sha256: matcher.source_fingerprint_sha256 };
  const candidate = { candidate_id: `regression:${fingerprint.semantic_name}:${input.target_build}`, exact_build: input.target_build, ...matcher.scores, ...gates, exception_audit: { status: exceptionAudit.status, exceptions: exceptionAudit.exceptions }, provenance: { ...reportProvenance, regression_report_schema: REGRESSION_REPORT_SCHEMA } };
  return { schema: REGRESSION_REPORT_SCHEMA, schema_version: 1, integration_schema: REGRESSION_INTEGRATION_SCHEMA, semantic_name: fingerprint.semantic_name, source_build: input.source_build, target_build: input.target_build, exact_build: input.target_build, promotion_authority: 'NONE', promotion_status: 'NOT_PROMOTED', gates, matcher_scores: matcher.scores, matcher_score_report: input.matcher_score_report, alignment: input.ground_truth_alignment, alignment_failures: aligned.failures, exception_audit: exceptionAudit, machine_suite_attestations: input.machine_suite_attestations, failed_machine_suite_attestations: failedMachineSuites, migration_decision_candidate: candidate, provenance: reportProvenance, conservation: { ...aligned.conservation, silent_fallback: 'FORBIDDEN' } };
}
module.exports = { GATE_FIELDS, REGRESSION_INTEGRATION_SCHEMA, REGRESSION_REPORT_SCHEMA, REGRESSION_SCHEMA_DOCUMENT, SCORE_FIELDS, protectedReference, rejectProtectedHoldout, regressionIntegrationSchemaDocument, runRegressionIntegration };
