'use strict';

const crypto = require('node:crypto');

const SEMANTIC_FINGERPRINT_SCHEMA = 'ROFL_SEMANTIC_FINGERPRINT_V1';
const SEMANTIC_FINGERPRINT_SCHEMA_VERSION = 1;
const EXCEPTION_REGISTRY_SCHEMA = 'ROFL_SEMANTIC_EXCEPTION_REGISTRY_V1';
const EXCEPTION_REGISTRY_SCHEMA_VERSION = 1;
const MIGRATION_POLICIES = Object.freeze(['AUTO_IF_UNIQUE', 'REVALIDATE_IF_AMBIGUOUS']);
const AVAILABILITY = Object.freeze(['VERIFIED', 'UNKNOWN', 'UNAVAILABLE']);
const INVARIANT_MODES = Object.freeze(['STRICT', 'SOFT', 'CHAMPION_EXCEPTION', 'MECHANIC_EXCEPTION']);
const EXCEPTION_SCOPES = Object.freeze(['CHAMPION', 'MECHANIC']);
const SHA256 = /^[a-f0-9]{64}$/i;
const BUILD = /^\d+\.\d+\.\d+\.\d+$/;
const PROTECTED_REFERENCE = /holdout|jungle[ _-]*objective/i;
const FORBIDDEN_OWNERSHIP_KEY = /^(?:map_truth|map_region|strategic_location|player_profile|behavior_inference)$/i;
const FORBIDDEN_OWNERSHIP_REFERENCE = /(?:\bmap[ _-](?:truth|region|knowledge|geometry|topology|behavior)\b|\bstrategic(?:[ _-]location)?\b|\bplayer[ _-]profile\b|\bbehavior(?:al)?[ _-](?:inference|profile|classification)\b)/i;
const FORBIDDEN_VERIFIED_SEMANTIC = /^(?:MAP_|STRATEGIC_|PLAYER_PROFILE|BEHAVIOR_)/;
const BINDING_KEYS = new Set(['route', 'packet_id', 'packet', 'discriminator', 'offset', 'field_offset']);
const STRUCTURAL_FIELDS = Object.freeze([
  'runtime_type', 'registration', 'callback', 'constructor', 'vtable', 'deserializer', 'serializer',
  'component', 'field_type', 'field_position', 'payload_shape', 'surrounding_fields', 'entity_relationship',
]);
const BEHAVIORAL_FIELDS = Object.freeze([
  'value_range', 'temporal_behavior', 'update_frequency', 'event_correlations', 'reset_behavior', 'persistence_behavior',
]);

function own(object, key) { return Object.prototype.hasOwnProperty.call(object, key); }
function isObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function requiredString(value, label) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError(`${label} must be a non-empty string`);
  return value;
}
function exactBuild(value, label = 'exact_build') {
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
function stable(value, seen = new WeakSet()) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('stable hash rejects non-finite numbers');
    return value;
  }
  if (typeof value === 'undefined' || typeof value === 'function' || typeof value === 'symbol') {
    throw new TypeError('stable hash rejects non-JSON values');
  }
  if (Array.isArray(value)) return value.map((item) => stable(item, seen));
  if (!isObject(value)) throw new TypeError('stable hash requires JSON data');
  if (seen.has(value)) throw new TypeError('stable hash rejects cyclic values');
  seen.add(value);
  const result = Object.fromEntries(Object.keys(value).sort((a, b) => a.localeCompare(b, 'en'))
    .map((key) => [key, stable(value[key], seen)]));
  seen.delete(value);
  return result;
}
function stableHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
}

function assertNoProtectedSemantics(value, path = '$', allowCanonical = false) {
  if (typeof value === 'string') {
    if (PROTECTED_REFERENCE.test(value)) throw new Error(`forbidden protected Holdout reference at ${path}`);
    if (FORBIDDEN_OWNERSHIP_REFERENCE.test(value)) throw new Error(`forbidden Parser ownership reference at ${path}`);
    return;
  }
  if (Array.isArray(value)) return value.forEach((item, index) => assertNoProtectedSemantics(item, `${path}[${index}]`, allowCanonical));
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    // The required behavioral_fingerprint container describes protocol-field behavior;
    // it never grants behavior-inference ownership.
    if (PROTECTED_REFERENCE.test(key)
      || (!(allowCanonical && ['behavioral_fingerprint', 'temporal_behavior', 'reset_behavior', 'persistence_behavior'].includes(key))
        && FORBIDDEN_OWNERSHIP_KEY.test(key))) {
      throw new Error(`forbidden protected/ownership key at ${path}.${key}`);
    }
    assertNoProtectedSemantics(child, `${path}.${key}`, allowCanonical);
  }
}

function assertOnlyKeys(object, permitted, label) {
  if (!isObject(object)) throw new TypeError(`${label} must be an object`);
  for (const key of Object.keys(object)) if (!permitted.includes(key)) throw new Error(`${label}.${key} is not permitted`);
}
function nonEmptyValue(value, label) {
  if (value === null || typeof value === 'undefined') throw new TypeError(`${label} must be explicit, not null`);
  if (typeof value === 'string') requiredString(value, label);
  else if (Array.isArray(value) && value.length === 0) throw new TypeError(`${label} must not be empty`);
  else if (isObject(value) && Object.keys(value).length === 0) throw new TypeError(`${label} must not be empty`);
}

function containsExplicitUnknownOrUnavailable(value, seen = new WeakSet()) {
  if (!isObject(value) && !Array.isArray(value)) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (isObject(value) && ['UNKNOWN', 'UNAVAILABLE'].includes(value.status)) return true;
  return Object.values(value).some((item) => containsExplicitUnknownOrUnavailable(item, seen));
}

function incompleteRequiredDimensions(fingerprint) {
  const paths = [];
  for (const field of STRUCTURAL_FIELDS) {
    if (containsExplicitUnknownOrUnavailable(fingerprint.structural_fingerprint[field])) paths.push(`structural_fingerprint.${field}`);
  }
  for (const field of BEHAVIORAL_FIELDS) {
    if (containsExplicitUnknownOrUnavailable(fingerprint.behavioral_fingerprint[field])) paths.push(`behavioral_fingerprint.${field}`);
  }
  return paths.sort();
}

function validateCompletenessContract(fingerprint, incompleteDimensions) {
  if (!incompleteDimensions.length) {
    if (fingerprint.promotion_eligible !== true) throw new Error('complete verified fingerprint must explicitly be promotion eligible');
    if (fingerprint.completeness !== undefined) throw new Error('complete verified fingerprint must not declare an incomplete completeness contract');
    return;
  }
  if (fingerprint.promotion_eligible !== false) {
    throw new Error('incomplete verified fingerprint with UNKNOWN/UNAVAILABLE required dimensions must not be promotion eligible');
  }
  if (fingerprint.migration_policy !== 'REVALIDATE_IF_AMBIGUOUS') {
    throw new Error('incomplete verified fingerprint must require REVALIDATE_IF_AMBIGUOUS');
  }
  const contract = fingerprint.completeness;
  if (!isObject(contract)) throw new TypeError('incomplete verified fingerprint requires a completeness contract');
  assertOnlyKeys(contract, ['status', 'incomplete_dimensions', 'blocking_policy', 'rationale'], 'completeness');
  if (contract.status !== 'INCOMPLETE') throw new Error('completeness.status must be INCOMPLETE');
  if (contract.blocking_policy !== 'REVALIDATE_IF_AMBIGUOUS') throw new Error('completeness.blocking_policy must require REVALIDATE_IF_AMBIGUOUS');
  requiredString(contract.rationale, 'completeness.rationale');
  if (!Array.isArray(contract.incomplete_dimensions) || contract.incomplete_dimensions.some((path) => typeof path !== 'string')) {
    throw new TypeError('completeness.incomplete_dimensions must be a string array');
  }
  const declared = [...new Set(contract.incomplete_dimensions)].sort();
  if (declared.length !== contract.incomplete_dimensions.length || JSON.stringify(declared) !== JSON.stringify(incompleteDimensions)) {
    throw new Error('completeness.incomplete_dimensions must exactly enumerate UNKNOWN/UNAVAILABLE required dimensions');
  }
}

function validateProvenance(provenance, label = 'provenance') {
  if (!isObject(provenance)) throw new TypeError(`${label} must be an object`);
  exactBuild(provenance.exact_build, `${label}.exact_build`);
  const hasReplay = provenance.replay_sha256 !== null && provenance.replay_sha256 !== undefined;
  const hasReplaySet = provenance.replay_set_manifest_sha256 !== null
    && provenance.replay_set_manifest_sha256 !== undefined;
  if (hasReplay === hasReplaySet) {
    throw new Error(`${label} requires exactly one replay_sha256 or replay_set_manifest_sha256`);
  }
  if (hasReplay) {
    sha(provenance.replay_sha256, `${label}.replay_sha256`);
  } else {
    sha(provenance.replay_set_manifest_sha256, `${label}.replay_set_manifest_sha256`);
  }
  sha(provenance.source_sha256, `${label}.source_sha256`);
  requiredString(provenance.source_kind, `${label}.source_kind`);
  assertNoProtectedSemantics(provenance, label, true);
}
function validateBuildBindings(bindings) {
  if (!Array.isArray(bindings) || bindings.length === 0) throw new TypeError('build_bindings must be a non-empty array');
  const ids = new Set();
  for (const [index, binding] of bindings.entries()) {
    if (!isObject(binding)) throw new TypeError(`build_bindings[${index}] must be an object`);
    requiredString(binding.binding_id, `build_bindings[${index}].binding_id`);
    if (ids.has(binding.binding_id)) throw new Error(`duplicate build binding ${binding.binding_id}`);
    ids.add(binding.binding_id);
    exactBuild(binding.exact_build, `build_bindings[${index}].exact_build`);
    validateProvenance(binding.provenance, `build_bindings[${index}].provenance`);
    if (binding.provenance.exact_build !== binding.exact_build) throw new Error(`build binding ${binding.binding_id} provenance build mismatch`);
    if (!isObject(binding.binding) || Object.keys(binding.binding).length === 0) throw new TypeError(`build binding ${binding.binding_id} must have a binding`);
    assertNoProtectedSemantics(binding, `build_bindings[${index}]`, true);
  }
  return ids;
}
function validateExactBuilds(records, bindingIds) {
  if (!Array.isArray(records) || records.length === 0) throw new TypeError('exact_builds_verified must be a non-empty array');
  const unique = new Set();
  for (const [index, record] of records.entries()) {
    if (!isObject(record)) throw new TypeError(`exact_builds_verified[${index}] must be an object`);
    exactBuild(record.exact_build, `exact_builds_verified[${index}].exact_build`);
    validateProvenance(record.provenance, `exact_builds_verified[${index}].provenance`);
    if (record.provenance.exact_build !== record.exact_build) throw new Error(`verified build ${record.exact_build} provenance mismatch`);
    requiredString(record.binding_id, `exact_builds_verified[${index}].binding_id`);
    if (!bindingIds.has(record.binding_id)) throw new Error(`verified build references unknown binding ${record.binding_id}`);
    const replayScope = record.provenance.replay_sha256
      ?? `set:${record.provenance.replay_set_manifest_sha256}`;
    const key = `${record.exact_build}/${record.binding_id}/${replayScope}`;
    if (unique.has(key)) throw new Error(`duplicate exact-build verification ${key}`);
    unique.add(key);
  }
}
function validateReferenceRows(rows, label, fields) {
  if (!Array.isArray(rows) || rows.length === 0) throw new TypeError(`${label} must be a non-empty array`);
  const ids = new Set();
  for (const [index, row] of rows.entries()) {
    if (!isObject(row)) throw new TypeError(`${label}[${index}] must be an object`);
    requiredString(row.reference_id, `${label}[${index}].reference_id`);
    if (ids.has(row.reference_id)) throw new Error(`duplicate ${label} reference ${row.reference_id}`);
    ids.add(row.reference_id);
    for (const field of fields) requiredString(row[field], `${label}[${index}].${field}`);
    validateProvenance(row.provenance, `${label}[${index}].provenance`);
    assertNoProtectedSemantics(row, `${label}[${index}]`, true);
  }
}

class ExceptionRegistry {
  constructor(entries = []) {
    if (!Array.isArray(entries)) throw new TypeError('exception registry entries must be an array');
    this._entries = [];
    this._byId = new Map();
    entries.forEach((entry) => this.add(entry));
  }

  add(entry) {
    if (!isObject(entry)) throw new TypeError('exception entry must be an object');
    requiredString(entry.exception_id, 'exception_id');
    if (this._byId.has(entry.exception_id)) throw new Error(`duplicate exception_id ${entry.exception_id}`);
    if (!EXCEPTION_SCOPES.includes(entry.scope)) throw new TypeError('exception scope must be CHAMPION or MECHANIC');
    requiredString(entry.semantic_name, 'exception semantic_name');
    if (!Array.isArray(entry.exact_builds) || entry.exact_builds.length === 0) throw new TypeError('exception exact_builds must be non-empty');
    entry.exact_builds.forEach((build) => exactBuild(build, 'exception exact_build'));
    if (entry.scope === 'CHAMPION') requiredString(entry.champion, 'champion exception champion');
    if (entry.scope === 'MECHANIC') requiredString(entry.mechanic, 'mechanic exception mechanic');
    requiredString(entry.rationale, 'exception rationale');
    validateProvenance(entry.provenance, 'exception provenance');
    assertNoProtectedSemantics(entry, 'exception', true);
    const frozen = Object.freeze(clone(entry));
    this._entries.push(frozen);
    this._byId.set(frozen.exception_id, frozen);
    return frozen;
  }

  get(exceptionId) { return this._byId.get(exceptionId) || null; }

  resolve({ semantic_name: semanticName, exact_build: exactBuildValue, champion = null, mechanic = null } = {}) {
    requiredString(semanticName, 'semantic_name');
    exactBuild(exactBuildValue);
    return this._entries.filter((entry) => entry.semantic_name === semanticName
      && entry.exact_builds.includes(exactBuildValue)
      && (entry.scope !== 'CHAMPION' || champion === entry.champion)
      && (entry.scope !== 'MECHANIC' || mechanic === entry.mechanic));
  }

  toJSON() {
    return {
      schema: EXCEPTION_REGISTRY_SCHEMA,
      schema_version: EXCEPTION_REGISTRY_SCHEMA_VERSION,
      entries: [...this._entries].sort((a, b) => a.exception_id.localeCompare(b.exception_id, 'en')),
    };
  }
}

function validateInvariant(invariant, index, registry, semanticName) {
  if (!isObject(invariant)) throw new TypeError(`cross_field_invariants[${index}] must be an object`);
  requiredString(invariant.invariant_id, `cross_field_invariants[${index}].invariant_id`);
  requiredString(invariant.expression, `cross_field_invariants[${index}].expression`);
  if (!INVARIANT_MODES.includes(invariant.mode)) throw new TypeError(`invalid invariant mode at ${invariant.invariant_id}`);
  requiredString(invariant.rationale, `cross_field_invariants[${index}].rationale`);
  const refs = invariant.exception_references ?? [];
  if (!Array.isArray(refs)) throw new TypeError(`exception_references for ${invariant.invariant_id} must be an array`);
  if (invariant.mode === 'STRICT' && refs.length) throw new Error(`STRICT invariant ${invariant.invariant_id} cannot reference exceptions`);
  if (invariant.mode === 'SOFT' && !own(invariant, 'tolerance')) throw new Error(`SOFT invariant ${invariant.invariant_id} requires explicit tolerance`);
  if (invariant.mode.endsWith('_EXCEPTION') && refs.length === 0) throw new Error(`${invariant.mode} invariant ${invariant.invariant_id} requires exceptions`);
  for (const reference of refs) {
    requiredString(reference, `exception reference for ${invariant.invariant_id}`);
    if (!registry) continue;
    const entry = registry.get(reference);
    if (!entry) throw new Error(`unknown exception reference ${reference}`);
    if (entry.semantic_name !== semanticName) throw new Error(`exception ${reference} belongs to another semantic`);
    const requiredScope = invariant.mode === 'CHAMPION_EXCEPTION' ? 'CHAMPION' : invariant.mode === 'MECHANIC_EXCEPTION' ? 'MECHANIC' : null;
    if (requiredScope && entry.scope !== requiredScope) throw new Error(`exception ${reference} has wrong scope`);
  }
  assertNoProtectedSemantics(invariant, `cross_field_invariants[${index}]`, true);
}

function validateSemanticFingerprint(fingerprint, { exceptionRegistry = null } = {}) {
  if (!isObject(fingerprint)) throw new TypeError('semantic fingerprint must be an object');
  if (fingerprint.schema !== SEMANTIC_FINGERPRINT_SCHEMA) throw new Error('invalid semantic fingerprint schema');
  if (fingerprint.schema_version !== SEMANTIC_FINGERPRINT_SCHEMA_VERSION) throw new Error('invalid semantic fingerprint schema_version');
  requiredString(fingerprint.semantic_name, 'semantic_name');
  if (!/^[A-Z][A-Z0-9_]*$/.test(fingerprint.semantic_name)) throw new TypeError('semantic_name must be canonical uppercase snake case');
  requiredString(fingerprint.canonical_schema_version, 'canonical_schema_version');
  if (!AVAILABILITY.includes(fingerprint.availability)) throw new TypeError('availability must be VERIFIED, UNKNOWN, or UNAVAILABLE');
  if (fingerprint.availability === 'VERIFIED'
      && FORBIDDEN_VERIFIED_SEMANTIC.test(fingerprint.semantic_name)) {
    throw new Error('verified semantic_name violates Parser ownership boundary');
  }
  assertNoProtectedSemantics(fingerprint, '$', true);
  if (fingerprint.availability !== 'VERIFIED') {
    if (fingerprint.promotion_eligible !== false) throw new Error(`${fingerprint.availability} fingerprint must not be promotion eligible`);
    requiredString(fingerprint.unavailability_reason, 'unavailability_reason');
    if (fingerprint.structural_fingerprint !== null || fingerprint.behavioral_fingerprint !== null
      || fingerprint.cross_field_invariants !== null) throw new Error('unknown/unavailable fingerprint must not fabricate semantic evidence');
    return [];
  }
  validateProvenance(fingerprint.provenance);
  assertOnlyKeys(fingerprint.structural_fingerprint, STRUCTURAL_FIELDS, 'structural_fingerprint');
  for (const field of STRUCTURAL_FIELDS) {
    if (!own(fingerprint.structural_fingerprint, field)) throw new Error(`missing structural_fingerprint.${field}`);
    nonEmptyValue(fingerprint.structural_fingerprint[field], `structural_fingerprint.${field}`);
  }
  for (const key of Object.keys(fingerprint.structural_fingerprint)) if (BINDING_KEYS.has(key)) throw new Error('build-specific binding is forbidden in structural fingerprint');
  assertOnlyKeys(fingerprint.behavioral_fingerprint, BEHAVIORAL_FIELDS, 'behavioral_fingerprint');
  for (const field of BEHAVIORAL_FIELDS) {
    if (!own(fingerprint.behavioral_fingerprint, field)) throw new Error(`missing behavioral_fingerprint.${field}`);
    nonEmptyValue(fingerprint.behavioral_fingerprint[field], `behavioral_fingerprint.${field}`);
  }
  if (!MIGRATION_POLICIES.includes(fingerprint.migration_policy)) throw new TypeError('invalid migration policy');
  validateCompletenessContract(fingerprint, incompleteRequiredDimensions(fingerprint));
  const bindingIds = validateBuildBindings(fingerprint.build_bindings);
  validateExactBuilds(fingerprint.exact_builds_verified, bindingIds);
  if (!Array.isArray(fingerprint.cross_field_invariants) || fingerprint.cross_field_invariants.length === 0) throw new TypeError('cross_field_invariants must be non-empty');
  fingerprint.cross_field_invariants.forEach((item, index) => validateInvariant(item, index, exceptionRegistry, fingerprint.semantic_name));
  validateReferenceRows(fingerprint.ground_truth_oracles, 'ground_truth_oracles', ['case_id', 'oracle_kind']);
  validateReferenceRows(fingerprint.negative_controls, 'negative_controls', ['control_kind', 'rejection_reason']);
  if (!Array.isArray(fingerprint.known_exceptions)) throw new TypeError('known_exceptions must be an array');
  for (const reference of fingerprint.known_exceptions) {
    requiredString(reference, 'known exception reference');
    if (exceptionRegistry && !exceptionRegistry.get(reference)) throw new Error(`unknown known exception ${reference}`);
  }
  return [];
}

class SemanticFingerprint {
  constructor(fingerprint, options = {}) {
    validateSemanticFingerprint(fingerprint, options);
    this._fingerprint = Object.freeze(clone(fingerprint));
    this.hash = stableHash(this._fingerprint);
    Object.freeze(this);
  }

  toJSON() { return clone(this._fingerprint); }
  static validate(fingerprint, options) { return validateSemanticFingerprint(fingerprint, options); }
  static stableHash(value) { return stableHash(value); }
}

function bootstrapFingerprintFromManifestRecord(record, { manifest_sha256 = null } = {}) {
  if (!isObject(record)) throw new TypeError('capability manifest record must be an object');
  requiredString(record.semantic_capability, 'manifest semantic_capability');
  exactBuild(record.build, 'manifest build');
  const unavailable = record.evidence_grade === 'UNAVAILABLE' || record.validation_status === 'UNAVAILABLE';
  const status = unavailable ? 'UNAVAILABLE' : 'UNKNOWN';
  const sourceHash = manifest_sha256 === null ? null : sha(manifest_sha256, 'manifest_sha256');
  const result = {
    schema: SEMANTIC_FINGERPRINT_SCHEMA,
    schema_version: SEMANTIC_FINGERPRINT_SCHEMA_VERSION,
    semantic_name: record.semantic_capability,
    canonical_schema_version: record.canonical_schema_version || 'UNKNOWN_MANIFEST_SCHEMA',
    availability: status,
    promotion_eligible: false,
    unavailability_reason: unavailable
      ? 'CAPABILITY_MANIFEST_DECLARES_UNAVAILABLE'
      : 'CAPABILITY_MANIFEST_EVIDENCE_IS_NOT_A_VERIFIED_SEMANTIC_FINGERPRINT',
    structural_fingerprint: null,
    behavioral_fingerprint: null,
    cross_field_invariants: null,
    manifest_evidence: {
      exact_build: record.build,
      evidence_grade: record.evidence_grade ?? 'UNKNOWN',
      validation_status: record.validation_status ?? 'UNKNOWN',
      manifest_sha256: sourceHash,
    },
  };
  validateSemanticFingerprint(result);
  return result;
}

function semanticFingerprintSchemaDocument() {
  return {
    schema: 'ROFL_SEMANTIC_FINGERPRINT_SCHEMA_DOCUMENT_V1',
    schema_version: SEMANTIC_FINGERPRINT_SCHEMA_VERSION,
    record_schema: SEMANTIC_FINGERPRINT_SCHEMA,
    availability: AVAILABILITY,
    invariant_modes: INVARIANT_MODES,
    migration_policies: MIGRATION_POLICIES,
    structural_fields: STRUCTURAL_FIELDS,
    behavioral_fields: BEHAVIORAL_FIELDS,
    rules: {
      exact_build_only: true,
      nearest_build_fallback: 'FORBIDDEN',
      semantic_truth_and_build_binding_separate: true,
      missing_values_are_never_observed_zero: true,
      protected_holdout_access: 'FORBIDDEN',
      parser_map_behavior_profile_ownership: 'FORBIDDEN',
      verified_incomplete_promotion: 'FORBIDDEN',
      incomplete_verified_policy: 'REVALIDATE_IF_AMBIGUOUS',
    },
  };
}

function validateSemanticFingerprintSchemaDocument(document) {
  if (!isObject(document)) throw new TypeError('semantic fingerprint schema document must be an object');
  if (document.schema !== 'ROFL_SEMANTIC_FINGERPRINT_SCHEMA_DOCUMENT_V1') throw new Error('invalid semantic fingerprint schema document');
  if (document.schema_version !== SEMANTIC_FINGERPRINT_SCHEMA_VERSION) throw new Error('invalid semantic fingerprint schema document version');
  if (document.record_schema !== SEMANTIC_FINGERPRINT_SCHEMA) throw new Error('invalid semantic fingerprint record schema');
  for (const [key, expected] of Object.entries({
    availability: AVAILABILITY,
    invariant_modes: INVARIANT_MODES,
    migration_policies: MIGRATION_POLICIES,
    structural_fields: STRUCTURAL_FIELDS,
    behavioral_fields: BEHAVIORAL_FIELDS,
  })) {
    if (JSON.stringify(document[key]) !== JSON.stringify(expected)) throw new Error(`invalid semantic fingerprint schema document ${key}`);
  }
  const rules = document.rules;
  if (!isObject(rules) || rules.exact_build_only !== true || rules.nearest_build_fallback !== 'FORBIDDEN'
      || rules.semantic_truth_and_build_binding_separate !== true
      || rules.missing_values_are_never_observed_zero !== true
      || rules.protected_holdout_access !== 'FORBIDDEN'
      || rules.parser_map_behavior_profile_ownership !== 'FORBIDDEN'
      || rules.verified_incomplete_promotion !== 'FORBIDDEN'
      || rules.incomplete_verified_policy !== 'REVALIDATE_IF_AMBIGUOUS') {
    throw new Error('invalid semantic fingerprint schema document rules');
  }
  return [];
}

function exceptionRegistrySchemaDocument() {
  return {
    schema: 'ROFL_SEMANTIC_EXCEPTION_REGISTRY_SCHEMA_DOCUMENT_V1',
    schema_version: EXCEPTION_REGISTRY_SCHEMA_VERSION,
    record_schema: EXCEPTION_REGISTRY_SCHEMA,
    scopes: EXCEPTION_SCOPES,
    required_scope_binding: ['semantic_name', 'exact_builds', 'CHAMPION.champion', 'MECHANIC.mechanic'],
    protected_holdout_access: 'FORBIDDEN',
  };
}

function validateExceptionRegistrySchemaDocument(document) {
  if (!isObject(document)) throw new TypeError('exception registry schema document must be an object');
  if (document.schema !== 'ROFL_SEMANTIC_EXCEPTION_REGISTRY_SCHEMA_DOCUMENT_V1') throw new Error('invalid exception registry schema document');
  if (document.schema_version !== EXCEPTION_REGISTRY_SCHEMA_VERSION) throw new Error('invalid exception registry schema document version');
  if (document.record_schema !== EXCEPTION_REGISTRY_SCHEMA) throw new Error('invalid exception registry record schema');
  if (JSON.stringify(document.scopes) !== JSON.stringify(EXCEPTION_SCOPES)) throw new Error('invalid exception registry scopes');
  if (JSON.stringify(document.required_scope_binding) !== JSON.stringify(['semantic_name', 'exact_builds', 'CHAMPION.champion', 'MECHANIC.mechanic'])) {
    throw new Error('invalid exception registry scope binding');
  }
  if (document.protected_holdout_access !== 'FORBIDDEN') throw new Error('invalid exception registry Holdout policy');
  return [];
}

module.exports = {
  AVAILABILITY,
  EXCEPTION_REGISTRY_SCHEMA,
  EXCEPTION_REGISTRY_SCHEMA_VERSION,
  EXCEPTION_SCOPES,
  INVARIANT_MODES,
  MIGRATION_POLICIES,
  SEMANTIC_FINGERPRINT_SCHEMA,
  SEMANTIC_FINGERPRINT_SCHEMA_VERSION,
  ExceptionRegistry,
  SemanticFingerprint,
  assertNoProtectedSemantics,
  bootstrapFingerprintFromManifestRecord,
  exceptionRegistrySchemaDocument,
  semanticFingerprintSchemaDocument,
  stableHash,
  validateExceptionRegistrySchemaDocument,
  validateSemanticFingerprintSchemaDocument,
  validateSemanticFingerprint,
};
