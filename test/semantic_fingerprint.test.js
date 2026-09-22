'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  ExceptionRegistry,
  MIGRATION_POLICIES,
  SemanticFingerprint,
  bootstrapFingerprintFromManifestRecord,
  exceptionRegistrySchemaDocument,
  semanticFingerprintSchemaDocument,
  stableHash,
  validateExceptionRegistrySchemaDocument,
  validateSemanticFingerprintSchemaDocument,
  validateSemanticFingerprint,
} = require('../src/semantic_fingerprint');

const BUILD = '16.16.805.0442';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

function provenance(build = BUILD, replay = SHA_A, source = SHA_B) {
  return { exact_build: build, replay_sha256: replay, source_sha256: source, source_kind: 'CONTROLLED_REPLAY' };
}
function corpusProvenance(build = BUILD, manifest = SHA_A, source = SHA_B) {
  return { exact_build: build, replay_set_manifest_sha256: manifest, source_sha256: source, source_kind: 'CONTROLLED_REPLAY_CORPUS' };
}
function registry() {
  return new ExceptionRegistry([
    { exception_id: 'hp-champion', scope: 'CHAMPION', semantic_name: 'CURRENT_HP', champion: 'Yone', exact_builds: [BUILD], rationale: 'temporary state', provenance: provenance() },
    { exception_id: 'hp-mechanic', scope: 'MECHANIC', semantic_name: 'CURRENT_HP', mechanic: 'TEMPORARY_HP', exact_builds: [BUILD], rationale: 'temporary state', provenance: provenance() },
  ]);
}
function fingerprint(overrides = {}) {
  return {
    schema: 'ROFL_SEMANTIC_FINGERPRINT_V1', schema_version: 1,
    semantic_name: 'CURRENT_HP', canonical_schema_version: 'ROFL_SEMANTIC_SCHEMA_V2', availability: 'VERIFIED', promotion_eligible: true,
    provenance: provenance(),
    structural_fingerprint: {
      runtime_type: 'AIHeroClient', registration: 'health callback family', callback: 'state update', constructor: 'hero state constructor', vtable: 'client vtable shape', deserializer: 'native decoder', serializer: 'receive serializer', component: 'hero state component', field_type: 'float32', field_position: 'state field ordinal', payload_shape: ['state'], surrounding_fields: ['level'], entity_relationship: 'hero subject',
    },
    behavioral_fingerprint: {
      value_range: { minimum: 0 }, temporal_behavior: 'damage decreases and heal increases', update_frequency: 'event driven', event_correlations: ['damage', 'heal'], reset_behavior: 'respawn restores', persistence_behavior: 'persists between updates',
    },
    build_bindings: [{ binding_id: '16_16_hp', exact_build: BUILD, provenance: provenance(), binding: { route: '0x010c', field_offset: 40 } }],
    exact_builds_verified: [{ exact_build: BUILD, binding_id: '16_16_hp', provenance: provenance() }],
    cross_field_invariants: [
      { invariant_id: 'nonnegative', expression: 'CURRENT_HP >= 0', mode: 'STRICT', rationale: 'numeric domain' },
      { invariant_id: 'bounded', expression: 'CURRENT_HP <= MAX_HP', mode: 'CHAMPION_EXCEPTION', rationale: 'temporary state exception', exception_references: ['hp-champion'] },
      { invariant_id: 'temporary', expression: 'CURRENT_HP <= EFFECTIVE_MAX_HP', mode: 'MECHANIC_EXCEPTION', rationale: 'temporary state exception', exception_references: ['hp-mechanic'] },
      { invariant_id: 'cadence', expression: 'updates are observed near transitions', mode: 'SOFT', tolerance: { max_lag_ms: 1000 }, rationale: 'transport cadence' },
    ],
    ground_truth_oracles: [{ reference_id: 'gt-1', case_id: 'case-1', oracle_kind: 'MACHINE_CONTROLLED', provenance: provenance() }],
    negative_controls: [{ reference_id: 'nc-1', control_kind: 'SCOREBOARD_SNAPSHOT', rejection_reason: 'coarse cadence', provenance: provenance() }],
    known_exceptions: ['hp-champion', 'hp-mechanic'], migration_policy: 'AUTO_IF_UNIQUE',
    ...overrides,
  };
}
function fingerprintWithCorpusProvenance() {
  const corpus = corpusProvenance();
  const base = fingerprint();
  return {
    ...base,
    provenance: corpus,
    build_bindings: base.build_bindings.map((binding) => ({ ...binding, provenance: corpus })),
    exact_builds_verified: base.exact_builds_verified.map((verified) => ({ ...verified, provenance: corpus })),
    ground_truth_oracles: base.ground_truth_oracles.map((oracle) => ({ ...oracle, provenance: corpus })),
    negative_controls: base.negative_controls.map((control) => ({ ...control, provenance: corpus })),
  };
}

test('verified fingerprint validates exact replay/source provenance and has deterministic stable hash', () => {
  const value = fingerprint();
  const semantic = new SemanticFingerprint(value, { exceptionRegistry: registry() });
  assert.equal(semantic.hash, stableHash(value));
  assert.equal(stableHash({ z: [2, 1], a: { q: true } }), stableHash({ a: { q: true }, z: [2, 1] }));
  assert.deepEqual(semantic.toJSON(), value);
  assert.deepEqual(MIGRATION_POLICIES, ['AUTO_IF_UNIQUE', 'REVALIDATE_IF_AMBIGUOUS']);
});

test('verified corpus provenance uses an explicit replay-set manifest hash instead of inventing one Replay hash', () => {
  const value = fingerprintWithCorpusProvenance();
  const semantic = new SemanticFingerprint(value, { exceptionRegistry: registry() });
  assert.equal(semantic.toJSON().provenance.replay_sha256, undefined);
  assert.equal(semantic.toJSON().provenance.replay_set_manifest_sha256, SHA_A);
  assert.throws(() => validateSemanticFingerprint(fingerprint({
    provenance: { ...provenance(), replay_set_manifest_sha256: SHA_B },
  }), { exceptionRegistry: registry() }), /exactly one replay_sha256 or replay_set_manifest_sha256/);
});

test('incomplete VERIFIED fingerprints require a complete no-promotion contract and revalidation policy', () => {
  const structural = { ...fingerprint().structural_fingerprint, payload_shape: { status: 'UNKNOWN', retained: 'opaque payload' } };
  const incomplete = fingerprint({
    structural_fingerprint: structural,
    promotion_eligible: false,
    migration_policy: 'REVALIDATE_IF_AMBIGUOUS',
    completeness: {
      status: 'INCOMPLETE',
      incomplete_dimensions: ['structural_fingerprint.payload_shape'],
      blocking_policy: 'REVALIDATE_IF_AMBIGUOUS',
      rationale: 'payload layout is explicitly retained as unknown',
    },
  });
  assert.deepEqual(validateSemanticFingerprint(incomplete, { exceptionRegistry: registry() }), []);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ structural_fingerprint: structural }), { exceptionRegistry: registry() }), /must not be promotion eligible/);
  assert.throws(() => validateSemanticFingerprint({ ...incomplete, migration_policy: 'AUTO_IF_UNIQUE' }, { exceptionRegistry: registry() }), /require REVALIDATE_IF_AMBIGUOUS/);
  assert.throws(() => validateSemanticFingerprint({
    ...incomplete,
    completeness: { ...incomplete.completeness, incomplete_dimensions: [] },
  }, { exceptionRegistry: registry() }), /exactly enumerate/);
});

test('fingerprints fail closed on build provenance, missing dimensions, route leakage, and invalid invariants', () => {
  const exceptions = registry();
  assert.throws(() => validateSemanticFingerprint(fingerprint({ provenance: { ...provenance(), exact_build: '16.16' } }), { exceptionRegistry: exceptions }), /four-component/);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ structural_fingerprint: { ...fingerprint().structural_fingerprint, runtime_type: null } }), { exceptionRegistry: exceptions }), /runtime_type/);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ structural_fingerprint: { ...fingerprint().structural_fingerprint, route: '0x1' } }), { exceptionRegistry: exceptions }), /not permitted/);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ cross_field_invariants: [{ invariant_id: 'bad', expression: 'x', mode: 'STRICT', rationale: 'x', exception_references: ['hp-champion'] }] }), { exceptionRegistry: exceptions }), /STRICT invariant/);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ cross_field_invariants: [{ invariant_id: 'bad', expression: 'x', mode: 'CHAMPION_EXCEPTION', rationale: 'x', exception_references: ['hp-mechanic'] }] }), { exceptionRegistry: exceptions }), /wrong scope/);
  assert.throws(() => stableHash({ value: Number.NaN }), /non-finite/);
});

test('exception registry scopes every exception to semantic, champion/mechanic, and exact build', () => {
  const exceptions = registry();
  assert.equal(exceptions.resolve({ semantic_name: 'CURRENT_HP', exact_build: BUILD, champion: 'Yone' }).length, 1);
  assert.equal(exceptions.resolve({ semantic_name: 'CURRENT_HP', exact_build: BUILD, champion: 'Ahri' }).length, 0);
  assert.equal(exceptions.resolve({ semantic_name: 'CURRENT_HP', exact_build: '16.15.801.3452', champion: 'Yone' }).length, 0);
  assert.throws(() => exceptions.add({ exception_id: 'bad', scope: 'CHAMPION', semantic_name: 'CURRENT_HP', champion: 'Yone', exact_builds: [BUILD], rationale: 'x', provenance: { ...provenance(), replay_sha256: 'bad' } }), /SHA-256/);
});

test('protected holdout paths and parser-forbidden ownership semantics are rejected before use', () => {
  assert.throws(() => validateSemanticFingerprint(fingerprint({ negative_controls: [{ reference_id: 'x', control_kind: 'x', rejection_reason: 'x', provenance: { ...provenance(), source_kind: 'JUNGLE_OBJECTIVE_HOLDOUT' } }] }), { exceptionRegistry: registry() }), /forbidden/);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ semantic_name: 'MAP_REGION' }), { exceptionRegistry: registry() }), /ownership boundary/);
  assert.throws(() => validateSemanticFingerprint(fingerprint({ structural_fingerprint: { ...fingerprint().structural_fingerprint, map_truth: 'forbidden' } }), { exceptionRegistry: registry() }), /forbidden/);
  assert.throws(() => new ExceptionRegistry([{ exception_id: 'bad', scope: 'MECHANIC', semantic_name: 'CURRENT_HP', mechanic: 'map behavior', exact_builds: [BUILD], rationale: 'x', provenance: provenance() }]), /forbidden/);
});

test('manifest bootstrap preserves UNKNOWN and UNAVAILABLE without promoting candidate evidence or fabricating zero', () => {
  const unavailable = bootstrapFingerprintFromManifestRecord({ semantic_capability: 'ARMOR', build: BUILD, canonical_schema_version: 'ROFL_SEMANTIC_SCHEMA_V2', evidence_grade: 'UNAVAILABLE', validation_status: 'UNAVAILABLE' }, { manifest_sha256: SHA_A });
  assert.equal(unavailable.availability, 'UNAVAILABLE');
  assert.equal(unavailable.promotion_eligible, false);
  assert.equal(unavailable.structural_fingerprint, null);
  const candidate = bootstrapFingerprintFromManifestRecord({ semantic_capability: 'CURRENT_HP', build: BUILD, evidence_grade: 'CANDIDATE', validation_status: 'CANDIDATE_ONLY' });
  assert.equal(candidate.availability, 'UNKNOWN');
  assert.equal(candidate.manifest_evidence.evidence_grade, 'CANDIDATE');
  assert.throws(() => validateSemanticFingerprint({ ...candidate, promotion_eligible: true }), /must not be promotion eligible/);
  const unavailableMap = bootstrapFingerprintFromManifestRecord({ semantic_capability: 'MAP_MECHANIC', build: BUILD, canonical_schema_version: 'ROFL_SEMANTIC_SCHEMA_V2', evidence_grade: 'UNAVAILABLE', validation_status: 'UNAVAILABLE' });
  assert.equal(unavailableMap.availability, 'UNAVAILABLE');
  assert.equal(unavailableMap.promotion_eligible, false);
  assert.equal(unavailableMap.structural_fingerprint, null);
  assert.notEqual(unavailableMap.availability, 'VERIFIED');
});

test('schema-document exports are complete and fail closed when a governing rule changes', () => {
  const semanticDocument = semanticFingerprintSchemaDocument();
  const exceptionDocument = exceptionRegistrySchemaDocument();
  assert.deepEqual(validateSemanticFingerprintSchemaDocument(semanticDocument), []);
  assert.equal(semanticDocument.rules.verified_incomplete_promotion, 'FORBIDDEN');
  assert.equal(semanticDocument.rules.incomplete_verified_policy, 'REVALIDATE_IF_AMBIGUOUS');
  assert.deepEqual(validateExceptionRegistrySchemaDocument(exceptionDocument), []);
  assert.throws(() => validateSemanticFingerprintSchemaDocument({
    ...semanticDocument,
    rules: { ...semanticDocument.rules, protected_holdout_access: 'ALLOWED' },
  }), /rules/);
  assert.throws(() => validateExceptionRegistrySchemaDocument({
    ...exceptionDocument, scopes: ['CHAMPION'],
  }), /scopes/);
});
