'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const manifestApi = require('../src/capability_manifest');
const repositoryRoot = path.resolve(__dirname, '..');

test('capability manifest covers the canonical vocabulary for each registered exact build', () => {
  const manifest = manifestApi.createCapabilityManifest();
  assert.deepEqual(manifestApi.validateCapabilityManifest(manifest), []);
  assert.equal(manifest.exact_build_only, true);
  assert.equal(manifest.nearest_build_fallback, 'FORBIDDEN');
  for (const build of [manifestApi.BUILD_16_15, manifestApi.BUILD_16_16]) {
    assert.deepEqual(manifest.build_profiles[build].records.map((record) => record.semantic_capability),
      manifestApi.CAPABILITY_VOCABULARY);
  }
});

test('manifest retains field-specific evidence and promotes only proven exact-build combat fields', () => {
  const manifest = manifestApi.createCapabilityManifest();
  const damage15 = manifestApi.queryCapability(manifest, { build: manifestApi.BUILD_16_15, capability: 'DAMAGE' });
  assert.equal(damage15.record.protocol_route, '0x028a');
  assert.equal(damage15.record.evidence_grade, 'VERIFIED_DIRECT');
  assert.match(damage15.record.field_mapping.amount, /^direct recorded amount/);
  const damageType15 = manifestApi.queryCapability(manifest, {
    build: manifestApi.BUILD_16_15, capability: 'DAMAGE_TYPE',
  });
  assert.equal(damageType15.record.evidence_grade, 'VERIFIED_DIRECT');
  assert.equal(damageType15.record.field_mapping.field_21_0, 'physical');
  assert.equal(damageType15.record.sample_count.event_count, 27625);
  const attribution15 = manifestApi.queryCapability(manifest, { build: manifestApi.BUILD_16_15, capability: 'DAMAGE_SOURCE_ATTRIBUTION' });
  assert.equal(attribution15.record.evidence_grade, 'VERIFIED_DIRECT');
  assert.equal(attribution15.record.validation_status, 'PARTIAL');
  assert.equal(attribution15.record.field_mapping.source_entity, 'direct');
  assert.equal(attribution15.record.field_mapping.spell_item_rune_passive, null);
  const damage16 = manifestApi.queryCapability(manifest, { build: manifestApi.BUILD_16_16, capability: 'DAMAGE' });
  assert.equal(damage16.record.protocol_route, '0x017f');
  assert.equal(damage16.record.evidence_grade, 'VERIFIED_DIRECT');
  assert.equal(damage16.record.validation_status, 'PASS');
  assert.equal(damage16.record.sample_count.event_count, 266332);
  const damageType16 = manifestApi.queryCapability(manifest, {
    build: manifestApi.BUILD_16_16, capability: 'DAMAGE_TYPE',
  });
  assert.equal(damageType16.record.evidence_grade, 'VERIFIED_DIRECT');
  assert.equal(damageType16.record.field_mapping.field_28_1, 'magic');
  const currentHp15 = manifestApi.queryCapability(manifest, {
    build: manifestApi.BUILD_16_15, capability: 'CURRENT_HP',
  });
  assert.equal(currentHp15.record.evidence_grade, 'UNAVAILABLE');
  assert.equal(currentHp15.record.sample_count.event_count, 6222445);
  assert.deepEqual(currentHp15.record.negative_examples,
    ['artifacts/semantic_coverage_v1/combat_candidate_report.json']);
  assert.match(currentHp15.record.known_limits.join(' '), /structural live-family candidates only/);
});

test('query API rejects unregistered builds and never selects a near profile', () => {
  const manifest = manifestApi.createCapabilityManifest();
  assert.deepEqual(manifestApi.queryCapability(manifest, { build: '16.17.0.0', capability: 'HERO_PATH' }), {
    status: 'UNSUPPORTED_BUILD', build: '16.17.0.0', record: null,
  });
});

test('semantic compatibility separates route, decoder, semantics, and canonical schema', () => {
  const manifest = manifestApi.createCapabilityManifest();
  const matrix = manifestApi.createSemanticCompatibilityMatrix(manifest);
  assert.deepEqual(manifestApi.validateSemanticCompatibilityMatrix(matrix), []);
  const pathRow = manifestApi.querySemanticCompatibility(matrix, 'HERO_PATH');
  assert.equal(pathRow.binary_compatible, 'NO');
  assert.equal(pathRow.decoder_compatible, 'NO');
  assert.equal(pathRow.semantic_compatible, 'YES');
  assert.match(pathRow.semantic_compatibility_declaration.rationale, /canonical HeroPath semantic/);
  assert.equal(pathRow.schema_compatible, 'YES');
  const participantRow = manifestApi.querySemanticCompatibility(matrix, 'PARTICIPANT_MAPPING');
  assert.equal(participantRow.semantic_compatible, 'UNVERIFIED');
  assert.equal(participantRow.schema_compatible, 'YES');
  const damageRow = manifestApi.querySemanticCompatibility(matrix, 'DAMAGE');
  assert.equal(damageRow.semantic_compatible, 'UNVERIFIED');
});

test('semantic equivalence is never inferred from matching evidence grades', () => {
  const manifest = manifestApi.createCapabilityManifest();
  const matrix = manifestApi.createSemanticCompatibilityMatrix(manifest);
  assert.equal(manifestApi.querySemanticCompatibility(matrix, 'ROFL_CONTAINER').semantic_compatible,
    'UNVERIFIED');

  const downgraded = structuredClone(manifest);
  const record = downgraded.build_profiles[manifestApi.BUILD_16_16].records
    .find((item) => item.semantic_capability === 'HERO_PATH');
  record.evidence_grade = 'UNAVAILABLE';
  record.validation_status = 'UNAVAILABLE';
  const downgradedMatrix = manifestApi.createSemanticCompatibilityMatrix(downgraded);
  assert.equal(manifestApi.querySemanticCompatibility(downgradedMatrix, 'HERO_PATH').semantic_compatible,
    'NOT_COMPARABLE');
});

test('manifest validation rejects malformed samples and evidence/status overclaims', () => {
  const invalid = structuredClone(manifestApi.createCapabilityManifest());
  const damage = invalid.build_profiles[manifestApi.BUILD_16_15].records
    .find((item) => item.semantic_capability === 'DAMAGE');
  damage.sample_count.event_count = -1;
  damage.evidence_grade = 'CANDIDATE';
  damage.validation_status = 'PASS';
  const errors = manifestApi.validateCapabilityManifest(invalid);
  assert.ok(errors.some((error) => error.includes('sample_count.event_count')));
  assert.ok(errors.some((error) => error.includes('candidate status inconsistency')));
});

test('write and read APIs preserve valid canonical JSON artifacts', () => {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-capability-manifest-'));
  try {
    const manifestPath = path.join(temporaryDirectory, 'capability_manifest.json');
    const matrixPath = path.join(temporaryDirectory, 'semantic_compatibility_matrix.json');
    manifestApi.writeCapabilityManifest(manifestPath);
    manifestApi.writeSemanticCompatibilityMatrix(matrixPath);
    assert.deepEqual(manifestApi.validateCapabilityManifest(manifestApi.readCapabilityManifest(manifestPath)), []);
    assert.deepEqual(manifestApi.validateSemanticCompatibilityMatrix(JSON.parse(fs.readFileSync(matrixPath, 'utf8'))), []);
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test('checked-in artifacts validate and match the canonical generators', () => {
  const artifactDirectory = path.join(repositoryRoot, 'artifacts', 'semantic_coverage_v1');
  const manifest = JSON.parse(fs.readFileSync(path.join(artifactDirectory, 'capability_manifest.json'), 'utf8'));
  const matrix = JSON.parse(fs.readFileSync(path.join(artifactDirectory, 'semantic_compatibility_matrix.json'), 'utf8'));
  assert.deepEqual(manifest, manifestApi.createCapabilityManifest());
  assert.deepEqual(matrix, manifestApi.createSemanticCompatibilityMatrix(manifest));
});
