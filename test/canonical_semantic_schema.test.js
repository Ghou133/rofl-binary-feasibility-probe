'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  CANONICAL_EVENT_TYPES,
  CANONICAL_SEMANTIC_SCHEMA_VERSION,
  ENTITY_TYPE_VOCABULARY,
  EVIDENCE_STATUS_VOCABULARY,
  assertAllowedInputPath,
  blankFields,
  buildCanonicalSemanticSchemaArtifacts,
  buildEntityTypeRegistry,
  buildExactBuildAdapterMetadata,
  canonicalSchemaDocument,
  createCanonicalRecord,
  validateCanonicalRecord,
} = require('../src/canonical_semantic_schema');
const { parseArgs } = require('../scripts/build_canonical_semantic_schema');

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function exactManifest() {
  const records = [
    ['PARTICIPANT_MAPPING', 'VERIFIED_DERIVED', 'PASS', 'metadata + exact network-id rule'],
    ['WARD_SPAWN', 'VERIFIED_DERIVED', 'PASS', '0x049a'],
    ['DAMAGE', 'VERIFIED_DIRECT', 'PASS', '0x017f'],
    ['DAMAGE_TYPE', 'VERIFIED_DIRECT', 'PASS', '0x017f'],
    ['HERO_PATH', 'VERIFIED_DERIVED', 'PASS', '0x00f6'],
    ['CAST_SPELL', 'UNAVAILABLE', 'UNAVAILABLE', null],
  ].map(([semantic_capability, evidence_grade, validation_status, protocol_route]) => ({
    semantic_capability, evidence_grade, validation_status, protocol_route,
    packet_registration_route: protocol_route, decoder_version: `fixture-${semantic_capability}`,
    field_mapping: {}, known_limits: [],
  }));
  return { exact_build_only: true, nearest_build_fallback: 'FORBIDDEN', build_profiles: {
    '16.16.805.0442': { records },
  } };
}

test('canonical schema declares all required domains and explicit evidence/null contracts', () => {
  assert.ok(CANONICAL_EVENT_TYPES.includes('HeroState'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('DamageEvent'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('BuffEvent'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('SpellCast'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('EntityLifecycle'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('WardEvent'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('ItemEvent'));
  assert.ok(CANONICAL_EVENT_TYPES.includes('ObjectiveEvent'));
  assert.deepEqual(ENTITY_TYPE_VOCABULARY, ['CHAMPION', 'MINION', 'MONSTER', 'WARD', 'MISSILE', 'STRUCTURE', 'OBJECTIVE', 'MAP_MECHANIC', 'UNKNOWN_ENTITY']);
  assert.ok(EVIDENCE_STATUS_VOCABULARY.includes('UNKNOWN'));
  assert.ok(EVIDENCE_STATUS_VOCABULARY.includes('NOT_GAMEPLAY_RELEVANT'));
  const schema = canonicalSchemaDocument();
  assert.equal(schema.schema_version, CANONICAL_SEMANTIC_SCHEMA_VERSION);
  assert.match(schema.consumer_contract.adapter_boundary, /only in exact-build adapter/i);
  assert.ok(schema.canonical_event_types.every((row) => Object.values(row.fields).every((field) => field.no_implicit_zero)));
});

test('canonical records preserve zero, require explicit null/unknown, provenance, and reject adapter leaks', () => {
  const blank = blankFields('DamageEvent');
  blank.fields.amount = 0;
  blank.field_evidence.amount = 'VERIFIED_DIRECT';
  const record = createCanonicalRecord('DamageEvent', {
    event_id: 'damage:fixture', exact_build: '16.16.805.0442', replay_sha256: 'a'.repeat(64), replay_time_ms: 1,
    fields: blank.fields, field_evidence: blank.field_evidence,
    evidence: { status: 'VERIFIED_DIRECT', limitations: ['stage remains unknown'] },
    provenance: { source_kind: 'ROFL', source_artifact_sha256: 'b'.repeat(64), parser_version: 'fixture', exact_build_adapter_id: 'fixture-DAMAGE' },
  });
  assert.equal(record.fields.amount, 0);
  assert.equal(record.fields.amount_semantic_stage, null);
  assert.equal(record.field_evidence.amount_semantic_stage, 'UNKNOWN');
  const invalidNull = structuredClone(record);
  invalidNull.field_evidence.amount = 'UNAVAILABLE';
  assert.throws(() => validateCanonicalRecord(invalidNull), /cannot be UNAVAILABLE/);
  const leaked = structuredClone(record);
  leaked.protocol_route = '0x017f';
  assert.throws(() => validateCanonicalRecord(leaked), /leaks exact-build adapter key/);
  const missing = structuredClone(record);
  delete missing.fields.amount;
  assert.throws(() => validateCanonicalRecord(missing), /exactly the declared/);
  assert.throws(() => createCanonicalRecord('DamageEvent', {}), /must be explicit/);
});

test('entity registry only marks participant-backed champions, wards, and unknown preservation verified', () => {
  const registry = buildEntityTypeRegistry(exactManifest());
  const byType = new Map(registry.entries.map((row) => [row.entity_type, row]));
  assert.equal(byType.get('CHAMPION').status, 'VERIFIED_DERIVED');
  assert.equal(byType.get('WARD').status, 'VERIFIED_DERIVED');
  assert.equal(byType.get('UNKNOWN_ENTITY').status, 'VERIFIED_DIRECT');
  for (const type of ['MINION', 'MONSTER', 'MISSILE', 'STRUCTURE', 'OBJECTIVE', 'MAP_MECHANIC']) {
    assert.equal(byType.get(type).status, 'UNAVAILABLE');
    assert.deepEqual(byType.get(type).verified_subtypes, []);
  }
});

test('exact-build routes stay in adapter metadata and reject nearest-build or missing exact profile', () => {
  const adapter = buildExactBuildAdapterMetadata(exactManifest());
  assert.ok(adapter.bindings.some((row) => row.semantic_capability === 'DAMAGE' && row.protocol_route === '0x017f'));
  const consumer = canonicalSchemaDocument();
  assert.equal(JSON.stringify(consumer).includes('0x017f'), false);
  assert.throws(() => buildExactBuildAdapterMetadata(exactManifest(), '16.16.805.0443'), /no exact profile/);
});

test('artifact build is deterministic, hashes content, and rejects Holdout before touching it', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'canonical-semantic-schema-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, 'input'), { recursive: true });
  fs.writeFileSync(path.join(root, 'input', 'manifest.json'), `${JSON.stringify(exactManifest(), null, 2)}\n`);
  const first = buildCanonicalSemanticSchemaArtifacts({ root, capabilityManifestPath: 'input/manifest.json', outputDirectory: 'out' });
  const second = buildCanonicalSemanticSchemaArtifacts({ root, capabilityManifestPath: 'input/manifest.json', outputDirectory: 'out' });
  assert.equal(first.files.length, 4);
  assert.deepEqual(first.files, second.files);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'out', 'artifact_manifest.json'), 'utf8'));
  assert.equal(manifest.self_hash_excluded, true);
  for (const row of manifest.files) assert.equal(sha256File(path.join(root, 'out', row.file)), row.sha256);
  assert.throws(() => assertAllowedInputPath('Jungle_Objective_Holdout/secret.json'), /Holdout paths are forbidden/);
  assert.throws(() => buildCanonicalSemanticSchemaArtifacts({ root, capabilityManifestPath: 'Jungle_Objective_Holdout/secret.json' }), /Holdout paths are forbidden/);
});

test('CLI parsing has strict exact-build defaults', () => {
  const defaults = parseArgs([]);
  assert.equal(defaults.exactBuild, '16.16.805.0442');
  assert.equal(defaults.outputDirectory, 'artifacts/full_semantic_baseline_v1/schema');
  assert.throws(() => parseArgs(['--bad']), /unknown option/);
});
