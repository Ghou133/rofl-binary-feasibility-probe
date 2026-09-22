'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const component = require('../src/exact_build_champion_component');
const { importMechanicsBuild } = require('../src/mechanics_build_importer');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function writeSource(root, name, value) {
  const target = path.join(root, name);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, value);
  return { path: target, sha256: sha256(value) };
}

function field(value, sourceField) {
  return value === null ? { value: null, missing: true, source_field: null }
    : { value, missing: false, source_field: sourceField, source_wrapper_field: 'baseValue' };
}

function fixture(root) {
  const executable = writeSource(root, 'Game/League of Legends.exe', Buffer.from('exact-build-exe'));
  const hashFiles = ['hashes.game.txt', 'hashes.binentries.txt', 'hashes.bintypes.txt', 'hashes.binfields.txt', 'hashes.binhashes.txt']
    .map((name) => ({ name, ...writeSource(root, `hashes/${name}`, Buffer.from(name)) }));
  const wad = writeSource(root, 'Game/DATA/FINAL/Champions/Aatrox.wad.client', Buffer.from('aatrox-wad'));
  const stats = {
    health: { base: field(650, 'baseHPModifiable'), per_level: field(114, 'hpPerLevelModifiable') },
    health_regen: { base: field(3, 'baseStaticHPRegenModifiable'), per_level: field(0.5, 'hpRegenPerLevelModifiable') },
    armor: { base: field(38, 'baseArmorModifiable'), per_level: field(4.8, 'armorPerLevelModifiable') },
    magic_resist: { base: field(32, 'baseMR'), per_level: field(2.05, 'mrPerLevel') },
    attack_damage: { base: field(60, 'baseDamageModifiable'), per_level: field(5, 'damagePerLevelModifiable') },
    attack_speed: { base_modifier: field(0.651, 'attackSpeedModifiable'), ratio: field(0.65, 'attackSpeedRatioModifiable'), per_level_percent: field(2.5, 'attackSpeedPerLevelModifiable') },
    movement_speed: { base: field(345, 'baseMoveSpeedModifiable') },
    resources: { primary: { type: field(0, 'arType') } },
  };
  const report = {
    schema: 'ROFL_EXACT_BUILD_CHAMPION_STATS_V1', status: 'EXACT_BUILD_EXTRACTED', exact_build: '16.16.805.0442',
    build_binding: { status: 'EXACT_BUILD_MATCH', requested_canonical: '16.16.805.0442', observed_canonical: '16.16.805.0442', ...executable },
    scope: { wad_directory: path.join(root, 'Game/DATA/FINAL/Champions'), enumeration: 'NONLOCALIZED_CHAMPIONS_DIRECT_CHILDREN_ONLY', parsed_member_per_wad: 'data/characters/<champion>/<champion>.bin ONLY', parsed_entry_per_bin: 'Characters/<champion>/CharacterRecords/Root ONLY' },
    source_hashes: { build_metadata: executable, cdtb_hash_files: hashFiles, champion_wads: [wad] },
    champion_count: 1,
    champions: [{ champion_wad_name: 'Aatrox', character_name: 'Aatrox', wad, root_bin: { wad_member_path: 'data/characters/aatrox/aatrox.bin', sha256: sha256('root-bin'), byte_size: 8 }, root_character_record: { entry_path: 'Characters/Aatrox/CharacterRecords/Root', type: 'CharacterRecord' }, normalized_stats: stats, missing_fields: [] }],
    protected_holdout: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
  };
  const reportPath = path.join(root, 'champion-stats.json');
  const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(reportPath, bytes);
  return { reportPath, expectedSha256: sha256(bytes), report };
}

test('maps every direct root CharacterRecord with direct values, nulls, provenance, and coverage', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'champion-component-'));
  try {
    const source = fixture(root);
    source.report.champions[0].normalized_stats.attack_speed.ratio = field(null, null);
    source.report.champions[0].missing_fields = ['attack_speed.ratio'];
    const bytes = Buffer.from(`${JSON.stringify(source.report, null, 2)}\n`);
    fs.writeFileSync(source.reportPath, bytes);
    const result = component.buildExactBuildChampionComponent({ ...source, expectedSha256: sha256(bytes) });
    const row = result.component.rows[0];
    assert.equal(result.component.consumer_permission, false);
    assert.equal(result.component.formula_semantics, 'NOT_CLAIMED');
    assert.equal(row.base_stats.armor, 38);
    assert.equal(row.growth_stats.attack_speed_percent, 2.5);
    assert.equal(row.base_stats.attack_speed_ratio, null);
    assert.equal(row.resource_type, 0);
    assert.equal(row.field_provenance['base_stats.armor'].source_field, 'baseArmorModifiable');
    assert.ok(row.missing_fields.includes('base_stats.attack_speed_ratio'));
    assert.equal(result.component.coverage.mapped_root_character_records, 1);
    assert.equal(result.component.coverage.per_stat_populated_rows['base_stats.attack_speed_ratio'], 0);
    assert.equal(result.component.coverage.per_stat_populated_rows.resource_type, 1);
    assert.equal(result.semanticScope.coverage_status, 'COMPLETE_EXACT_BUILD_COMPONENT_COVERAGE');
    assert.match(result.semanticScope.validation_evidence_sha256, /^[a-f0-9]{64}$/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('rejects report hash, build binding, source hash, and direct or realpath Holdout paths', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'champion-component-'));
  try {
    const source = fixture(root);
    assert.throws(() => component.buildExactBuildChampionComponent({ ...source, expectedSha256: '0'.repeat(64) }), /report hash mismatch/);
    source.report.build_binding.observed_canonical = '16.16.805.0443';
    let bytes = Buffer.from(`${JSON.stringify(source.report)}\n`);
    fs.writeFileSync(source.reportPath, bytes);
    assert.throws(() => component.buildExactBuildChampionComponent({ ...source, expectedSha256: sha256(bytes) }), /canonical exact-build mismatch/);
    source.report.build_binding.observed_canonical = '16.16.805.0442';
    source.report.source_hashes.champion_wads[0].sha256 = 'a'.repeat(64);
    source.report.champions[0].wad.sha256 = 'a'.repeat(64);
    bytes = Buffer.from(`${JSON.stringify(source.report)}\n`);
    fs.writeFileSync(source.reportPath, bytes);
    assert.throws(() => component.buildExactBuildChampionComponent({ ...source, expectedSha256: sha256(bytes) }), /champion WAD source 0 hash mismatch/);
    assert.throws(() => component.assertNoHoldoutPath(path.join(root, 'Protected_Holdout', 'input'), 'fixture'), /restricted Holdout/);
    const holdout = path.join(root, 'named-Holdout-target');
    fs.mkdirSync(holdout);
    const alias = path.join(root, 'safe-alias');
    try { fs.symlinkSync(holdout, alias, 'junction'); } catch { return; }
    assert.throws(() => component.canonicalizeExistingSafePath(alias, 'alias'), /restricted Holdout/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('writes a descriptor-ready component, validation evidence, and artifact closure deterministically', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'champion-component-'));
  try {
    const source = fixture(root);
    const first = component.writeExactBuildChampionComponentArtifacts({ ...source, outputDir: path.join(root, 'out') });
    const firstComponent = fs.readFileSync(first.paths.component);
    const second = component.writeExactBuildChampionComponentArtifacts({ ...source, outputDir: path.join(root, 'out') });
    assert.deepEqual(fs.readFileSync(second.paths.component), firstComponent);
    assert.equal(second.descriptor.component, 'champion');
    assert.equal(second.descriptor.consumer_permission, false);
    assert.equal(second.descriptor.semantic_scope.validation_evidence_sha256,
      second.validationEvidence.validation_evidence_sha256);
    const imported = importMechanicsBuild({ sources: [second.descriptor] });
    assert.equal(imported.components.champion.status, 'VERIFIED_EXACT_BUILD_NORMALIZED');
    assert.equal(imported.components.champion.rows[0].id, 'Aatrox');
    assert.equal(imported.consumer_permission, false);
    assert.ok(fs.existsSync(second.paths.closure));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('unverified test fixtures are explicitly non-publishable and rejected by the mechanics importer', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'champion-component-unverified-'));
  try {
    const source = fixture(root);
    const falseHash = 'a'.repeat(64);
    source.report.source_hashes.champion_wads[0].sha256 = falseHash;
    source.report.champions[0].wad.sha256 = falseHash;
    const bytes = Buffer.from(`${JSON.stringify(source.report, null, 2)}\n`);
    fs.writeFileSync(source.reportPath, bytes);
    const options = {
      ...source,
      expectedSha256: sha256(bytes),
      verifySourceBytes: false,
      allowUnverifiedTestFixture: true,
      outputDir: path.join(root, 'out'),
    };
    assert.throws(() => component.buildExactBuildChampionComponent({ ...options, allowUnverifiedTestFixture: false }),
      /only for an explicit unverified test fixture/);
    const result = component.writeExactBuildChampionComponentArtifacts(options);
    assert.equal(result.component.status, 'UNVERIFIED_SOURCE_BYTES_ROOT_CHARACTER_RECORDS_NORMALIZED');
    assert.equal(result.component.publication_eligible, false);
    assert.equal(result.validationEvidence.evidence_grade, 'UNVERIFIED_SOURCE_BYTES');
    assert.equal(result.semanticScope.validation_status, 'SOURCE_BYTES_NOT_VERIFIED');
    assert.equal(result.descriptor.exact_build_identity.status, 'SOURCE_BYTES_NOT_VERIFIED');
    assert.equal(result.descriptor.publication_eligible, false);
    const imported = importMechanicsBuild({ sources: [result.descriptor] });
    assert.equal(imported.components.champion.status, 'UNAVAILABLE_EXACT_BUILD_GATE_FAILED');
    assert.equal(imported.components.champion.rows.length, 0);
    assert.equal(imported.source_inventory[0].status, 'EXACT_BUILD_IDENTITY_OR_EQUIVALENCE_REJECTED');
    assert.equal(imported.consumer_permission, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
