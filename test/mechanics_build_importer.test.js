'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  COMPONENTS, COMPONENT_SEMANTIC_CONTRACTS, EXACT_BUILD, diffMechanicsBuilds, importMechanicsBuild, sha256File,
  writeMechanicsBuildArtifacts,
} = require('../src/mechanics_build_importer');

function hash(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function writeFixture(dir, name, value) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name);
  const text = `${JSON.stringify(value)}\n`;
  fs.writeFileSync(file, text);
  return { file, sha256: hash(text) };
}

function exactDescriptor(component, fixture) {
  const contract = COMPONENT_SEMANTIC_CONTRACTS[component];
  return {
    id: `${component}-local-exact`, component, path: fixture.file, expected_sha256: fixture.sha256,
    source: 'LOCAL_EXACT_BUILD_GAME_ASSET', declared_version: EXACT_BUILD, declared_build: EXACT_BUILD,
    evidence_grade: 'VERIFIED_DIRECT',
    exact_build_identity: { build: EXACT_BUILD, status: 'VERIFIED_EXACT_BUILD_IDENTITY' },
    content_equivalence: { target_build: EXACT_BUILD, status: 'NOT_REQUIRED_IDENTITY_DIRECT' },
    semantic_scope: {
      schema: 'ROFL_COMPONENT_SEMANTIC_SCOPE_V1', component, scope: contract.scope,
      coverage_status: 'COMPLETE_EXACT_BUILD_COMPONENT_COVERAGE',
      validation_status: 'VERIFIED_COMPONENT_SEMANTICS', evidence_grade: 'VERIFIED_DIRECT',
      validation_evidence_sha256: '1'.repeat(64), validated_fields: [...contract.required_fields],
    },
  };
}

function completeSources(dir, changedArmor = false) {
  return COMPONENTS.map((component) => {
    const plural = `${component}s`;
    const value = component === 'champion'
      ? { [plural]: [{ id: 'Ashe', base_stats: { armor: changedArmor ? 27 : 26 }, growth_stats: { armor: 4 } }, { id: 'Braum', base_stats: { armor: 47 }, growth_stats: { armor: 5 } }] }
      : component === 'item'
        ? { [plural]: [{ id: 'item-one', always_active_stats: { armor: 20 }, conditional_effects: [] }] }
        : component === 'rune'
          ? { [plural]: [{ id: 'rune-one', persistent_effects: [], conditional_effects: [] }] }
          : component === 'buff'
            ? { [plural]: [{ id: 'buff-one', stat_modifiers: [] }] }
            : { [plural]: [{ id: 'formula-one', expression: 'x+y', inputs: ['x', 'y'] }] };
    return exactDescriptor(component, writeFixture(dir, `${component}.json`, value));
  });
}

test('exact-build fixture imports all mechanics components and hashes every explicit source', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-exact-'));
  try {
    const mechanics = importMechanicsBuild({ sources: completeSources(dir) });
    assert.equal(mechanics.exact_build, EXACT_BUILD);
    assert.equal(mechanics.status, 'READY');
    assert.equal(mechanics.consumer_permission, true);
    assert.equal(mechanics.source_inventory.length, COMPONENTS.length);
    for (const component of COMPONENTS) {
      assert.equal(mechanics.components[component].status, 'VERIFIED_EXACT_BUILD_NORMALIZED');
      assert.ok(mechanics.components[component].rows.length > 0);
    }
    assert.equal(mechanics.components.champion.rows[0].id, 'Ashe');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('wrong build and source hash fail before normalization', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-invalid-'));
  try {
    const sources = completeSources(dir);
    assert.throws(() => importMechanicsBuild({ requestedBuild: '16.16.805.0443', sources }), /exact-build request mismatch/);
    sources[0].expected_sha256 = '0'.repeat(64);
    assert.throws(() => importMechanicsBuild({ sources }), /hash mismatch/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('direct Holdout source path is rejected before a read or hash', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-direct-'));
  try {
    const holdout = path.join(dir, 'fixture-Holdout'); fs.mkdirSync(holdout);
    const fixture = writeFixture(holdout, 'champion.json', { champions: [{ id: 'Ashe' }] });
    const originalRead = fs.readFileSync; let read = false;
    fs.readFileSync = function guarded(file, ...args) { if (String(file).includes('fixture-Holdout')) read = true; return originalRead.call(this, file, ...args); };
    try { assert.throws(() => importMechanicsBuild({ sources: [exactDescriptor('champion', fixture)] }), /restricted Holdout path/); }
    finally { fs.readFileSync = originalRead; }
    assert.equal(read, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('alias resolving into Holdout is rejected after realpath and before a read', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-alias-'));
  try {
    const holdout = path.join(dir, 'fixture-Holdout-target'); const alias = path.join(dir, 'safe-alias');
    fs.mkdirSync(holdout); const fixture = writeFixture(holdout, 'champion.json', { champions: [{ id: 'Ashe' }] });
    fs.symlinkSync(holdout, alias, 'junction');
    const aliased = { ...fixture, file: path.join(alias, 'champion.json') };
    const originalRead = fs.readFileSync; let read = false;
    fs.readFileSync = function guarded(file, ...args) { if (String(file).includes('safe-alias') || String(file).includes('Holdout')) read = true; return originalRead.call(this, file, ...args); };
    try { assert.throws(() => importMechanicsBuild({ sources: [exactDescriptor('champion', aliased)] }), /restricted Holdout path/); }
    finally { fs.readFileSync = originalRead; }
    assert.equal(read, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('patch-family source is inventoried as a negative control and cannot authorize values', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-patch-'));
  try {
    const fixture = writeFixture(dir, 'champion.json', { champions: [{ id: 'Ashe', base_stats: { armor: 26 }, growth_stats: { armor: 4 } }] });
    const source = { ...exactDescriptor('champion', fixture), id: 'champion-patch-reference',
      patch_family: true, binding_status: 'PATCH_FAMILY_PINNED',
      exact_build_identity: { build: EXACT_BUILD, status: 'VERIFIED_EXACT_BUILD_IDENTITY' } };
    const mechanics = importMechanicsBuild({ sources: [source] });
    assert.equal(mechanics.status, 'FAIL_CLOSED_MISSING_OR_REJECTED_INPUTS');
    assert.equal(mechanics.components.champion.rows.length, 0);
    assert.equal(mechanics.source_inventory[0].status, 'PATCH_FAMILY_REFERENCE_REJECTED');
    assert.equal(mechanics.consumer_permission, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('exact-build descriptive JSON without a semantic scope contract is inventoried but cannot authorize mechanics', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-descriptive-'));
  try {
    const fixture = writeFixture(dir, 'champion.json', { champions: [{ id: 'Ashe', armor: 26 }] });
    const source = exactDescriptor('champion', fixture);
    delete source.semantic_scope;
    const mechanics = importMechanicsBuild({ sources: [source] });
    assert.equal(mechanics.components.champion.status, 'UNAVAILABLE_EXACT_BUILD_GATE_FAILED');
    assert.equal(mechanics.components.champion.rows.length, 0);
    assert.equal(mechanics.source_inventory[0].semantic_scope_gate, 'FAIL');
    assert.equal(mechanics.source_inventory[0].status, 'EXACT_BUILD_SEMANTIC_SCOPE_REJECTED');
    assert.equal(mechanics.consumer_permission, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('exact-build scope claims reject partial component records missing validated fields', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-partial-'));
  try {
    const fixture = writeFixture(dir, 'item.json', { items: [{ id: 'item-one', always_active_stats: { armor: 20 } }] });
    const mechanics = importMechanicsBuild({ sources: [exactDescriptor('item', fixture)] });
    assert.equal(mechanics.components.item.status, 'UNAVAILABLE_EXACT_BUILD_GATE_FAILED');
    assert.equal(mechanics.components.item.rows.length, 0);
    assert.equal(mechanics.source_inventory[0].semantic_scope_gate, 'PASS');
    assert.equal(mechanics.source_inventory[0].component_field_gate, 'FAIL');
    assert.equal(mechanics.source_inventory[0].status, 'EXACT_BUILD_COMPONENT_FIELDS_REJECTED');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('exact-build scope claims reject component-inappropriate validated field shapes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-invalid-shape-'));
  try {
    const fixture = writeFixture(dir, 'formula.json', { formulas: [{ id: 'formula-one', expression: '', inputs: 'x,y' }] });
    const mechanics = importMechanicsBuild({ sources: [exactDescriptor('formula', fixture)] });
    assert.equal(mechanics.components.formula.rows.length, 0);
    assert.equal(mechanics.source_inventory[0].component_field_gate, 'FAIL');
    assert.equal(mechanics.consumer_permission, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('missing components fail closed without filesystem discovery', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-missing-'));
  try {
    const mechanics = importMechanicsBuild({ sources: [completeSources(dir)[0]] });
    assert.equal(mechanics.status, 'FAIL_CLOSED_MISSING_OR_REJECTED_INPUTS');
    assert.deepEqual(mechanics.missing_inputs, ['item', 'rune', 'buff', 'formula']);
    assert.equal(mechanics.consumer_permission, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an empty explicit source set reports every required input as missing', () => {
  const mechanics = importMechanicsBuild();
  assert.equal(mechanics.status, 'FAIL_CLOSED_MISSING_OR_REJECTED_INPUTS');
  assert.deepEqual(mechanics.missing_inputs, COMPONENTS);
  assert.equal(mechanics.source_inventory.length, 0);
});

test('artifact closure is deterministic, closes payload hashes, and build diff is stable', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mechanics-importer-artifacts-'));
  try {
    const first = writeMechanicsBuildArtifacts({ outputDir: path.join(root, 'a'), sources: completeSources(path.join(root, 'sources-a')) });
    const second = writeMechanicsBuildArtifacts({ outputDir: path.join(root, 'b'), sources: completeSources(path.join(root, 'sources-b')) });
    assert.deepEqual(first.mechanics, second.mechanics);
    assert.deepEqual(first.closure, second.closure);
    for (const artifact of first.closure.artifact_hashes) {
      const file = path.join(first.paths.mechanics ? path.dirname(first.paths.mechanics) : root, artifact.path);
      assert.equal(fs.statSync(file).size, artifact.bytes);
      assert.equal(sha256File(file), artifact.sha256);
    }
    const changed = importMechanicsBuild({ sources: completeSources(path.join(root, 'sources-changed'), true) });
    const diff = diffMechanicsBuilds(first.mechanics, changed);
    assert.equal(diff.components.champion.changed.length, 1);
    assert.equal(diff.components.champion.changed[0].id, 'id:Ashe');
    assert.deepEqual(diff, diffMechanicsBuilds(first.mechanics, changed));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
