'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const registry = require('../src/exact_build_defense_registry');

const root = path.resolve(__dirname, '..');
const defaults = registry.defaultPaths(root);

function copyEvidence(target) {
  const image = path.join(target, 'runtime.bin');
  const xrefs = path.join(target, 'xrefs.json');
  const blocks = path.join(target, 'blocks.json');
  fs.copyFileSync(defaults.runtimeImagePath, image);
  const imagePath = path.resolve(image);
  for (const pair of [
    [defaults.identifierXrefsPath, xrefs],
    [defaults.registrationBlockPath, blocks]
  ]) {
    const value = JSON.parse(fs.readFileSync(pair[0], 'utf8'));
    value.image_path = imagePath;
    fs.writeFileSync(pair[1], JSON.stringify(value));
  }
  return { image: image, xrefs: xrefs, blocks: blocks };
}

function optionsFor(files) {
  return {
    runtimeImagePath: files.image,
    identifierXrefsPath: files.xrefs,
    registrationBlockPath: files.blocks,
    expectedImageSha256: registry.EXACT_IMAGE_SHA256
  };
}

const result = registry.buildExactBuildDefenseFieldRegistry(Object.assign(defaults, {
  expectedImageSha256: registry.EXACT_IMAGE_SHA256
}));
assert.strictEqual(result.status, registry.STATUS);
assert.ok(result.field_registry_offsets.length > 0);
assert.strictEqual(result.consumer_permission.selector_mapping_0x0412, 'NOT_PUBLISHED');
assert.strictEqual(result.consumer_permission.operation_semantics, 'NOT_PUBLISHED');
assert.strictEqual(result.consumer_permission.stacking_or_order, 'NOT_PUBLISHED');
assert.deepStrictEqual(result.protected_holdout_access, registry.HOLDOUT_ACCESS);
for (const row of result.field_registry_offsets) {
  assert.ok(registry.PERMITTED_FIELD_NAMES.has(row.field_name));
  assert.ok(Number.isInteger(row.struct_offset));
  assert.ok(row.provenance.occurrences.length > 0);
  assert.strictEqual(row.status, registry.STATUS);
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-build-registry-'));
const copied = copyEvidence(temporary);
const badBlocks = JSON.parse(fs.readFileSync(copied.blocks, 'utf8'));
const firstRegisteredArmorXref = 2198851;
let changed = false;
for (const block of badBlocks.disassembly) {
  for (const instruction of block.instructions) {
    if (instruction.rva === firstRegisteredArmorXref) {
      instruction.bytes = '90';
      changed = true;
    }
  }
}
assert.ok(changed);
fs.writeFileSync(copied.blocks, JSON.stringify(badBlocks));
assert.throws(function () {
  registry.buildExactBuildDefenseFieldRegistry(optionsFor(copied));
}, /instruction bytes|registration evidence/i);

const directHoldout = path.join(temporary, 'Holdout', 'no-read.json');
assert.throws(function () {
  registry.assertNoHoldoutPath(directHoldout, 'fixture');
}, /Holdout/);
assert.throws(function () {
  registry.assertNoHoldoutPath(path.join(temporary, 'Jungle Objective Holdout', 'no-read.json'),
    'fixture');
}, /Holdout/);

const fakeHoldout = path.join(temporary, 'real-target', 'Holdout');
fs.mkdirSync(fakeHoldout, { recursive: true });
const alias = path.join(temporary, 'safe-alias');
try {
  fs.symlinkSync(fakeHoldout, alias, 'junction');
  assert.throws(function () {
    registry.assertNoHoldoutPath(path.join(alias, 'unreadable.json'), 'fixture');
  }, /Holdout/);
} catch (error) {
  if (!/Holdout/.test(error.message)) throw error;
}

const output = path.join(temporary, 'registry.json');
const originalBlocks = JSON.parse(fs.readFileSync(defaults.registrationBlockPath, 'utf8'));
fs.writeFileSync(copied.blocks, JSON.stringify(originalBlocks));
const restored = JSON.parse(fs.readFileSync(copied.blocks, 'utf8'));
restored.image_path = path.resolve(copied.image);
fs.writeFileSync(copied.blocks, JSON.stringify(restored));
const written = registry.writeExactBuildDefenseFieldRegistry(output, optionsFor(copied));
assert.strictEqual(written.status, registry.STATUS);
assert.strictEqual(JSON.parse(fs.readFileSync(output, 'utf8')).artifact_type, 'VERIFIED_EXACT_IMAGE_FIELD_REGISTRY_OFFSETS');

fs.rmSync(temporary, { recursive: true, force: true });
console.log('exact_build_defense_registry.test.js: PASS');
