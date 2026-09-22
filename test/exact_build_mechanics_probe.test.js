'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD, buildExactBuildMechanicsData, defaultInputs, sha256File, writeProbeArtifacts,
} = require('../src/exact_build_mechanics_probe');

const ROOT = path.resolve(__dirname, '..');

test('fresh exact-image probe verifies bounded bytes but fails closed on mechanics semantics', () => {
  const result = buildExactBuildMechanicsData({ rootDir: ROOT });
  const data = result.exact_build_mechanics_data;
  assert.equal(data.status, 'EVIDENCE_EXHAUSTED');
  assert.equal(data.decision, 'NO_EXACT_BUILD_DERIVED_P0_STAT_PERMISSION');
  assert.equal(data.level_growth_static_probe.float32_bits_le, '6666263f');
  assert.equal(data.level_growth_static_probe.exact_image_xref_count, 8);
  assert.equal(data.level_growth_static_probe.exact_image_call_site_instruction_count, 204);
  assert.equal(data.level_growth_static_probe.exact_build_growth_rule_bound, false);
  assert.equal(data.bounded_exact_image_modifier_name_targets.exact_image_reference_count, 12);
  assert.equal(data.bounded_exact_image_modifier_name_targets.item_id_value_table_bound, false);
  assert.equal(data.bounded_exact_image_modifier_name_targets.target_set_complete, false);
  assert.match(data.bounded_exact_image_modifier_name_targets.rationale,
    /not a unique or complete modifier registry/);
  assert.equal(data.exact_image_item_modifier_registry, undefined);
  assert.equal(data.patch_family_negative_control.accepted_as_exact_build_mechanics, false);
  assert.equal(result.exception_registry.exception_count, 6);
  assert.ok(result.exception_registry.exceptions.every((row) => row.consumer_permission === false));
});

test('wrong requested build is rejected before mechanics construction', () => {
  assert.throws(() => buildExactBuildMechanicsData({
    rootDir: ROOT, requestedBuild: '16.16.805.0443',
  }), /exact-build request mismatch/);
});

test('wrong runtime image hash is rejected even when caller supplies its path', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-image-'));
  try {
    const inputs = defaultInputs(ROOT);
    const copy = path.join(dir, 'runtime.bin');
    fs.copyFileSync(inputs.runtimeImage, copy);
    const fd = fs.openSync(copy, 'r+');
    fs.writeSync(fd, Buffer.from([0xff]), 0, 1, 0);
    fs.closeSync(fd);
    assert.throws(() => buildExactBuildMechanicsData({
      rootDir: ROOT, inputs: { ...inputs, runtimeImage: copy },
    }), /runtime image source hash mismatch/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('wrong registered evidence source hash is rejected', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-source-'));
  try {
    const inputs = defaultInputs(ROOT);
    const copy = path.join(dir, 'growth.json');
    fs.copyFileSync(inputs.growthXrefs, copy);
    fs.appendFileSync(copy, ' ');
    assert.throws(() => buildExactBuildMechanicsData({
      rootDir: ROOT, inputs: { ...inputs, growthXrefs: copy },
    }), /growth xrefs source hash mismatch/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('patch-family values remain an explicit negative control, not exact-build mechanics', () => {
  const data = buildExactBuildMechanicsData({ rootDir: ROOT }).exact_build_mechanics_data;
  assert.equal(data.exact_build, EXACT_BUILD);
  assert.equal(data.patch_family_negative_control.declared_binding_status,
    'PATCH_FAMILY_PINNED_EXACT_BUILD_EQUIVALENCE_NOT_INDEPENDENTLY_PROVEN');
  assert.equal(data.patch_family_negative_control.status, 'REJECTED_FOR_EXACT_BUILD_DERIVATION');
  assert.equal(data.components.champion_base_and_growth.exact_build_bound, false);
  assert.equal(data.components.item_stat_contributions.exact_build_bound, false);
});

test('direct restricted input name is rejected before the file is read or hashed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-direct-input-'));
  try {
    const inputs = defaultInputs(ROOT);
    const restrictedDir = path.join(dir, 'fixture-Holdout');
    fs.mkdirSync(restrictedDir);
    const copy = path.join(restrictedDir, 'growth.json');
    fs.copyFileSync(inputs.growthXrefs, copy);
    const originalRead = fs.readFileSync;
    let restrictedReadAttempted = false;
    fs.readFileSync = function guardedRead(file, ...args) {
      if (path.resolve(String(file)).startsWith(path.resolve(restrictedDir))) {
        restrictedReadAttempted = true;
      }
      return originalRead.call(this, file, ...args);
    };
    try {
      assert.throws(() => buildExactBuildMechanicsData({
        rootDir: ROOT, inputs: { ...inputs, growthXrefs: copy },
      }), /restricted path/);
    } finally {
      fs.readFileSync = originalRead;
    }
    assert.equal(restrictedReadAttempted, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('junction alias to a restricted input is rejected after realpath resolution', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-alias-input-'));
  try {
    const inputs = defaultInputs(ROOT);
    const restrictedDir = path.join(dir, 'fixture-Holdout-target');
    const aliasDir = path.join(dir, 'safe-alias');
    fs.mkdirSync(restrictedDir);
    fs.copyFileSync(inputs.growthXrefs, path.join(restrictedDir, 'growth.json'));
    fs.symlinkSync(restrictedDir, aliasDir, 'junction');
    const originalRead = fs.readFileSync;
    let restrictedReadAttempted = false;
    fs.readFileSync = function guardedRead(file, ...args) {
      const requested = path.resolve(String(file));
      if (requested.startsWith(path.resolve(restrictedDir))
        || requested.startsWith(path.resolve(aliasDir))) restrictedReadAttempted = true;
      return originalRead.call(this, file, ...args);
    };
    try {
      assert.throws(() => buildExactBuildMechanicsData({
        rootDir: ROOT, inputs: { ...inputs, growthXrefs: path.join(aliasDir, 'growth.json') },
      }), /restricted path/);
    } finally {
      fs.readFileSync = originalRead;
    }
    assert.equal(restrictedReadAttempted, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('direct restricted output is rejected and no target is created', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-direct-output-'));
  try {
    const outputDir = path.join(dir, 'result-Holdout', 'nested');
    assert.throws(() => writeProbeArtifacts({ rootDir: ROOT, outputDir }), /restricted path/);
    assert.equal(fs.existsSync(outputDir), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('junction alias to restricted output is rejected and no target is created', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-alias-output-'));
  try {
    const restrictedDir = path.join(dir, 'result-Holdout-target');
    const aliasDir = path.join(dir, 'safe-output-alias');
    fs.mkdirSync(restrictedDir);
    fs.symlinkSync(restrictedDir, aliasDir, 'junction');
    const outputDir = path.join(aliasDir, 'generated');
    assert.throws(() => writeProbeArtifacts({ rootDir: ROOT, outputDir }), /restricted path/);
    assert.equal(fs.existsSync(path.join(restrictedDir, 'generated')), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('artifact writer is deterministic and every manifest entry is byte/hash bound', () => {
  const a = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-a-'));
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-mechanics-b-'));
  try {
    const first = writeProbeArtifacts({ rootDir: ROOT, outputDir: a });
    const second = writeProbeArtifacts({ rootDir: ROOT, outputDir: b });
    assert.deepEqual(first.exact_build_mechanics_data, second.exact_build_mechanics_data);
    assert.deepEqual(first.exception_registry, second.exception_registry);
    assert.deepEqual(first.manifest, second.manifest);
    for (const artifact of first.manifest.artifacts) {
      const file = path.join(a, artifact.path);
      assert.equal(fs.statSync(file).size, artifact.bytes);
      assert.equal(sha256File(file), artifact.sha256);
    }
  } finally {
    fs.rmSync(a, { recursive: true, force: true });
    fs.rmSync(b, { recursive: true, force: true });
  }
});
