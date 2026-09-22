'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  displayIntervalHypotheses, runHudRuntimeStateBridge, verifyCallback, verifyFormulaWriter,
  verifyFormulaReader, verifyHeroStatsNegativeEvidence, verifyStaticArtifact,
} = require('../src/hud_runtime_state_bridge');

const ROOT = path.resolve(__dirname, '..');

test('unverified HUD projection remains a multi-hypothesis interval', () => {
  const rows = displayIntervalHypotheses(41);
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((row) => row.projection), ['FLOOR', 'ROUND_NEAREST', 'TRUNCATE_TOWARD_ZERO']);
  assert.deepEqual(rows[0], { projection: 'FLOOR', lower: 41, upper: 42, lower_closed: true, upper_closed: false });
  assert.equal(rows[1].boundary_rule, 'TIE_BEHAVIOR_UNRESOLVED');
});

test('writer proof fails closed unless exact selector and float destination instructions exist', () => {
  assert.throws(() => verifyFormulaWriter({ disassembly: [] }), /vector read not verified/);
});

test('callback, lane ordering and 0x010c behavior evidence fail closed when corrupted', () => {
  const evidenceDir = path.join(ROOT, '.omo', 'evidence', 'quant_runtime_bridge');
  const hud = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'hud_and_state_consumer_disassembly.json'), 'utf8'));
  const writer = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'state_writer_disassembly_and_xrefs.json'), 'utf8'));
  const selector = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'stat_formula_selector_writer_slice.json'), 'utf8'));
  const callbackAdd = hud.disassembly.flatMap((slice) => slice.instructions).find((row) => row.rva === 0x002a5c04);
  callbackAdd.operands = 'rcx, 0x49b0';
  assert.throws(() => verifyCallback(hud), /owner offset not verified/);

  const laneAdvance = writer.disassembly.flatMap((slice) => slice.instructions).find((row) => row.rva === 0x00999eab);
  laneAdvance.operands = 'rdi, [rdi + 8]';
  assert.throws(() => verifyFormulaWriter(writer, selector), /pre-store lane advance not verified/);

  const summary = JSON.parse(fs.readFileSync(path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'emulation',
    'packet_010c_all_latest_four_decoded.jsonl.summary.json'), 'utf8'));
  const crossCheck = JSON.parse(fs.readFileSync(path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'profiler',
    'packet_010c_hero_stats_cross_check.json'), 'utf8'));
  const deepReport = JSON.parse(fs.readFileSync(path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'hero_state',
    'hero_state_damage_defense_deep_report_16_16.json'), 'utf8'));
  crossCheck.decoded_source_full_consume_count = 799;
  assert.throws(() => verifyHeroStatsNegativeEvidence(summary, crossCheck, deepReport), /behavior cross-check mismatch/);
});

test('same runtime image path with forged static instruction bytes fails closed', () => {
  const evidenceDir = path.join(ROOT, '.omo', 'evidence', 'quant_runtime_bridge');
  const source = path.join(evidenceDir, 'hud_and_state_consumer_disassembly.json');
  const forged = JSON.parse(fs.readFileSync(source, 'utf8'));
  const instruction = forged.disassembly.flatMap((slice) => slice.instructions)[0];
  instruction.bytes = instruction.bytes === '90' ? '91' : '90';
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hud-static-forged-'));
  const forgedFile = path.join(temp, 'hud_and_state_consumer_disassembly.json');
  fs.writeFileSync(forgedFile, `${JSON.stringify(forged)}\n`);
  const runtimeImage = path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
    'league_16.16.805.0442.memory.bin');
  assert.equal(path.resolve(forged.image_path), path.resolve(runtimeImage));
  assert.throws(() => verifyStaticArtifact(forged, runtimeImage, 'hudDisassembly', source),
    /instruction bytes mismatch/);
  assert.throws(() => verifyStaticArtifact(forged, runtimeImage, 'hudDisassembly', forgedFile),
    /static artifact hash mismatch/);
});

test('generic formula reader proof fails closed when selector/lane load is corrupted', () => {
  const evidenceDir = path.join(ROOT, '.omo', 'evidence', 'quant_runtime_bridge');
  const contexts = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'hud_runtime_bounded_static_contexts.json'), 'utf8'));
  const reader = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'stat_formula_reader_xrefs.json'), 'utf8'));
  const callers = JSON.parse(fs.readFileSync(path.join(evidenceDir, 'stat_formula_accessor_call_sites.json'), 'utf8'));
  const laneLoad = reader.disassembly.flatMap((slice) => slice.instructions).find((row) => row.rva === 0x00995cb6);
  laneLoad.operands = 'ecx, dword ptr [rdx + rbx*4 + 0x10]';
  const image = fs.readFileSync(path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
    'league_16.16.805.0442.memory.bin'));
  assert.throws(() => verifyFormulaReader(contexts, reader, callers, image), /lane load not verified/);
});

test('exact-build static bridge generates nonempty, hash-manifested evidence without runtime access', () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hud-runtime-bridge-e2e-'));
  const { report, paths } = runHudRuntimeStateBridge({ rootDir: ROOT, outputDir });
  assert.equal(report.exact_build, '16.16.805.0442');
  assert.equal(report.runtime_dynamic_access.status, 'RUNTIME_DYNAMIC_ACCESS_BLOCKED');
  assert.equal(report.runtime_dynamic_access.process_attached, false);
  assert.equal(report.stat_formula_outputs.exact_full_consume_count, 130484);
  assert.equal(report.stat_formula_outputs.writer.float_lane_write_rva, '0x00999eb2');
  assert.deepEqual(report.stat_formula_outputs.writer.destination_lane_offsets_hex, ['0x14', '0x18', '0x1c', '0x20']);
  assert.equal(report.stat_formula_outputs.reader.status, 'VERIFIED_DIRECT_GENERIC_SELECTOR_LANE_READER');
  assert.equal(report.stat_formula_outputs.reader.verified_static_consumer_mappings[0].semantic, 'MANA_REGEN');
  assert.equal(report.stat_formula_outputs.reader.verified_static_consumer_mappings[0].numeric_format, '%0.f');
  assert.equal(report.stat_formula_outputs.reader.wrapper_direct_caller_count, 0);
  assert.equal(report.buff_stat_modifiers.exact_full_consume_count, 714);
  assert.equal(report.hud_display_function.promoted_function, null);
  assert.equal(report.hud_display_function.hypothesis_set_scope, 'NON_EXHAUSTIVE');
  assert.equal(report.hero_stats_010c.behavior_proof.latest_four_full_consume_count, 1370);
  assert.equal(report.local_static_exhaustion_boundary.status, 'LOCAL_STATIC_BOUNDED_ROUTES_EXHAUSTED');
  assert.deepEqual(report.local_static_exhaustion_boundary.remaining_bounded_local_routes, []);
  assert.equal(report.local_static_exhaustion_boundary.derived_local_routes.item_contributions.modifier_name_xref_count, 12);
  assert.ok(report.p0_semantics.every((row) => row.derived.value === 'UNKNOWN'));
  assert.deepEqual(report.public_capability_changes, []);
  assert.ok(Object.values(report.protected_holdout).every((value) => value === false));
  const manifest = JSON.parse(fs.readFileSync(paths.manifestPath, 'utf8'));
  assert.equal(manifest.artifacts.length, 2);
  for (const artifact of manifest.artifacts) {
    const file = path.join(outputDir, artifact.path);
    const digest = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    assert.equal(digest, artifact.sha256);
    assert.ok(artifact.bytes > 0);
  }
});

test('runtime image identity mismatch is rejected before evidence is accepted', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hud-runtime-bridge-'));
  const fakeImage = path.join(temp, 'runtime.bin');
  fs.writeFileSync(fakeImage, 'not the exact image');
  const inputs = require('../src/hud_runtime_state_bridge').defaultInputs(ROOT);
  inputs.runtimeImage = fakeImage;
  assert.throws(() => runHudRuntimeStateBridge({ rootDir: ROOT, outputDir: temp, inputs }), /runtime image mismatch/);
});
