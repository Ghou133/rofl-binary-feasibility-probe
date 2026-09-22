'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_IMAGE_SHA256,
  assertSafePath,
  probeExactCombatDataflow,
} = require('../src/exact_combat_dataflow_probe');

const ROOT = path.resolve(__dirname, '..');

test('actual exact-image probe finds bounded edges and fails closed on all requested promotions', () => {
  const report = probeExactCombatDataflow({ rootDir: ROOT });
  assert.equal(report.image.sha256, EXACT_IMAGE_SHA256);
  assert.equal(report.status, 'EVIDENCE_EXHAUSTED');
  assert.equal(report.exact_instruction_anchors.length, 21);
  assert.equal(report.route_bindings.length, 5);
  assert.deepEqual(report.route_bindings.map((row) => row.route),
    ['0x017f', '0x0371', '0x0112', '0x0265', '0x01e1']);
  assert.equal(report.machine_derived_contiguous_instruction_intervals.length, 8);
  assert.ok(report.bounded_scope
    .inspector_emitted_instruction_count_independently_matched_to_raw_image > 1000);
  for (const chain of report.machine_derived_contiguous_instruction_intervals) {
    assert.equal(chain.validation,
      'CONTIGUOUS_RAW_BYTES_MATCHED_REQUIRED_RVA_ANCHORS_WITHIN_LINEAR_ENTRY_RET_ENVELOPE');
    assert.ok(chain.contiguous_instruction_count >= chain.required_steps.length);
    assert.match(chain.linear_function_envelope.entry_rva, /^0x/);
    assert.match(chain.linear_function_envelope.return_rva, /^0x/);
    assert.ok(chain.linear_function_envelope.instruction_count > 0);
    assert.equal(chain.interval_sha256.length, 64);
    assert.equal(chain.instructions.length, chain.contiguous_instruction_count);
  }
  const chains = new Map(report.machine_derived_contiguous_instruction_intervals
    .map((row) => [row.id, row]));
  const hasStep = (id, rva, operands) => chains.get(id).instructions
    .some((row) => row.rva === rva && row.operands === operands);
  assert.ok(hasStep('damage_field_24_reload_to_target_virtual_call', '0x002a81ef',
    'eax, dword ptr [rsi + 0x24]'));
  assert.ok(hasStep('damage_field_24_reload_to_target_virtual_call', '0x002a820d',
    'xmm1, dword ptr [rsp + 0x68]'));
  assert.ok(hasStep('damage_field_24_reload_to_target_virtual_call', '0x002a8216', 'rdi'));
  assert.ok(hasStep('on_event_parameter_and_event_id_to_dispatch', '0x0049b0db',
    'rax, qword ptr [rbx + 0x18]'));
  assert.ok(hasStep('on_event_parameter_and_event_id_to_dispatch', '0x0049b138',
    '0x140498ef0'));
  assert.ok(hasStep('death_field_10_decode_to_virtual_call', '0x002440ec',
    'eax, dword ptr [r13 + 0x10]'));
  assert.ok(hasStep('shield_field_10_decode_to_direct_dispatch', '0x002a7934',
    'eax, dword ptr [rbx + 0x10]'));
  assert.ok(hasStep('shield_field_10_decode_to_direct_dispatch', '0x002a798b',
    '0x140bb6640'));
  assert.equal(report.field_bindings.DAMAGE_RECORDED_AMOUNT_STAGE_UNKNOWN.route, '0x017f');
  assert.equal(report.field_bindings.GENERIC_ON_EVENT_PARAMETER.route, '0x0371');
  assert.match(report.field_bindings.GENERIC_ON_EVENT_PARAMETER.semantic_limit, /does not itself/);
  assert.equal(report.field_bindings.SHIELD_ABSORBED.route, '0x01e1');
  for (const capability of [
    'DAMAGE_STAGE', 'CURRENT_HP', 'HEAL_EFFECTIVE', 'OVERHEAL',
    'SHIELD_REMAINING', 'SHIELD_INSTANCE',
  ]) {
    assert.equal(report.promotion_decisions[capability].decision, 'NO_PUBLIC_PROMOTION');
    assert.equal(report.promotion_decisions[capability].status, 'EVIDENCE_EXHAUSTED');
  }
  assert.match(report.traces.damage_0x017f_field_24.missing_edge, /No resolved instruction path/);
  assert.equal(report.bounded_scope.string_proximity_used_as_semantic_evidence, false);
  assert.equal(report.bounded_scope.protected_holdout_accessed_enumerated_hashed_or_consumed, false);
});

test('lexical Holdout paths are rejected before filesystem access', () => {
  assert.throws(() => assertSafePath(path.join(ROOT, 'Protected Holdout', 'input.bin')), /Holdout/);
});

test('realpath guard rejects a symlink or junction resolving into a Holdout path', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'combat-dataflow-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const protectedDir = path.join(base, 'Jungle Objective Holdout');
  const safeDir = path.join(base, 'safe');
  fs.mkdirSync(protectedDir);
  try {
    fs.symlinkSync(protectedDir, safeDir, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    t.skip(`symlink/junction unavailable: ${error.code}`);
    return;
  }
  assert.throws(() => assertSafePath(safeDir), /Holdout/);
});

test('wrong image bytes are rejected before static conclusions', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'combat-dataflow-bad-image-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const image = path.join(base, 'runtime.bin');
  fs.writeFileSync(image, Buffer.alloc(64));
  assert.throws(() => probeExactCombatDataflow({ rootDir: ROOT, imagePath: image }), /SHA mismatch/);
});

test('forged inspector is rejected by trusted implementation hash before execution', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'combat-dataflow-forged-inspector-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const inspector = path.join(base, 'inspect_runtime_image.py');
  fs.writeFileSync(inspector, 'print("forged JSON")\n');
  assert.throws(() => probeExactCombatDataflow({ rootDir: ROOT, inspectorScript: inspector }),
    /trusted inspector implementation SHA mismatch/);
});

test('tampered exact-build route registration artifact is rejected before route binding', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'combat-dataflow-route-tamper-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const original = path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'runtime',
    'hero_combat_state_runtime_trace_16_16.json');
  const tampered = path.join(base, 'route-bindings.json');
  const buffer = fs.readFileSync(original);
  buffer[buffer.length - 2] ^= 1;
  fs.writeFileSync(tampered, buffer);
  assert.throws(() => probeExactCombatDataflow({ rootDir: ROOT, routeBindingArtifact: tampered }),
    /route binding artifact SHA mismatch/);
});

test('tampered semantic field profile is rejected before field claims', (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'combat-dataflow-profile-tamper-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const original = path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'emulation', 'profiles',
    'packet_017f.json');
  const tampered = path.join(base, 'packet_017f.json');
  fs.copyFileSync(original, tampered);
  fs.appendFileSync(tampered, ' ');
  assert.throws(() => probeExactCombatDataflow({ rootDir: ROOT, damageProfileArtifact: tampered }),
    /damage profile artifact SHA mismatch/);
});
