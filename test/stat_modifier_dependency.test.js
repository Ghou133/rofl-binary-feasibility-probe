'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD, FORMULA_PROFILE_SHA256, RUNTIME_IMAGE_SHA256, acceptUniqueIdentity,
  analyzeTemporalDependencies, assertNonHoldoutPath, physicalPacketIdentity,
  finalizeEvidenceManifest, runStatModifierDependencyAudit, semanticDecision,
  validateAdjustmentEvent, validateFormulaRow, verifyRecordLayout,
} = require('../src/stat_modifier_dependency');

const ROOT = path.resolve(__dirname, '..');
const hash = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

function fixtureInstructions() {
  const rows = [
    [0x00395921, 'imul', 'r15, rax, 0x1c'], [0x00395980, 'movzx', 'edi, byte ptr [r14 + 0x10]'],
    [0x00395989, 'mov', 'eax, dword ptr [r14 + 0x18]'], [0x003959d1, 'mov', 'eax, dword ptr [r14 + 0xc]'],
    [0x00395a0f, 'mov', 'eax, dword ptr [r14 + 8]'], [0x00395a4a, 'mov', 'eax, dword ptr [r14 + 0x14]'],
    [0x00395b1c, 'movss', 'dword ptr [rdx + 4], xmm6'], [0x00395b21, 'mov', 'byte ptr [rdx + 0x15], 0'],
    [0x00395b2d, 'movss', 'dword ptr [rdx + 8], xmm7'], [0x00395b32, 'movss', 'dword ptr [rdx + 0x10], xmm8'],
    [0x00395b38, 'movss', 'dword ptr [rdx + 0xc], xmm9'], [0x00395b3e, 'mov', 'byte ptr [rdx + 0x14], 1'],
  ].map(([rva, mnemonic, operands]) => ({ rva, mnemonic, operands }));
  return { disassembly: [{ instructions: rows }] };
}

test('record layout requires every exact consumer instruction and keeps roles neutral', () => {
  const layout = verifyRecordLayout(fixtureInstructions());
  assert.equal(layout.source_record_stride_bytes, 28);
  assert.equal(layout.source_encoded_fields.field_a.offset, 8);
  assert.equal(layout.source_encoded_fields.adjustment_kind.offset, 16);
  assert.equal(layout.source_encoded_fields.field_d.offset, 24);
  assert.match(layout.flags_evidence, /NO_PACKET_FLAG_OR_OPERATION_SEMANTIC/);
  const broken = fixtureInstructions();
  broken.disassembly[0].instructions[0].operands = 'r15, rax, 0x20';
  assert.throws(() => verifyRecordLayout(broken), /instruction mismatch/);
});

test('temporal dependency analysis preserves zero-delta counterexample and does not infer causality', () => {
  const adjustment = [{ replay_sha256: 'r', entity_network_id: 1, entity_network_id_hex: '0x1',
    replay_time_ms: 100, source_packet: { raw_payload_sha256: 'a' } }];
  const groups = new Map([['r:1', [
    { time: 90, selector: 194, lanes: [1, 2, 3, 4] },
    { time: 110, selector: 194, lanes: [1, 2, 3, 4] },
  ]] ]);
  const result = analyzeTemporalDependencies(adjustment, groups);
  assert.equal(result.same_replay_entity_formula_series_count, 1);
  assert.equal(result.zero_lane_delta_count, 1);
  assert.equal(result.nonzero_lane_delta_count, 0);
  assert.equal(result.nearest_formula_window_counts_ms['10'], 1);
});

test('semantic decision refuses selector, operation, value, and flat/percent promotion', () => {
  const decision = semanticDecision({ adjustment_kind_counts: { 0: 714 } },
    { selector_counts: { 194: 130484 } }, { same_replay_entity_formula_series_count: 12 });
  assert.equal(decision.selector.status, 'UNKNOWN');
  assert.equal(decision.operation.status, 'UNKNOWN');
  assert.equal(decision.value.status, 'UNKNOWN');
  assert.equal(decision.flat_percent.status, 'UNRESOLVED');
  assert.deepEqual(decision.formula_dependency.promoted_edges, []);
});

test('Holdout paths fail closed before access', () => {
  assert.throws(() => assertNonHoldoutPath(path.join(ROOT, 'Jungle_Objective_Holdout', 'x.json')),
    /Holdout input is forbidden/);
});

test('0x0412 source validation rejects wrong schema, event type, build, and route', () => {
  const valid = {
    schema_version: 1, event_type: 'BUFF_STAT_ADJUSTMENT_STORAGE_RESEARCH_V1',
    exact_build: EXACT_BUILD, replay_sha256: 'a'.repeat(64), replay_time_ms: 1,
    entity_network_id: 1, source_packet: { packet_id: 0x0412, payload_length: 17,
      raw_payload_sha256: 'b'.repeat(64) },
  };
  const accepted = structuredClone(valid);
  assert.equal(validateAdjustmentEvent(accepted), accepted);
  for (const mutate of [
    (row) => { row.schema_version = 2; },
    (row) => { row.event_type = 'OTHER'; },
    (row) => { row.exact_build = '16.15.0'; },
    (row) => { row.source_packet.packet_id = 0x042f; },
  ]) {
    const row = structuredClone(valid);
    mutate(row);
    assert.throws(() => validateAdjustmentEvent(row), /mismatch/);
  }
});

test('0x042f source validation rejects wrong schema, route, opcode, and runtime identity', () => {
  const valid = {
    schema_version: 1, replay_version: EXACT_BUILD, packet_id: 0x042f, packet_type: '0x042f',
    decoded_opcode: 0x042f, decoded_opcode_hex: '0x042f', opcode_matches_profile: true,
    fully_consumed: true, deserialize_return_al: 1, decoder_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    decoder_profile_sha256: FORMULA_PROFILE_SHA256.formulaP0, raw_payload_sha256: 'a'.repeat(64),
    replay_sha256: 'b'.repeat(64), raw_param: 1, replay_time_ms: 1,
    decoded_fields: { outputs: [{ output_kind_storage: 194,
      formula_values_storage_hex: '00'.repeat(16) }] },
  };
  assert.equal(validateFormulaRow(valid, FORMULA_PROFILE_SHA256.formulaP0), valid);
  for (const [mutate, pattern] of [
    [(row) => { row.schema_version = 2; }, /schema mismatch/],
    [(row) => { row.packet_id = 0x0412; }, /route mismatch/],
    [(row) => { row.decoded_opcode = 0x0412; }, /opcode mismatch/],
    [(row) => { row.decoder_runtime_image_sha256 = '0'.repeat(64); }, /runtime SHA mismatch/],
  ]) {
    const row = structuredClone(valid);
    mutate(row);
    assert.throws(() => validateFormulaRow(row, FORMULA_PROFILE_SHA256.formulaP0), pattern);
  }
});

test('physical packet identity deduplicates an exact repeated row', () => {
  const row = { replay_sha256: 'r', chunk_stream: 'game_chunk', chunk_index: 1,
    decompressed_block_offset: 2, decompressed_payload_offset: 3, occurrence_index: 4,
    raw_param: 5, raw_payload_sha256: 'p' };
  const seen = new Set();
  assert.equal(acceptUniqueIdentity(seen, physicalPacketIdentity(row)), true);
  assert.equal(acceptUniqueIdentity(seen, physicalPacketIdentity(structuredClone(row))), false);
  row.occurrence_index += 1;
  assert.equal(acceptUniqueIdentity(seen, physicalPacketIdentity(row)), true);
});

test('strict bracketing does not use an exact-time row as both before and after', () => {
  const adjustment = [{ replay_sha256: 'r', entity_network_id: 1, entity_network_id_hex: '0x1',
    replay_time_ms: 100, source_packet: { raw_payload_sha256: 'a' } }];
  const groups = new Map([['r:1', [{ time: 100, selector: 194, lanes: [0, 0, 0, 0] },
    { time: 101, selector: 194, lanes: [1, 1, 1, 1] }]]]);
  const result = analyzeTemporalDependencies(adjustment, groups);
  assert.equal(result.same_timestamp_formula_count, 1);
  assert.equal(result.bracketed_by_strict_before_after_count, 0);
  assert.equal(result.same_selector_comparable_count, 0);
});

test('fresh exact-build audit conserves 714/130484 and writes nonempty hash-bound evidence', async () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'modifier-dependency-'));
  try {
    const { report, paths } = await runStatModifierDependencyAudit({ rootDir: ROOT, outputDir });
    assert.equal(report.exact_build, EXACT_BUILD);
    assert.equal(report.adjustment_observations.record_count, 714);
    assert.equal(report.formula_observations.row_count, 130484);
    assert.equal(report.record_layout.source_record_stride_bytes, 28);
    assert.deepEqual(report.semantic_decision.formula_dependency.promoted_edges, []);
    assert.equal(report.protected_holdout.consume, false);
    assert.equal(report.formula_observations.duplicate_packet_count, 0);
    assert.equal(report.formula_observations.rejected_row_count, 0);
    assert.equal(report.adjustment_observations.duplicate_record_count, 0);
    assert.ok(!fs.existsSync(paths.manifest));
    fs.writeFileSync(paths.testResults,
      '<testsuites><!-- tests 9 --><!-- pass 9 --><!-- fail 0 --></testsuites>\n');
    finalizeEvidenceManifest({ outputDir, testResultsPath: paths.testResults });
    const manifest = JSON.parse(fs.readFileSync(paths.manifest, 'utf8'));
    assert.equal(manifest.artifacts.length, 5);
    for (const artifact of manifest.artifacts) {
      const file = path.join(outputDir, artifact.path);
      assert.ok(fs.statSync(file).size > 0);
      assert.equal(fs.statSync(file).size, artifact.bytes);
      assert.equal(hash(file), artifact.sha256);
    }
  } finally {
    fs.rmSync(outputDir, { recursive: true, force: true });
  }
});
