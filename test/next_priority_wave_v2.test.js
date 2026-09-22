'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  KDA_CALLBACK_RVA,
  ROUTE_IDS,
  RUNTIME_SHA256,
  anchorCorrelation,
  decodeKdaObject,
  recoverInlineFactory0023,
  recoverKdaCallback,
  rejectProtectedPath,
  rotateRight8,
  sha256,
  swapAdjacentBits,
} = require('../src/next_priority_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'next_priority_wave',
);
const RUNTIME_PATH = path.join(
  ROOT,
  'artifacts',
  'new_build_rofl_compatibility_gate_v1',
  'runtime',
  'league_16.16.805.0442.memory.bin',
);

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

test('exact-build route scope and byte transforms are deterministic', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.equal(ROUTE_IDS.length, 20);
  assert.equal(new Set(ROUTE_IDS).size, 20);
  for (let value = 0; value < 256; value += 1) {
    assert.equal(rotateRight8(rotateRight8(value, 3), 5), value);
    assert.equal(swapAdjacentBits(swapAdjacentBits(value)), value);
  }
});

test('protected Holdout paths are rejected before any read/hash operation', () => {
  assert.throws(
    () => rejectProtectedPath(path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.rofl')),
    /protected Holdout path is forbidden/,
  );
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
});

test('bounded alternate runtime searches close inline factory and KDA callback', () => {
  const image = fs.readFileSync(RUNTIME_PATH);
  assert.equal(sha256(image), RUNTIME_SHA256);
  const inline = recoverInlineFactory0023(image);
  assert.equal(inline.case_rva_hex, '0x00eda7e9');
  assert.equal(inline.constructor_kind, 'INLINE_FACTORY_CASE_NO_STANDALONE_CONSTRUCTOR');
  assert.equal(inline.packet_object_vtable_rva_hex, '0x01b10e30');
  assert.equal(inline.deserializer_rva_hex, '0x00f1d210');
  assert.equal(inline.bounded_search_exhausted, true);
  const callback = recoverKdaCallback(image);
  assert.equal(KDA_CALLBACK_RVA, 0x00334ae0);
  assert.equal(callback.callback_receive_target_rva_hex, '0x00334ae0');
  assert.equal(callback.decoded_object_reads.length, 3);
  assert.equal(callback.bounded_search_exhausted, true);
});

test('KDA protected-u32 transforms recover exact plaintext', () => {
  const image = fs.readFileSync(RUNTIME_PATH);
  const decoded = decodeKdaObject(
    '4008b141010000006b01e6e6b1020040131313134445454599999999',
    image,
  );
  assert.deepEqual(decoded, { kills_u32: 0, deaths_u32: 1, assists_u32: 0 });
});

test('anchor correlation retains shifted controls and counterexamples', () => {
  const byReplay = new Map([['replay', [
    { time: 1000, raw_param: 1 },
    { time: 2000, raw_param: 2 },
  ]] ]);
  const result = anchorCorrelation([
    { replay_sha256: 'replay', time: 1000, raw_param: 1 },
    { replay_sha256: 'replay', time: 1500, raw_param: 9 },
    { replay_sha256: 'replay', time: 5000, raw_param: 9 },
  ], byReplay);
  assert.equal(result.exact_time_count, 1);
  assert.equal(result.exact_time_same_raw_param_count, 1);
  assert.equal(result.far_over_500ms_count, 1);
  assert.equal(typeof result.shifted_137ms_within_10ms_rate, 'number');
  assert.equal(typeof result.shifted_997ms_within_10ms_rate, 'number');
  assert.equal(result.semantic_claim, null);
});

test('generated deep audit conserves every route and closes all local evidence', () => {
  const report = readJson('next_priority_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.scope.length, 20);
  assert.equal(report.full_inventory.target_row_count, 274937);
  assert.equal(report.full_inventory.distinct_payload_row_count, 27355);
  assert.equal(report.full_inventory.target_occurrence_weight_conserved, true);
  assert.equal(report.runtime_static_recovery.identities.length, 20);
  assert.equal(report.runtime_static_recovery.all_routes_closed, true);
  assert.equal(report.decisions.route_decisions.length, 20);
  assert.equal(report.decisions.all_routes_have_one_decision, true);
  assert.equal(report.decisions.all_current_local_evidence_exhausted, true);
  assert.equal(report.saturation.current_local_evidence_saturated, true);
  assert.equal(report.determinism.extraction_match, true);
  assert.equal(report.determinism.exact_native_execution_rerun, true);
  assert.equal(report.determinism.all_match, true);
  assert.equal(report.validations.all_pass, true);
  for (const route of Object.values(report.routes)) {
    assert.equal(route.payload.occurrence_weight_conserved, true);
    for (const family of ['damage', 'death', 'path', 'cast', 'buff', 'item', 'scoreboard']) {
      const correlation = route.anchor_correlations_with_shifted_controls[family];
      assert.equal(typeof correlation.shifted_137ms_within_10ms_count, 'number');
      assert.equal(typeof correlation.shifted_997ms_within_10ms_count, 'number');
      assert.equal(correlation.semantic_claim, null);
    }
  }
  for (const route of Object.values(report.native_exact_emulation.routes)) {
    assert.equal(route.all_distinct_payloads_attempted, true);
    assert.equal(route.full_occurrence_weight_conserved, true);
  }
  assert.deepEqual(report.safety, {
    explicit_safe_latest_four_only: true,
    replay_directory_discovery: false,
    protected_holdout_enumerated: false,
    protected_holdout_read: false,
    protected_holdout_hashed: false,
    protected_holdout_decoded: false,
    protected_holdout_tested: false,
    protected_holdout_consumed: false,
  });
});

test('KDA promotion has independent terminal metadata support', () => {
  const report = readJson('next_priority_wave_audit_16_16.json');
  const kda = report.independent_kda_validation;
  assert.equal(kda.terminal_metadata_check_count, 40);
  assert.equal(kda.terminal_metadata_match_count, 30);
  assert.equal(kda.exact_component_metadata_match_count, 108);
  assert.equal(kda.component_metadata_check_count, 120);
  assert.equal(kda.all_terminal_components_at_or_below_final_metadata, true);
  assert.equal(kda.semantic_field_role_validation_pass, true);
  const decision = report.decisions.route_decisions.find((row) => row.packet_id === 0x016b);
  assert.equal(decision.decision, 'PROMOTE');
  assert.deepEqual(decision.publishable_fields, [
    'subject_network_id=raw_param',
    'replay_time_ms',
    'kills_u32',
    'deaths_u32',
    'assists_u32',
  ]);
  assert.equal(decision.evidence_exhausted, true);
});
