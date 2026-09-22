'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { assertFrozenOrPublicSourceHash } = require('./support/public_release_hash_bridge');

const {
  CALLBACK_FIELD_RECOVERY,
  EXACT_BUILD,
  ROUTE_IDS,
  RUNTIME_SHA256,
  SHARED_CODEC_FIELD_RECOVERY,
  decodeAmmoObject,
  decodeCircularRestriction,
  decodeObjectAttacherOffset,
  decodeTargetNetworkId,
  recoverRuntimeIdentities,
  rejectProtectedPath,
  rotateRight8,
  sha256,
  swapAdjacentBits,
} = require('../src/unknown_p1_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'unknown_p1_wave');
const RUNTIME_PATH = path.join(
  ROOT,
  'artifacts',
  'new_build_rofl_compatibility_gate_v1',
  'runtime',
  'league_16.16.805.0442.memory.bin',
);
const REGISTRY_PATH = path.join(ROOT, 'artifacts', 'full_semantic_baseline_v1', 'observed_route_registry.json');

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

function fileSha(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('exact-build scope and byte transforms are deterministic', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.deepEqual(ROUTE_IDS, [0x0101, 0x0213, 0x0471, 0x00ab, 0x01b3, 0x018e, 0x0374, 0x0316]);
  assert.equal(new Set(ROUTE_IDS).size, 8);
  assert.deepEqual(Object.keys(CALLBACK_FIELD_RECOVERY).sort(), ['0x0101', '0x018e', '0x0213', '0x0374', '0x0471']);
  assert.deepEqual(Object.keys(SHARED_CODEC_FIELD_RECOVERY), ['0x01b3']);
  for (let value = 0; value < 256; value += 1) {
    assert.equal(rotateRight8(rotateRight8(value, 3), 5), value);
    assert.equal(swapAdjacentBits(swapAdjacentBits(value)), value);
  }
});

test('protected Holdout paths are rejected before reads or hashes', () => {
  assert.throws(
    () => rejectProtectedPath(path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.rofl')),
    /protected Holdout path is forbidden/,
  );
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
});

test('exact runtime identity chains and callback object reads close', () => {
  const image = fs.readFileSync(RUNTIME_PATH);
  assert.equal(sha256(image), RUNTIME_SHA256);
  const registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
  const identities = recoverRuntimeIdentities(registry, image);
  assert.equal(identities.length, 8);
  assert.equal(identities.every((row) => row.validations.all_pass), true);
  const reads = Object.fromEntries(identities.map((row) => [
    row.packet_discriminator,
    row.callback_exact_object_reads.map((entry) => entry.offset),
  ]));
  assert.deepEqual(reads['0x0101'], ['0x10']);
  assert.deepEqual(reads['0x0213'], ['0x10', '0x14', '0x18', '0x1c', '0x20', '0x24']);
  assert.deepEqual(reads['0x018e'], ['0x10']);
  assert.deepEqual(reads['0x0374'], ['0x10', '0x14', '0x18']);
});

test('generated audit conserves the full inventory and saturates local evidence', () => {
  const report = readJson('unknown_p1_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.scope.length, 8);
  assert.equal(report.full_inventory.target_row_count, 38434);
  assert.equal(report.full_inventory.distinct_payload_row_count > 0, true);
  assert.equal(report.full_inventory.target_occurrence_weight_conserved, true);
  assert.equal(report.full_inventory.registry_observed_counts_match, true);
  assert.equal(report.runtime_static_recovery.identities.length, 8);
  assert.equal(report.runtime_static_recovery.all_routes_closed, true);
  assert.equal(report.determinism.extraction_match, true);
  assert.equal(report.determinism.exact_native_execution_rerun, true);
  assert.equal(report.determinism.all_match, true);
  assert.equal(report.decisions.route_decisions.length, 8);
  assert.deepEqual(report.decisions.decision_counts, {
    PROMOTE: 7,
    KEEP_CANDIDATE: 0,
    REJECT: 0,
    REPURPOSE: 1,
  });
  assert.equal(report.decisions.all_current_local_evidence_exhausted, true);
  assert.equal(report.saturation.current_local_evidence_saturated, true);
  assert.deepEqual(report.saturation.remaining_local_executable_steps, []);
  assert.deepEqual(report.saturation.actionable_hypotheses, []);
  assert.equal(report.validations.all_pass, true);
  for (const route of Object.values(report.routes)) {
    assert.equal(route.payload.occurrence_weight_conserved, true);
    for (const family of ['damage', 'hero_death', 'path', 'cast', 'buff', 'item', 'scoreboard']) {
      const correlation = route.anchor_correlations_with_shifted_controls[family];
      assert.equal(typeof correlation.shifted_137ms_within_10ms_count, 'number');
      assert.equal(typeof correlation.shifted_997ms_within_10ms_count, 'number');
      assert.equal(correlation.semantic_claim, null);
    }
  }
  for (const route of Object.values(report.native_exact_emulation.routes)) {
    assert.equal(route.all_distinct_payloads_attempted, true);
    assert.equal(route.full_occurrence_weight_conserved, true);
    assert.equal(route.conserved_failure_occurrence_weight, 0);
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

test('callback plaintext transformations are reproduced from native objects', () => {
  const report = readJson('unknown_p1_wave_audit_16_16.json');
  const image = fs.readFileSync(RUNTIME_PATH);
  const fixtures = {
    '0x0101': ['native/route_0101_distinct_decoded.jsonl', (hex) => ({ target_network_id_u32: decodeTargetNetworkId(hex, image) })],
    '0x0213': ['native/route_0213_distinct_decoded.jsonl', (hex) => decodeAmmoObject(hex, image)],
    '0x0471': ['native/route_0471_distinct_decoded.jsonl', (hex) => ({ target_network_id_u32: decodeTargetNetworkId(hex, image) })],
    '0x01b3': ['native/route_01b3_distinct_decoded.jsonl', (hex) => ({ secondary_character_data_network_id_u32: decodeTargetNetworkId(hex, image) })],
    '0x018e': ['native/route_018e_distinct_decoded.jsonl', (hex) => decodeObjectAttacherOffset(hex)],
    '0x0374': ['native/route_0374_distinct_decoded.jsonl', (hex) => decodeCircularRestriction(hex, image)],
  };
  for (const [packetType, [relativePath, decoder]] of Object.entries(fixtures)) {
    const first = fs.readFileSync(path.join(ARTIFACT_ROOT, relativePath), 'utf8')
      .split(/\r?\n/).filter(Boolean).map(JSON.parse)
      .find((row) => !row.emulation_error && row.fully_consumed && row.object_hex);
    assert.ok(first, `${packetType} native fixture missing`);
    const decoded = decoder(first.object_hex);
    const example = report.native_exact_emulation.routes[packetType]
      .callback_plaintext_analysis.decoded_examples
      .find((row) => row.raw_payload_sha256 === first.raw_payload_sha256);
    assert.ok(example, `${packetType} decoded example missing`);
    assert.deepEqual(decoded, example.decoded);
  }
  assert.equal(
    report.native_exact_emulation.routes['0x0101']
      .callback_plaintext_analysis.target_network_id_like_occurrence_weight > 0,
    true,
  );
});

test('machine decisions retain neutral fields and explicit external thresholds', () => {
  const decisions = readJson('unknown_p1_wave_machine_decisions_16_16.json');
  assert.equal(decisions.route_decisions.length, 8);
  assert.equal(decisions.capability_decisions.length, 5);
  assert.equal(decisions.domain_decisions.length, 5);
  for (const row of decisions.route_decisions) {
    assert.equal(row.actual_reverse_engineering_executed, true);
    assert.equal(row.evidence_exhausted, true);
    assert.deepEqual(row.actionable_hypotheses, []);
    assert.deepEqual(row.remaining_local_executable_steps, []);
    assert.equal(row.next_required_evidence.length > 0, true);
  }
  const ammo = decisions.route_decisions.find((row) => row.packet_discriminator === '0x0213');
  assert.equal(ammo.publishable_fields.includes('ammo_slot_index_u32'), true);
  assert.equal(ammo.publishable_fields.includes('ammo_max_count_or_default_s32'), true);
  assert.equal(ammo.publishable_fields.includes('ammo_current_count_or_sentinel_s32'), true);
  assert.equal(ammo.publishable_fields.includes('neutral_plaintext_f32_lane_10'), true);
  assert.equal(ammo.publishable_fields.includes('neutral_plaintext_u8_lane_20'), true);
  assert.equal(ammo.publishable_fields.includes('neutral_plaintext_f32_lane_24'), true);
  assert.equal(decisions.protected_holdout.enumerated, false);
  assert.equal(decisions.protected_holdout.consumed, false);
});

test('hash manifest is stable and verifies every listed artifact', () => {
  const manifest = readJson('hashes_16_16.json');
  assert.equal(manifest.exact_build, EXACT_BUILD);
  assert.equal(manifest.files.length > 20, true);
  for (const entry of manifest.files) {
    const filePath = path.join(ROOT, entry.path);
    assertFrozenOrPublicSourceHash(entry, filePath, fileSha);
  }
});
