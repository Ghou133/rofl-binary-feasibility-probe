'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT = path.join(
  ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'named_gameplay_wave',
);
const REPORT = path.join(ARTIFACT, 'named_gameplay_wave_audit_16_16.json');
const DECISIONS = path.join(ARTIFACT, 'named_gameplay_wave_decisions_16_16.json');
const HASHES = path.join(ARTIFACT, 'named_gameplay_wave_hashes_16_16.json');
const RAW_MANIFEST = path.join(ARTIFACT, 'named_gameplay_routes_raw_16_16.jsonl.manifest.json');

const ROUTES = [
  0x04c0, 0x0312, 0x00a3, 0x014c, 0x04ab, 0x0046, 0x00f0,
  0x0226, 0x0089, 0x021d, 0x0455, 0x0491, 0x01ae, 0x0134,
  0x031d, 0x004c, 0x039f, 0x02da, 0x02b6, 0x039d, 0x0139,
  0x00a1, 0x01ed, 0x013f, 0x03e4, 0x01a5, 0x02c2, 0x0021,
  0x007f, 0x008f, 0x01c3, 0x02e4, 0x034c,
].sort((left, right) => left - right);

function readJson(filePath) {
  assert.equal(/holdout/i.test(filePath), false);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function numericKeys(distribution) {
  return Object.keys(distribution).map(Number).sort((left, right) => left - right);
}

test('governance gate is recorded and the protected Holdout policy is all false', () => {
  const gate = fs.readFileSync(path.join(ARTIFACT, 'ARCHITECTURE_GATE.md'), 'utf8');
  assert.match(gate, /PROJECT_CONTEXT_LOADED = YES/);
  assert.match(gate, /ARCHITECTURE_GATE = PASS/);
  const report = readJson(REPORT);
  assert.equal(report.project_context_loaded, true);
  assert.equal(report.architecture_gate, 'PASS');
  assert.deepEqual(report.protected_holdout_policy, {
    read: false, enumerate: false, hash: false, decode: false, test: false, consume: false,
  });
  assert.equal(report.explicit_allowlist.directory_discovery_used, false);
  for (const input of Object.values(report.inputs)) {
    assert.equal(/holdout/i.test(input.path), false);
    assert.match(input.sha256, /^[a-f0-9]{64}$/);
  }
});

test('full raw export and route decisions conserve all 33 assigned routes', () => {
  const manifest = readJson(RAW_MANIFEST);
  const report = readJson(REPORT);
  const decisions = readJson(DECISIONS);
  assert.equal(manifest.target_replay_version, '16.16.805.0442');
  assert.equal(manifest.selected_packet_count, 142124);
  assert.equal(manifest.replay_count, 4);
  assert.ok(manifest.replays.every((row) => row.parser_error_count === 0));
  assert.deepEqual([...manifest.packet_ids].sort((a, b) => a - b), ROUTES);
  assert.equal(report.conservation.raw_row_count, 142124);
  assert.equal(report.conservation.raw_row_conservation_pass, true);
  assert.equal(report.conservation.runtime_route_conservation_pass, true);
  assert.deepEqual(
    decisions.route_decisions.map((row) => row.packet_id).sort((a, b) => a - b),
    ROUTES,
  );
  assert.deepEqual(decisions.saturation, {
    current_safe_local_resource_saturated: true,
    route_count: 33,
    capability_count: 33,
    domain_count: 15,
    local_actionable_hypothesis_count: 0,
    remaining_evidence_class: 'EXTERNAL_OR_NEW_CONTROLLED_REPLAY_ONLY',
  });
});

test('every route, capability, and domain decision records real work and an external-only gate', () => {
  const decisions = readJson(DECISIONS);
  for (const groupName of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    assert.ok(decisions[groupName].length > 0);
    for (const row of decisions[groupName]) {
      assert.equal(row.actual_reverse_engineering_executed, true);
      assert.equal(row.evidence_exhausted, true);
      assert.deepEqual(row.actionable_hypotheses, []);
      assert.equal(row.external_only_gate.required, true);
      assert.equal(row.external_only_gate.local_safe_evidence_remaining, false);
      assert.ok(row.next_required_evidence.length > 0);
    }
  }
  const counts = decisions.route_decisions.reduce((result, row) => {
    result[row.decision] = (result[row.decision] ?? 0) + 1;
    return result;
  }, {});
  assert.deepEqual(counts, { PROMOTE: 18, REPURPOSE: 15 });
});

test('exact runtime native samples fully consume every direct-factory route', () => {
  const report = readJson(REPORT);
  assert.equal(report.conservation.native_sample_row_count, 900);
  for (const packetId of ROUTES) {
    const key = `0x${packetId.toString(16).padStart(4, '0')}`;
    const native = report.native_decode_profiles[key];
    if (packetId === 0x0021) {
      assert.equal(native.status, 'NO_DIRECT_FACTORY_PROFILE');
      continue;
    }
    assert.equal(native.status, 'EXACT_NATIVE_SAMPLE_FULL_CONSUME', key);
    assert.equal(native.successful_full_consume_count, native.selected_sample_count, key);
    assert.deepEqual(native.emulation_errors, {}, key);
  }
  const itemBroadcast = report.native_decode_profiles['0x014c'];
  assert.equal(itemBroadcast.emulation_side_effect_hooks.length, 1);
  assert.equal(itemBroadcast.emulation_side_effect_hooks[0].semantic_effect_bypassed, false);
  assert.equal(itemBroadcast.emulation_side_effect_hooks[0].collection_clear_and_return_path_executed, true);
});

test('structural field mining recovers bounded collection counts and negative controls', () => {
  const report = readJson(REPORT);
  const behavior = (route, field) => report.native_decode_profiles[route]
    .protected_storage_field_behavior.find((row) => row.name === field);
  assert.deepEqual(numericKeys(behavior('0x014c', 'modifier_record_count_20_u32')
    .direct_structural_numeric_distribution), [0, 1, 2]);
  assert.deepEqual(numericKeys(behavior('0x02da', 'modifier_record_count_20_u32')
    .direct_structural_numeric_distribution), [1, 2]);
  assert.deepEqual(numericKeys(behavior('0x02b6', 'spell_modifier_record_count_18_u32')
    .direct_structural_numeric_distribution), [0, 5, 10, 15, 20, 25]);
  assert.deepEqual(numericKeys(behavior('0x039d', 'buff_modifier_record_count_18_u32')
    .direct_structural_numeric_distribution), [0]);
  assert.deepEqual(numericKeys(behavior('0x04c0', 'restriction_record_count_18_u32')
    .direct_structural_numeric_distribution), [0, 1]);
});

test('temporal mining proves keyframe bundles and rejects direct cast/damage aliases', () => {
  const report = readJson(REPORT);
  const pair = report.exact_time_cross_route_matrix.find((row) => (
    row.source_route === '0x00a3' && row.target_route === '0x014c'
  ));
  assert.equal(pair.exact_time_same_param_rate, 1);
  const visibility = report.anchor_time_behavior['0x021d'];
  assert.ok(visibility['0x01cf'].exact < visibility['0x01cf'].eligible);
  assert.ok(visibility['0x017f'].exact < visibility['0x017f'].eligible);
  assert.equal(report.raw_route_profiles['0x039d'].stream_counts.keyframe, 1370);
  assert.equal(report.raw_route_profiles['0x021d'].stream_counts.game_chunk, 1907);
});

test('artifact hash manifest attests every declared output', () => {
  const hashes = readJson(HASHES);
  assert.equal(hashes.exact_build, '16.16.805.0442');
  assert.ok(hashes.artifacts.length >= 5);
  for (const artifact of hashes.artifacts) {
    assert.equal(/holdout/i.test(artifact.path), false);
    assert.equal(fs.statSync(artifact.path).size, artifact.size);
    assert.equal(sha256(artifact.path), artifact.sha256);
  }
});

test('reproducible validator accepts the generated decision bundle', () => {
  const result = spawnSync(
    'python',
    [path.join(ROOT, 'scripts', 'audit_named_gameplay_wave_16_16.py'), '--validate-only'],
    { cwd: ROOT, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, 'PASS');
});
