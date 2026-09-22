'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { assertFrozenOrPublicSourceHash } = require('./support/public_release_hash_bridge');

const {
  EXACT_BUILD,
  ROUTE_IDS,
  RUNTIME_SHA256,
  classifyNativeFailure,
  decodeMissileTriggerScalarObject,
  decodeMovementDriverKindObject,
  decodeTurretFlagsObject,
  rejectProtectedPath,
  sha256,
  validateDecisionBundle,
} = require('../src/residual_p7_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2',
  'residual_p7_wave');
const RUNTIME_PATH = path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
  'runtime', 'league_16.16.805.0442.memory.bin');

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

function fileSha(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('P7 scope is exact-build bound to the seven delegated routes', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.deepEqual(ROUTE_IDS, [
    0x04ce, 0x0441, 0x0278, 0x046e, 0x00fc, 0x011a, 0x0433,
  ]);
  assert.equal(new Set(ROUTE_IDS).size, 7);
  assert.equal(sha256(fs.readFileSync(RUNTIME_PATH)), RUNTIME_SHA256);
});

test('protected Holdout paths are rejected before reads or hashes', () => {
  assert.throws(
    () => rejectProtectedPath(path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.rofl')),
    /protected Holdout path is forbidden/,
  );
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
});

test('callback decoders reproduce exact byte transforms', () => {
  const turret = Buffer.alloc(0x14);
  turret.set([0x73, 0x92, 0x00, 0xff], 0x10);
  assert.equal(decodeTurretFlagsObject(turret.toString('hex')), 0xb2ef08fa);

  const movement = Buffer.alloc(0x48);
  movement[0x40] = 0x47;
  assert.equal(decodeMovementDriverKindObject(movement.toString('hex')), 0x84);

  const missile = Buffer.alloc(0x30);
  missile.set([0x55, 0x55, 0x55, 0x55], 0x28);
  const scalar = decodeMissileTriggerScalarObject(missile.toString('hex'));
  assert.equal(scalar.decoded_u32_bits, 0);
  assert.equal(scalar.decoded_f32, 0);
});

test('native failures retain precise external-state locations', () => {
  const classified = classifyNativeFailure(
    'Invalid memory write (UC_ERR_WRITE_UNMAPPED); rip=0x140010203; address=0x25cc4670',
  );
  assert.equal(classified.class, 'EXTERNAL_RUNTIME_HEAP_TLS_OR_PROCESS_STATE');
  assert.equal(classified.fault_rip, '0x140010203');
  assert.equal(classified.missing_address, '0x25cc4670');
  assert.equal(classifyNativeFailure(
    'deserialize_return_al=0;fully_consumed=false',
  ).class, 'UNCLASSIFIED_NATIVE_FAILURE');
});

test('generated audit conserves every exact occurrence and native disposition', () => {
  const report = readJson('residual_p7_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.project_context_loaded, true);
  assert.equal(report.architecture_gate, 'PASS');
  assert.deepEqual(report.scope, ROUTE_IDS.map((packetId) =>
    `0x${packetId.toString(16).padStart(4, '0')}`));
  assert.equal(report.conservation.target_row_count, 195);
  assert.equal(report.conservation.target_occurrence_weight_conserved, true);
  assert.equal(report.conservation.registry_callback_counts_match, true);
  assert.equal(report.conservation.deterministic_extraction_match, true);
  assert.equal(report.native_determinism.all_match, true);
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.saturation.current_safe_local_resource_saturated, true);
  assert.equal(report.saturation.local_actionable_hypothesis_count, 0);
  assert.deepEqual(report.protected_holdout, {
    enumerated: false, read: false, hashed: false,
    decoded: false, tested: false, consumed: false,
  });
  for (const route of Object.values(report.routes)) {
    assert.equal(route.payload.occurrence_weight_conserved, true);
    for (const correlation of Object.values(route.anchor_correlations_with_shifted_controls)) {
      assert.equal(typeof correlation.shifted_137ms_within_10ms_count, 'number');
      assert.equal(typeof correlation.shifted_997ms_within_10ms_count, 'number');
      assert.equal(correlation.semantic_claim, null);
    }
  }
  for (const route of Object.values(report.native_exact_emulation.routes)) {
    assert.equal(route.all_distinct_payloads_attempted, true);
    assert.equal(route.full_occurrence_weight_conserved, true);
    assert.equal(route.all_failures_external_runtime_state, true);
    assert.equal(route.successful_full_consume_occurrence_weight
      + route.conserved_failure_occurrence_weight,
    route.full_inventory_occurrence_weight);
  }
});

test('every RTTI owner target and logical callback signature is exact', () => {
  const report = readJson('residual_p7_static_runtime_16_16.json');
  const expected = {
    '0x04ce': ['PKT_S2C_StartSpellTargeter_s', 'AIHeroClient', '0x00333c00'],
    '0x0441': ['PKT_S2C_SetMovementDriver_s', 'AIBaseClient', '0x002a4aa0'],
    '0x0278': ['PKT_NPC_AddFakeBuffs_s', 'BuffManagerClient', '0x008ccbd0'],
    '0x046e': ['PKT_S2C_AddSpellModifier_s', 'AIBaseClient', '0x002a0980'],
    '0x00fc': ['PKT_S2C_MissileScriptTrigger_s', 'MissileClient', '0x00974210'],
    '0x011a': ['PKT_UpdateTurretFlags_s', 'AITurretClient', '0x00335590'],
    '0x0433': ['PKT_Building_Die_s', 'BuildingClient', '0x00e258f8'],
  };
  assert.equal(report.runtime_sha256, RUNTIME_SHA256);
  assert.equal(report.all_routes_factory_closed, true);
  assert.equal(report.all_rtti_owner_targets_verified, true);
  assert.equal(report.all_callback_logic_signatures_verified, true);
  assert.ok(report.pdata_scan.function_count > 100000);
  assert.ok(report.pdata_scan.instruction_byte_count > 20000000);
  for (const [packetType, [name, owner, target]] of Object.entries(expected)) {
    const route = report.routes[packetType];
    assert.equal(route.receive_identity.runtime_type_name, name);
    assert.equal(route.receive_identity.callback_owner_type, owner);
    assert.equal(route.receive_identity.callback_receive_target_rva_hex, target);
    assert.equal(route.callback_static_analysis.all_required_signatures_match, true);
    assert.ok(route.callback_static_analysis.required_signatures.length >= 2);
    assert.equal(route.validations.all_factory_checks_pass, true);
  }
  assert.equal(report.routes['0x0441'].callback_static_analysis
    .logical_span_crosses_pdata_fragments, true);
  assert.equal(report.routes['0x0433'].callback_static_analysis
    .consumer.owner_slot_offset_hex, '0x0758');
  assert.equal(report.routes['0x0433'].callback_static_analysis
    .consumer.external_live_owner_vtable_required, true);
});

test('0x011a and 0x0433 publish only bounded Structure semantics', () => {
  const report = readJson('residual_p7_wave_audit_16_16.json');
  const flags = report.native_exact_emulation.routes['0x011a'].callback_decoded_fields;
  assert.equal(flags.field, 'turret_flags_u32');
  assert.equal(flags.object_offset, '0x10');
  assert.equal(flags.transitions.decoded_event_count, 30);
  assert.ok(flags.transitions.transition_count > 0);
  assert.ok(flags.transitions.same_timestamp_transition_count > 0);
  assert.match(flags.callback_consumer, /bit test 0x10/);

  const movement = report.native_exact_emulation.routes['0x0441'].callback_decoded_fields;
  assert.equal(movement.field, 'movement_driver_discriminator_u8');
  assert.equal(movement.weighted_value_distribution.reduce((sum, row) => sum + row.count, 0), 10);

  const missile = report.native_exact_emulation.routes['0x00fc'].callback_decoded_fields;
  assert.equal(missile.field, 'callback_decoded_f32_lane');
  assert.equal(missile.finite_occurrence_weight + missile.nonfinite_occurrence_weight, 87);

  const structure = report.structure_discrimination;
  const turret = structure.route_011a_named_carrier_vs_identity_boundary;
  assert.equal(turret.callback_owner, 'AITurretClient');
  assert.ok(turret.repeated_same_timestamp_same_entity_group_count > 0);
  assert.ok(turret.forbidden_identity_inferences.includes('map_identity'));
  const building = structure.route_0433_named_carrier_vs_lifecycle_boundary;
  assert.equal(building.callback_owner, 'BuildingClient');
  assert.equal(building.occurrence_count, 13);
  assert.ok(building.dampener_switch_state_relation.exact_time_same_raw_param_count > 0);
  assert.ok(building.forbidden_identity_inferences.includes('turret'));
  assert.ok(building.forbidden_identity_inferences.includes('inhibitor'));
  assert.equal(building.live_virtual_dispatch_blocker.owner_vtable_slot_offset_hex, '0x0758');
});

test('route, capability, and domain machine decisions are exhausted and external-only', () => {
  const decisions = readJson('residual_p7_wave_machine_decisions_16_16.json');
  assert.equal(validateDecisionBundle(decisions), true);
  assert.equal(decisions.route_decisions.length, 7);
  assert.equal(decisions.capability_decisions.length, 7);
  assert.equal(decisions.domain_decisions.length, 7);
  assert.deepEqual(decisions.decision_counts, {
    PROMOTE: 7,
    REPURPOSE: 0,
    KEEP_CANDIDATE: 0,
    REJECT: 0,
  });
  for (const group of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    for (const row of decisions[group]) {
      assert.equal(row.actual_reverse_engineering_executed, true);
      assert.equal(row.evidence_exhausted, true);
      assert.deepEqual(row.actionable_hypotheses, []);
      assert.ok(row.next_required_evidence.length > 0);
      assert.equal(row.external_only_gate.required, true);
      assert.equal(row.external_only_gate.local_safe_evidence_remaining, false);
    }
  }
  const building = decisions.route_decisions.find((row) => row.packet_discriminator === '0x0433');
  assert.match(building.next_required_evidence[0], /slot \+0x758/);
  assert.match(building.field_semantic_boundary, /live concrete BuildingClient vtable/);
});

test('hash manifest verifies every listed artifact and excludes itself', () => {
  const manifest = readJson('hashes_16_16.json');
  assert.equal(manifest.exact_build, EXACT_BUILD);
  assert.equal(manifest.files.length > 30, true);
  assert.equal(manifest.files.some((entry) => entry.path.endsWith('/hashes_16_16.json')), false);
  for (const entry of manifest.files) {
    const filePath = path.join(ROOT, entry.path);
    assertFrozenOrPublicSourceHash(entry, filePath, fileSha);
  }
  assert.deepEqual(manifest.protected_holdout, {
    enumerated: false, read: false, hashed: false,
    decoded: false, tested: false, consumed: false,
  });
});
