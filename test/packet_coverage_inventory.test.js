'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { BUILD_PROFILES } = require('../src/build_registry');
const {
  buildPacketCoverageInventory,
  numericPacketId,
} = require('../src/packet_coverage_inventory');

test('inventory groups only by exact build and deterministically describes raw packet coverage', () => {
  const damageRoute = BUILD_PROFILES['16.15.801.3452'].packet_routes.hero_damage;
  const records = [
    {
      replay_version: '16.15.801.3452', packet_id: 0x7fff, payload_length: 8, raw_param: 0,
      replay_time_ms: 10,
      source: { source_kind: 'RAW_ROFL', source_path: 'fixture.rofl', replay_sha256: 'a'.repeat(64) },
    },
    { replay_version: '16.15.801.3452', packet_id: damageRoute, payload_length: 12, raw_param: 0x400000ae, replay_time_ms: 200 },
    { replay_version: '16.15.801.3452', packet_id: 0x7fff, payload_length: 4, raw_param: 42, replay_time_ms: 900 },
    { replay_version: '16.15.801.3452', packet_id: damageRoute, payload_length: 12, raw_param: 0x400000af, replay_time_ms: 400 },
    { replay_version: '16.16.805.0442', packet_id: damageRoute, payload_length: 6, raw_param: 0, replay_time_ms: 300 },
  ];
  const inventory = buildPacketCoverageInventory(records);
  assert.equal(inventory.input_record_count, 5);
  assert.deepEqual(inventory.builds.map((row) => row.game_version), ['16.15.801.3452', '16.16.805.0442']);
  assert.equal(inventory.packets.length, 3);

  const known = inventory.packets.find((row) => row.build === '16.15.801.3452'
    && row.packet_id === damageRoute);
  assert.equal(known.currently_decoded_as_status, 'EXACT_BUILD_ROUTE_REGISTERED');
  assert.deepEqual(known.decoded_as.map((entry) => entry.capability), ['hero_damage']);
  assert.equal(known.possible_category, 'COMBAT');
  assert.equal(known.confidence, 'VERIFIED_DIRECT');
  assert.equal(known.entity_candidate.kind, 'CHAMPION_NETWORK_ID_RANGE_CANDIDATE');
  assert.deepEqual(known.payload_size_distribution, [{ payload_length: 12, count: 2 }]);
  assert.equal(known.temporal_behavior.pattern, 'STARTUP_CONCENTRATED_CANDIDATE');

  const unknown = inventory.packets.find((row) => row.packet_id === 0x7fff);
  assert.equal(unknown.currently_decoded_as_status, 'UNREGISTERED_EXACT_BUILD_RAW_ONLY');
  assert.equal(unknown.possible_category, 'UNKNOWN');
  assert.equal(unknown.confidence, 'CANDIDATE');
  assert.equal(unknown.research_priority, 'P2_LOW_FREQUENCY_UNKNOWN_PACKET_CANDIDATE');
  assert.deepEqual(unknown.payload_size_distribution, [
    { payload_length: 4, count: 1 },
    { payload_length: 8, count: 1 },
  ]);
  assert.ok(unknown.provenance.some((row) => row.source_kind === 'RAW_ROFL'));

  assert.deepEqual(inventory, buildPacketCoverageInventory([...records].reverse()));
});

test('inventory reports the verified migrated 16.16 damage route and rejects build-less packet records', () => {
  const candidateRoute = BUILD_PROFILES['16.16.805.0442'].packet_routes.hero_damage;
  const inventory = buildPacketCoverageInventory([{
    game_version: '16.16.805.0442', packet_id: candidateRoute, payload_length: 9, raw_param: 0,
  }]);
  assert.equal(inventory.packets[0].currently_decoded_as_status, 'EXACT_BUILD_ROUTE_REGISTERED');
  assert.equal(inventory.packets[0].confidence, 'VERIFIED_DIRECT');
  assert.equal(inventory.packets[0].possible_category, 'COMBAT');
  assert.throws(() => buildPacketCoverageInventory([{ packet_id: 1, payload_length: 0 }]), /exact game_version/);
  assert.equal(numericPacketId('0x00f6'), 0x00f6);
});
