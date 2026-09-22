'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  MIGRATION_STATUSES,
  buildFullSemanticMigration,
  diffPacketInventories,
  migrateCapabilities,
} = require('../src/full_semantic_migration');
const { parseArgs } = require('../scripts/run_full_semantic_migration');

function inventory(build, packets) {
  return {
    schema_version: 'PACKET_COVERAGE_INVENTORY_V1',
    input_record_count: packets.reduce((sum, row) => sum + row.count, 0),
    builds: [{ game_version: build, packet_type_count: packets.length }],
    packets: packets.map((row) => ({
      build,
      packet_id: row.id,
      count: row.count,
      payload_size_distribution: row.lengths.map((payload_length) => ({
        payload_length, count: 1,
      })),
      currently_decoded_as_status: row.decode ?? 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
      possible_category: row.category ?? 'UNKNOWN',
      confidence: row.confidence ?? 'CANDIDATE',
    })),
  };
}

function record(capability, overrides = {}) {
  return {
    semantic_capability: capability,
    evidence_grade: 'VERIFIED_DIRECT',
    validation_status: 'PASS',
    protocol_route: '0x0001',
    packet_registration_route: '0x0001',
    decoder_version: 'decoder-v1',
    field_mapping: { value: 'direct' },
    ...overrides,
  };
}

function manifest(previousBuild = '1.0.0.0001', currentBuild = '2.0.0.0002') {
  return {
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    capability_vocabulary: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'],
    build_profiles: {
      [previousBuild]: {
        records: [
          record('A'),
          record('B', { protocol_route: '0x0002' }),
          record('C', { protocol_route: '0x0003' }),
          record('D', { protocol_route: '0x0004' }),
          record('E', { protocol_route: '0x0005' }),
          record('F', { protocol_route: '0x0006' }),
          record('G', { protocol_route: '0x0007' }),
        ],
      },
      [currentBuild]: {
        records: [
          record('A'),
          record('B', { protocol_route: '0x0202' }),
          record('C', { protocol_route: '0x0003', field_mapping: { value: 'derived' } }),
          record('D', { protocol_route: '0x0004', evidence_grade: 'VERIFIED_DERIVED' }),
          record('E', { protocol_route: '0x0005', evidence_grade: 'CANDIDATE', validation_status: 'CANDIDATE_ONLY' }),
          record('F', { protocol_route: null, packet_registration_route: null, evidence_grade: 'UNAVAILABLE', validation_status: 'UNAVAILABLE' }),
          record('H', { protocol_route: '0x0008' }),
        ],
      },
    },
  };
}

function registration(build, routes) {
  return {
    build,
    observed_route_count: routes.length,
    status_counts: { UNIQUE_CALLBACK_RTTI_NAME: routes.length },
    routes: routes.map(([packet_id, name, owner]) => ({
      packet_id,
      packet_id_hex: `0x${packet_id.toString(16).padStart(4, '0')}`,
      observed_count: packet_id * 10,
      callback_mapping_status: 'UNIQUE_CALLBACK_RTTI_NAME',
      callbacks: [{ name, callback_owner_type: owner }],
    })),
  };
}

test('packet diff conserves every route and exposes new, removed, and shape-changed rows', () => {
  const previous = inventory('old', [
    { id: 1, count: 4, lengths: [2] },
    { id: 2, count: 3, lengths: [3] },
    { id: 3, count: 2, lengths: [4] },
  ]);
  const current = inventory('new', [
    { id: 1, count: 5, lengths: [2] },
    { id: 2, count: 8, lengths: [3, 5] },
    { id: 4, count: 9, lengths: [6] },
  ]);
  const diff = diffPacketInventories(previous, current, 'old', 'new');
  assert.equal(diff.conservation.status, 'PASS');
  assert.deepEqual(diff.NEW_PACKET_DIFF.map((row) => row.packet_id), [4]);
  assert.deepEqual(diff.REMOVED_PACKET_DIFF.map((row) => row.packet_id), [3]);
  assert.equal(diff.routes.find((row) => row.packet_id === 2).status, 'PAYLOAD_SHAPE_CHANGED');
  assert.equal(diff.routes.find((row) => row.packet_id === 1).status, 'UNCHANGED_ROUTE_AND_PAYLOAD_SHAPE');
});

test('capability migration assigns exactly one permitted evidence-conservative status', () => {
  const result = migrateCapabilities(manifest(), '1.0.0.0001', '2.0.0.0002');
  const statuses = Object.fromEntries(result.capabilities.map((row) => [row.capability, row.status]));
  assert.deepEqual(statuses, {
    A: 'UNCHANGED_VERIFIED',
    B: 'ROUTE_MOVED',
    C: 'FIELD_SHIFT',
    D: 'SEMANTIC_CHANGED',
    E: 'NEEDS_REVALIDATION',
    F: 'UNSUPPORTED',
    G: 'UNKNOWN',
    H: 'NEEDS_REVALIDATION',
  });
  assert.deepEqual(Object.keys(result.status_counts), MIGRATION_STATUSES);
  assert.equal(Object.values(result.status_counts).reduce((sum, value) => sum + value, 0), 8);
});

test('full migration emits packet/component/runtime diffs and a deterministic research queue', () => {
  const previousBuild = '1.0.0.0001';
  const currentBuild = '2.0.0.0002';
  const input = {
    previous_build: previousBuild,
    current_build: currentBuild,
    previous_inventory: inventory(previousBuild, [{ id: 1, count: 2, lengths: [2] }]),
    current_inventory: inventory(currentBuild, [
      { id: 1, count: 3, lengths: [2] },
      { id: 9, count: 50, lengths: [7] },
    ]),
    capability_manifest: manifest(previousBuild, currentBuild),
    previous_registration_map: registration(previousBuild, [[1, 'PKT_Old', 'Hero']]),
    current_registration_map: registration(currentBuild, [
      [1, 'PKT_Old', 'Hero'], [9, 'PKT_New', 'NewComponent'],
    ]),
    runtime_attestation: {
      build: currentBuild, sha256: 'a'.repeat(64), expected_sha256: 'a'.repeat(64),
      status: 'VERIFIED_EXACT_BUILD',
    },
    replay_samples: [{ build: currentBuild, sha256: 'b'.repeat(64), path: 'sample.rofl' }],
  };
  const result = buildFullSemanticMigration(input);
  assert.equal(result.nearest_build_fallback, 'FORBIDDEN');
  assert.equal(result.conservation.silent_discard, 'FORBIDDEN');
  assert.deepEqual(result.NEW_PACKET_DIFF.map((row) => row.packet_id), [9]);
  assert.deepEqual(result.NEW_COMPONENT_DIFF, ['NewComponent']);
  assert.deepEqual(result.NEW_RUNTIME_NAME_DIFF, ['PKT_New']);
  assert.equal(result.research_queue[0].key, '0x0009');
  assert.equal(result.status, 'MIGRATION_ANALYSIS_COMPLETE');
});

test('migration fails closed on mixed builds, wrong inventory scope, and fallback-enabled manifests', () => {
  const previousBuild = '1.0.0.0001';
  const currentBuild = '2.0.0.0002';
  const base = {
    previous_build: previousBuild,
    current_build: currentBuild,
    previous_inventory: inventory(previousBuild, [{ id: 1, count: 1, lengths: [1] }]),
    current_inventory: inventory(currentBuild, [{ id: 1, count: 1, lengths: [1] }]),
    capability_manifest: manifest(previousBuild, currentBuild),
    runtime_attestation: { build: currentBuild, sha256: 'a'.repeat(64), status: 'VERIFIED_EXACT_BUILD' },
    replay_samples: [{ build: currentBuild, sha256: 'b'.repeat(64) }],
  };
  assert.throws(() => buildFullSemanticMigration({
    ...base, replay_samples: [{ build: previousBuild, sha256: 'b'.repeat(64) }],
  }), /exact current build/);
  assert.throws(() => buildFullSemanticMigration({
    ...base, current_inventory: inventory(previousBuild, [{ id: 1, count: 1, lengths: [1] }]),
  }), /exactly build/);
  assert.throws(() => buildFullSemanticMigration({
    ...base, capability_manifest: { ...base.capability_manifest, nearest_build_fallback: 'ALLOWED' },
  }), /forbid nearest-build fallback/);
});

test('CLI requires explicit inputs, preserves build literals, and never performs directory discovery', () => {
  const parsed = parseArgs([
    '--runtime', 'runtime.bin',
    '--replay', 'a.rofl',
    '--replay', 'b.rofl',
    '--previous-build', '16.15.801.3452',
    '--previous-inventory', 'old.json',
    '--current-inventory', 'new.json',
    '--capability-manifest', 'manifest.json',
    '--output', 'migration.json',
  ]);
  assert.equal(parsed.previous_build, '16.15.801.3452');
  assert.equal(parsed.replay.length, 2);
  assert.throws(() => parseArgs([
    '--runtime', 'runtime.bin', '--previous-build', 'old',
    '--previous-inventory', 'old.json', '--capability-manifest', 'manifest.json',
    '--output', 'migration.json',
  ]), /explicit --replay/);
});

