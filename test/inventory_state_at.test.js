'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { EXACT_BUILD, assertSafeArtifactPath, inventoryStateIndex, inventory_state_at } = require('../src/inventory_state_at');
const { build, validateGovernedItemSet } = require('../scripts/build_inventory_state_at');

function fullSnapshot(time, entries, scope = 'LIVE_STREAM_RESET') {
  return {
    event_type: 'ITEM_STATE_SNAPSHOT', exact_build: EXACT_BUILD, subject_entity_id: 0x400000ae,
    replay_time_ms: time, inventory_entries: entries, snapshot_scope: scope,
    raw_packet_ref: { packet_id: scope === 'KEYFRAME_OBSERVATION' ? 0x0311 : 0x02ea },
  };
}

test('live inventory snapshot is direct at observation and carried only until a published ambiguity', () => {
  const index = inventoryStateIndex([
    fullSnapshot(100, [{ slot_index: 0, item_identifier: '1001', stack_count: 1 }]),
    { event_type: 'ITEM_SWAP', exact_build: EXACT_BUILD, subject_entity_id: 0x400000ae,
      replay_time_ms: 200, source_slot_index: 0, target_slot_index: 1 },
    fullSnapshot(300, [{ slot_index: 1, item_identifier: '1001', stack_count: 1 }]),
  ]);
  const direct = inventory_state_at(index, 0x400000ae, 100);
  assert.equal(direct.status, 'DIRECT_SNAPSHOT');
  assert.equal(direct.slots[0].item_identifier, '1001');
  assert.equal(direct.slots[0].state, 'DIRECT_SNAPSHOT_ENTRY');
  assert.equal(inventory_state_at(index, 0x400000ae, 150).status, 'CARRIED_FORWARD');
  assert.equal(inventory_state_at(index, 0x400000ae, 200).status, 'UNKNOWN');
  assert.equal(inventory_state_at(index, 0x400000ae, 200).reason, 'SWAP_HAS_NO_PUBLISHED_ITEM_IDENTITY');
  assert.equal(inventory_state_at(index, 0x400000ae, 300).status, 'DIRECT_SNAPSHOT');
});

test('keyframe snapshot is an exact observation rather than a live mutation', () => {
  const index = inventoryStateIndex([
    fullSnapshot(100, [{ slot_index: 0, item_identifier: '1001', stack_count: 1 }], 'KEYFRAME_OBSERVATION'),
  ]);
  assert.equal(inventory_state_at(index, 0x400000ae, 100).status, 'DIRECT_SNAPSHOT');
  assert.equal(inventory_state_at(index, 0x400000ae, 101).status, 'UNKNOWN');
});

test('special-slot set remains a partial direct observation without a full snapshot', () => {
  const index = inventoryStateIndex([{
    event_type: 'ITEM_STATE_SET', exact_build: EXACT_BUILD, subject_entity_id: 0x400000ae,
    replay_time_ms: 0, slot_index: 8, item_id: 1200, stack_count: 1,
  }]);
  const state = inventory_state_at(index, 0x400000ae, 0);
  assert.equal(state.status, 'PARTIAL_DIRECT_SLOT_SET');
  assert.equal(state.completeness, 'PARTIAL');
  assert.equal(state.slots[0].item_identifier, '1200');
  assert.equal(state.slots[0].state, 'DIRECT_SLOT_SET');
});

test('exact build mismatch and unsafe paths fail closed', () => {
  assert.throws(() => inventoryStateIndex([{
    event_type: 'ITEM_STATE_SET', exact_build: '16.15.801.3452', subject_entity_id: 1,
    replay_time_ms: 0, slot_index: 8, item_id: 1200, stack_count: 1,
  }]));
  const index = inventoryStateIndex([]);
  assert.equal(inventory_state_at(index, 1, 0, { exact_build: '16.15.801.3452' }).reason, 'UNSUPPORTED_EXACT_BUILD');
  assert.throws(() => assertSafeArtifactPath('C:/tmp/Jungle_Objective_Holdout_V1/input.json'));
});

test('substitution maps never transform inventory and unknown mutations invalidate it', () => {
  const index = inventoryStateIndex([
    fullSnapshot(1, [{ slot_index: 0, item_identifier: '1001', stack_count: 1 }]),
    { event_type: 'ITEM_SUBSTITUTION_MAP_UPDATE', exact_build: EXACT_BUILD, subject_entity_id: 0x400000ae,
      replay_time_ms: 2 },
    { event_type: 'INVENTORY_MUTATION_UNKNOWN', exact_build: EXACT_BUILD, subject_entity_id: 0x400000ae,
      replay_time_ms: 3 },
  ]);
  assert.equal(inventory_state_at(index, 0x400000ae, 2).status, 'CARRIED_FORWARD');
  assert.equal(inventory_state_at(index, 0x400000ae, 3).status, 'UNKNOWN');
});

test('a direct slot set creates a per-slot-provenanced composite, never a direct whole snapshot', () => {
  const index = inventoryStateIndex([
    fullSnapshot(10, [{ slot_index: 0, item_identifier: '1001', stack_count: 1 }]),
    { event_type: 'ITEM_STATE_SET', exact_build: EXACT_BUILD, subject_entity_id: 0x400000ae,
      replay_time_ms: 20, slot_index: 8, item_id: 3340, stack_count: 1,
      raw_packet_ref: { packet_id: 0x006c } },
  ]);
  const atSet = inventory_state_at(index, 0x400000ae, 20);
  const later = inventory_state_at(index, 0x400000ae, 21);
  assert.equal(atSet.status, 'DERIVED_COMPOSITE_STATE');
  assert.equal(later.status, 'CARRIED_FORWARD_COMPOSITE_STATE');
  assert.equal(atSet.slots[0].provenance.event_type, 'ITEM_STATE_SNAPSHOT');
  assert.equal(atSet.slots[8].provenance.event_type, 'ITEM_STATE_SET');
});

function governedRow(overrides = {}) {
  return {
    replay_version: EXACT_BUILD,
    packet_id: 0x006c,
    packet_type: '0x006c',
    fully_consumed: true,
    decoder_profile: 'entity_item_deep_16_16_006c',
    decoder_profile_sha256: 'a'.repeat(64),
    decoder_runtime_image_sha256: 'b'.repeat(64),
    decoded_fields: { item_id_0x1c: 1200, slot_index_0x22: 8, stack_count_0x78: 1 },
    ...overrides,
  };
}

test('governed item-set binding rejects mixed decoder provenance and wrong build', () => {
  const summary = {
    build: EXACT_BUILD,
    runtime_image_sha256: 'b'.repeat(64),
    set_item_special_slot: { event_count: 2, native_full_consume_count: 2 },
  };
  assert.throws(() => validateGovernedItemSet([
    governedRow(), governedRow({ decoder_profile_sha256: 'c'.repeat(64) }),
  ], summary), /decoder profile SHA-256/);
  assert.throws(() => validateGovernedItemSet([
    governedRow({ replay_version: '16.15.801.3452' }), governedRow(),
  ], summary), /route\/build\/opcode provenance mismatch/);
});

test('junction ancestor guard prevents output creation and emitted artifacts are deterministic', () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'inventory-state-at-'));
  try {
    const protectedTarget = path.join(temporary, 'holdout');
    const junction = path.join(temporary, 'apparently-safe-output');
    fs.mkdirSync(protectedTarget);
    fs.symlinkSync(protectedTarget, junction, 'junction');
    const forbiddenOutput = path.join(junction, 'nested', 'output');
    assert.throws(() => assertSafeArtifactPath(forbiddenOutput), /protected Holdout realpath/);
    assert.throws(() => build(forbiddenOutput), /protected Holdout realpath/);
    assert.equal(fs.existsSync(path.join(protectedTarget, 'nested')), false);

    const outputA = path.join(temporary, 'out-a');
    const outputB = path.join(temporary, 'out-b');
    const first = build(outputA);
    const second = build(outputB);
    assert.equal(
      fs.readFileSync(first.outputPath, 'utf8'),
      fs.readFileSync(second.outputPath, 'utf8'),
    );
    assert.equal(
      fs.readFileSync(first.manifestPath, 'utf8'),
      fs.readFileSync(second.manifestPath, 'utf8'),
    );
    assert.equal(first.manifestSha256, second.manifestSha256);
    const manifest = JSON.parse(fs.readFileSync(first.manifestPath, 'utf8'));
    assert.deepEqual(Object.keys(manifest.artifacts[0]).sort(), ['bytes', 'path', 'sha256']);
    assert.equal(manifest.artifacts[0].path, 'inventory_state_at_audit.json');
    assert.equal(manifest.artifacts[0].bytes, fs.statSync(first.outputPath).size);
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
});
