'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buffEventFromDecodedRow,
  canonicalProtectionEventsFromDecodedRows,
  deathTimerEventFromDecodedRow,
  inventorySnapshotEvent,
  inventorySwapEvent,
  itemSubstitutionMapEvent,
  spellCastEventFromDecodedRow,
  supportQuestStageEventsFromRows,
} = require('../src/decoders/deep_recovery_events_16_16');
const { canonicalizeSemanticEvent } = require('../src/semantic_api');

const SHA = 'a'.repeat(64);
const BUILD = '16.16.805.0442';

function replay() {
  return {
    source_sha256: SHA,
    source_path: 'safe.rofl',
    header: { version: BUILD },
    tail: { stats: Array.from({ length: 10 }, (_, index) => ({
      SKIN: index === 0 ? 'Vex' : `C${index + 1}`,
      TEAM_POSITION: [4, 9].includes(index) ? 'UTILITY' : 'TOP',
    })) },
  };
}

function baseRow(packetId, values = {}) {
  return {
    replay_sha256: SHA,
    replay_version: BUILD,
    replay_time_ms: 100,
    packet_id: packetId,
    raw_param: 0x400000ae,
    fully_consumed: true,
    deserialize_return_al: 1,
    ...values,
  };
}

function assertPublicScope(event) {
  assert.equal(event.exact_build, BUILD);
  assert.equal(event.game_version, BUILD);
  assert.equal(event.patch, '16.16');
  assert.equal(event.build_profile, event.decoder_profile);
  assert.equal(event.replay_sha256, SHA);
}

test('death timer exact inverse publishes a timer without inventing respawn time', () => {
  const event = deathTimerEventFromDecodedRow(replay(), baseRow(0x0074, {
    object_hex: 'a88cb141010000007400e6e6b100004099999794',
    decoded_opcode: 0x0074,
    opcode_matches_profile: true,
    decoder_runtime_image_sha256:
      '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55',
    decoder_profile_sha256:
      '3c813628deb00f2c6f44bdb3920dccb621b19b0a26ccdd723cc6f781ac7a349b',
    raw_payload_sha256: 'b'.repeat(64),
  }));
  assert.equal(event.death_timer_seconds, 10);
  assertPublicScope(event);
  assert.equal(event.respawn_timestamp_ms, null);
  assert.equal(event.participant_id, 1);
  const canonical = canonicalizeSemanticEvent('EntityLifecycle', event);
  assert.equal(canonical.fields.death_timer_seconds, 10);
  assert.equal(canonical.fields.respawn_timestamp_ms, null);
  assert.equal(JSON.stringify(canonical).includes('0x0074'), false);
});

test('Buff adapter publishes operation/routing structure but not target, stack, or duration', () => {
  const event = buffEventFromDecodedRow(replay(), baseRow(0x0326, {
    build: BUILD,
    target_network_id_candidate: 0x400000ae,
    slot_candidate: 3,
    u32_candidates: { '0x04': 1234 },
    packet_object_sha256: 'c'.repeat(64),
  }));
  assert.equal(event.operation, 'ADD');
  assertPublicScope(event);
  assert.equal(event.routing_entity_id, 0x400000ae);
  assert.equal(event.subject_entity_id, null);
  assert.equal(event.buff_identifier, '0x000004d2');
  assert.equal(event.stack_count, null);
  const canonical = canonicalizeSemanticEvent('BuffEvent', event);
  assert.equal(canonical.fields.routing_entity_id, 0x400000ae);
  assert.equal(canonical.fields.subject_entity_id, null);
});

test('Cast adapter keeps a numeric identifier and only derives caster on exact roster-name match', () => {
  const event = spellCastEventFromDecodedRow(replay(), baseRow(0x01cf, {
    build: BUILD,
    spell_key_candidate: 126588972,
    caster_name_exact_translator: 'Vex',
    caster_network_id_candidate: 0x400000ae,
    packet_object_sha256: 'd'.repeat(64),
  }));
  assert.equal(event.caster_entity_id, 0x400000ae);
  assertPublicScope(event);
  assert.equal(event.numeric_spell_key, 126588972);
  assert.match(event.spell_identifier, /^0x/);
  assert.equal(event.target_entity_id, null);
  assert.equal(event.cast_time_seconds, null);
});

test('Protection canonicalization suppresses only exact shield duplicate pairs', () => {
  const common = {
    build: BUILD,
    replay_sha256: SHA,
    replay_time_ms: 200,
    packet_id: 0x0371,
    schema_id_matches_cross_build_hypothesis: true,
    parameter_size_matches_cross_build_hypothesis: true,
    parameter_blob_sha256: 'e'.repeat(64),
    source_network_id_candidate: 0x400000ae,
    target_network_id_candidate: 0x400000af,
    amount_candidate: 100,
  };
  const events = canonicalProtectionEventsFromDecodedRows(replay(), [
    { ...common, event_id: 0x00ed },
    { ...common, event_id: 0x00ee },
  ]);
  assert.equal(events.length, 1);
  assertPublicScope(events[0]);
  assert.equal(events[0].protection_type, 'SHIELD_APPLICATION');
  assert.equal(events[0].amount_stage, 'APPLICATION_OR_GENERATED');
  assert.equal(events[0].duplicate_suppressed, true);
  assert.throws(() => canonicalProtectionEventsFromDecodedRows(replay(), [
    { ...common, event_id: 0x00ed },
  ]), /duplicate-pair gate/);
});

test('Item adapters expose exact snapshot/swap/substitution fields without buy-sell-undo causes', () => {
  const snapshot = inventorySnapshotEvent(replay(), baseRow(0x02ea, {
    chunk_stream: 'game_chunk',
    inventory_entries: [
      { slot: 2, item_id: 1001, stack_count: 1 },
      { slot: 0, item_id: 2001, stack_count: 1 },
    ],
  }));
  assert.equal(snapshot.operation, 'INVENTORY_SNAPSHOT');
  assertPublicScope(snapshot);
  assert.deepEqual(snapshot.inventory_entries.map((row) => row.slot_index), [0, 2]);
  assert.equal(snapshot.snapshot_scope, 'LIVE_STREAM_RESET');

  const swap = inventorySwapEvent(replay(), baseRow(0x01e8, {
    first_slot_index: 1, second_slot_index: 5,
  }));
  assert.equal(swap.operation, 'SWAP');
  assertPublicScope(swap);
  assert.equal(swap.source_slot_index, 1);
  assert.equal(swap.target_slot_index, 5);

  const substitution = itemSubstitutionMapEvent(replay(), baseRow(0x005a, {
    source_item_id: 1001, target_item_id: 2422,
  }));
  assert.equal(substitution.operation, 'SUBSTITUTION_MAP_UPDATE');
  assertPublicScope(substitution);
  assert.equal(substitution.source_item_identifier, '1001');
  assert.equal(substitution.target_item_identifier, '2422');
  assert.throws(() => itemSubstitutionMapEvent(replay(), baseRow(0x005a, {
    source_item_id: 3363, target_item_id: 3340,
  })), /unverified item substitution pair/);
});

test('support quest adapter emits only utility rows and conserves noncanonical residuals', () => {
  const rows = [];
  for (let index = 0; index < 10; index += 1) {
    const participant = index + 1;
    const code = participant === 5 || participant === 10 ? 'f0393186' : 'f0f83186';
    rows.push(baseRow(0x0064, {
      raw_param: 0,
      replay_time_ms: 300,
      occurrence_index: index,
      payload_length: 7,
      raw_payload_hex: `00${code}${participant.toString(16).padStart(4, '0')}`,
    }));
  }
  const result = supportQuestStageEventsFromRows(replay(), rows);
  assert.equal(result.events.length, 2);
  result.events.forEach(assertPublicScope);
  assert.deepEqual(result.events.map((row) => row.stage), [1, 1]);
  assert.deepEqual(result.events.map((row) => row.subject_entity_id),
    [0x400000b2, 0x400000b7]);
  assert.equal(result.input_conserved, true);
  assert.equal(result.residual_row_count, 0);
});
