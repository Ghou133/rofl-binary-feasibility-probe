'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DAMAGE_PROFILE,
  damageEventFromDecodedRow,
  isDamageDecodedRow,
  participantMetadata,
} = require('../src/decoders/damage_16_16');

function replay() {
  return {
    source_path: 'synthetic-16-16.rofl',
    source_sha256: 'replay-sha',
    header: { version: DAMAGE_PROFILE.replay_version },
    tail: {
      stats: Array.from({ length: 10 }, (_, index) => ({
        SKIN: index === 1 ? 'Talon' : index === 7 ? 'Locke' : `Champion${index + 1}`,
        TEAM: index < 5 ? 100 : 200,
      })),
    },
  };
}

function decodedRow(overrides = {}) {
  return {
    replay_path: 'synthetic-16-16.rofl',
    replay_sha256: 'replay-sha',
    replay_version: DAMAGE_PROFILE.replay_version,
    replay_time_ms: 238173,
    chunk_index: 13,
    chunk_id: 10,
    chunk_stream: 'game_chunk',
    decompressed_block_offset: 443708,
    decompressed_payload_offset: 443712,
    packet_id: DAMAGE_PROFILE.replay_block_packet_id,
    payload_length: 17,
    raw_param: 0x400000af,
    raw_param_hex: '0x400000af',
    raw_payload_hex: '35486537fabc6efaa2046096c0e19419b2',
    raw_payload_sha256: 'payload-sha',
    decoder_profile: DAMAGE_PROFILE.id,
    decoder_runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    deserialize_return_al: 1,
    fully_consumed: true,
    decoded_opcode: DAMAGE_PROFILE.client_opcode,
    opcode_matches_profile: true,
    decoded_fields: {
      field_10_u32: 0x400000b5,
      field_14_u32: 0x400000af,
      field_18_storage_u8: 174,
      field_1c_u32: 0,
      field_20_u8: 0,
      field_21_u8: 5,
      field_24_f32: 42.43879318237305,
      field_28_u8: 1,
      field_2c_f32: 0,
      field_30_u32: 22053941,
    },
    ...overrides,
  };
}

test('16.16 UnitApplyDamage row publishes verified direct fields without inventing amount stage', () => {
  const sourceReplay = replay();
  const row = decodedRow();
  assert.equal(isDamageDecodedRow(sourceReplay, row), true);
  const event = damageEventFromDecodedRow(sourceReplay, row, participantMetadata(sourceReplay));
  assert.equal(event.source_participant_id, 8);
  assert.equal(event.target_participant_id, 2);
  assert.equal(event.game_version, DAMAGE_PROFILE.replay_version);
  assert.equal(event.patch, '16.16');
  assert.equal(event.build_profile, DAMAGE_PROFILE.id);
  assert.equal(event.replay_sha256, 'replay-sha');
  assert.equal(event.timestamp_ms, row.replay_time_ms);
  assert.equal(event.source_champion, 'Locke');
  assert.equal(event.target_champion, 'Talon');
  assert.equal(event.amount, 42.43879318237305);
  assert.equal(event.damage_type, 'magic');
  assert.equal(event.damage_type_code, 1);
  assert.equal(event.amount_semantic_stage, 'UNKNOWN');
  assert.equal(event.pre_mitigation_amount, null);
  assert.equal(event.post_mitigation_amount, null);
  assert.equal(event.effective_damage, null);
  assert.equal(event.spell_key, null);
  assert.equal(event.protocol_fields.field_30_u32, 22053941);
  assert.equal(event.raw_packet_ref.payload_sha256, 'payload-sha');
});

test('16.16 damage type mapping is exact and unknown codes remain unknown', () => {
  const sourceReplay = replay();
  for (const [code, expected] of [[0, 'physical'], [1, 'magic'], [2, 'true']]) {
    const row = decodedRow({
      decoded_fields: { ...decodedRow().decoded_fields, field_28_u8: code },
    });
    assert.equal(damageEventFromDecodedRow(sourceReplay, row).damage_type, expected);
  }
  const unknown = decodedRow({
    decoded_fields: { ...decodedRow().decoded_fields, field_28_u8: 9 },
  });
  const event = damageEventFromDecodedRow(sourceReplay, unknown);
  assert.equal(event.damage_type, null);
  assert.equal(event.damage_type_status, 'UNKNOWN');
});

test('16.16 damage decoder rejects wrong build, runtime, incomplete, and invalid amount rows', () => {
  const sourceReplay = replay();
  assert.equal(isDamageDecodedRow(sourceReplay, decodedRow({
    decoder_runtime_image_sha256: 'wrong',
  })), false);
  assert.equal(isDamageDecodedRow(sourceReplay, decodedRow({ fully_consumed: false })), false);
  assert.equal(isDamageDecodedRow(sourceReplay, decodedRow({
    decoded_fields: { ...decodedRow().decoded_fields, field_24_f32: null },
  })), false);
  assert.equal(isDamageDecodedRow({ ...sourceReplay, header: { version: '16.17.0.0' } }, decodedRow()), false);
});
