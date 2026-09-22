'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DEATH_PROFILE,
  DEATH_RUNTIME_DECODER_PROFILE,
  decodeHeroDeathBlock,
  decodeHeroDeathDecodedRow,
  hasHeroDeathSignature,
  killerNetworkIdFromStorage,
} = require('../src/decoders/death_16_16');

function replay(version = DEATH_PROFILE.replay_version) {
  return {
    source_path: 'synthetic.rofl',
    source_sha256: 'a'.repeat(64),
    header: { version },
    tail: { stats: Array.from({ length: 10 }, (_, index) => ({
      SKIN: index === 4 ? 'Alistar' : `Champion${index + 1}`,
      TEAM: index < 5 ? 100 : 200,
    })) },
  };
}

function block(rawParam = 0x400001b2) {
  const payload = Buffer.from('001122334455', 'hex');
  return {
    packet_id: 0x0112,
    timestamp_ms: 727429,
    param: rawParam,
    payload,
    payload_length: payload.length,
    offset: 10,
    payload_offset: 20,
  };
}

const chunk = { stream_tag: 1, stream: 'game_chunk', index: 3, chunk_id: 4, offset: 100 };

test('16.16 HeroDeath publishes only verified route time and victim fields', () => {
  const event = decodeHeroDeathBlock(replay(), chunk, block());
  assert.equal(event.event_type, 'death');
  assert.equal(event.victim_participant_id, 5);
  assert.equal(event.victim_champion, 'Alistar');
  assert.equal(event.victim_network_id, 0x400001b2);
  assert.equal(event.victim_entity_type, 'CHAMPION');
  assert.equal(event.replay_time_ms, 727429);
  assert.equal(event.killer_network_id, null);
  assert.equal(event.assists, null);
  assert.equal(event.field_confidence.inner_payload_fields, 'UNKNOWN');
  assert.equal(event.raw_packet_ref.packet_id, 0x0112);
});

test('16.16 HeroDeath rejects wrong build, stream, route, and nonparticipant param', () => {
  assert.equal(decodeHeroDeathBlock(replay('16.17.0.0'), chunk, block()), null);
  assert.equal(hasHeroDeathSignature(block(), { ...chunk, stream_tag: 2 }), false);
  assert.equal(decodeHeroDeathBlock(replay(), chunk, { ...block(), packet_id: 0x0113 }), null);
  assert.equal(decodeHeroDeathBlock(replay(), chunk, block(0x400000ad)), null);
});

test('16.16 HeroDeath exact helper inverse publishes killer and retains unknown inner fields', () => {
  const decoded = {
    replay_path: 'synthetic.rofl',
    replay_sha256: 'a'.repeat(64),
    replay_version: DEATH_PROFILE.replay_version,
    replay_time_ms: 170545,
    chunk_stream: 'game_chunk',
    packet_id: 0x0112,
    raw_param: 0x400000b1,
    raw_payload_hex: '081b',
    raw_payload_sha256: 'b'.repeat(64),
    decoded_fields: {
      unknown_u32_0x18: 2199526018,
      unknown_u32_0x1c: 0,
    },
    decoder_profile: DEATH_RUNTIME_DECODER_PROFILE,
    decoder_profile_sha256: DEATH_PROFILE.profile_sha256,
    decoder_runtime_image_sha256: DEATH_PROFILE.runtime_image_sha256,
    decoded_opcode: 0x0112,
    opcode_matches_profile: true,
    deserialize_return_al: 1,
    fully_consumed: true,
  };
  assert.equal(killerNetworkIdFromStorage(2199526018), 0x400000b6);
  const event = decodeHeroDeathDecodedRow(replay(), decoded);
  assert.equal(event.victim_participant_id, 4);
  assert.equal(event.killer_network_id, 0x400000b6);
  assert.equal(event.killer_participant_id, 9);
  assert.equal(event.killer_champion, 'Champion9');
  assert.equal(event.field_confidence.killer_network_id, 'VERIFIED_DIRECT');
  assert.equal(event.assists, null);
  assert.equal(event.field_confidence.assists, 'UNAVAILABLE');
  assert.equal(event.field_evidence.assists.nonempty_assist_counterexample_count, 242);
  assert.equal(event.protocol_fields.unknown_u32_0x1c, 0);
  assert.equal(event.protocol_fields.all_other_inner_field_semantics, 'UNKNOWN_RETAINED_RAW');
});
