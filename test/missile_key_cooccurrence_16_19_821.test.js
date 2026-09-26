'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { resolveCapability } = require('../src/build_registry');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821: FORCE_PROFILE,
  decodeProtectedForceCreateMissileComparisonKeyU32,
} = require('../src/decoders/rofl_16_19_821_force_create_missile_packet_candidate');
const {
  CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_821: CHANGE_PROFILE,
  CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_V2_821: CHANGE_PROFILE_V2,
} = require('../src/decoders/rofl_16_19_821_change_missile_target_packet_candidate');
const {
  MISSILE_KEY_COOCCURRENCE_821_PROFILE: PAIR_PROFILE,
  associateMissileKeyCooccurrence821: associate,
} = require('../src/decoders/rofl_16_19_821_missile_key_cooccurrence_candidate');

const BUILD = '16.19.821.7343';
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

function protectedBytesFor(key) {
  const encoded = Buffer.alloc(4);
  const wanted = Buffer.alloc(4);
  wanted.writeUInt32LE(key);
  for (let i = 0; i < 4; i += 1) {
    let found = false;
    for (let candidate = 0; candidate < 256; candidate += 1) {
      const bytes = Buffer.alloc(4);
      bytes[i] = candidate;
      if (((decodeProtectedForceCreateMissileComparisonKeyU32(
        bytes.toString('hex')) >>> (i * 8)) & 255) === wanted[i]) {
        encoded[i] = candidate;
        found = true;
        break;
      }
    }
    assert.equal(found, true);
  }
  return encoded.toString('hex');
}

function packet(id, param, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture(entries, changeProfile = CHANGE_PROFILE) {
  const body = Buffer.concat(entries.map(({ kind, key, time }) => packet(
    kind === 'force' ? 0x0087 : 0x040c,
    kind === 'force' ? 0x400000ae : key,
    kind === 'force' ? Buffer.from([0xf0, 0, 0]) : Buffer.from([0x95, 0, 0]),
    time,
  )));
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const forceRows = [];
  const changeRows = [];
  let index = 0;
  const walked = walkBlocks(replay, (block, chunk) => {
    const { kind, key } = entries[index++];
    const profile = kind === 'force' ? FORCE_PROFILE : changeProfile;
    const ref = {
      source_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      chunk_index: chunk.index,
      chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream,
      chunk_file_offset: chunk.offset,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      packet_id: block.packet_id,
      replay_time_ms: block.timestamp_ms,
      payload_length: block.payload_length,
      raw_param: block.param,
      raw_payload_hex: block.payload.toString('hex'),
      raw_payload_sha256: sha(block.payload),
    };
    const row = {
      event_type: kind === 'force' ? 'FORCE_CREATE_MISSILE_PACKET_CANDIDATE'
        : 'CHANGE_MISSILE_TARGET_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: block.timestamp_ms, raw_param: block.param,
      packet_name_candidate: profile.packet_name,
      native_protected_comparison_bytes_hex: protectedBytesFor(
        kind === 'force' ? key : 0),
      native_callback_comparison_key_u32: kind === 'force' ? key : 0,
      native_callback_witness_status: 'SYNTHETIC_RECEIVER_PRE_COMPARE',
      live_receiver_lookup_status: 'UNKNOWN',
      live_receiver_comparison_status: 'UNKNOWN',
      source_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
      missile_identity_status: 'UNKNOWN', target_status: 'UNKNOWN',
      creation_effect_status: 'UNKNOWN', target_change_effect_status: 'UNKNOWN',
      causality_status: 'UNKNOWN', confidence: 'CANDIDATE',
      semantic_status: profile.evidence_status, raw_packet_ref: ref,
    };
    (kind === 'force' ? forceRows : changeRows).push(row);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const outcome = (profile, rows, packetId) => ({
    status: 'CANDIDATE', profile_id: profile.id,
    evidence_status: profile.evidence_status, input_packet_id: packetId,
    input_count: rows.length, event_count: rows.length, events: rows,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: rows.length,
    native_input_sha256: sha(`input-${packetId}`),
    native_output_sha256: sha(`output-${packetId}`),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: FORCE_PROFILE.evidence_runtime_image_sha256,
  });
  return {
    replay,
    forceCreateMissilePacketOutcome: outcome(FORCE_PROFILE, forceRows, 0x0087),
    changeMissileTargetPacketOutcome: outcome(changeProfile, changeRows, 0x040c),
  };
}

test('exact 821 capability is registered only on its full build', () => {
  assert.equal(resolveCapability(BUILD, 'missile_key_cooccurrence').status,
    'CANDIDATE');
  assert.notEqual(resolveCapability('16.19.820.7193',
    'missile_key_cooccurrence').status, 'CANDIDATE');
  assert.equal(PAIR_PROFILE.depends_on.length, 2);
});

test('physical order, 2s window, ambiguity, unmatched and controls stay explicit', () => {
  const a = 0x40000200;
  const b = 0x40000500;
  const c = 0x40000600;
  const input = fixture([
    { kind: 'force', key: a, time: 1000 },
    { kind: 'change', key: a, time: 1000 },
    { kind: 'force', key: a, time: 1000 },
    { kind: 'change', key: a, time: 1100 },
    { kind: 'change', key: b, time: 1200 },
    { kind: 'force', key: b, time: 1300 },
    { kind: 'change', key: c, time: 1400 },
    { kind: 'force', key: a + 0x100, time: 1500 },
    { kind: 'change', key: a, time: 1600 },
    { kind: 'change', key: a, time: 4000 },
  ]);
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 6);
  assert.equal(result.force_source_count, 4);
  assert.equal(result.preceding_equal_key_count, 3);
  assert.equal(result.unique_preceding_equal_key_count, 1);
  assert.equal(result.ambiguous_multiple_preceding_count, 2);
  assert.equal(result.no_preceding_equal_key_count, 3);
  assert.equal(result.future_equal_key_only_count, 1);
  assert.equal(result.no_equal_key_anywhere_count, 1);
  assert.equal(result.old_preceding_equal_key_only_count, 1);
  assert.equal(result.plus_0x100_control_preceding_count, 1);
  assert.equal(result.future_equal_key_within_window_count, 2);
  assert.equal(result.preceding_and_future_equal_key_within_window_count, 1);
  assert.equal(result.events[0].preceding_lag_ms, 0);
  assert.equal(result.events[0].force_preceding_equal_key_count, 1);
  assert.equal(result.events[1].association_status,
    'AMBIGUOUS_MULTIPLE_PRECEDING_EQUAL_KEYS');
  assert.equal(result.events[1].force_packet_ref, null);
  assert.equal(result.events[2].association_status, 'NO_PRECEDING_EQUAL_KEY');
  assert.equal(result.events[2].force_future_equal_key_count, 1);
  assert.equal(result.events[5].force_older_preceding_equal_key_count, 2);
  assert.equal(result.events[5].force_packet_ref, null);
});

test('V2 source is accepted while malformed native source fails closed', () => {
  const input = fixture([
    { kind: 'force', key: 0x40000200, time: 1000 },
    { kind: 'change', key: 0x40000200, time: 1100 },
  ], CHANGE_PROFILE_V2);
  assert.equal(associate(input.replay, input).status, 'CANDIDATE');
  input.forceCreateMissilePacketOutcome.events[0]
    .native_callback_comparison_key_u32 ^= 0x100;
  const failed = associate(input.replay, input);
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.events, null);
});

test('zero full key is recorded but never treated as an identity association', () => {
  const input = fixture([
    { kind: 'force', key: 0, time: 1000 },
    { kind: 'change', key: 0, time: 1100 },
  ]);
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.zero_force_comparison_key_count, 1);
  assert.equal(result.zero_change_header_count, 1);
  assert.equal(result.preceding_equal_key_count, 0);
  assert.equal(result.events[0].association_status, 'ZERO_HEADER_KEY_EXCLUDED');
  assert.equal(result.events[0].zero_header_raw_preceding_equal_key_count, 1);
  assert.equal(result.events[0].force_packet_ref, null);
});

test('physical predecessor with a later timestamp remains a conflict', () => {
  const input = fixture([
    { kind: 'force', key: 0x40000200, time: 2000 },
    { kind: 'change', key: 0x40000200, time: 1000 },
  ]);
  const result = associate(input.replay, input);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.timestamp_order_conflict_count, 1);
  assert.equal(result.preceding_equal_key_count, 0);
  assert.equal(result.events[0].association_status, 'TIMESTAMP_ORDER_CONFLICT');
  assert.equal(result.events[0].force_packet_ref, null);
});

test('missing and wrong-build dependencies never become a zero-count success', () => {
  const input = fixture([{ kind: 'force', key: 0x40000200, time: 1000 }]);
  const missing = associate(input.replay, {
    forceCreateMissilePacketOutcome: input.forceCreateMissilePacketOutcome,
  });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.event_count, null);
  input.changeMissileTargetPacketOutcome.runtime_image_sha256 = sha('wrong image');
  assert.equal(associate(input.replay, input).status, 'DECODE_FAILED');
});
