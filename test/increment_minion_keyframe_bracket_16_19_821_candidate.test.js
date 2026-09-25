'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { PROFILES } = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821: PACKET_PROFILE,
} = require('../src/decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');
const { RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE: profile,
  associateIncrementMinionKeyframeBracketCandidates821: associate,
} = require('../src/decoders/rofl_16_19_821_increment_minion_keyframe_bracket_candidate');

const BUILD = '16.19.821.7343';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));
const LOOKUP_BYTES = new Map([
  [0x400000b1, '26d7d7e7'],
  [0x400000b6, '07d7d7e7'],
]);

function packet(packetId, rawParam, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function snapshotPayload(value) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  const decoded = Buffer.alloc(4);
  decoded.writeFloatLE(value);
  for (let index = 0; index < 4; index += 1) {
    payload[1262 - 0x3c - index] = ENCODE.get(decoded[index]);
  }
  return payload;
}

function ref(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
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
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function fixture({ version = BUILD, keyframeTimes = [0, 1000], countsByFrame = null,
  packets = [{ rawParam: 0x400000b1, timeMs: 500, payloadHex: '3a2618' },
    { rawParam: 0x400000b6, timeMs: 750, payloadHex: '380718' }],
  } = {}) {
  const values = countsByFrame ?? keyframeTimes.map((_, index) => index === 0 ? {} : {
    [0x400000b1]: 5, [0x400000b6]: 2,
  });
  const gameChunk = { stream: 1, body: Buffer.concat(packets.map((spec) =>
      packet(0x03a7, spec.rawParam, Buffer.from(spec.payloadHex, 'hex'),
        spec.timeMs))) };
  const chunks = [];
  for (let frame = 0; frame < keyframeTimes.length; frame += 1) {
    chunks.push({ stream: 2,
      body: Buffer.concat(Array.from({ length: 10 }, (_, index) => {
        const rawParam = 0x400000ae + index;
        return packet(0x0089, rawParam,
          snapshotPayload(values[frame]?.[rawParam] ?? 0), keyframeTimes[frame]);
      })) });
    if (frame === keyframeTimes.length - 2) chunks.push(gameChunk);
  }
  const replay = replayFromChunks(chunks, version);
  const snapshotEvents = [];
  const packetEvents = [];
  walkBlocks(replay, (block, chunk) => {
    const rawRef = ref(replay, block, chunk);
    if (block.packet_id === 0x0089) {
      const bytes = Array.from({ length: 4 }, (_, index) =>
        block.payload[1262 - 0x3c - index]);
      const value = Buffer.from(bytes.map((byte) =>
        decodeRuntimeCountByte(byte))).readFloatLE(0);
      snapshotEvents.push({
        event_type: 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: SNAPSHOT_PROFILE.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: block.param >>> 0,
        participant_id_candidate: (block.param >>> 0) - 0x400000ae + 1,
        raw_payload_field_bytes_hex: Buffer.from(bytes.reverse()).toString('hex'),
        minions_killed_raw_f32_candidate: value,
        minions_killed_floor_candidate: value,
        observation_kind: 'KEYFRAME_SNAPSHOT', confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        raw_packet_ref: rawRef,
      });
    } else {
      packetEvents.push({
        event_type: 'INCREMENT_MINION_KILLS_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: PACKET_PROFILE.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        raw_param: block.param >>> 0,
        raw_payload_hex: block.payload.toString('hex'),
        raw_selector_byte: block.payload[0],
        native_object_lookup_key_bytes_hex: LOOKUP_BYTES.get(block.param >>> 0),
        callback_lookup_key_candidate: block.param >>> 0,
        callback_lookup_key_matches_raw_param: true,
        conditional_counter_write_status: 'UNKNOWN',
        semantic_cs_effect_status: 'UNKNOWN',
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY',
        raw_packet_ref: rawRef,
      });
    }
  }, { strict: true });
  const incrementMinionKillsPacketOutcome = {
    status: 'CANDIDATE', profile_id: PACKET_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    evidence_callback_transform_sha256:
      PACKET_PROFILE.evidence_callback_transform_sha256,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    input_packet_id: 0x03a7, input_count: packetEvents.length,
    event_count: packetEvents.length, events: packetEvents,
  };
  const minionsKilledSnapshotOutcome = {
    status: 'CANDIDATE', profile_id: SNAPSHOT_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    runtime_image_used: false, input_packet_id: 0x0089,
    input_count: snapshotEvents.length, event_count: snapshotEvents.length,
    keyframe_count: keyframeTimes.length, observed_participant_count: 10,
    descent_count: values.slice(1).reduce((count, frameValues, frameIndex) =>
      count + Array.from({ length: 10 }, (_, index) => 0x400000ae + index)
        .filter((rawParam) => (frameValues?.[rawParam] ?? 0)
          < (values[frameIndex]?.[rawParam] ?? 0)).length, 0),
    events: snapshotEvents,
  };
  return { replay, incrementMinionKillsPacketOutcome, minionsKilledSnapshotOutcome };
}

test('821 minion bracket links exact same key and adjacent sampled endpoints only', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(profile.capability, 'increment_minion_keyframe_bracket');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.packet_count, 2);
  assert.equal(result.snapshot_count, 20);
  assert.equal(result.keyframe_count, 2);
  assert.equal(result.observed_interval_count, 10);
  assert.equal(result.bracketed_packet_count, 2);
  assert.equal(result.distinct_bracket_count, 2);
  assert.equal(result.unbracketed_packet_count, 0);
  assert.equal(result.verified_raw_packet_count, 22);
  assert.deepEqual(result.events.map((row) => [row.participant_id_candidate,
    row.previous_snapshot_minions_killed_candidate,
    row.current_snapshot_minions_killed_candidate,
    row.observed_endpoint_delta_candidate]), [
    [4, 0, 5, 5], [9, 0, 2, 2],
  ]);
  assert.deepEqual(result.events[0].raw_packet_refs.map((ref) => ref.packet_id),
    [0x03a7, 0x0089, 0x0089]);
  assert.equal(result.events[0].live_lookup_status, 'UNKNOWN');
  assert.equal(result.events[0].semantic_cs_effect_status, 'UNKNOWN');
  for (const field of ['last_hit', 'minion_id', 'packet_cs_delta',
    'effective_counter_write']) {
    assert.equal(field in result.events[0], false);
  }
});

test('821 minion bracket keeps unbracketed packets and zero endpoint difference explicit', () => {
  const values = fixture({ keyframeTimes: [1000, 2000], packets: [
    { rawParam: 0x400000b1, timeMs: 500, payloadHex: '3a2618' },
    { rawParam: 0x400000b1, timeMs: 1500, payloadHex: '3a2618' },
    { rawParam: 0x400000b6, timeMs: 2000, payloadHex: '380718' },
    { rawParam: 0x400000b6, timeMs: 2500, payloadHex: '380718' },
  ] });
  const result = associate(values.replay, values);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 1);
  assert.equal(result.unbracketed_packet_count, 3);
  assert.deepEqual(result.unbracketed_packets.map((row) => row.reason), [
    'BEFORE_FIRST_SNAPSHOT', 'ON_KEYFRAME_BOUNDARY', 'AFTER_LAST_SNAPSHOT',
  ]);
  assert.equal(result.unbracketed_packets[0].raw_packet_ref.packet_id, 0x03a7);
  const zero = fixture();
  for (const row of zero.minionsKilledSnapshotOutcome.events) {
    if (row.replay_time_ms === 1000 && row.hero_raw_param === 0x400000b1) {
      // The synthetic source packet still says five, so physical verification
      // must reject a fabricated zero rather than silently emit it.
      row.minions_killed_raw_f32_candidate = 0;
      row.minions_killed_floor_candidate = 0;
    }
  }
  assert.equal(associate(zero.replay, zero).status, 'INCONSISTENT');
});

test('821 minion bracket preserves zero and negative sampled endpoint deltas', () => {
  for (const [lastValue, expectedDelta] of [[5, 0], [3, -2]]) {
    const values = fixture({
      keyframeTimes: [0, 1000, 2000],
      countsByFrame: [{}, { [0x400000b1]: 5 },
        { [0x400000b1]: lastValue }],
      packets: [{ rawParam: 0x400000b1, timeMs: 1500,
        payloadHex: '3a2618' }],
    });
    const result = associate(values.replay, values);
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.events[0].previous_snapshot_minions_killed_candidate, 5);
    assert.equal(result.events[0].current_snapshot_minions_killed_candidate,
      lastValue);
    assert.equal(result.events[0].observed_endpoint_delta_candidate,
      expectedDelta);
    assert.equal(result.events[0].semantic_cs_effect_status, 'UNKNOWN');
  }
});

test('821 minion bracket rejects wrong build, source bytes, image and identity', () => {
  const wrongBuild = fixture({ version: '16.19.820.7193' });
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  const changed = fixture();
  changed.replay.buffer[0] ^= 1;
  assert.equal(associate(changed.replay, changed).status, 'DECODE_FAILED');
  const wrongImage = fixture();
  wrongImage.incrementMinionKillsPacketOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
  const wrongKey = fixture();
  wrongKey.incrementMinionKillsPacketOutcome.events[0].callback_lookup_key_candidate += 1;
  assert.equal(associate(wrongKey.replay, wrongKey).status, 'INCONSISTENT');
  const foreign = fixture();
  foreign.minionsKilledSnapshotOutcome.events[0].replay_sha256 = 'f'.repeat(64);
  assert.equal(associate(foreign.replay, foreign).status, 'INCONSISTENT');
});

test('821 minion bracket rejects incomplete roster, duplicate source and bad raw references', () => {
  const missing = fixture();
  missing.minionsKilledSnapshotOutcome.events.pop();
  missing.minionsKilledSnapshotOutcome.event_count -= 1;
  missing.minionsKilledSnapshotOutcome.input_count -= 1;
  assert.equal(associate(missing.replay, missing).status, 'INCONSISTENT');
  const duplicate = fixture();
  duplicate.incrementMinionKillsPacketOutcome.events.push(
    structuredClone(duplicate.incrementMinionKillsPacketOutcome.events[0]));
  duplicate.incrementMinionKillsPacketOutcome.event_count += 1;
  duplicate.incrementMinionKillsPacketOutcome.input_count += 1;
  assert.equal(associate(duplicate.replay, duplicate).status, 'INCONSISTENT');
  const badRef = fixture();
  badRef.minionsKilledSnapshotOutcome.events[0].raw_packet_ref.raw_payload_sha256 =
    'f'.repeat(64);
  assert.equal(associate(badRef.replay, badRef).status, 'INCONSISTENT');
});

test('821 minion bracket rejects ambiguous keyframe time and participant roster', () => {
  const time = fixture({ keyframeTimes: [1000, 1000] });
  const ambiguousTime = associate(time.replay, time);
  assert.equal(ambiguousTime.status, 'INCONSISTENT');
  assert.match(ambiguousTime.error, /strictly increasing/);
  const roster = fixture();
  const duplicate = roster.minionsKilledSnapshotOutcome.events[1];
  duplicate.hero_raw_param = 0x400000ae;
  duplicate.participant_id_candidate = 1;
  duplicate.raw_packet_ref.raw_param = 0x400000ae;
  const ambiguousRoster = associate(roster.replay, roster);
  assert.equal(ambiguousRoster.status, 'INCONSISTENT');
  assert.match(ambiguousRoster.error, /roster is ambiguous/);
});

test('821 minion bracket distinguishes missing source outcomes', () => {
  const values = fixture();
  const missing = associate(values.replay, {
    minionsKilledSnapshotOutcome: values.minionsKilledSnapshotOutcome,
  });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);
  const unavailable = fixture();
  unavailable.incrementMinionKillsPacketOutcome.status = 'MISSING_INPUT';
  assert.equal(associate(unavailable.replay, unavailable).status, 'MISSING_INPUT');
  const failed = fixture();
  failed.incrementMinionKillsPacketOutcome.status = 'DECODE_FAILED';
  assert.equal(associate(failed.replay, failed).status, 'DECODE_FAILED');
  const inconsistent = fixture();
  inconsistent.minionsKilledSnapshotOutcome.status = 'INCONSISTENT';
  assert.equal(associate(inconsistent.replay, inconsistent).status, 'INCONSISTENT');
});
