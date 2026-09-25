'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { runtimeByteLookupTable821 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'circular_movement_restriction_packet';
const PACKET_ID = 0x0464;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE_BYTES = 48_488_448;
const BYTE_TABLE_RVA = 0x1ac5610;
const BYTE_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const SCALAR_TRANSFORM_SHA256 = '1c03503a6e01dd840b12db1aadb27271dcc9a1e3c34a6d68aad50d7626b0aef5';
const VECTOR_TRANSFORM_SHA256 = 'b60f1c5d50083d4b884184becb607e97fb2f34751d41b66a55e7b78b2738e745';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_CIRCULAR_MOVEMENT_RESTRICTION_PACKET_FIELDS';
const MAX_TOTAL_PACKETS = 12_000;
// Saved-output queries use the already pinned 821 table. Live decoding still
// requires the whole mapped image and checks its SHA-256 before accepting a
// candidate packet.

// Every 24-byte 0x0464 packet in the eleven KR Replays has one of these
// eight native-consumed record headers. Other headers must be researched
// before this candidate accepts them, even when their length matches.
const OBSERVED_RECORD_PREFIXES = new Set([
  '37acbb2393d15e28', '37acab2393d15e28',
  '37acbf2393d15e28', '37acb32393d15e28',
  '37acabbdef01224a', '37acbbbdef01224a',
  '37acbfbdef01224a', '37acb3bdef01224a',
]);

const CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-circular-movement-restriction-packet-runtime-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_SyncCircularMovementRestriction_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_byte_table_sha256: BYTE_TABLE_SHA256,
  evidence_scalar_transform_sha256: SCALAR_TRANSFORM_SHA256,
  evidence_vector_transform_sha256: VECTOR_TRANSFORM_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration, constructor, nested-record deserializer and callback; 68242 route packets in 11 KR Replays have the accepted 1-byte or 24-byte shape; all 129 record-bearing packets were fully consumed in an isolated native probe',
  known_limits: Object.freeze([
    'A one-byte packet has zero native records; an accepted 24-byte packet has one. This is packet structure, not an observed gameplay state transition.',
    'The scalar and three-vector are anonymous packet fields reconstructed from exact-image callback byte transforms; no world position, path, actor, owner, or effective restriction is established.',
    'The raw parameter is preserved without participant or receiver interpretation. The native base-reader probe injects it from Replay framing.',
    'Only the exact-build stream, marker, length and eight record headers observed in the 11 KR Replays are accepted.',
    'The exact-build mapped runtime image is required to verify its SHA-256 and callback byte table.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function ror8(value, count) {
  return ((value >>> count) | (value << (8 - count))) & 0xff;
}

function swapAdjacentBits(value) {
  return (((value & 0xd5) << 1) | ((value >>> 1) & 0x55)) & 0xff;
}

// Exact 821 nested record callback at RVA 0x00356310..0x0035632c.
function scalarTransformByte(value, table) {
  let decoded = table[(value - 0x0b) & 0xff];
  decoded = ror8(decoded, 1);
  decoded = (decoded + 0x10) & 0xff;
  decoded ^= 0xcb;
  decoded = ror8(decoded, 5);
  return (~decoded) & 0xff;
}

// Exact 821 nested record callback at RVA 0x00356350..0x00356376.
function vectorTransformByte(value, table) {
  const shuffled = swapAdjacentBits(value);
  return table[((ror8(shuffled, 3) ^ 0xd2) + 0x24) & 0xff];
}

const PINNED_BYTE_TABLE = runtimeByteLookupTable821();
if (PINNED_BYTE_TABLE.length !== 256 || sha256(PINNED_BYTE_TABLE) !== BYTE_TABLE_SHA256) {
  throw new Error('pinned exact-821 circular packet byte table differs');
}
const PINNED_SCALAR_TRANSFORM = Buffer.from(Array.from({ length: 256 }, (_, value) =>
  scalarTransformByte(value, PINNED_BYTE_TABLE)));
const PINNED_VECTOR_TRANSFORM = Buffer.from(Array.from({ length: 256 }, (_, value) =>
  vectorTransformByte(value, PINNED_BYTE_TABLE)));
if (sha256(PINNED_SCALAR_TRANSFORM) !== SCALAR_TRANSFORM_SHA256
    || sha256(PINNED_VECTOR_TRANSFORM) !== VECTOR_TRANSFORM_SHA256) {
  throw new Error('pinned exact-821 circular packet callback transforms differ');
}

function packetRef(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
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
    raw_payload_sha256: Buffer.isBuffer(block.payload) ? sha256(block.payload) : null,
  };
}

function collectRows(replay, precollected) {
  if (precollected) return rowsFor821Capability(replay, precollected, CAPABILITY);
  const rows = [];
  let observedPacketCount = 0;
  const walked = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== PACKET_ID) return;
    observedPacketCount += 1;
    if (rows.length >= MAX_TOTAL_PACKETS) return;
    rows.push({
      block: {
        offset: block.offset, payload_offset: block.payload_offset,
        payload_length: block.payload_length, payload: Buffer.from(block.payload),
        timestamp_ms: block.timestamp_ms, packet_id: block.packet_id,
        param: block.param,
      },
      chunk: {
        index: chunk.index, chunk_id: chunk.chunk_id, stream: chunk.stream,
        stream_tag: chunk.stream_tag, offset: chunk.offset,
      },
    });
  }, { strict: true });
  if (walked.errors.length) throw new Error(`${walked.errors.length} Replay framing errors`);
  return { rows, scanned_block_count: walked.block_count,
    observed_packet_count_minimum: observedPacketCount };
}

function shapeOf(block, chunk) {
  if (chunk.stream_tag !== 1 && chunk.stream_tag !== 2) return null;
  if ((chunk.stream_tag === 1 && chunk.stream !== 'game_chunk')
      || (chunk.stream_tag === 2 && chunk.stream !== 'keyframe')) return null;
  const payload = block.payload;
  if (payload.length === 1 && payload[0] === 0x36) return 'empty1';
  if (payload.length === 24 && OBSERVED_RECORD_PREFIXES.has(payload.subarray(0, 8).toString('hex'))) {
    return 'record24';
  }
  return null;
}

function nativeRecordVectorBytes(payload) {
  // Exact native record +0x10..+0x1b is wire dwords 12, 20, 16, each reversed.
  return Buffer.concat([
    Buffer.from(payload.subarray(12, 16)).reverse(),
    Buffer.from(payload.subarray(20, 24)).reverse(),
    Buffer.from(payload.subarray(16, 20)).reverse(),
  ]);
}

function decodeCircularMovementRestrictionPayload821(rawPayloadHex, {
  scalarTransform = PINNED_SCALAR_TRANSFORM,
  vectorTransform = PINNED_VECTOR_TRANSFORM,
} = {}) {
  if (typeof rawPayloadHex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(rawPayloadHex)) {
    return null;
  }
  const payload = Buffer.from(rawPayloadHex, 'hex');
  if (payload.length === 1 && payload[0] === 0x36) {
    return {
      packet_shape_candidate: 'empty1', packet_record_count_candidate: 0,
      raw_protected_scalar_bytes_hex: null, raw_protected_vector_bytes_hex: null,
      callback_scalar_bytes_hex: null, callback_vector_bytes_hex: null,
      anonymous_scalar_f32_candidate: null, anonymous_vector_xyz_f32_candidate: null,
    };
  }
  if (payload.length !== 24
      || !OBSERVED_RECORD_PREFIXES.has(payload.subarray(0, 8).toString('hex'))
      || !Buffer.isBuffer(scalarTransform) || scalarTransform.length !== 256
      || !Buffer.isBuffer(vectorTransform) || vectorTransform.length !== 256) {
    return null;
  }
  const rawScalarBytes = Buffer.from(payload.subarray(8, 12));
  const rawVectorBytes = nativeRecordVectorBytes(payload);
  const callbackScalarBytes = Buffer.from(rawScalarBytes.map((byte) => scalarTransform[byte]));
  const callbackVectorBytes = Buffer.from(rawVectorBytes.map((byte) => vectorTransform[byte]));
  const scalar = callbackScalarBytes.readFloatLE(0);
  const vector = {
    x: callbackVectorBytes.readFloatLE(0),
    y: callbackVectorBytes.readFloatLE(4),
    z: callbackVectorBytes.readFloatLE(8),
  };
  if (![scalar, vector.x, vector.y, vector.z].every(Number.isFinite)) return null;
  return {
    packet_shape_candidate: 'record24', packet_record_count_candidate: 1,
    raw_protected_scalar_bytes_hex: rawScalarBytes.toString('hex'),
    raw_protected_vector_bytes_hex: rawVectorBytes.toString('hex'),
    callback_scalar_bytes_hex: callbackScalarBytes.toString('hex'),
    callback_vector_bytes_hex: callbackVectorBytes.toString('hex'),
    anonymous_scalar_f32_candidate: scalar,
    anonymous_vector_xyz_f32_candidate: vector,
  };
}

function decodeCircularMovementRestrictionPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  void pythonExecutable;
  const profile = CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_byte_table_sha256: BYTE_TABLE_SHA256,
    evidence_scalar_transform_sha256: SCALAR_TRANSFORM_SHA256,
    evidence_vector_transform_sha256: VECTOR_TRANSFORM_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `circular movement restriction packet candidate supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  let selected;
  try {
    selected = collectRows(replay, precollected);
  } catch (error) {
    return fail('DECODE_FAILED', `Replay framing failed: ${error.message}`);
  }
  if (selected.error) return fail('DECODE_FAILED', `Replay route source failed: ${selected.error}`);
  const { rows, scanned_block_count: scannedBlockCount } = selected;
  const observedCount = selected.observed_packet_count
    ?? selected.observed_packet_count_minimum ?? (Array.isArray(rows) ? rows.length : 0);
  if (observedCount > MAX_TOTAL_PACKETS) {
    return fail('UNSUPPORTED', `circular movement restriction input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows)) return fail('DECODE_FAILED', '821 route scan returned no packet rows');
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x0464 circular movement restriction route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  const shapeCounts = { empty1: 0, record24: 0 };
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isSafeInteger(block.param) || block.param < 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id)) {
      return failed('DECODE_FAILED', '0x0464 packet has invalid source, parameter, or framing fields', {
        first_failed_packet_ref: block && chunk ? packetRef(replay, block, chunk) : null,
      });
    }
    const shape = shapeOf(block, chunk);
    if (!shape) {
      return failed('DECODE_FAILED', '0x0464 packet differs from native-observed stream, marker, length, or record header', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
        raw_payload_hex: block.payload.toString('hex'),
      });
    }
    shapeCounts[shape] += 1;
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return failed('MISSING_INPUT', 'exact 16.19.821.7343 mapped runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      observed_shape_counts: shapeCounts,
    });
  }
  const imagePath = path.resolve(runtimeImagePath);
  let table;
  try {
    const stat = fs.statSync(imagePath);
    if (!stat.isFile() || stat.size !== IMAGE_BYTES) {
      return failed('DECODE_FAILED', 'runtime image has an unexpected type or size', {
        runtime_image_status: 'HASH_MISMATCH', observed_shape_counts: shapeCounts,
      });
    }
    const image = fs.readFileSync(imagePath);
    if (sha256(image) !== IMAGE_SHA256) {
      return failed('DECODE_FAILED', 'runtime image SHA-256 mismatch', {
        runtime_image_status: 'HASH_MISMATCH', observed_shape_counts: shapeCounts,
      });
    }
    table = Buffer.from(image.subarray(BYTE_TABLE_RVA, BYTE_TABLE_RVA + 256));
  } catch (error) {
    return failed('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      observed_shape_counts: shapeCounts,
    });
  }
  const scalarTransform = Buffer.from(Array.from({ length: 256 }, (_, value) =>
    scalarTransformByte(value, table)));
  const vectorTransform = Buffer.from(Array.from({ length: 256 }, (_, value) =>
    vectorTransformByte(value, table)));
  if (sha256(table) !== BYTE_TABLE_SHA256 || new Set(table).size !== 256
      || sha256(scalarTransform) !== SCALAR_TRANSFORM_SHA256
      || sha256(vectorTransform) !== VECTOR_TRANSFORM_SHA256
      || new Set(scalarTransform).size !== 256 || new Set(vectorTransform).size !== 256) {
    return failed('DECODE_FAILED', 'exact 821 callback byte transforms differ from native image', {
      runtime_image_status: 'HASH_MISMATCH', observed_shape_counts: shapeCounts,
    });
  }
  const events = [];
  for (const { block, chunk } of rows) {
    const payload = block.payload;
    const ref = packetRef(replay, block, chunk);
    const decodedPayload = decodeCircularMovementRestrictionPayload821(
      payload.toString('hex'), { scalarTransform, vectorTransform });
    if (!decodedPayload) {
      return failed('DECODE_FAILED', '0x0464 packet has nonfinite anonymous callback fields', {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: IMAGE_SHA256, observed_shape_counts: shapeCounts,
        first_failed_packet_ref: ref,
      });
    }
    events.push({
      event_type: 'CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      raw_payload_hex: payload.toString('hex'),
      raw_selector_byte: payload[0],
      ...decodedPayload,
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      raw_packet_ref: ref,
    });
  }
  return {
    ...base, status: 'CANDIDATE', known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      raw_payload_hex: 'VERIFIED_DIRECT', raw_selector_byte: 'VERIFIED_DIRECT',
      packet_record_count_candidate: 'CANDIDATE_EXACT_RUNTIME_PACKET_STRUCTURE',
      anonymous_scalar_f32_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      anonymous_vector_xyz_f32_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    },
    input_count: inputCount, event_count: events.length,
    observed_shape_counts: shapeCounts, scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821,
  decodeCircularMovementRestrictionPayload821,
  decodeCircularMovementRestrictionPacketCandidates821,
};
