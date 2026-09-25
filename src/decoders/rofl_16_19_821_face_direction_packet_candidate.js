'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'face_direction_packet';
const PACKET_ID = 0x038e;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE_BYTES = 48_488_448;
const SCALAR_TABLE_RVA = 0x1ab62d0;
const SCALAR_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const VECTOR_TRANSFORM_SHA256 = '60ce4d2b71a8bdc2608e7264cb37c024907704563f87d1b91d7ba1a81cbee4b7';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_FACE_DIRECTION_PACKET_UNIT_VECTOR';
const MAX_TOTAL_PACKETS = 32_768;
const GAME_13_MARKERS = new Set([0x93, 0x83, 0x9b]);
const GAME_17_MARKERS = new Set([0x87, 0x81, 0x85, 0x89, 0x95, 0x97, 0x99, 0x91]);

const FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-face-direction-packet-runtime-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_FaceDirection_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_vector_transform_sha256: VECTOR_TRANSFORM_SHA256,
  evidence_scalar_table_sha256: SCALAR_TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration, constructor, deserializer and callback; 262393 observed packets in 11 KR Replays have the three accepted stream/length shapes',
  known_limits: Object.freeze([
    'The packet-local vector is obtained from the exact 821 native object bytes and callback byte transform; it is not a proven world position or path.',
    'The optional scalar is present on observed 17-byte game packets; a 13-byte packet has no scalar bytes and is reported as null.',
    'The callback reads live AIBaseClient state and conditionally invokes another method; no actor or direction effect is established from Replay bytes.',
    'The raw parameter is preserved without a participant or actor identity assignment.',
    'Only the stream, length, and marker combinations observed in the 11 exact-build KR Replays are accepted.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function swapAdjacentBits(byte) {
  return (((byte & 0xd5) << 1) | ((byte >>> 1) & 0x55)) & 0xff;
}

function ror8(byte, count) {
  return ((byte >>> count) | (byte << (8 - count))) & 0xff;
}

// Recovered from exact-image FaceDirection callback RVA 0x2bf460.
function decodeVectorByte(byte) {
  return swapAdjacentBits((ror8(swapAdjacentBits(byte) ^ 0x79, 4) - 0x2a) & 0xff);
}

const VECTOR_TRANSFORM = Buffer.from(
  Array.from({ length: 256 }, (_, byte) => decodeVectorByte(byte)),
);
if (sha256(VECTOR_TRANSFORM) !== VECTOR_TRANSFORM_SHA256
    || new Set(VECTOR_TRANSFORM).size !== 256) {
  throw new Error('821 FaceDirection vector transform differs from pinned native callback');
}

function transformFaceDirectionVectorBytes821(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 13) {
    throw new RangeError('FaceDirection vector requires at least 13 payload bytes');
  }
  return Buffer.from(Array.from({ length: 12 }, (_, index) =>
    VECTOR_TRANSFORM[payload[12 - index]]));
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
  const marker = block.payload[0];
  if (chunk.stream_tag === 2 && chunk.stream === 'keyframe'
      && block.payload_length === 13 && marker === 0x83) return 'keyframe13';
  if (chunk.stream_tag === 1 && chunk.stream === 'game_chunk') {
    if (block.payload_length === 13 && GAME_13_MARKERS.has(marker)) return 'game13';
    if (block.payload_length === 17 && GAME_17_MARKERS.has(marker)) return 'game17';
  }
  return null;
}

function decodeFaceDirectionPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  // Kept in the common decoder signature; the exact-image arithmetic is local.
  void pythonExecutable;
  const profile = FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_vector_transform_sha256: VECTOR_TRANSFORM_SHA256,
    evidence_scalar_table_sha256: SCALAR_TABLE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `FaceDirection packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `FaceDirection input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows)) return fail('DECODE_FAILED', '821 route scan returned no packet rows');
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x038e FaceDirection route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  const shapeCounts = { keyframe13: 0, game13: 0, game17: 0 };
  for (const row of rows) {
    const { block, chunk } = row;
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isSafeInteger(block.param) || block.param < 0
        || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id)) {
      return failed('DECODE_FAILED', '0x038e packet has invalid source, parameter, or framing fields', {
        first_failed_packet_ref: block && chunk ? packetRef(replay, block, chunk) : null,
      });
    }
    const shape = shapeOf(block, chunk);
    if (!shape) {
      return failed('DECODE_FAILED', '0x038e packet differs from observed KR stream, length, or marker', {
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
  let scalarTable;
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
    scalarTable = Buffer.from(image.subarray(SCALAR_TABLE_RVA, SCALAR_TABLE_RVA + 256));
  } catch (error) {
    return failed('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      observed_shape_counts: shapeCounts,
    });
  }
  if (sha256(scalarTable) !== SCALAR_TABLE_SHA256 || new Set(scalarTable).size !== 256) {
    return failed('DECODE_FAILED', 'exact 821 scalar table differs from native image', {
      runtime_image_status: 'HASH_MISMATCH', observed_shape_counts: shapeCounts,
    });
  }
  const events = [];
  for (const { block, chunk } of rows) {
    const payload = block.payload;
    const shape = shapeOf(block, chunk);
    const ref = packetRef(replay, block, chunk);
    // Native object +0x14..+0x1f reverses wire bytes 1..12. The callback
    // transforms those object bytes before comparing three f32 components.
    const vectorBytes = transformFaceDirectionVectorBytes821(payload);
    const x = vectorBytes.readFloatLE(0);
    const y = vectorBytes.readFloatLE(4);
    const z = vectorBytes.readFloatLE(8);
    const normSquared = x * x + y * y + z * z;
    if (![x, y, z].every(Number.isFinite)
        || !Number.isFinite(normSquared) || Math.abs(normSquared - 1) > 0.001) {
      return failed('DECODE_FAILED', '0x038e packet vector fails finite unit-length check', {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: IMAGE_SHA256, observed_shape_counts: shapeCounts,
        first_failed_packet_ref: ref,
      });
    }
    let scalar = null;
    if (shape === 'game17') {
      const scalarBytes = Buffer.from(payload.subarray(13, 17).map((byte) =>
        scalarTable[scalarTable[byte] ^ 0x29]));
      scalar = scalarBytes.readFloatLE(0);
      if (!Number.isFinite(scalar) || scalar < 0) {
        return failed('DECODE_FAILED', '0x038e optional scalar fails finite nonnegative check', {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, observed_shape_counts: shapeCounts,
          first_failed_packet_ref: ref,
        });
      }
    }
    events.push({
      event_type: 'FACE_DIRECTION_PACKET_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      raw_payload_hex: payload.toString('hex'),
      raw_selector_byte: payload[0],
      raw_optional_scalar_bytes_hex: shape === 'game17'
        ? payload.subarray(13, 17).toString('hex') : null,
      packet_shape_candidate: shape,
      packet_vector_xyz_f32_candidate: { x, y, z },
      optional_scalar_f32_candidate: scalar,
      semantic_direction_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      raw_packet_ref: ref,
    });
  }
  return {
    ...base, status: 'CANDIDATE',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      raw_payload_hex: 'VERIFIED_DIRECT', raw_selector_byte: 'VERIFIED_DIRECT',
      raw_optional_scalar_bytes_hex: 'VERIFIED_DIRECT',
      packet_vector_xyz_f32_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      optional_scalar_f32_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    },
    input_count: inputCount, event_count: events.length,
    observed_shape_counts: shapeCounts,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821,
  decodeFaceDirectionPacketCandidates821,
  transformFaceDirectionVectorBytes821,
};
