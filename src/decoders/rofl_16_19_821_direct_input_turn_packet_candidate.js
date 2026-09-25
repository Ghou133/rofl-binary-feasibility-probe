'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const REPLAY_VERSION = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const CALLBACK_TRANSFORM_SHA256 = 'ca8d6ef04b90a4c767e9801b47ea4ee8d38e70b59c2dd80ec0bceb7b3563517e';
const PACKET_ID = 0x00ba;
const CAPABILITY = 'direct_input_movement_turn_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 8192;
const MAX_TOTAL_PACKETS = 20_000;
const MAX_REQUEST_BYTES = 4_000_000;

function ror8(value, amount) {
  return ((value >>> amount) | (value << (8 - amount))) & 0xff;
}

function callbackTransformByte(value) {
  const rotated = ror8(value, 1);
  const shuffled = (((rotated & 0xd5) << 1) | ((rotated >>> 1) & 0x55)) & 0xff;
  return ror8((ror8(shuffled, 6) + 0x25) & 0xff, 3);
}

const CALLBACK_TRANSFORM_TABLE = Buffer.from(
  Array.from({ length: 256 }, (_, value) => callbackTransformByte(value)),
);
if (sha256(CALLBACK_TRANSFORM_TABLE) !== CALLBACK_TRANSFORM_SHA256) {
  throw new Error('821 direct-input callback transform table differs from pinned image');
}

const DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-direct-input-movement-turn-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1, 2]),
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_DirectInputMovementDriverServerTurnData_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_transform_sha256: CALLBACK_TRANSFORM_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration, constructor, deserializer and callback; 8463/8463 route packets fully consumed across 11 KR Replays',
  known_limits: Object.freeze([
    'The three callback-transformed f32 fields are packet fields, not a confirmed world position or general hero path.',
    'The static callback writes a triple on a driver-state branch; individual Replay packets are not dynamically observed taking that branch.',
    'The packet raw parameter is retained without participant, owner or target interpretation.',
    'The emulated shared base-parameter helper injects Replay framing raw_param; object-parameter agreement is stub consistency.',
    'Only the observed 13-byte selector 0x85 game/keyframe packet shape is accepted.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
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
    if (rows.length === MAX_TOTAL_PACKETS) return;
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

function decodeDirectInputMovementTurnPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_transform_sha256: CALLBACK_TRANSFORM_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `direct-input movement turn packet candidate supports only ${REPLAY_VERSION}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }
  let selected;
  try {
    selected = collectRows(replay, precollected);
  } catch (error) {
    return fail('DECODE_FAILED', `Replay framing failed: ${error.message}`);
  }
  if (selected.error) {
    return fail('DECODE_FAILED', `Replay route source failed: ${selected.error}`);
  }
  const { rows, scanned_block_count: scannedBlockCount } = selected;
  if (selected.observed_packet_count_minimum > MAX_TOTAL_PACKETS) {
    return fail('UNSUPPORTED', `direct-input movement turn runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: selected.observed_packet_count_minimum,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x00ba direct-input movement turn route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  if (inputCount > MAX_TOTAL_PACKETS) {
    return failed('UNSUPPORTED', `direct-input movement turn runtime input exceeds ${MAX_TOTAL_PACKETS} packets`);
  }
  for (const { block, chunk } of rows) {
    const param = block.param >>> 0;
    if (![1, 2].includes(chunk.stream_tag) || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || param === 0
        || block.payload_length !== 13 || block.payload[0] !== 0x85) {
      return failed('DECODE_FAILED', '0x00ba packet differs from observed KR stream, selector or length', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return failed('MISSING_INPUT', 'exact 16.19.821.7343 mapped runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const imagePath = path.resolve(runtimeImagePath);
  try {
    const stat = fs.statSync(imagePath);
    if (!stat.isFile() || stat.size > MAX_IMAGE_BYTES) {
      return failed('MISSING_INPUT', 'runtime image is not a bounded file', {
        missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      });
    }
  } catch (error) {
    return failed('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_direct_input_turn_packet_16_19_821.py');
  const events = [];
  for (let start = 0; start < rows.length; start += MAX_BATCH_PACKETS) {
    const batch = rows.slice(start, start + MAX_BATCH_PACKETS);
    const request = JSON.stringify({
      replay_version: REPLAY_VERSION,
      packets: batch.map(({ block, chunk }) => ({
        packet_id: block.packet_id, stream_tag: chunk.stream_tag,
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
      })),
    });
    if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
      return failed('UNSUPPORTED', 'direct-input movement turn runtime request exceeds bounded input size', {
        runtime_image_used: start > 0,
      });
    }
    const run = childProcess.spawnSync(python, ['-B', script, '--image', imagePath], {
      input: request, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60000,
    });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `Python exited ${run.status}`).trim().slice(0, 1500);
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
      const wrongImage = /runtime image SHA-256 mismatch|record transform table differs|callback transform differs/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime direct-input movement turn decoder failed: ${detail}`, {
          ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
          runtime_image_used: start > 0 ? true : wrongImage ? false : null,
          runtime_image_status: wrongImage ? 'HASH_MISMATCH'
            : missingPython ? 'NOT_CHECKED' : 'EXECUTION_FAILED',
        });
    }
    let decoded;
    try {
      decoded = JSON.parse(run.stdout);
    } catch (error) {
      return failed('DECODE_FAILED', `runtime direct-input movement turn output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0 ? true : null,
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || decoded.callback_transform_sha256 !== CALLBACK_TRANSFORM_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime direct-input movement turn output identity or packet count differs', {
        runtime_image_used: start > 0 ? true : null,
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const rawVector = Buffer.from(block.payload.subarray(1)).reverse();
      const expectedCallbackVector = Buffer.from(rawVector.map(
        (value) => CALLBACK_TRANSFORM_TABLE[value]));
      const transformed = typeof row?.callback_vector_bytes_hex === 'string'
        && /^[0-9a-f]{24}$/.test(row.callback_vector_bytes_hex)
        ? Buffer.from(row.callback_vector_bytes_hex, 'hex') : null;
      const decodedFloats = transformed
        ? [0, 4, 8].map((offset) => transformed.readFloatLE(offset)) : null;
      if (row?.status !== 'DECODED' || row.input_index !== index
          || row.raw_param !== ref.raw_param || row.raw_payload_sha256 !== ref.raw_payload_sha256
          || row.deserialize_return_al !== 1 || row.bytes_consumed !== block.payload_length
          || row.native_packet_id !== PACKET_ID || row.native_raw_param !== ref.raw_param
          || row.raw_object_vector_bytes_hex !== rawVector.toString('hex')
          || row.callback_vector_bytes_hex !== expectedCallbackVector.toString('hex')
          || !decodedFloats || !decodedFloats.every(Number.isFinite)
          || row.opaque_f32_0x10 !== decodedFloats[0]
          || row.opaque_f32_0x14 !== decodedFloats[1]
          || row.opaque_f32_0x18 !== decodedFloats[2]) {
        return failed('DECODE_FAILED', `runtime direct-input movement turn packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        opaque_f32_0x10: row.opaque_f32_0x10,
        opaque_f32_0x14: row.opaque_f32_0x14,
        opaque_f32_0x18: row.opaque_f32_0x18,
        raw_object_vector_bytes_hex: row.raw_object_vector_bytes_hex,
        callback_vector_bytes_hex: row.callback_vector_bytes_hex,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
        raw_packet_ref: ref,
      });
    }
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      opaque_f32_0x10: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_f32_0x14: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_f32_0x18: 'CANDIDATE_EXACT_RUNTIME_FIELD',
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821,
  decodeDirectInputMovementTurnPacketCandidates821,
};
