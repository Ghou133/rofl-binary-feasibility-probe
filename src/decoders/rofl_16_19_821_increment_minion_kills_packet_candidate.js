'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const TRANSFORM_SHA256 = '51a5a168ef2528cbf77c181560d98a91ee83478d556568d0ba855a16ce0e4150';
const PACKET_ID = 0x03a7;
const CAPABILITY = 'increment_minion_kills_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 2048;
const MAX_TOTAL_PACKETS = 10_000;
const MAX_REQUEST_BYTES = 4_000_000;
const OBSERVED_PAYLOADS = new Set([
  '380718', '382618', '382718', '38e518',
  '390718', '392618', '392718', '39e518',
  '3a0718', '3a2618', '3a2718', '3ae518',
  '3d0718', '3d2618', '3d2718', '3de518',
  '3e0718', '3e2618', '3e2718', '3e8b18', '3ecb18', '3ee518', '3ee618',
  '3f0718', '3f2618', '3f2718', '3fcb18', '3fe518', '3fe618',
]);

const INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-increment-minion-kills-packet-runtime-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_IncrementMinionKills_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_transform_sha256: TRANSFORM_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration, constructor, deserializer and callback; 279/279 observed game packets natively fully consumed across 11 KR Replays',
  known_limits: Object.freeze([
    'The callback lookup key is independently decoded from native packet object +0x10; object +0x0c receives Replay raw_param through the emulated base-reader hook.',
    'The callback contains a conditional f32 +1 write after live object lookups, but neither lookup success nor a stat change is observed for these Replay packets.',
    'The 279 observed route packets do not cover the 16,567 standard MINIONS_KILLED Replay-tail total; do not treat packet count as individual CS events.',
    'No participant identity, minion identity, last hit, CS delta, or XP gain is assigned by this decoder.',
    'Only the 29 observed three-byte game-stream payloads and canonical raw-parameter family are accepted.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function ror8(value, amount) {
  return ((value >>> amount) | (value << (8 - amount))) & 0xff;
}

function callbackTransformByte(byte) {
  let value = (byte - 2) & 0xff;
  value = ror8(value, 7);
  value = (value + 0x1c) & 0xff;
  value = ror8(value, 4);
  value = (value + 0x75) & 0xff;
  value = ror8(value, 2);
  value = (value - 0x7c) & 0xff;
  return (((value & 0xd5) << 1) | ((value >>> 1) & 0x55)) & 0xff;
}

const CALLBACK_TRANSFORM_TABLE = Buffer.from(
  Array.from({ length: 256 }, (_, byte) => callbackTransformByte(byte)),
);
if (sha256(CALLBACK_TRANSFORM_TABLE) !== TRANSFORM_SHA256) {
  throw new Error('821 IncrementMinionKills callback transform differs from pinned image');
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

function lookupKeyFromNativeBytes(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const bytes = Buffer.from(rawHex, 'hex');
  const decoded = Buffer.from(bytes.map((byte) => CALLBACK_TRANSFORM_TABLE[byte]));
  return decoded.readUInt32LE(0);
}

function decodeIncrementMinionKillsPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_transform_sha256: TRANSFORM_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `IncrementMinionKills packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `IncrementMinionKills input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows)) return fail('DECODE_FAILED', '821 route scan returned no packet rows');
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x03a7 IncrementMinionKills route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  for (const { block, chunk } of rows) {
    if (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk'
        || block.packet_id !== PACKET_ID || !Buffer.isBuffer(block.payload)
        || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || (block.param >>> 0) < 0x400000ae || (block.param >>> 0) > 0x400000b7
        || !OBSERVED_PAYLOADS.has(block.payload.toString('hex'))) {
      return failed('DECODE_FAILED', '0x03a7 packet differs from observed KR stream, parameter or payload', {
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
    'decode_increment_minion_kills_packet_16_19_821.py');
  const events = [];
  for (let start = 0; start < rows.length; start += MAX_BATCH_PACKETS) {
    const batch = rows.slice(start, start + MAX_BATCH_PACKETS);
    const request = JSON.stringify({
      replay_version: BUILD,
      packets: batch.map(({ block, chunk }) => ({
        packet_id: block.packet_id, stream_tag: chunk.stream_tag,
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
      })),
    });
    if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
      return failed('UNSUPPORTED', 'IncrementMinionKills runtime request exceeds bounded size', {
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
      const wrongImage = /runtime image SHA-256 mismatch|callback transform differs/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime IncrementMinionKills decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime IncrementMinionKills output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0 ? true : null,
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || decoded.callback_transform_sha256 !== TRANSFORM_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime IncrementMinionKills output identity or packet count differs', {
        runtime_image_used: start > 0 ? true : null,
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const decodedLookupKey = lookupKeyFromNativeBytes(
        row?.native_object_lookup_key_bytes_hex);
      if (row?.status !== 'DECODED' || row.input_index !== index
          || row.raw_param !== ref.raw_param || row.raw_payload_sha256 !== ref.raw_payload_sha256
          || row.deserialize_return_al !== 1 || row.bytes_consumed !== block.payload_length
          || row.native_packet_id !== PACKET_ID || row.native_raw_param !== ref.raw_param
          || decodedLookupKey !== ref.raw_param
          || row.callback_lookup_key_candidate !== decodedLookupKey) {
        return failed('DECODE_FAILED', `runtime IncrementMinionKills packet ${start + index} did not match callback key`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'INCREMENT_MINION_KILLS_PACKET_CANDIDATE',
        game_version: BUILD,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        raw_payload_hex: block.payload.toString('hex'),
        raw_selector_byte: block.payload[0],
        native_object_lookup_key_bytes_hex: row.native_object_lookup_key_bytes_hex,
        callback_lookup_key_candidate: decodedLookupKey,
        callback_lookup_key_matches_raw_param: true,
        conditional_counter_write_status: 'UNKNOWN',
        semantic_cs_effect_status: 'UNKNOWN',
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY',
        raw_packet_ref: ref,
      });
    }
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      raw_payload_hex: 'VERIFIED_DIRECT', raw_selector_byte: 'VERIFIED_DIRECT',
      native_object_lookup_key_bytes_hex: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      callback_lookup_key_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821,
  decodeIncrementMinionKillsPacketCandidates821,
};
