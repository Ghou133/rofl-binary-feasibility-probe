'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { runtimeByteLookupTable821 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'show_health_bar_packet';
const PACKET_ID = 0x0165;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE_SIZE = 48_488_448;
const CALLBACK_TABLE_RVA = 0x1ab62d0;
const CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const MAX_TOTAL_PACKETS = 100_000;
const MAX_NATIVE_REQUEST_BYTES = 16 * 1024 * 1024;
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_SHOW_HEALTH_BAR_PACKET_FIELDS';

const CALLBACK_TABLE = runtimeByteLookupTable821();

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

if (CALLBACK_TABLE.length !== 256 || sha256(CALLBACK_TABLE) !== CALLBACK_TABLE_SHA256) {
  throw new Error('pinned exact 821 ShowHealthBar callback table differs');
}

const SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-show-health-bar-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_ShowHealthBar_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  evidence_registration_rva: '0x2612d9',
  evidence_callback_rva: '0x2c2c20',
  evidence_constructor_rva: '0xec12b0',
  evidence_deserializer_rva: '0x10eaa10',
  runtime_image_required: true,
  evidence_scope: '89515/89515 observed 0x0165 packets in 11 exact-build KR Replays natively fully consumed, across keyframe and game streams; callback byte and zero flag match the pinned image for both observed one-byte payloads',
  known_limits: Object.freeze([
    'The callback field represents a presentation flag candidate, not health amount, damage, healing, or an effective combat change.',
    'The Replay raw parameter is retained without actor, participant, or receiver attribution.',
    'Only raw payload bytes 4a and 4b were observed; the native deserializer also accepts other one-byte values, which are outside this candidate.',
    'Every selected packet needs an exact-image native full-consumption witness; an unseen byte, excess packet count, wrong image, or damaged Replay fails the whole capability.',
  ]),
});

function callbackByteFromObjectByte(encoded, table = CALLBACK_TABLE) {
  let value = table[(encoded + 0x41) & 0xff];
  value = (~value) & 0xff;
  value = ((value >>> 7) | (value << 1)) & 0xff;
  return (~value) & 0xff;
}

// Both raw bytes and their object +0x10 bytes are exhaustive over the 11
// observed KR Replays. A saved query can check this packet-local mapping
// without reopening the Replay or running native code.
function decodeShowHealthBarPayload821(rawPayloadHex) {
  if (rawPayloadHex !== '4a' && rawPayloadHex !== '4b') return null;
  const objectByte = rawPayloadHex === '4a' ? 0xa5 : 0xfd;
  const callbackByte = callbackByteFromObjectByte(objectByte);
  if ((rawPayloadHex === '4a' && callbackByte !== 1)
      || (rawPayloadHex === '4b' && callbackByte !== 0)) return null;
  return {
    raw_payload_byte_hex: rawPayloadHex,
    native_object_byte_0x10_hex: objectByte.toString(16).padStart(2, '0'),
    callback_byte_candidate: callbackByte,
    callback_zero_flag_candidate: Number(callbackByte === 0),
  };
}

function packetRef(replay, block, chunk) {
  const payload = Buffer.isBuffer(block.payload) ? block.payload : null;
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
    raw_payload_hex: payload?.toString('hex') ?? null,
    raw_payload_sha256: payload ? sha256(payload) : null,
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

function nativeInputSha256(rows) {
  const hash = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const { block } of rows) {
    header.writeUInt32LE(block.param >>> 0, 0);
    header.writeUInt32LE(block.payload.length, 4);
    hash.update(header);
    hash.update(block.payload);
  }
  return hash.digest('hex');
}

function decodeShowHealthBarPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `ShowHealthBar packet candidate supports only ${BUILD}`);
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
  const scannedBlockCount = selected.scanned_block_count;
  const observedCount = selected.observed_packet_count_minimum
    ?? selected.observed_packet_count ?? selected.rows?.length;
  if (observedCount > MAX_TOTAL_PACKETS) {
    return fail('UNSUPPORTED', `ShowHealthBar input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      input_count: observedCount, observed_packet_count_minimum: observedCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', '821 ShowHealthBar route scan returned incomplete packet rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x0165 ShowHealthBar route is absent', {
      input_count: 0, observed_payload_counts: { '4a': 0, '4b': 0 },
      scanned_block_count: scannedBlockCount,
    });
  }
  const payloadCounts = { '4a': 0, '4b': 0 };
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param <= 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id)
        || !((chunk.stream_tag === 1 && chunk.stream === 'game_chunk')
          || (chunk.stream_tag === 2 && chunk.stream === 'keyframe'))) {
      return fail('DECODE_FAILED', '0x0165 packet has invalid Replay source or framing fields', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: block && chunk ? packetRef(replay, block, chunk) : null,
      });
    }
    const rawHex = block.payload.toString('hex');
    if (!decodeShowHealthBarPayload821(rawHex)) {
      return fail('DECODE_FAILED', '0x0165 payload is outside observed KR one-byte shapes', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    payloadCounts[rawHex] += 1;
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return fail('MISSING_INPUT', 'exact 16.19.821.7343 mapped runtime image is required', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  let image;
  try {
    const imagePath = path.resolve(runtimeImagePath);
    const stat = fs.statSync(imagePath);
    if (!stat.isFile() || stat.size > 64 * 1024 * 1024) throw new Error('not a bounded file');
    image = fs.readFileSync(imagePath);
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const imageSha = sha256(image);
  if (image.length !== IMAGE_SIZE || imageSha !== IMAGE_SHA256) {
    return fail('DECODE_FAILED', 'exact 821 runtime image SHA-256 mismatch', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'HASH_MISMATCH', runtime_image_sha256: imageSha,
    });
  }
  const callbackTable = image.subarray(CALLBACK_TABLE_RVA, CALLBACK_TABLE_RVA + 256);
  if (sha256(callbackTable) !== CALLBACK_TABLE_SHA256
      || !callbackTable.equals(CALLBACK_TABLE)) {
    return fail('DECODE_FAILED', 'exact 821 ShowHealthBar callback table differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'TABLE_MISMATCH', runtime_image_sha256: imageSha,
    });
  }
  const inputSha = nativeInputSha256(rows);
  const nativeRequest = JSON.stringify({
    replay_version: BUILD, packet_id: PACKET_ID,
    packets: rows.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]),
  });
  if (Buffer.byteLength(nativeRequest) > MAX_NATIVE_REQUEST_BYTES) {
    return fail('UNSUPPORTED', '0x0165 native witness request exceeds 16 MiB', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    });
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_show_health_bar_packet_16_19_821.py');
  const nativeRun = childProcess.spawnSync(python,
    ['-B', script, '--image', path.resolve(runtimeImagePath), '--batch'], {
      input: nativeRequest, encoding: 'utf8', maxBuffer: 1_000_000,
      timeout: 120_000, windowsHide: true,
    });
  if (nativeRun.error || nativeRun.status !== 0) {
    const detail = String(nativeRun.error?.message || nativeRun.stderr
      || nativeRun.stdout || `exit ${nativeRun.status}`).trim().slice(0, 1500);
    const missingPython = nativeRun.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `0x0165 native witness unavailable or failed: ${detail}`, {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: missingPython ? 'UNAVAILABLE' : 'FAILED',
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
      });
  }
  let native;
  try {
    native = JSON.parse(nativeRun.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `0x0165 native witness output is invalid JSON: ${error.message}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native?.replay_version !== BUILD || native.runtime_image_sha256 !== IMAGE_SHA256
      || native.packet_id !== PACKET_ID || native.packet_count !== observedCount
      || native.input_sha256 !== inputSha
      || !Number.isInteger(native.native_full_success_count)
      || !Number.isInteger(native.callback_flag_one_count)) {
    return fail('DECODE_FAILED', '0x0165 native witness identity or input digest differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native.native_full_success_count !== observedCount || native.first_failure !== null
      || native.callback_flag_one_count !== payloadCounts['4b']) {
    const failedIndex = native.first_failure?.index;
    return fail('DECODE_FAILED', `0x0165 native packet did not match the observed callback: ${native.first_failure?.reason || 'count mismatch'}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
      native_full_success_count: native.native_full_success_count,
      first_failed_packet_ref: Number.isInteger(failedIndex)
        && failedIndex >= 0 && failedIndex < rows.length
        ? packetRef(replay, rows[failedIndex].block, rows[failedIndex].chunk) : null,
    });
  }
  const events = rows.map(({ block, chunk }) => ({
    event_type: 'SHOW_HEALTH_BAR_PACKET_CANDIDATE',
    game_version: BUILD,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256 ?? null,
    replay_time_ms: block.timestamp_ms,
    raw_param: block.param >>> 0,
    packet_name_candidate: profile.packet_name,
    ...decodeShowHealthBarPayload821(block.payload.toString('hex')),
    semantic_effect_status: 'UNKNOWN',
    confidence: 'CANDIDATE',
    semantic_status: EVIDENCE_STATUS,
    raw_packet_ref: packetRef(replay, block, chunk),
  }));
  return {
    ...base,
    status: 'CANDIDATE', input_count: observedCount, event_count: events.length,
    events, scanned_block_count: scannedBlockCount,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      callback_byte_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      callback_zero_flag_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    },
    observed_payload_counts: payloadCounts,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: native.native_full_success_count,
    native_input_sha256: inputSha,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: imageSha,
  };
}

module.exports = {
  SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821,
  decodeShowHealthBarPacketCandidates821,
  decodeShowHealthBarPayload821,
};
