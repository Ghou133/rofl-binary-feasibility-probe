'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'notify_contextual_situation_packet';
const PACKET_ID = 0x0113;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE_SIZE = 48_488_448;
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_CONTEXTUAL_SITUATION_STRING';
const MAX_PACKETS = 8_000;
const NOTIFY_CONTEXTUAL_SITUATION_OBSERVED_LENGTHS_821 = Object.freeze([
  14, 15, 16, 17, 19, 24,
]);
const NOTIFY_CONTEXTUAL_SITUATION_OBSERVED_STRINGS_821 = Object.freeze([
  'RecallChannelingUpdate', 'RecallLeadIn', 'RecallWindDown', 'RecallCancel',
  'AttackVisionplant', 'AttackBlastcone', 'EatHoneyfruit',
]);
const OBSERVED_LENGTHS = new Set(NOTIFY_CONTEXTUAL_SITUATION_OBSERVED_LENGTHS_821);
const OBSERVED_STRINGS = new Set(NOTIFY_CONTEXTUAL_SITUATION_OBSERVED_STRINGS_821);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

const NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-notify-contextual-situation-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_NotifyContextualSituation_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xf01897',
  evidence_constructor_rva: '0xeb3b50',
  evidence_deserializer_rva: '0x102d520',
  evidence_callback_rva: '0x2c9820',
  runtime_image_required: true,
  evidence_scope: '37229/37229 game-stream route 0x0113 packets from 11 exact-build KR Replays natively fully consumed; bounded native string pointers, lengths, capacities, NUL terminators, and strict UTF-8 validated for all rows',
  known_limits: Object.freeze([
    'The decoded string is a packet-local native field. Names such as RecallLeadIn do not prove the corresponding action or effect.',
    'The callback has a conditional live-receiver call; whether it executes for a Replay packet is unknown.',
    'The Replay raw parameter is retained without actor, participant, or team attribution.',
    'Only six packet lengths and seven string values observed in the 11 KR Replays are selected. New shapes or values fail closed.',
  ]),
});

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
  let observedCount = 0;
  const walked = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== PACKET_ID) return;
    observedCount += 1;
    if (rows.length >= MAX_PACKETS) return;
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
    observed_packet_count_minimum: observedCount };
}

function nativeInputSha256(rows) {
  const digest = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const { block } of rows) {
    header.writeUInt32LE(block.param >>> 0, 0);
    header.writeUInt32LE(block.payload.length, 4);
    digest.update(header);
    digest.update(block.payload);
  }
  return digest.digest('hex');
}

function validNativeRow(nativeRow, block) {
  if (nativeRow == null || typeof nativeRow !== 'object'
      || !OBSERVED_STRINGS.has(nativeRow.contextual_situation)
      || typeof nativeRow.contextual_situation_utf8_hex !== 'string'
      || !/^(?:[0-9a-f]{2})+$/.test(nativeRow.contextual_situation_utf8_hex)
      || !Number.isInteger(nativeRow.native_string_length)
      || !Number.isInteger(nativeRow.native_string_capacity)
      || nativeRow.native_string_length <= 0
      || nativeRow.native_string_length >= nativeRow.native_string_capacity
      || nativeRow.native_string_capacity > 512
      || nativeRow.raw_payload_sha256 !== sha256(block.payload)) return false;
  const bytes = Buffer.from(nativeRow.contextual_situation_utf8_hex, 'hex');
  if (bytes.length !== nativeRow.native_string_length) return false;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      === nativeRow.contextual_situation;
  } catch {
    return false;
  }
}

function decodeNotifyContextualSituationPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `NotifyContextualSituation packet candidate supports only ${BUILD}`);
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
  if (observedCount > MAX_PACKETS) {
    return fail('UNSUPPORTED', `NotifyContextualSituation input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, observed_packet_count_minimum: observedCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', '821 NotifyContextualSituation route scan returned incomplete packet rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x0113 NotifyContextualSituation route is absent', {
      input_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !OBSERVED_LENGTHS.has(block.payload.length)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param <= 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id)
        || chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk') {
      return fail('DECODE_FAILED', '0x0113 packet has unobserved shape or invalid Replay source', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: block && chunk ? packetRef(replay, block, chunk) : null,
      });
    }
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
    if (!stat.isFile() || stat.size > 64 * 1024 * 1024) {
      throw new Error('not a bounded file');
    }
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
  const inputSha = nativeInputSha256(rows);
  const nativeRequest = JSON.stringify({
    replay_version: BUILD, packet_id: PACKET_ID,
    packets: rows.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]),
  });
  if (Buffer.byteLength(nativeRequest) > 8 * 1024 * 1024) {
    return fail('UNSUPPORTED', '0x0113 native witness request exceeds 8 MiB', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_PRECHECKED', runtime_image_used: false,
      native_witness_status: 'NOT_RUN',
    });
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_notify_contextual_situation_packet_16_19_821.py');
  const nativeRun = childProcess.spawnSync(python,
    ['-B', script, '--image', path.resolve(runtimeImagePath)], {
      input: nativeRequest, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
      timeout: 120_000, windowsHide: true,
    });
  if (nativeRun.error || nativeRun.status !== 0) {
    const detail = String(nativeRun.error?.message || nativeRun.stderr
      || nativeRun.stdout || `exit ${nativeRun.status}`).trim().slice(0, 1500);
    const missingPython = nativeRun.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `0x0113 native witness unavailable or failed: ${detail}`, {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: missingPython ? 'MATCHED_PRECHECKED' : 'MATCHED_USED',
        runtime_image_used: !missingPython,
        native_witness_status: missingPython ? 'UNAVAILABLE' : 'FAILED',
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
      });
  }
  let native;
  try {
    native = JSON.parse(nativeRun.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `0x0113 native witness output is invalid JSON: ${error.message}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native?.replay_version !== BUILD || native.runtime_image_sha256 !== IMAGE_SHA256
      || native.packet_id !== PACKET_ID || native.packet_count !== observedCount
      || native.input_sha256 !== inputSha || !Array.isArray(native.rows)
      || native.native_full_success_count !== observedCount
      || native.first_failure !== null || native.rows.length !== observedCount) {
    return fail('DECODE_FAILED', '0x0113 native witness identity or input digest differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  const events = [];
  for (let index = 0; index < rows.length; index += 1) {
    const { block, chunk } = rows[index];
    const nativeRow = native.rows[index];
    if (!validNativeRow(nativeRow, block)) {
      return fail('DECODE_FAILED', `0x0113 native string row ${index} differs from packet bytes`, {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: 'FAILED',
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    events.push({
      event_type: 'NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      packet_name_candidate: profile.packet_name,
      contextual_situation: nativeRow.contextual_situation,
      contextual_situation_utf8_hex: nativeRow.contextual_situation_utf8_hex,
      native_string_length: nativeRow.native_string_length,
      native_string_capacity: nativeRow.native_string_capacity,
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      raw_packet_ref: packetRef(replay, block, chunk),
    });
  }
  return {
    ...base,
    status: 'CANDIDATE', input_count: observedCount, event_count: events.length,
    events, scanned_block_count: scannedBlockCount,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      contextual_situation: 'CANDIDATE_EXACT_RUNTIME_NATIVE_STRING',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: native.native_full_success_count,
    native_input_sha256: inputSha,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: imageSha,
  };
}

module.exports = {
  NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE_PROFILE_821,
  NOTIFY_CONTEXTUAL_SITUATION_OBSERVED_LENGTHS_821,
  NOTIFY_CONTEXTUAL_SITUATION_OBSERVED_STRINGS_821,
  decodeNotifyContextualSituationPacketCandidates821,
};
