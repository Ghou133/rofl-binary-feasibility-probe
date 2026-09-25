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
const CAPABILITY = 'on_shutdown_event_packet';
const PACKET_ID = 0x040a;
const PAYLOAD_LENGTH = 105;
const BLOB_LENGTH = 96;
const CHILD_EVENT_ID = 0x00e8;
const RAW_EVENT_ID_HEX = '0x49af';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 2_000;
const MAX_BATCH_PACKETS = 1_000;
const MAX_REQUEST_BYTES = 1_000_000;

const ON_SHUTDOWN_EVENT_PACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-shutdown-event-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1]),
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_OnEvent_s',
  child_event_id: CHILD_EVENT_ID,
  registered_event_name: 'OnShutdown',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_packet_callback_rva: '0x4ce3a0',
  evidence_child_id_write_rvas: Object.freeze(['0x373bb0', '0x3a4368']),
  evidence_event_name_table_rva: '0x1ef7330',
  runtime_image_required: true,
  evidence_scope: 'exact 821 image names child 0x00e8 OnShutdown; all 72 observed length-105 game OnEvent packets across 11 KR Replays natively consumed and had that child ID, with no same-length foreign-child controls',
  known_limits: Object.freeze([
    'OnShutdown is an exact-image event label. This marker does not prove a gameplay shutdown effect.',
    'Child +0x04, +0x58, and +0x5c are anonymously decoded u32 values. Their receiver and field roles are unresolved.',
    'The 105-byte shape had no foreign child ID in the 11 observed Replays. Native child ID 0x00e8 and raw ID 0x49af are still required.',
    'The emulated base reader injects the Replay raw param; object-param equality is a consistency check, not actor proof.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function validU32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
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
    raw_payload_sha256: sha256(block.payload),
  };
}

function collectRows(replay, precollected) {
  if (precollected) return rowsFor821Capability(replay, precollected, CAPABILITY);
  const rows = [];
  let observedPacketCount = 0;
  const walked = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== PACKET_ID || block.payload_length !== PAYLOAD_LENGTH) return;
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

function decodeOnShutdownEventPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = ON_SHUTDOWN_EVENT_PACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    input_packet_scope: 'child_00e8_length_105',
    child_event_id: CHILD_EVENT_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, target_packet_count: null,
    excluded_child_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `OnShutdown event packet candidate supports only ${REPLAY_VERSION}`);
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
  const scannedBlockCount = selected.scanned_block_count;
  const observedPacketCount = selected.observed_packet_count_minimum
    ?? selected.observed_packet_count ?? selected.rows?.length;
  if (observedPacketCount > MAX_TOTAL_PACKETS) {
    return fail('UNSUPPORTED', `on-shutdown event runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedPacketCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows)) {
    return fail('DECODE_FAILED', '821 on-shutdown event route scan returned no packet rows', {
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a length-105 packet shape is absent', {
      observed_raw_shape_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  for (const { block, chunk } of rows) {
    if (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk'
        || block.packet_id !== PACKET_ID || block.payload_length !== PAYLOAD_LENGTH
        || !Buffer.isBuffer(block.payload) || block.payload.length !== PAYLOAD_LENGTH
        || !Number.isSafeInteger(block.timestamp_ms)
        || !validU32(block.param) || block.param === 0) {
      return failed('DECODE_FAILED', '0x040a length-105 packet framing differs from observed KR scope', {
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
    'decode_on_shutdown_event_packet_16_19_821.py');
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
      return failed('UNSUPPORTED', 'on-shutdown event runtime request exceeds bounded input size', {
        runtime_image_used: start > 0,
      });
    }
    const run = childProcess.spawnSync(python, ['-B', script, '--image', imagePath], {
      input: request, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 60000,
    });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `Python exited ${run.status}`).trim().slice(0, 1500);
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
      const wrongImage = /runtime image SHA-256 mismatch/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime on-shutdown event decoder failed: ${detail}`, {
          ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
          runtime_image_used: start > 0,
          runtime_image_status: wrongImage ? 'HASH_MISMATCH'
            : missingPython ? 'NOT_CHECKED' : 'EXECUTION_FAILED',
        });
    }
    let decoded;
    try {
      decoded = JSON.parse(run.stdout);
    } catch (error) {
      return failed('DECODE_FAILED', `runtime on-shutdown event output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime on-shutdown event output identity or packet count differs', {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const blob = /^[0-9a-f]{192}$/.test(row?.event_blob_hex ?? '')
        ? Buffer.from(row.event_blob_hex, 'hex') : null;
      if (!row || typeof row !== 'object'
          || row.status !== 'DECODED'
          || row.input_index !== index || row.raw_param !== ref.raw_param
          || row.raw_payload_sha256 !== ref.raw_payload_sha256
          || row.deserialize_return_al !== 1 || row.bytes_consumed !== PAYLOAD_LENGTH
          || row.native_packet_id !== PACKET_ID || row.native_raw_param !== ref.raw_param
          || row.event_id !== CHILD_EVENT_ID
          || row.raw_event_id_hex !== RAW_EVENT_ID_HEX
          || row.event_blob_length !== BLOB_LENGTH || blob === null
          || !/^[0-9a-f]{64}$/.test(row.event_blob_sha256)
          || sha256(blob) !== row.event_blob_sha256
          || !validU32(row.event_u32_0x04)
          || !validU32(row.event_u32_0x58) || !validU32(row.event_u32_0x5c)
          || blob.readUInt32LE(0x04) !== row.event_u32_0x04
          || blob.readUInt32LE(0x58) !== row.event_u32_0x58
          || blob.readUInt32LE(0x5c) !== row.event_u32_0x5c) {
        return failed('DECODE_FAILED', `runtime on-shutdown event packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'ON_SHUTDOWN_EVENT_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        child_event_id: CHILD_EVENT_ID,
        registered_event_name: 'OnShutdown',
        event_u32_0x04: row.event_u32_0x04,
        event_u32_0x58: row.event_u32_0x58,
        event_u32_0x5c: row.event_u32_0x5c,
        raw_event_id_hex: row.raw_event_id_hex,
        event_blob_sha256: row.event_blob_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
        raw_packet_ref: ref,
      });
    }
  }
  return {
    ...base,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      child_event_id: 'VERIFIED_EXACT_CALLBACK',
      registered_event_name: 'VERIFIED_EXACT_IMAGE_NAME_TABLE',
      event_u32_0x04: 'CANDIDATE_EXACT_RUNTIME_ANONYMOUS_CHILD_FIELD',
      event_u32_0x58: 'CANDIDATE_EXACT_RUNTIME_ANONYMOUS_CHILD_FIELD',
      event_u32_0x5c: 'CANDIDATE_EXACT_RUNTIME_ANONYMOUS_CHILD_FIELD',
    },
    input_count: inputCount,
    target_packet_count: events.length,
    excluded_child_count: 0,
    excluded_child_ids: {},
    event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  ON_SHUTDOWN_EVENT_PACKET_821_PROFILE,
  decodeOnShutdownEventPacketCandidates821,
};
