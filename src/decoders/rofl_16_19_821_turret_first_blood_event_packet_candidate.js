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
const CAPABILITY = 'turret_first_blood_event_packet';
const PACKET_ID = 0x040a;
const CHILD_EVENT_ID = 0x003d;
const RAW_EVENT_ID_HEX = '0x4986';
const PAYLOAD_LENGTH = 116;
const BLOB_LENGTH = 108;
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 2_000;
const MAX_BATCH_PACKETS = 2_000;
const MAX_REQUEST_BYTES = 1_000_000;

const TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-turret-first-blood-event-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1]),
  replay_block_packet_id: PACKET_ID,
  payload_length: PAYLOAD_LENGTH,
  packet_name: 'PKT_OnEvent_s',
  child_event_id: CHILD_EVENT_ID,
  child_event_name: 'OnTurretFirstBlood',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_event_name_entry_rva: '0x1ef7cb8',
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: 11 native child 0x003d packets and 820 same-length foreign-child controls among 831 fully consumed 0x040a/116 parents',
  known_limits: Object.freeze([
    'The event name is an exact-image label. A packet does not prove objective first blood, actor role, or game-state transition.',
    'The 108-byte native child blob is anonymous; its field roles and any effect are UNKNOWN.',
    'The 116-byte parent route has four observed same-length foreign child IDs. Raw suffix fingerprints only select native checks; the native child ID is authoritative.',
    'One target packet occurs in each of the 11 supplied KR Replays. Absence in another Replay is PROFILE_UNAVAILABLE, not an observed zero count.',
    'Unknown same-length fingerprints and native identity disagreement fail closed. Excluded foreign controls retain raw source references.',
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

function rawShape(payload) {
  // These five complete suffixes uniquely partitioned the 831 length-116
  // parents in the supplied KR corpus. They are selectors, not a child decode.
  const tail = payload.subarray(PAYLOAD_LENGTH - 6).toString('hex');
  if (tail === '247152269586') return 'target';
  if (tail === '247152269548') return 'observed_foreign_0004';
  if (tail === '247152269506') return 'observed_foreign_0035';
  if (tail === '247152269566') return 'observed_foreign_003b';
  if (tail === '247152269518') return 'observed_foreign_0046';
  return null;
}

function decodeTurretFirstBloodEventPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    input_packet_scope: 'child_003d_length_116',
    child_event_id: CHILD_EVENT_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `OnTurretFirstBlood packet candidate supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `OnTurretFirstBlood runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedPacketCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows)) {
    return fail('DECODE_FAILED', '821 OnTurretFirstBlood route scan returned no packet rows', {
      scanned_block_count: scannedBlockCount,
    });
  }
  const target = [];
  const excludedForeign = [];
  for (const { block, chunk } of rows) {
    if (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk'
        || block.packet_id !== PACKET_ID || block.payload_length !== PAYLOAD_LENGTH
        || !Buffer.isBuffer(block.payload) || block.payload.length !== PAYLOAD_LENGTH
        || !Number.isSafeInteger(block.timestamp_ms)
        || !validU32(block.param) || block.param === 0) {
      return fail('DECODE_FAILED', '0x040a/116 OnEvent packet framing differs from observed KR scope', {
        scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    const shape = rawShape(block.payload);
    if (shape === 'target') target.push({ block, chunk });
    else if (shape?.startsWith('observed_foreign_')) {
      excludedForeign.push(packetRef(replay, block, chunk));
    } else {
      return fail('DECODE_FAILED', 'unrecognized 0x040a/116 OnEvent raw child fingerprint', {
        scanned_block_count: scannedBlockCount,
        observed_same_length_packet_count: rows.length,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
  }
  const exclusions = {
    observed_same_length_packet_count: rows.length,
    excluded_same_length_foreign_count: excludedForeign.length,
    excluded_same_length_foreign_packet_refs: excludedForeign,
  };
  if (target.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a/116 OnTurretFirstBlood raw shape is absent', {
      ...exclusions, observed_raw_shape_count: 0,
      scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = target.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    ...exclusions, input_count: inputCount,
    scanned_block_count: scannedBlockCount, ...extra,
  });
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
    'decode_turret_first_blood_event_packet_16_19_821.py');
  const events = [];
  for (let start = 0; start < target.length; start += MAX_BATCH_PACKETS) {
    const batch = target.slice(start, start + MAX_BATCH_PACKETS);
    const request = JSON.stringify({
      replay_version: REPLAY_VERSION,
      packets: batch.map(({ block, chunk }) => ({
        packet_id: block.packet_id, stream_tag: chunk.stream_tag,
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
      })),
    });
    if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
      return failed('UNSUPPORTED', 'OnTurretFirstBlood runtime request exceeds bounded input size', {
        runtime_image_used: start > 0,
      });
    }
    const run = childProcess.spawnSync(python, ['-B', script, '--image', imagePath], {
      input: request, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 60000,
    });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `Python exited ${run.status}`).trim().slice(0, 1500);
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
      const wrongImage = /runtime image SHA-256 mismatch/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime OnTurretFirstBlood packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime OnTurretFirstBlood packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime OnTurretFirstBlood output identity or packet count differs', {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const valid = row && row.status === 'DECODED'
        && row.input_index === index
        && row.raw_param === ref.raw_param
        && row.raw_payload_sha256 === ref.raw_payload_sha256
        && row.deserialize_return_al === 1
        && row.bytes_consumed === PAYLOAD_LENGTH
        && row.native_packet_id === PACKET_ID
        && row.native_raw_param === ref.raw_param
        && row.event_id === CHILD_EVENT_ID
        && row.raw_event_id_hex === RAW_EVENT_ID_HEX
        && row.event_blob_length === BLOB_LENGTH
        && typeof row.event_blob_hex === 'string'
        && /^[0-9a-f]{216}$/.test(row.event_blob_hex)
        && /^[0-9a-f]{64}$/.test(row.event_blob_sha256);
      const blob = valid ? Buffer.from(row.event_blob_hex, 'hex') : null;
      if (!valid || sha256(blob) !== row.event_blob_sha256) {
        return failed('DECODE_FAILED', `runtime OnTurretFirstBlood packet ${start + index} did not match exact child scope`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'TURRET_FIRST_BLOOD_EVENT_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        event_id: CHILD_EVENT_ID,
        event_name: profile.child_event_name,
        raw_event_id_hex: row.raw_event_id_hex,
        event_blob_hex: row.event_blob_hex,
        event_blob_sha256: row.event_blob_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_FIRST_BLOOD_PACKET',
        raw_packet_ref: ref,
      });
    }
  }
  return {
    ...base, ...exclusions, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_FIRST_BLOOD_PACKET',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      event_id: 'VERIFIED_EXACT_NATIVE_CHILD',
      event_name: 'VERIFIED_EXACT_IMAGE_LABEL',
      event_blob_hex: 'VERIFIED_EXACT_NATIVE_BLOB',
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE,
  decodeTurretFirstBloodEventPacketCandidates821,
};
