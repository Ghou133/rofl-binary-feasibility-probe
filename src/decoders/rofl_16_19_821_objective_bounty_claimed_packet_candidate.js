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
const CAPABILITY = 'objective_bounty_claimed_packet';
const PACKET_ID = 0x040a;
const CHILD_EVENT_ID = 0x0113;
const RAW_EVENT_ID_HEX = '0x09e5';
const CONTROL_IDS = new Set([0x00cb, 0x00cf, 0x0101, 0x0102, 0x0107, 0x0114, 0x0115]);
const PAYLOAD_LENGTH = 17;
const BLOB_LENGTH = 8;
const OBSERVED_BLOB_U32_0X00 = 469;
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 10_000;
const MAX_BATCH_PACKETS = 2_000;
const MAX_REQUEST_BYTES = 1_000_000;

const OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-objective-bounty-claimed-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1]),
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_OnEvent_s',
  payload_length: PAYLOAD_LENGTH,
  child_event_id: CHILD_EVENT_ID,
  child_event_name: 'OnObjectiveBountyClaimed',
  event_blob_length: BLOB_LENGTH,
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_event_name_table_rva: '0x1ef7330',
  evidence_event_name_entry_rva: '0x1ef9e28',
  runtime_image_required: true,
  evidence_scope: 'exact 821 image name table labels child 0x0113 OnObjectiveBountyClaimed; native parent fully consumes all 5621 observed length-17 packets, including 11 target and 5610 same-length foreign controls across 11 KR Replays',
  known_limits: Object.freeze([
    'The event name is an exact-image table label. A packet does not prove an objective bounty was paid or any game-state transition.',
    'Native child +0x04 is an anonymous u32 value. Actor, target, object, and effect roles are UNKNOWN.',
    'No child-specific callback or callback-read field mapping has been established for 0x0113.',
    'The 11 target packets occur in seven of 11 KR Replays; 5610 native same-length foreign-child packets are explicitly excluded.',
    'Replay raw_param differs from native child +0x04 in all 11 targets and is preserved separately.',
    'The observed child +0x00 value 469 and raw event ID 0x09e5 are exact-sample gates. Other shapes fail closed.',
    'The emulated base reader injects the Replay raw param; object-param equality is a consistency check, not independent actor proof.',
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

function decodeObjectiveBountyClaimedEventPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    input_packet_scope: 'child_0113_length_17',
    child_event_id: CHILD_EVENT_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, target_packet_count: null,
    same_length_control_count: null, same_length_control_ids: null,
    same_length_control_refs: null,
    event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `OnObjectiveBountyClaimed packet candidate supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `OnObjectiveBountyClaimed runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedPacketCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows)) {
    return fail('DECODE_FAILED', '821 OnObjectiveBountyClaimed route scan returned no packet rows', {
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a length-17 OnEvent packet shape is absent', {
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
      return failed('DECODE_FAILED', '0x040a OnObjectiveBountyClaimed packet framing differs from observed KR scope', {
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
    'decode_objective_bounty_claimed_packet_16_19_821.py');
  const events = [];
  const sameLengthControlIds = {};
  const sameLengthControlRefs = [];
  let sameLengthControlCount = 0;
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
      return failed('UNSUPPORTED', 'OnObjectiveBountyClaimed runtime request exceeds bounded input size', {
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
        `exact runtime OnObjectiveBountyClaimed packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime OnObjectiveBountyClaimed packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime OnObjectiveBountyClaimed output identity or packet count differs', {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const isTarget = row?.event_id === CHILD_EVENT_ID;
      const valid = row && (row.status === 'DECODED' || row.status === 'EXCLUDED_CHILD')
        && row.input_index === index
        && row.raw_param === ref.raw_param
        && row.raw_payload_sha256 === ref.raw_payload_sha256
        && row.deserialize_return_al === 1
        && row.bytes_consumed === PAYLOAD_LENGTH
        && row.native_packet_id === PACKET_ID
        && row.native_raw_param === ref.raw_param
        && (isTarget || CONTROL_IDS.has(row.event_id))
        && row.status === (isTarget ? 'DECODED' : 'EXCLUDED_CHILD')
        && /^0x[0-9a-f]{4}$/.test(row.raw_event_id_hex)
        && (!isTarget || row.raw_event_id_hex === RAW_EVENT_ID_HEX)
        && row.event_blob_length === BLOB_LENGTH
        && validU32(row.event_schema_u32_0x00)
        && (!isTarget || row.event_schema_u32_0x00 === OBSERVED_BLOB_U32_0X00)
        && validU32(row.blob_u32_0x04)
        && typeof row.event_blob_hex === 'string'
        && /^[0-9a-f]{16}$/.test(row.event_blob_hex)
        && /^[0-9a-f]{64}$/.test(row.event_blob_sha256);
      const blob = valid ? Buffer.from(row.event_blob_hex, 'hex') : null;
      if (!valid || sha256(blob) !== row.event_blob_sha256
          || blob.readUInt32LE(0) !== row.event_schema_u32_0x00
          || blob.readUInt32LE(4) !== row.blob_u32_0x04) {
        return failed('DECODE_FAILED', `runtime OnObjectiveBountyClaimed packet ${start + index} did not match exact child scope`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      if (!isTarget) {
        sameLengthControlCount += 1;
        const key = `0x${row.event_id.toString(16).padStart(4, '0')}`;
        sameLengthControlIds[key] = (sameLengthControlIds[key] || 0) + 1;
        sameLengthControlRefs.push({
          child_event_id: row.event_id,
          raw_event_id_hex: row.raw_event_id_hex,
          raw_packet_ref: ref,
        });
        continue;
      }
      events.push({
        event_type: 'OBJECTIVE_BOUNTY_CLAIMED_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        event_id: CHILD_EVENT_ID,
        event_name: profile.child_event_name,
        event_schema_u32_0x00: row.event_schema_u32_0x00,
        blob_u32_0x04: row.blob_u32_0x04,
        raw_event_id_hex: row.raw_event_id_hex,
        event_blob_hex: row.event_blob_hex,
        event_blob_sha256: row.event_blob_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
        raw_packet_ref: ref,
      });
    }
  }
  if (events.length === 0) {
    return failed('PROFILE_UNAVAILABLE', 'OnEvent child 0x0113 was not observed among native length-17 packets', {
      observed_raw_shape_count: inputCount,
      same_length_control_count: sameLengthControlCount,
      same_length_control_ids: sameLengthControlIds,
      same_length_control_refs: sameLengthControlRefs,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: IMAGE_SHA256,
    });
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      event_id: 'VERIFIED_EXACT_NATIVE_CHILD_ID',
      event_name: 'VERIFIED_EXACT_IMAGE_NAME_TABLE',
      event_schema_u32_0x00: 'OBSERVED_EXACT_NATIVE_CHILD_FIELD',
      blob_u32_0x04: 'CANDIDATE_ANONYMOUS_NATIVE_CHILD_FIELD',
      event_blob_hex: 'VERIFIED_EXACT_NATIVE_CHILD_BYTES',
    },
    input_count: inputCount,
    target_packet_count: events.length,
    same_length_control_count: sameLengthControlCount,
    same_length_control_ids: sameLengthControlIds,
    same_length_control_refs: sameLengthControlRefs,
    event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE,
  decodeObjectiveBountyClaimedEventPacketCandidates821,
};
