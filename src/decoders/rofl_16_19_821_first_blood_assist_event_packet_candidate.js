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
const CAPABILITY = 'first_blood_assist_event_packet';
const PACKET_ID = 0x040a;
const TARGET_ID = 0x0017;
const CONTROL_ID = 0x002c;
const PAYLOAD_LENGTH = 16;
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 2_000;
const MAX_BATCH_PACKETS = 2_000;
const MAX_REQUEST_BYTES = 1_000_000;

const FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-first-blood-assist-event-packet-runtime-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1]),
  replay_block_packet_id: PACKET_ID,
  payload_length: PAYLOAD_LENGTH,
  packet_name: 'PKT_OnEvent_s',
  child_event_id: TARGET_ID,
  child_event_name: 'OnFirstBloodAssist',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_parent_constructor_rva: '0xe9eb00',
  evidence_parent_deserializer_rva: '0xffbe20',
  evidence_child_id_transform_rva: '0x4ce450',
  evidence_event_name_table_entry_rva: '0x1ef76c8',
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: nine native child 0x0017 packets in eight Replays and three same-length 0x002c controls; all 12 parent packets fully consumed',
  known_limits: Object.freeze([
    'OnFirstBloodAssist is the exact-image name-table label; a packet does not prove an actual first blood or assist.',
    'The eight-byte child blob is retained as opaque bytes and SHA-256; no child field, actor, participant, or gameplay role is assigned.',
    'The 16-byte parent shape also contains OnReviveAlly child 0x002c, which must be excluded by exact native child identity.',
    'Three of 11 observed KR Replays have no child 0x0017; absence is PROFILE_UNAVAILABLE, not a decoded zero.',
    'Any co-timed hero_assist candidate is separate evidence, not a semantic interpretation of this marker.',
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
    if (chunk.stream_tag !== 1 || block.packet_id !== PACKET_ID
        || block.payload_length !== PAYLOAD_LENGTH) return;
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
  }, { includeStreams: [1], strict: true });
  if (walked.errors.length) throw new Error(`${walked.errors.length} Replay framing errors`);
  return { rows, scanned_block_count: walked.block_count,
    observed_packet_count_minimum: observedPacketCount };
}

function decodeFirstBloodAssistEventPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    input_packet_scope: 'child_0017_length_16',
    child_event_id: TARGET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, target_packet_count: null,
    excluded_same_length_foreign_count: null,
    excluded_same_length_foreign_packet_refs: null,
    event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `OnFirstBloodAssist packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `OnFirstBloodAssist runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedPacketCount, scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows)) {
    return fail('DECODE_FAILED', '821 OnFirstBloodAssist route scan returned no packet rows', {
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a/16 OnEvent packet shape is absent', {
      observed_same_length_packet_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  for (const { block, chunk } of rows) {
    if (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk'
        || block.packet_id !== PACKET_ID || block.payload_length !== PAYLOAD_LENGTH
        || !Buffer.isBuffer(block.payload) || block.payload.length !== PAYLOAD_LENGTH
        || !Number.isSafeInteger(block.timestamp_ms)
        || !validU32(block.param) || block.param === 0) {
      return fail('DECODE_FAILED', '0x040a/16 OnEvent packet framing differs from observed KR scope', {
        scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
  }
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: rows.length, observed_same_length_packet_count: rows.length,
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
    'decode_first_blood_assist_event_packet_16_19_821.py');
  const events = [];
  const excludedForeign = [];
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
      return failed('UNSUPPORTED', 'OnFirstBloodAssist runtime request exceeds bounded input size');
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
        `exact runtime OnFirstBloodAssist packet decoder failed: ${detail}`, {
          ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
          runtime_image_status: wrongImage ? 'HASH_MISMATCH'
            : missingPython ? 'NOT_CHECKED' : 'EXECUTION_FAILED',
        });
    }
    let decoded;
    try {
      decoded = JSON.parse(run.stdout);
    } catch (error) {
      return failed('DECODE_FAILED', `runtime OnFirstBloodAssist output is not JSON: ${error.message}`, {
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime OnFirstBloodAssist identity or packet count differs', {
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const target = row?.event_id === TARGET_ID;
      const control = row?.event_id === CONTROL_ID;
      const valid = row
        && (target || control)
        && row.status === (target ? 'DECODED' : 'EXCLUDED_CHILD')
        && row.input_index === index
        && row.raw_param === ref.raw_param
        && row.raw_payload_sha256 === ref.raw_payload_sha256
        && row.deserialize_return_al === 1
        && row.bytes_consumed === PAYLOAD_LENGTH
        && row.native_packet_id === PACKET_ID
        && row.native_raw_param === ref.raw_param
        && row.raw_event_id_hex === (target ? '0x49e4' : '0x49ca')
        && row.event_blob_length === 8
        && typeof row.event_blob_hex === 'string'
        && /^[0-9a-f]{16}$/.test(row.event_blob_hex)
        && /^[0-9a-f]{64}$/.test(row.event_blob_sha256);
      if (!valid || sha256(Buffer.from(row.event_blob_hex, 'hex')) !== row.event_blob_sha256) {
        return failed('DECODE_FAILED', `runtime OnFirstBloodAssist packet ${start + index} differs`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256,
          first_failed_packet_ref: ref,
        });
      }
      if (control) {
        excludedForeign.push(ref);
        continue;
      }
      events.push({
        event_type: 'FIRST_BLOOD_ASSIST_EVENT_PACKET_CANDIDATE',
        game_version: BUILD,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        child_event_id: TARGET_ID,
        registered_event_name: profile.child_event_name,
        raw_event_id_hex: row.raw_event_id_hex,
        event_blob_hex: row.event_blob_hex,
        event_blob_sha256: row.event_blob_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
        raw_packet_ref: ref,
      });
    }
  }
  const details = {
    ...base,
    observed_same_length_packet_count: rows.length,
    input_count: rows.length,
    target_packet_count: events.length,
    excluded_same_length_foreign_count: excludedForeign.length,
    excluded_same_length_foreign_packet_refs: excludedForeign,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256,
  };
  if (events.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a/16 OnFirstBloodAssist child is absent', details);
  }
  return {
    ...details,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      child_event_id: 'VERIFIED_EXACT_NATIVE_CHILD',
      registered_event_name: 'VERIFIED_EXACT_IMAGE_LABEL',
      event_blob_hex: 'VERIFIED_EXACT_NATIVE_BLOB',
    },
    event_count: events.length,
    events,
  };
}

module.exports = {
  FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE,
  decodeFirstBloodAssistEventPacketCandidates821,
};
