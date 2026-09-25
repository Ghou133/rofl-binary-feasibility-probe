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
const CAPABILITY = 'champion_die_event_packet';
const PACKET_ID = 0x040a;
const CHILD_EVENT_ID = 0x0004;
const CONTROL_IDS = new Set([0x0035, 0x003b, 0x003d, 0x0046]);
const PAYLOAD_LENGTH = 116;
const BLOB_LENGTH = 108;
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 10_000;
const MAX_BATCH_PACKETS = 2_000;
const MAX_REQUEST_BYTES = 1_000_000;

const CHAMPION_DIE_EVENT_PACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-champion-die-event-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1]),
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_OnEvent_s',
  child_event_id: CHILD_EVENT_ID,
  child_event_name: 'OnChampionDie',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_event_name_table_rva: '0x1ef7330',
  evidence_params_die_registration_rva: '0x270e81',
  evidence_params_die_callback_rva: '0x2b55b0',
  runtime_image_required: true,
  evidence_scope: 'exact 821 image name table labels child 0x0004 OnChampionDie; registration and handler directly read child +0x04; 831/831 observed length-116 parents natively consumed across 11 KR Replays, including 655 target packets and 176 same-length controls',
  known_limits: Object.freeze([
    'The name is an exact image label. This packet does not prove an effective death, a victim, a killer, or a state transition.',
    'Child +0x04 is an anonymous u32 field. Replay raw_param differs from it in all 655 observed target packets.',
    'The 116-byte parent shape contains four other observed child IDs; the native child ID is checked for every selected packet.',
    'No causal matching, deduplication, or aggregation with other death and kill packets is performed.',
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

function decodeChampionDieEventPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = CHAMPION_DIE_EVENT_PACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    input_packet_scope: 'child_0004_length_116',
    child_event_id: CHILD_EVENT_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `OnChampionDie packet candidate supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `OnChampionDie runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedPacketCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows)) {
    return fail('DECODE_FAILED', '821 OnChampionDie route scan returned no packet rows', {
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a length-116 OnEvent packet shape is absent', {
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
      return failed('DECODE_FAILED', '0x040a OnChampionDie packet framing differs from observed KR scope', {
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
    'decode_champion_die_event_packet_16_19_821.py');
  const events = [];
  const controlCounts = new Map();
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
      return failed('UNSUPPORTED', 'OnChampionDie runtime request exceeds bounded input size', {
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
        `exact runtime OnChampionDie packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime OnChampionDie packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime OnChampionDie output identity or packet count differs', {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const commonValid = row && row.input_index === index
        && row.raw_param === ref.raw_param
        && row.raw_payload_sha256 === ref.raw_payload_sha256
        && row.deserialize_return_al === 1
        && row.bytes_consumed === PAYLOAD_LENGTH
        && row.native_packet_id === PACKET_ID
        && row.native_raw_param === ref.raw_param
        && row.event_blob_length === BLOB_LENGTH
        && /^0x[0-9a-f]{4}$/.test(row.raw_event_id_hex)
        && typeof row.event_blob_hex === 'string'
        && /^[0-9a-f]{216}$/.test(row.event_blob_hex)
        && /^[0-9a-f]{64}$/.test(row.event_blob_sha256);
      const blob = commonValid ? Buffer.from(row.event_blob_hex, 'hex') : null;
      if (!commonValid || sha256(blob) !== row.event_blob_sha256 || !(
        (row.status === 'DECODED' && row.event_id === CHILD_EVENT_ID
          && validU32(row.event_u32_0x04)
          && blob.readUInt32LE(4) === row.event_u32_0x04)
        || (row.status === 'CONTROL' && CONTROL_IDS.has(row.event_id)
          && row.event_u32_0x04 === undefined)
      )) {
        return failed('DECODE_FAILED', `runtime OnChampionDie packet ${start + index} did not match exact child scope`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      if (row.status === 'CONTROL') {
        controlCounts.set(row.event_id, (controlCounts.get(row.event_id) || 0) + 1);
        continue;
      }
      events.push({
        event_type: 'CHAMPION_DIE_EVENT_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        event_id: CHILD_EVENT_ID,
        event_name: profile.child_event_name,
        event_u32_0x04: row.event_u32_0x04,
        raw_event_id_hex: row.raw_event_id_hex,
        event_blob_sha256: row.event_blob_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_ON_CHAMPION_DIE_PACKET',
        raw_packet_ref: ref,
      });
    }
  }
  const controlPacketCount = [...controlCounts.values()].reduce((sum, count) => sum + count, 0);
  const byControlId = Object.fromEntries([...controlCounts.entries()]
    .sort(([left], [right]) => left - right)
    .map(([eventId, count]) => [`0x${eventId.toString(16).padStart(4, '0')}`, count]));
  if (events.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a length-116 packets contain no OnChampionDie child', {
      input_count: inputCount, event_count: 0, events: [],
      observed_same_length_control_count: controlPacketCount,
      observed_same_length_control_ids: byControlId,
      scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: IMAGE_SHA256,
    });
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_ON_CHAMPION_DIE_PACKET',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      event_id: 'VERIFIED_EXACT_CALLBACK',
      event_name: 'VERIFIED_EXACT_IMAGE_LABEL',
      event_u32_0x04: 'CANDIDATE_DIRECT_PARAMS_DIE_FIELD',
    },
    input_count: inputCount, event_count: events.length,
    observed_same_length_control_count: controlPacketCount,
    observed_same_length_control_ids: byControlId,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
  decodeChampionDieEventPacketCandidates821,
};
