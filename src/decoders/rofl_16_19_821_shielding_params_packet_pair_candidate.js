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
const CAPABILITY = 'shielding_params_packet_pair';
const PACKET_ID = 0x040a;
const PAYLOAD_LENGTH = 29;
const EVENT_F0 = 0x00f0;
const EVENT_EF = 0x00ef;
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 10_000;
const MAX_BATCH_PACKETS = 3_000;
const MAX_REQUEST_BYTES = 1_000_000;

const SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-shielding-params-packet-pair-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1]),
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_OnEvent_s',
  child_event_ids: Object.freeze([EVENT_F0, EVENT_EF]),
  child_event_names: Object.freeze(['OnGrantShield', 'OnReceiveShield']),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_packet_callback_rva: '0x4ce3a0',
  evidence_shielding_registration_rva: '0x272241',
  evidence_on_grant_callback_rva: '0x2ba5c0',
  evidence_on_receive_callback_rva: '0x2cf080',
  runtime_image_required: true,
  evidence_scope: 'exact 821 image registers ShieldingParams children 0x00f0/0x00ef; 5556/5556 observed length-29 OnEvent packets natively consumed across 11 KR Replays; 2778 exact child-blob pairs',
  known_limits: Object.freeze([
    'Each row is one paired OnEvent report, not a proved shield application or absorption.',
    'Child +0x08 and +0x0c are anonymous u32 fields. No caster, source, recipient, or target role is assigned.',
    'Child +0x10 is exposed as an opaque raw f32. Negative and zero values occur; it is not labeled generated, absorbed, or effective shield.',
    'The two child packets carry identical blobs in these 11 Replays; both raw packet references are retained.',
    'Replay raw_param may differ across a pair and is not used for pairing or actor assignment.',
    'Only observed 29-byte game-stream OnEvent packets are selected; both child IDs and their exact native shapes are checked.',
    'The emulated base reader injects the Replay raw param; object-param equality is a consistency check, not independent actor proof.',
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

function validU32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function decodeShieldingParamsPacketPairCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    input_packet_scope: 'child_00ef_00f0_length_29',
    child_event_ids: [EVENT_F0, EVENT_EF],
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `ShieldingParams packet pair supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `ShieldingParams runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: observedPacketCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows)) {
    return fail('DECODE_FAILED', '821 ShieldingParams route scan returned no packet rows', {
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x040a length-29 ShieldingParams packet shape is absent', {
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
      return failed('DECODE_FAILED', '0x040a ShieldingParams packet framing differs from observed KR scope', {
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
    'decode_shielding_params_packet_pair_16_19_821.py');
  const decodedEntries = [];
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
      return failed('UNSUPPORTED', 'ShieldingParams runtime request exceeds bounded input size', {
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
        `exact runtime ShieldingParams packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime ShieldingParams packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime ShieldingParams output identity or packet count differs', {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      const expectedRawEventId = row?.event_id === EVENT_F0 ? '0x492b' : '0x4951';
      const blob = /^[0-9a-f]{40}$/.test(row?.event_blob_hex ?? '')
        ? Buffer.from(row.event_blob_hex, 'hex') : null;
      if (row?.status !== 'DECODED' || row.input_index !== index
          || row.raw_param !== ref.raw_param || row.raw_payload_sha256 !== ref.raw_payload_sha256
          || row.deserialize_return_al !== 1 || row.bytes_consumed !== PAYLOAD_LENGTH
          || row.native_packet_id !== PACKET_ID || row.native_raw_param !== ref.raw_param
          || (row?.event_id !== EVENT_F0 && row?.event_id !== EVENT_EF)
          || row.raw_event_id_hex !== expectedRawEventId
          || row.event_blob_length !== 20 || blob === null
          || row.event_blob_sha256 !== sha256(blob)
          || row.event_schema_u32_0x00 !== 469 || row.event_reserved_u32_0x04 !== 0
          || !validU32(row.event_u32_0x08) || !validU32(row.event_u32_0x0c)
          || typeof row.event_raw_f32_0x10 !== 'number'
          || !Number.isFinite(row.event_raw_f32_0x10)
          || blob.readUInt32LE(0) !== 469 || blob.readUInt32LE(4) !== 0
          || blob.readUInt32LE(8) !== row.event_u32_0x08
          || blob.readUInt32LE(12) !== row.event_u32_0x0c
          || !Object.is(blob.readFloatLE(16), row.event_raw_f32_0x10)) {
        return failed('DECODE_FAILED', `runtime ShieldingParams packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      decodedEntries.push({ row, ref });
    }
  }
  const paired = new Map();
  for (const entry of decodedEntries) {
    const { row, ref } = entry;
    const key = JSON.stringify([ref.chunk_index, ref.replay_time_ms, row.event_blob_hex]);
    let pair = paired.get(key);
    if (!pair) {
      pair = { [EVENT_F0]: null, [EVENT_EF]: null };
      paired.set(key, pair);
    }
    if (pair[row.event_id]) {
      return failed('DECODE_FAILED', 'duplicate ShieldingParams child within one candidate pair', {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
      });
    }
    pair[row.event_id] = entry;
  }
  const events = [];
  for (const pair of paired.values()) {
    const grant = pair[EVENT_F0];
    const receive = pair[EVENT_EF];
    if (!grant || !receive || grant.ref.decompressed_block_offset >= receive.ref.decompressed_block_offset
        || grant.ref.chunk_id !== receive.ref.chunk_id
        || grant.ref.chunk_file_offset !== receive.ref.chunk_file_offset) {
      return failed('DECODE_FAILED', 'ShieldingParams child pair is missing, out of order, or source-mismatched', {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: IMAGE_SHA256,
        first_failed_packet_ref: grant?.ref ?? receive?.ref ?? null,
      });
    }
    const { row } = grant;
    events.push({
      event_type: 'SHIELDING_PARAMS_PACKET_PAIR_CANDIDATE',
      game_version: REPLAY_VERSION,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: grant.ref.replay_time_ms,
      child_event_ids: [EVENT_F0, EVENT_EF],
      event_u32_0x08: row.event_u32_0x08,
      event_u32_0x0c: row.event_u32_0x0c,
      event_raw_f32_0x10: row.event_raw_f32_0x10,
      event_blob_sha256: row.event_blob_sha256,
      raw_event_id_hex_by_child: {
        on_grant_shield_0x00f0: grant.row.raw_event_id_hex,
        on_receive_shield_0x00ef: receive.row.raw_event_id_hex,
      },
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_SHIELDING_PARAMS_PAIR',
      raw_packet_refs: [grant.ref, receive.ref],
    });
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_SHIELDING_PARAMS_PAIR',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      child_event_ids: 'VERIFIED_EXACT_CALLBACK_AND_REGISTRATION',
      event_u32_0x08: 'CANDIDATE_EXACT_RUNTIME_FIELD_DIRECTLY_READ_BY_CALLBACK',
      event_u32_0x0c: 'CANDIDATE_EXACT_RUNTIME_FIELD_DIRECTLY_READ_BY_CALLBACK',
      event_raw_f32_0x10: 'OPAQUE_EXACT_RUNTIME_RAW_F32',
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE,
  decodeShieldingParamsPacketPairCandidates821,
};
