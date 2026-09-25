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
const CALLBACK_TABLE_SHA256 = Object.freeze({
  opaque_u8_0x10: '3340642441bdc1f66c2c855975ae3e284b950a52c5dc07ff2a065bf3888a6e0c',
  opaque_u8_0x11: '61fc4c46a9d37a0903bbf158b451700ef9fe3a1e696c03e64ed6ff822c29a0a6',
  opaque_u32_0x14: 'aa27fc5460d2a1a0773bc04795f20cb38b9e16cd7d515fc09d10971249a1df13',
  opaque_f32_0x18: 'e2d6e56b4c82c95a6c7aa8efe0aef9abef9a2cdcc6958ba97b09d8637767c3ca',
  opaque_f32_0x1c: '0a2ced1eb36b6eb3436e42dc4a057436c7bc01a28cf72e6b98e631a97910fb27',
});
const PACKET_ID = 0x02d9;
const CAPABILITY = 'npc_buff_update_count_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 20_000;
const MAX_TOTAL_PACKETS = 25_000;
const MAX_REQUEST_BYTES = 4_000_000;
const OBSERVED_PAYLOAD_LENGTHS = new Set([4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15]);

const NPC_BUFF_UPDATE_COUNT_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-buff-update-count-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_NPC_BuffUpdateCount_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration/callback; 18282/18282 and 12352/12352 native full packets in two KR Replays; 110/110 route-shape samples from 11 KR Replays',
  known_limits: Object.freeze([
    'The packet class name and decoded fields do not prove a successful buff counter update.',
    'Object offsets 0x10, 0x11, 0x14, 0x18 and 0x1c remain anonymous; no owner, buff identity, target, counter meaning or lifecycle is inferred.',
    'Native full consumption is not route-exclusive; some foreign 0x0194 and 0x01ad payloads also fully consume under this deserializer.',
    'Only the observed game-stream 821 packet lengths are accepted.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function callbackTablesMatch(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === Object.keys(CALLBACK_TABLE_SHA256).length
    && Object.entries(CALLBACK_TABLE_SHA256)
      .every(([name, digest]) => value[name] === digest);
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

function decodeNpcBuffUpdateCountPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = NPC_BUFF_UPDATE_COUNT_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `BuffUpdateCount packet candidate supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `BuffUpdateCount runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: selected.observed_packet_count_minimum,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x02d9 BuffUpdateCount route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  if (inputCount > MAX_TOTAL_PACKETS) {
    return failed('UNSUPPORTED', `BuffUpdateCount runtime input exceeds ${MAX_TOTAL_PACKETS} packets`);
  }
  for (const { block, chunk } of rows) {
    const param = block.param >>> 0;
    if (chunk.stream_tag !== 1 || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || param === 0) {
      return failed('DECODE_FAILED', '0x02d9 packet framing differs from observed KR scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (!OBSERVED_PAYLOAD_LENGTHS.has(block.payload_length)) {
      return failed('DECODE_FAILED', '0x02d9 payload length differs from observed KR scope', {
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
    'decode_buff_update_count_packet_16_19_821.py');
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
      return failed('UNSUPPORTED', 'BuffUpdateCount runtime request exceeds bounded input size', {
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
        `exact runtime BuffUpdateCount packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime BuffUpdateCount packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !callbackTablesMatch(decoded.callback_table_sha256)
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime BuffUpdateCount output identity or packet count differs', {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const ref = packetRef(replay, block, chunk);
      const row = decoded.results[index];
      if (row?.status !== 'DECODED' || row.input_index !== index
          || row.raw_param !== ref.raw_param || row.raw_payload_sha256 !== ref.raw_payload_sha256
          || row.deserialize_return_al !== 1 || row.bytes_consumed !== block.payload_length
          || row.native_packet_id !== PACKET_ID || row.native_raw_param !== ref.raw_param
          || !Number.isInteger(row.opaque_u8_0x10) || row.opaque_u8_0x10 < 0
          || row.opaque_u8_0x10 > 0xff
          || !Number.isInteger(row.opaque_u8_0x11) || row.opaque_u8_0x11 < 0
          || row.opaque_u8_0x11 > 0xff
          || !Number.isInteger(row.opaque_u32_0x14) || row.opaque_u32_0x14 < 0
          || row.opaque_u32_0x14 > 0xffffffff
          || !Number.isFinite(row.opaque_f32_0x18)
          || !Number.isFinite(row.opaque_f32_0x1c)
          || !/^[0-9a-f]{2}$/.test(row.raw_u8_0x10_hex)
          || !/^[0-9a-f]{2}$/.test(row.raw_u8_0x11_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x14_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_f32_0x18_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_f32_0x1c_hex)) {
        return failed('DECODE_FAILED', `runtime BuffUpdateCount packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'NPC_BUFF_UPDATE_COUNT_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        opaque_u8_0x10: row.opaque_u8_0x10,
        opaque_u8_0x11: row.opaque_u8_0x11,
        opaque_u32_0x14: row.opaque_u32_0x14,
        opaque_f32_0x18: row.opaque_f32_0x18,
        opaque_f32_0x1c: row.opaque_f32_0x1c,
        raw_object_u8_0x10_hex: row.raw_u8_0x10_hex,
        raw_object_u8_0x11_hex: row.raw_u8_0x11_hex,
        raw_object_u32_0x14_hex: row.raw_u32_0x14_hex,
        raw_object_f32_0x18_hex: row.raw_f32_0x18_hex,
        raw_object_f32_0x1c_hex: row.raw_f32_0x1c_hex,
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
      opaque_u8_0x10: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_u8_0x11: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_u32_0x14: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_f32_0x18: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_f32_0x1c: 'CANDIDATE_EXACT_RUNTIME_FIELD',
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  NPC_BUFF_UPDATE_COUNT_PACKET_CANDIDATE_PROFILE_821,
  decodeNpcBuffUpdateCountPacketCandidates821,
};
