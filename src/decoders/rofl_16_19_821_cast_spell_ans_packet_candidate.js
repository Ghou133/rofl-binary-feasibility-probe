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
const CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const PACKET_ID = 0x01da;
const CAPABILITY = 'cast_spell_ans_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 8192;
const MAX_TOTAL_PACKETS = 100000;
const MAX_REQUEST_BYTES = 4_000_000;
const MIN_OBSERVED_PAYLOAD_BYTES = 97;
const MAX_OBSERVED_PAYLOAD_BYTES = 189;
const OBSERVED_SELECTORS = new Set([0x05, 0x11, 0x15, 0x17, 0x19, 0x1b]);

const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_NPC_CastSpellAns_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 native constructor/deserializer fully consumed 63496 route packets from 11 KR Replays; two callback-transformed object fields remain opaque',
  known_limits: Object.freeze([
    'The packet class name does not prove a successful spell cast.',
    'Spell identity, slot, owner, target, cast action and gameplay meaning are unavailable.',
    'Only observed 821 packet selectors, payload lengths and stream tags are accepted.',
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
    raw_payload_sha256: Buffer.isBuffer(block.payload) ? sha256(block.payload) : null,
  };
}

function collectRows(replay, precollected) {
  if (precollected) return rowsFor821Capability(replay, precollected, CAPABILITY);
  const rows = [];
  const walked = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== PACKET_ID) return;
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
  return { rows, scanned_block_count: walked.block_count };
}

function decodeCastSpellAnsPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821;
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
    return fail('UNSUPPORTED', `cast packet candidate supports only ${REPLAY_VERSION}`);
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
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x01da CastSpellAns route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  if (inputCount > MAX_TOTAL_PACKETS) {
    return failed('UNSUPPORTED', `cast runtime input exceeds ${MAX_TOTAL_PACKETS} packets`);
  }
  for (const { block, chunk } of rows) {
    const param = block.param >>> 0;
    if (![1, 2].includes(chunk.stream_tag) || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || param === 0) {
      return failed('DECODE_FAILED', '0x01da packet framing differs from observed KR scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (block.payload_length < MIN_OBSERVED_PAYLOAD_BYTES
        || block.payload_length > MAX_OBSERVED_PAYLOAD_BYTES
        || !OBSERVED_SELECTORS.has(block.payload[0])) {
      return failed('DECODE_FAILED', '0x01da payload differs from observed KR scope', {
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
    'decode_cast_spell_ans_packet_16_19_821.py');
  const events = [];
  for (let start = 0; start < rows.length; start += MAX_BATCH_PACKETS) {
    const batch = rows.slice(start, start + MAX_BATCH_PACKETS);
    const request = JSON.stringify({
      replay_version: REPLAY_VERSION,
      packets: batch.map(({ block }) => ({
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
      })),
    });
    if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
      return failed('UNSUPPORTED', 'cast runtime request exceeds bounded input size', {
        runtime_image_used: start > 0,
      });
    }
    const run = childProcess.spawnSync(python, ['-B', script, '--image', imagePath], {
      input: request, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60000,
    });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `Python exited ${run.status}`).trim();
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
      const wrongImage = /runtime image SHA-256 mismatch|record transform table differs|callback transform table differs/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime cast packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime cast output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0,
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || decoded.callback_table_sha256 !== CALLBACK_TABLE_SHA256
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime cast output identity or packet count differs', {
        runtime_image_used: start > 0,
        runtime_image_status: 'EXECUTION_FAILED',
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
          || !/^[0-9a-f]{2}$/.test(row.raw_flag_byte_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_i32_bytes_hex)
          || ![0, 1].includes(row.opaque_flag_0x148)
          || !Number.isInteger(row.opaque_i32_0x14c)
          || row.opaque_i32_0x14c < -0x80000000
          || row.opaque_i32_0x14c > 0x7fffffff) {
        return failed('DECODE_FAILED', `runtime cast packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'NPC_CAST_SPELL_ANS_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        opaque_flag_0x148: row.opaque_flag_0x148,
        opaque_i32_0x14c: row.opaque_i32_0x14c,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
        raw_packet_ref: ref,
      });
    }
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821,
  decodeCastSpellAnsPacketCandidates821,
};
