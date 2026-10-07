'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'anonymous_029c_packet';
const PACKET_ID = 0x029c;
const IMAGE_SIZE = 48_488_448;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const TABLE_SHA256 = 'ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_029C_ANONYMOUS_U32';
const MAX_PACKETS = 50_000;
const MAX_NATIVE_BATCH = 10_000;
const PREFIXES = new Set([0x70, 0x76, 0x78, 0x7a, 0x7c, 0x7e]);
const TABLE_HEX =
  '3ed305a70914bd1ee05db06e9bd632ee5172685a97a9a067c54259557f37c9ac'
  + '8d0a5c462ca3d9d4d1077d3924edfe8e6199e33d1b089273f4adf0fccaa2ec38'
  + '182acd87afd74a1dc67a2e30bc4f58be4d13fb8ace3f0185e98c201caa35262d'
  + 'b42b3b19b8b545a8ff4712e5cc502716980b83f59129b2f91f0c868475641a0f'
  + 'e67c02049a94344e53efdcb1f8815206fac70eb6cf7721116f2582a64c600d7e'
  + '93aec4eb5f9d62968f892fdd435ea1e2f1a49c88cb5678bf2223366c48715470'
  + '74ba69e8e1e4e715bb6640105ba5c831f728f2f333b9fd00f6de579e0379b33a'
  + 'c26bdbd08b63176d9fd2ab49d5c0eada3c95b7447bdf90764bc36580416ac1d8';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function rol8(value, count) {
  return ((value << count) | (value >>> (8 - count))) & 255;
}

function ror8(value, count) {
  return ((value >>> count) | (value << (8 - count))) & 255;
}

const table = Buffer.from(TABLE_HEX, 'hex');
if (table.length !== 256 || sha256(table) !== TABLE_SHA256) {
  throw new Error('exact 821 0x029c protection table differs');
}
const inverse = Buffer.alloc(256);
const seen = new Set();
for (let value = 0; value < 256; value += 1) {
  let protectedByte = table[table[rol8(value, 1)]];
  protectedByte = ror8((protectedByte - 0x72) & 255, 5);
  protectedByte = (((protectedByte & 0xd5) << 1)
    | ((protectedByte >>> 1) & 0x55)) & 255;
  if (seen.has(protectedByte)) throw new Error('0x029c protection inverse is not unique');
  seen.add(protectedByte);
  inverse[protectedByte] = value;
}
if (seen.size !== 256 || inverse[0xe3] !== 0 || inverse[0x18] !== 255) {
  throw new Error('exact 821 0x029c protection inverse differs');
}

function decodeProtectedAnonymous029cU32(protectedHex) {
  if (typeof protectedHex !== 'string' || !/^[0-9a-f]{8}$/.test(protectedHex)) {
    return null;
  }
  const bytes = Buffer.from(protectedHex, 'hex');
  const decoded = Buffer.from(bytes.map((byte) => inverse[byte]));
  return decoded.readUInt32LE(0);
}

function isObservedAnonymous029cPayload(payload) {
  return Buffer.isBuffer(payload)
    && ((payload.length === 1 && payload[0] === 0x72)
      || ((payload.length === 3 || payload.length === 4)
        && PREFIXES.has(payload[0])));
}

const ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-anonymous-029c-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xf06643',
  evidence_constructor_rva: '0xe9abf0',
  evidence_vtable_rva: '0x1ba3c88',
  evidence_deserializer_rva: '0xf88030',
  evidence_protection_table_sha256: TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: 457095/457095 0x029c game packets fully consumed natively, 13 observed shapes, max 48258 per Replay',
  known_limits: Object.freeze([
    'No exact-image packet class or callback name has been proved for 0x029c.',
    'The object +0x10 selector is zero in the observed corpus; +0x14 is an anonymous decoded u32 or 0xffffffff sentinel.',
    'The u32 is packet-local. Actor, target, object role, receiver state, behavior and effect are UNKNOWN.',
    'Only exact-build 821 game packets in the 13 shapes observed on 11 KR Replays are accepted.',
  ]),
});

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
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: sha256(block.payload),
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
        timestamp_ms: block.timestamp_ms, packet_id: block.packet_id, param: block.param,
      },
      chunk: {
        index: chunk.index, chunk_id: chunk.chunk_id, stream: chunk.stream,
        stream_tag: chunk.stream_tag, offset: chunk.offset,
      },
    });
  }, { strict: true });
  if (walked.errors.length) throw new Error(`${walked.errors.length} Replay framing errors`);
  return { rows, observed_packet_count_minimum: observedCount,
    scanned_block_count: walked.block_count };
}

function hashInput(rows) {
  const hash = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const { block } of rows) {
    header.writeUInt32LE(block.param >>> 0, 0);
    header.writeUInt32LE(block.payload.length, 4);
    hash.update(header).update(block.payload);
  }
  return hash.digest('hex');
}

function updateOutputHash(hash, nativeRow) {
  const value = Buffer.alloc(4);
  value.writeUInt32LE(nativeRow.anonymous_u32_candidate, 0);
  hash.update(Buffer.from(nativeRow.native_protected_selector_byte_hex, 'hex'))
    .update(Buffer.from(nativeRow.native_protected_u32_hex, 'hex')).update(value);
}

function validRow(nativeRow, block) {
  if (!nativeRow || nativeRow.native_protected_selector_byte_hex !== '3e'
      || nativeRow.native_selector_u8 !== 0
      || typeof nativeRow.native_protected_u32_hex !== 'string'
      || !/^[0-9a-f]{8}$/.test(nativeRow.native_protected_u32_hex)
      || nativeRow.raw_payload_sha256 !== sha256(block.payload)) return false;
  const value = decodeProtectedAnonymous029cU32(nativeRow.native_protected_u32_hex);
  return value === nativeRow.anonymous_u32_candidate
    && nativeRow.anonymous_u32_is_sentinel === (value === 0xffffffff)
    && ((block.payload.length === 1 && value === 0xffffffff)
      || (block.payload.length !== 1 && value >>> 24 === 0x40));
}

function decodeAnonymous029cPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id, input_packet_id: PACKET_ID,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `anonymous 0x029c packet candidate supports only ${BUILD}`);
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
  const { rows, scanned_block_count: scannedBlockCount } = selected;
  const observedCount = selected.observed_packet_count_minimum
    ?? selected.observed_packet_count ?? rows?.length;
  if (observedCount > MAX_PACKETS) {
    return fail('UNSUPPORTED', `anonymous 0x029c input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', 'anonymous 0x029c route scan returned incomplete rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) return fail('PROFILE_UNAVAILABLE', 'KR 0x029c packet route is absent', {
    input_count: 0, scanned_block_count: scannedBlockCount,
  });
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Number.isInteger(block.param) || block.param < 0 || block.param > 0xffffffff
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !isObservedAnonymous029cPayload(block.payload)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id) || chunk.chunk_id < 0
        || chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk') {
      return fail('DECODE_FAILED', '0x029c packet has unobserved shape or invalid source', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: block && chunk ? packetRef(replay, block, chunk) : null,
      });
    }
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return fail('MISSING_INPUT', 'exact KR 821 mapped runtime image is required', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  let image;
  try {
    const stat = fs.statSync(path.resolve(runtimeImagePath));
    if (!stat.isFile() || stat.size !== IMAGE_SIZE) throw new Error('wrong file size');
    image = fs.readFileSync(path.resolve(runtimeImagePath));
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const imageSha = sha256(image);
  if (imageSha !== IMAGE_SHA256) {
    return fail('DECODE_FAILED', 'exact 821 runtime image SHA-256 mismatch', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'HASH_MISMATCH', runtime_image_sha256: imageSha,
    });
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_anonymous_029c_packet_16_19_821.py');
  const allInputHash = hashInput(rows);
  const outputHash = crypto.createHash('sha256');
  const events = [];
  let nativeRuns = 0;
  for (let start = 0; start < rows.length; start += MAX_NATIVE_BATCH) {
    const batch = rows.slice(start, start + MAX_NATIVE_BATCH);
    const request = JSON.stringify({ replay_version: BUILD, packet_id: PACKET_ID,
      packets: batch.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]) });
    if (Buffer.byteLength(request) > 512 * 1024) {
      return fail('UNSUPPORTED', 'anonymous 0x029c native witness batch exceeds 512 KiB', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: nativeRuns ? 'MATCHED_USED' : 'MATCHED_PRECHECKED',
        runtime_image_used: nativeRuns > 0,
      });
    }
    const run = childProcess.spawnSync(python,
      ['-B', script, '--image', path.resolve(runtimeImagePath)], {
        input: request, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
        timeout: 120_000, windowsHide: true,
      });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `exit ${run.status}`).trim().slice(0, 1500);
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]/.test(detail);
      return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `anonymous 0x029c native witness failed: ${detail}`, {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: missingPython && !nativeRuns
            ? 'MATCHED_PRECHECKED' : 'MATCHED_USED',
          runtime_image_used: !missingPython || nativeRuns > 0,
          native_witness_status: missingPython ? 'UNAVAILABLE' : 'FAILED',
          ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        });
    }
    nativeRuns += 1;
    let native;
    try { native = JSON.parse(run.stdout); } catch (error) {
      return fail('DECODE_FAILED', `native witness output is not JSON: ${error.message}`, {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      });
    }
    if (native?.replay_version !== BUILD || native.runtime_image_sha256 !== IMAGE_SHA256
        || native.packet_id !== PACKET_ID || native.packet_count !== batch.length
        || native.input_sha256 !== hashInput(batch)
        || native.native_full_success_count !== batch.length
        || native.first_failure !== null || !Array.isArray(native.rows)
        || native.rows.length !== batch.length) {
      return fail('DECODE_FAILED', 'native 0x029c batch identity or input digest differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      });
    }
    const batchOutputHash = crypto.createHash('sha256');
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const nativeRow = native.rows[index];
      if (!validRow(nativeRow, block)) {
        return fail('DECODE_FAILED', `native 0x029c row ${start + index} differs from packet`, {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      updateOutputHash(batchOutputHash, nativeRow);
      updateOutputHash(outputHash, nativeRow);
      events.push({
        event_type: 'ANONYMOUS_029C_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
        native_protected_selector_byte_hex: nativeRow.native_protected_selector_byte_hex,
        native_selector_u8: nativeRow.native_selector_u8,
        native_protected_u32_hex: nativeRow.native_protected_u32_hex,
        anonymous_u32_candidate: nativeRow.anonymous_u32_candidate,
        anonymous_u32_is_sentinel: nativeRow.anonymous_u32_is_sentinel,
        actor_status: 'UNKNOWN', target_status: 'UNKNOWN',
        object_role_status: 'UNKNOWN', receiver_state_status: 'UNKNOWN',
        behavior_status: 'UNKNOWN', effect_status: 'UNKNOWN',
        confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
        raw_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (native.native_output_sha256 !== batchOutputHash.digest('hex')) {
      return fail('DECODE_FAILED', 'native 0x029c batch output digest differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      });
    }
  }
  return {
    ...base, status: 'CANDIDATE', input_count: observedCount,
    event_count: events.length, events, scanned_block_count: scannedBlockCount,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      native_selector_u8: 'CANDIDATE_EXACT_RUNTIME_NATIVE_OBJECT',
      anonymous_u32_candidate: 'CANDIDATE_EXACT_RUNTIME_NATIVE_OBJECT',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: events.length, native_batch_count: nativeRuns,
    native_input_sha256: allInputHash,
    native_output_sha256: outputHash.digest('hex'),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: imageSha,
  };
}

module.exports = {
  ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821,
  isObservedAnonymous029cPayload,
  decodeProtectedAnonymous029cU32,
  decodeAnonymous029cPacketCandidates821,
};
