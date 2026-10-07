'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'set_dimension_missile_packet';
const PACKET_ID = 0x008a;
const IMAGE_SIZE = 48_488_448;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_SET_DIMENSION_MISSILE_CALLBACK_U8';
const MAX_PACKETS = 40_000;
const MAX_NATIVE_BATCH = 10_000;
const OBSERVED_LENGTHS = new Set([3, 4, 5]);
const SHORT_PREFIXES = new Set([0x45, 0x4d, 0x55, 0x65, 0x75, 0x7d]);
const LONG_PREFIXES = new Set([
  0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
  0x50, 0x52, 0x54, 0x56, 0x60, 0x62, 0x64, 0x66,
  0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
]);
const OBSERVED_ARGUMENT_BY_PROTECTED_BYTE = Object.freeze({ d5: 0, a7: 6 });

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// The native helper executes the exact callback table transform. This map is
// restricted to the two protected bytes seen in all 218,764 Replay packets.
function decodeProtectedSetDimensionMissileArgumentU8(rawHex) {
  if (typeof rawHex !== 'string'
      || !Object.hasOwn(OBSERVED_ARGUMENT_BY_PROTECTED_BYTE, rawHex)) return null;
  return OBSERVED_ARGUMENT_BY_PROTECTED_BYTE[rawHex];
}

function isObservedSetDimensionMissilePayload(payload) {
  return Buffer.isBuffer(payload)
    && ((payload.length === 3 && SHORT_PREFIXES.has(payload[0]))
      || (payload.length === 4
        && (SHORT_PREFIXES.has(payload[0]) || LONG_PREFIXES.has(payload[0])))
      || (payload.length === 5 && LONG_PREFIXES.has(payload[0])));
}

const SET_DIMENSION_MISSILE_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-set-dimension-missile-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_SetDimensionMissile_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xeffc77',
  evidence_constructor_rva: '0xeccbe0',
  evidence_deserializer_rva: '0x111f960',
  evidence_callback_rva: '0x998520',
  evidence_callback_pre_receiver_rva: '0x99855e',
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays have 218,764 game 0x008a packets across 60 observed length/prefix shapes; all fully consumed natively. The exact callback yields a packet-local u8 from object +0x14 before its receiver method.',
  known_limits: Object.freeze([
    'The callback u8 is packet-local; execution stops before the live receiver method.',
    'The SetDimensionMissile RTTI does not establish receiver state, missile identity, owner, target, actual dimension change, effect, or causality.',
    'Six of eleven sampled 0x0087 payloads also satisfy the 0x008a deserializer; packet framing ID is required.',
    'Only exact KR 821 game packets with the 60 observed length/prefix shapes and two observed callback arguments are accepted.',
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
        timestamp_ms: block.timestamp_ms, packet_id: block.packet_id,
        param: block.param,
      },
      chunk: {
        index: chunk.index, chunk_id: chunk.chunk_id,
        stream: chunk.stream, stream_tag: chunk.stream_tag, offset: chunk.offset,
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
  hash.update(Buffer.from(nativeRow.native_protected_dimension_byte_hex, 'hex'))
    .update(Buffer.from([nativeRow.native_callback_argument_u8]));
}

function validRow(nativeRow, block) {
  return nativeRow && typeof nativeRow.native_protected_dimension_byte_hex === 'string'
    && /^[0-9a-f]{2}$/.test(nativeRow.native_protected_dimension_byte_hex)
    && nativeRow.native_callback_witness_status === 'STOPPED_BEFORE_RECEIVER_METHOD'
    && Number.isInteger(nativeRow.native_callback_argument_u8)
    && nativeRow.native_callback_argument_u8 >= 0
    && nativeRow.native_callback_argument_u8 <= 255
    && nativeRow.native_callback_argument_u8
      === decodeProtectedSetDimensionMissileArgumentU8(nativeRow.native_protected_dimension_byte_hex)
    && nativeRow.raw_payload_sha256 === sha256(block.payload);
}

function decodeSetDimensionMissilePacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = SET_DIMENSION_MISSILE_PACKET_CANDIDATE_PROFILE_821;
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
    return fail('UNSUPPORTED', `SetDimensionMissile packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `set-dimension-missile input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', 'set-dimension-missile route scan returned incomplete rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) return fail('PROFILE_UNAVAILABLE', 'KR 0x008a packet route is absent', {
    input_count: 0, scanned_block_count: scannedBlockCount,
  });
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !isObservedSetDimensionMissilePayload(block.payload)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param < 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id) || chunk.chunk_id < 0
        || (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk')) {
      return fail('DECODE_FAILED', '0x008a packet has unobserved length or invalid source', {
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
    'decode_set_dimension_missile_packet_16_19_821.py');
  const allInputHash = hashInput(rows);
  const outputHash = crypto.createHash('sha256');
  const events = [];
  let nativeRuns = 0;
  for (let start = 0; start < rows.length; start += MAX_NATIVE_BATCH) {
    const batch = rows.slice(start, start + MAX_NATIVE_BATCH);
    const request = JSON.stringify({ replay_version: BUILD, packet_id: PACKET_ID,
      packets: batch.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]) });
    if (Buffer.byteLength(request) > 512 * 1024) {
      return fail('UNSUPPORTED', 'set-dimension-missile native witness batch exceeds 512 KiB', {
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
        `set-dimension-missile native witness failed: ${detail}`, {
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
      return fail('DECODE_FAILED', 'native batch identity or input digest differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      });
    }
    const batchOutputHash = crypto.createHash('sha256');
    for (let index = 0; index < batch.length; index += 1) {
      const { block, chunk } = batch[index];
      const nativeRow = native.rows[index];
      if (!validRow(nativeRow, block)) {
        return fail('DECODE_FAILED', `native row ${start + index} differs from packet`, {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      updateOutputHash(batchOutputHash, nativeRow);
      updateOutputHash(outputHash, nativeRow);
      events.push({
        event_type: 'SET_DIMENSION_MISSILE_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
        packet_name_candidate: profile.packet_name,
        native_protected_dimension_byte_hex: nativeRow.native_protected_dimension_byte_hex,
        native_callback_argument_u8: nativeRow.native_callback_argument_u8,
        native_callback_witness_status: nativeRow.native_callback_witness_status,
        live_receiver_status: 'UNKNOWN',
        source_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
        missile_identity_status: 'UNKNOWN', target_status: 'UNKNOWN',
        dimension_change_status: 'UNKNOWN', gameplay_effect_status: 'UNKNOWN',
        causality_status: 'UNKNOWN',
        confidence: 'CANDIDATE',
        semantic_status: EVIDENCE_STATUS,
        raw_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (native.native_output_sha256 !== batchOutputHash.digest('hex')) {
      return fail('DECODE_FAILED', 'native batch output digest differs', {
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
      native_callback_argument_u8: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
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
  SET_DIMENSION_MISSILE_PACKET_CANDIDATE_PROFILE_821,
  SET_DIMENSION_MISSILE_OBSERVED_LENGTHS_821: OBSERVED_LENGTHS,
  isObservedSetDimensionMissilePayload,
  decodeProtectedSetDimensionMissileArgumentU8,
  decodeSetDimensionMissilePacketCandidates821,
};
