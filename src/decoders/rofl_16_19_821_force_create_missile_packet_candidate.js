'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'force_create_missile_packet';
const PACKET_ID = 0x0087;
const IMAGE_SIZE = 48_488_448;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_FORCE_CREATE_MISSILE_COMPARISON_KEY';
const MAX_PACKETS = 40_000;
const MAX_NATIVE_BATCH = 10_000;
const OBSERVED_LENGTHS = new Set([3, 4]);
const OBSERVED_PREFIXES = new Set([0xf0, 0xf1, 0xf2, 0xf4, 0xf6, 0xf7]);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function ror8(value, amount) {
  return ((value >>> amount) | (value << (8 - amount))) & 0xff;
}

// Exact 821 callback RVA 0x2bf770..0x2bf790 transforms object +0x10 before
// comparing it with a receiver-dependent value at +0xac.
function decodeProtectedForceCreateMissileComparisonKeyU32(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const encoded = Buffer.from(rawHex, 'hex');
  const decoded = Buffer.alloc(4);
  for (let i = 0; i < 4; i += 1) {
    decoded[i] = (ror8((ror8(encoded[i], 6) - 0x56) & 0xff, 3) - 0x3a) & 0xff;
  }
  return decoded.readUInt32LE(0);
}

function isObservedForceCreateMissilePayload(payload) {
  return Buffer.isBuffer(payload) && OBSERVED_LENGTHS.has(payload.length)
    && OBSERVED_PREFIXES.has(payload[0]);
}

const FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-force-create-missile-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_ForceCreateMissile_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xeffb9f',
  evidence_constructor_rva: '0xeac850',
  evidence_deserializer_rva: '0x10f0690',
  evidence_callback_rva: '0x2bf6d0',
  evidence_callback_receiver_call_rva: '0x98b410',
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays have 206,957 game 0x0087 packets across 12 observed shapes; all fully consumed natively. A synthetic receiver exposes the packet-local +0x10 comparison u32 before the receiver-dependent comparison.',
  known_limits: Object.freeze([
    'The callback comparison u32 is packet-local; the receiver is synthetic and execution stops before the comparison or action call.',
    'The ForceCreateMissile RTTI does not establish a live receiver match, missile identity, owner, target, actual creation, effect, or causal link.',
    'Only exact KR 821 game packets with the 12 observed selector/length shapes are accepted.',
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
  const key = Buffer.alloc(4);
  key.writeUInt32LE(nativeRow.native_callback_comparison_key_u32);
  hash.update(Buffer.from(nativeRow.native_protected_comparison_bytes_hex, 'hex')).update(key);
}

function validRow(nativeRow, block) {
  return nativeRow && typeof nativeRow.native_protected_comparison_bytes_hex === 'string'
    && /^[0-9a-f]{8}$/.test(nativeRow.native_protected_comparison_bytes_hex)
    && nativeRow.native_callback_witness_status === 'SYNTHETIC_RECEIVER_PRE_COMPARE'
    && Number.isInteger(nativeRow.native_callback_comparison_key_u32)
    && nativeRow.native_callback_comparison_key_u32 >= 0
    && nativeRow.native_callback_comparison_key_u32 <= 0xffffffff
    && nativeRow.native_callback_comparison_key_u32
      === decodeProtectedForceCreateMissileComparisonKeyU32(nativeRow.native_protected_comparison_bytes_hex)
    && nativeRow.raw_payload_sha256 === sha256(block.payload);
}

function decodeForceCreateMissilePacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821;
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
    return fail('UNSUPPORTED', `ForceCreateMissile packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `force-create-missile input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', 'force-create-missile route scan returned incomplete rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) return fail('PROFILE_UNAVAILABLE', 'KR 0x0087 packet route is absent', {
    input_count: 0, scanned_block_count: scannedBlockCount,
  });
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !isObservedForceCreateMissilePayload(block.payload)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param < 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id) || chunk.chunk_id < 0
        || (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk')) {
      return fail('DECODE_FAILED', '0x0087 packet has unobserved length or invalid source', {
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
    'decode_force_create_missile_packet_16_19_821.py');
  const allInputHash = hashInput(rows);
  const outputHash = crypto.createHash('sha256');
  const events = [];
  let nativeRuns = 0;
  for (let start = 0; start < rows.length; start += MAX_NATIVE_BATCH) {
    const batch = rows.slice(start, start + MAX_NATIVE_BATCH);
    const request = JSON.stringify({ replay_version: BUILD, packet_id: PACKET_ID,
      packets: batch.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]) });
    if (Buffer.byteLength(request) > 512 * 1024) {
      return fail('UNSUPPORTED', 'force-create-missile native witness batch exceeds 512 KiB', {
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
        `force-create-missile native witness failed: ${detail}`, {
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
        event_type: 'FORCE_CREATE_MISSILE_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
        packet_name_candidate: profile.packet_name,
        native_protected_comparison_bytes_hex: nativeRow.native_protected_comparison_bytes_hex,
        native_callback_comparison_key_u32: nativeRow.native_callback_comparison_key_u32,
        native_callback_witness_status: nativeRow.native_callback_witness_status,
        live_receiver_lookup_status: 'UNKNOWN',
        source_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
        missile_identity_status: 'UNKNOWN', target_status: 'UNKNOWN',
        creation_effect_status: 'UNKNOWN', causality_status: 'UNKNOWN',
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
      native_callback_comparison_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
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
  FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821,
  FORCE_CREATE_MISSILE_OBSERVED_LENGTHS_821: OBSERVED_LENGTHS,
  isObservedForceCreateMissilePayload,
  decodeProtectedForceCreateMissileComparisonKeyU32,
  decodeForceCreateMissilePacketCandidates821,
};
