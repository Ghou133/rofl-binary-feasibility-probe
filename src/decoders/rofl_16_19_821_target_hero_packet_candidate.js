'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'target_hero_packet';
const PACKET_ID = 0x0265;
const IMAGE_SIZE = 48_488_448;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_TARGET_HERO_CALLBACK_KEY';
const MAX_PACKETS = 40_000;
const MAX_NATIVE_BATCH = 10_000;
const OBSERVED_LENGTHS = new Set([1, 3]);
const OBSERVED_THREE_BYTE_PREFIXES = new Set([0x30, 0x31, 0x32, 0x34, 0x35, 0x37]);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// Exact pinned 821 table RVA 0x1ab62d0, callback 0x2bb950..0x2bb9bd.
const CALLBACK_TABLE = Buffer.from([
  'd75682dc83028f2935042171799e927fcb976a5105c76fe640637e345b470778',
  '5a96b8b92c995e6ed1754161245f4aaa4bcf0ed4865dba1d3f2bdf62f0330055',
  'cafc19acf3662369bceb46f89c50874d6d108e88be1bb5da4e1a13cc2209ada4',
  '9d30a6e57dfac91712c2fde1bbe70b98bfbd1137c07cf795b6dd49f4812a9f1c',
  'fb8d9a727b577a43b3a953e459202fa8f67436a085f1a7147031840cb2a5dbe8',
  '16ae3d25b1cd9b0367155cea1f39a1440a8b76de606593f264d5c1c84c064fb7',
  'edfee0f9a2184891ce1e3cb46c425494e328e90127ec0d45ff26efe28aabd9f5',
  '08c4af32c56b80c6c358eea33e2d0f893ab0d2d33873d8d08c7790523bd62e68',
].join(''), 'hex');
if (sha256(CALLBACK_TABLE)
    !== '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b') {
  throw new Error('exact 821 TargetHero callback table differs');
}

function decodeProtectedTargetHeroLookupKeyU32(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const decoded = Buffer.alloc(4);
  const encoded = Buffer.from(rawHex, 'hex');
  for (let i = 0; i < 4; i += 1) {
    const first = CALLBACK_TABLE[encoded[i]];
    const second = CALLBACK_TABLE[(~first) & 0xff];
    const folded = (((second & 0xd5) << 1) | ((second >>> 1) & 0x55)) & 0xff;
    decoded[i] = CALLBACK_TABLE[folded];
  }
  return decoded.readUInt32LE(0);
}

function isObservedTargetHeroPayload(payload) {
  return Buffer.isBuffer(payload) && ((payload.length === 1 && payload[0] === 0x33)
    || (payload.length === 3 && OBSERVED_THREE_BYTE_PREFIXES.has(payload[0])));
}

const TARGET_HERO_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-target-hero-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_AI_TargetHeroS2C_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xf05c17',
  evidence_constructor_rva: '0xe99060',
  evidence_deserializer_rva: '0xf19ec0',
  evidence_callback_rva: '0x2bb950',
  evidence_callback_receiver_call_rva: '0x2d2be0',
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays have 62219 game 0x0265 packets in two observed lengths; every original packet natively fully consumed with one +0x10 callback u32 before receiver access',
  known_limits: Object.freeze([
    'The callback u32 is packet-local; native execution stops before the receiver-dependent call because the captured image lacks live receiver state.',
    'The TargetHero RTTI and callback argument do not establish a resolved target object, source actor, target state, or gameplay effect.',
    'Only exact KR 821 game packets with the two observed payload shapes are accepted.',
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
  key.writeUInt32LE(nativeRow.native_callback_lookup_key_u32);
  hash.update(Buffer.from(nativeRow.native_protected_lookup_bytes_hex, 'hex')).update(key);
}

function validRow(nativeRow, block) {
  return nativeRow && typeof nativeRow.native_protected_lookup_bytes_hex === 'string'
    && /^[0-9a-f]{8}$/.test(nativeRow.native_protected_lookup_bytes_hex)
    && Number.isInteger(nativeRow.native_callback_lookup_key_u32)
    && nativeRow.native_callback_lookup_key_u32 >= 0
    && nativeRow.native_callback_lookup_key_u32 <= 0xffffffff
    && nativeRow.native_callback_lookup_key_u32
      === decodeProtectedTargetHeroLookupKeyU32(nativeRow.native_protected_lookup_bytes_hex)
    && nativeRow.raw_payload_sha256 === sha256(block.payload);
}

function decodeTargetHeroPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = TARGET_HERO_PACKET_CANDIDATE_PROFILE_821;
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
    return fail('UNSUPPORTED', `target hero packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `target-hero input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', 'target-hero route scan returned incomplete rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) return fail('PROFILE_UNAVAILABLE', 'KR 0x0265 packet route is absent', {
    input_count: 0, scanned_block_count: scannedBlockCount,
  });
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !isObservedTargetHeroPayload(block.payload)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param < 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id) || chunk.chunk_id < 0
        || (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk')) {
      return fail('DECODE_FAILED', '0x0265 packet has unobserved length or invalid source', {
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
    'decode_target_hero_packet_16_19_821.py');
  const allInputHash = hashInput(rows);
  const outputHash = crypto.createHash('sha256');
  const events = [];
  let nativeRuns = 0;
  for (let start = 0; start < rows.length; start += MAX_NATIVE_BATCH) {
    const batch = rows.slice(start, start + MAX_NATIVE_BATCH);
    const request = JSON.stringify({ replay_version: BUILD, packet_id: PACKET_ID,
      packets: batch.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]) });
    if (Buffer.byteLength(request) > 512 * 1024) {
      return fail('UNSUPPORTED', 'target-hero native witness batch exceeds 512 KiB', {
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
        `target-hero native witness failed: ${detail}`, {
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
        event_type: 'TARGET_HERO_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
        packet_name_candidate: profile.packet_name,
        native_protected_lookup_bytes_hex: nativeRow.native_protected_lookup_bytes_hex,
        native_callback_lookup_key_u32: nativeRow.native_callback_lookup_key_u32,
        native_receiver_call_status: 'NOT_EXECUTED',
        source_actor_status: 'UNKNOWN', target_object_status: 'UNKNOWN',
        target_state_status: 'UNKNOWN',
        semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
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
      native_callback_lookup_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
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
  TARGET_HERO_PACKET_CANDIDATE_PROFILE_821,
  TARGET_HERO_OBSERVED_LENGTHS_821: OBSERVED_LENGTHS,
  isObservedTargetHeroPayload,
  decodeProtectedTargetHeroLookupKeyU32,
  decodeTargetHeroPacketCandidates821,
};
