'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'item_charges_packet';
const PACKET_ID = 0x0437;
const IMAGE_SIZE = 48_488_448;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_0437_CALLBACK_ARGS';
const MAX_PACKETS = 10_000;
const MAX_NATIVE_BATCH = 10_000;
const OBSERVED_LENGTHS = new Set([1, 2, 3, 4]);
const CALLBACK_TABLE_HEX =
  'd75682dc83028f2935042171799e927fcb976a5105c76fe640637e345b4707785a96b8b92c995e6ed1754161245f4aaa4bcf0ed4865dba1d3f2bdf62f03300'
  + '55cafc19acf3662369bceb46f89c50874d6d108e88be1bb5da4e1a13cc2209ada49d30a6e57dfac91712c2fde1bbe70b98bfbd1137c07cf795b6dd49f48'
  + '12a9f1cfb8d9a727b577a43b3a953e459202fa8f67436a085f1a7147031840cb2a5dbe816ae3d25b1cd9b0367155cea1f39a1440a8b76de606593f264'
  + 'd5c1c84c064fb7edfee0f9a2184891ce1e3cb46c425494e328e90127ec0d45ff26efe28aabd9f508c4af32c56b80c6c358eea33e2d0f893ab0d2d33873d8d08c7790523bd62e68';
const CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const SELECTOR_TRANSFORM_SHA256 = '61f9f62e7192a413310d9d7ed4367cfa0cfabad1c194a1c09428b1833e69a046';
const VALUE_BYTE_TRANSFORM_SHA256 = '44dee3eddb30902944dade859ea00c11fb6df5699cf2baad986e6c17d54e7a13';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function ror8(value, count) {
  return ((value >>> count) | (value << (8 - count))) & 0xff;
}

function rol8(value, count) {
  return ((value << count) | (value >>> (8 - count))) & 0xff;
}

const callbackTable = Buffer.from(CALLBACK_TABLE_HEX, 'hex');
if (callbackTable.length !== 256 || sha256(callbackTable) !== CALLBACK_TABLE_SHA256) {
  throw new Error('exact 821 0x0437 callback table differs');
}
const selectorTransform = Buffer.from(Array.from({ length: 256 }, (_, byte) =>
  (~ror8((callbackTable[(~ror8((byte - 0x7e) & 0xff, 6)) & 0xff]
    + 0x78) & 0xff, 5)) & 0xff));
const valueByteTransform = Buffer.from(Array.from({ length: 256 }, (_, byte) =>
  callbackTable[(callbackTable[callbackTable[rol8((~byte) & 0xff, 2)]]
    - 0x1b) & 0xff]));
if (sha256(selectorTransform) !== SELECTOR_TRANSFORM_SHA256
    || sha256(valueByteTransform) !== VALUE_BYTE_TRANSFORM_SHA256
    || new Set(selectorTransform).size !== 256
    || new Set(valueByteTransform).size !== 256) {
  throw new Error('exact 821 0x0437 callback transforms differ');
}

// The image's callback uses these packet-object bytes before touching receiver state.
function decodeProtectedItemChargesCallbackBytes(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const raw = Buffer.from(rawHex, 'hex');
  return {
    selector_u8: selectorTransform[raw[2]],
    value_u16: valueByteTransform[raw[0]] | (valueByteTransform[raw[1]] << 8),
  };
}

const ITEM_CHARGES_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-item-charges-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_SetItemCharges_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xf0bb2a',
  evidence_constructor_rva: '0xebda80',
  evidence_deserializer_rva: '0x1041380',
  evidence_callback_rva: '0x350250',
  evidence_callback_range_check_rva: '0x2af490',
  evidence_pre_receiver_callsite_rva: '0x350310',
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays have 40439 game-chunk 0x0437 packets in four observed lengths; every original packet natively fully consumed and reached the receiver callsite after the native selector range check',
  known_limits: Object.freeze([
    'The callback selector and value are packet-local arguments; execution stops before a method that reads receiver state.',
    'Packet naming and callback arguments do not establish actual item identity, charge state, slot, owner, or gameplay effect.',
    'Only exact KR 821 game chunks with payload lengths 1, 2, 3, or 4 are accepted.',
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
  const args = Buffer.alloc(6);
  args.writeUInt32LE(nativeRow.native_callback_selector_u8, 0);
  args.writeUInt16LE(nativeRow.native_callback_value_u16, 4);
  hash.update(Buffer.from(nativeRow.native_protected_callback_bytes_hex, 'hex'))
    .update(args);
}

function validRow(nativeRow, block) {
  const decoded = decodeProtectedItemChargesCallbackBytes(
    nativeRow?.native_protected_callback_bytes_hex);
  return decoded && Number.isInteger(nativeRow.native_callback_selector_u8)
    && nativeRow.native_callback_selector_u8 >= 0
    && nativeRow.native_callback_selector_u8 <= 0x26
    && nativeRow.native_callback_selector_u8 === decoded.selector_u8
    && Number.isInteger(nativeRow.native_callback_value_u16)
    && nativeRow.native_callback_value_u16 >= 0
    && nativeRow.native_callback_value_u16 <= 0xffff
    && nativeRow.native_callback_value_u16 === decoded.value_u16
    && nativeRow.raw_payload_sha256 === sha256(block.payload);
}

function decodeItemChargesPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = ITEM_CHARGES_PACKET_CANDIDATE_PROFILE_821;
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
    return fail('UNSUPPORTED', `item charges packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `item charges input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', 'item charges route scan returned incomplete rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) return fail('PROFILE_UNAVAILABLE', 'KR 0x0437 packet route is absent', {
    input_count: 0, scanned_block_count: scannedBlockCount,
  });
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || !OBSERVED_LENGTHS.has(block.payload.length)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param < 0 || block.param > 0xffffffff
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id) || chunk.chunk_id < 0
        || chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk') {
      return fail('DECODE_FAILED', '0x0437 packet has unobserved length or invalid source', {
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
    'decode_item_charges_packet_16_19_821.py');
  const allInputHash = hashInput(rows);
  const outputHash = crypto.createHash('sha256');
  const events = [];
  let nativeRuns = 0;
  for (let start = 0; start < rows.length; start += MAX_NATIVE_BATCH) {
    const batch = rows.slice(start, start + MAX_NATIVE_BATCH);
    const request = JSON.stringify({ replay_version: BUILD, packet_id: PACKET_ID,
      stream_tag: 1,
      packets: batch.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]) });
    if (Buffer.byteLength(request) > 512 * 1024) {
      return fail('UNSUPPORTED', 'item charges native witness batch exceeds 512 KiB', {
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
        `item charges native witness failed: ${detail}`, {
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
        event_type: 'ITEM_CHARGES_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
        packet_name_candidate: profile.packet_name,
        native_protected_callback_bytes_hex:
          nativeRow.native_protected_callback_bytes_hex,
        native_callback_selector_u8: nativeRow.native_callback_selector_u8,
        native_callback_value_u16: nativeRow.native_callback_value_u16,
        native_pre_receiver_witness: 'NATIVE_RANGE_CHECK_PASSED',
        native_receiver_status: 'NOT_EXECUTED',
        item_identity_status: 'UNKNOWN', charge_state_status: 'UNKNOWN',
        slot_identity_status: 'UNKNOWN', owner_status: 'UNKNOWN',
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
      native_callback_selector_u8: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
      native_callback_value_u16: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL_PRE_RECEIVER',
    native_pre_receiver_witness: 'NATIVE_RANGE_CHECK_PASSED',
    native_full_success_count: events.length, native_batch_count: nativeRuns,
    native_input_sha256: allInputHash,
    native_output_sha256: outputHash.digest('hex'),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: imageSha,
  };
}

module.exports = {
  ITEM_CHARGES_PACKET_CANDIDATE_PROFILE_821,
  ITEM_CHARGES_OBSERVED_LENGTHS_821: OBSERVED_LENGTHS,
  decodeProtectedItemChargesCallbackBytes,
  decodeItemChargesPacketCandidates821,
};
