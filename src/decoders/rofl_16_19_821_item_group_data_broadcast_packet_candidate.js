'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'item_group_data_broadcast_packet';
const PACKET_ID = 0x013f;
const IMAGE_SIZE = 48_488_448;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_NATIVE_ITEM_GROUP_LOOKUP_KEY';
const MAX_PACKETS = 150_000;
const MAX_NATIVE_BATCH = 10_000;
const OBSERVED_SHAPES = new Set([
  '7:80', '7:84', '7:86',
  '8:80', '8:81', '8:82', '8:83', '8:84', '8:85', '8:86', '8:87',
  '9:81', '9:82', '9:85', '9:87',
]);
const RAW_PARAM_MIN = 0x400000ae;
const RAW_PARAM_MAX = 0x400000b7;
// The native callback's complete 256-byte +0x20 transform, derived only from
// this pinned 821 image. Query validation uses it without a runtime image.
const TRANSFORM_HEX =
  'a0bed279e01ee60bdcfa2a4b7b4c0c9511e77293d5ce17b2b4983bf681d7ea55'
  + '5856052e6cbaf36b63bbb9e4095ca2e251c54190778f022106874f1c2c8962df'
  + '7a6a4a2616fbef440325d8cd2fd4d91939eb4301b68baeb8108c71a66064308'
  + 'e3e4666ab50572bc94ed05f5ea4edbc4208e11bb5da69613a14e570922085f8'
  + 'a9bda5f7270eaa942d12349f9eb77486fdac4d1aec2413fcdb9b3ffe1d22a8'
  + '5b9c97827f3583151fdd6dffd17cf0de9129539dee31c876789a0db140b0f25'
  + 'dcabf7dadc3cc38c675c4d3f4995af93dc136a788375967526518078ac2a168'
  + '6f47f184b3e354f50fd6a396cf000a23733c456ecbe932497e0448c0e8af33c'
  + '7288d80';
const TRANSFORM_SHA256 = '61f9f62e7192a413310d9d7ed4367cfa0cfabad1c194a1c09428b1833e69a046';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

const TRANSFORM = Buffer.from(TRANSFORM_HEX, 'hex');
if (TRANSFORM.length !== 256 || sha256(TRANSFORM) !== TRANSFORM_SHA256
    || new Set(TRANSFORM).size !== 256) {
  throw new Error('exact 821 item-group callback transform differs');
}

function decodeProtectedLookupU32(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const raw = Buffer.from(rawHex, 'hex');
  const decoded = Buffer.from(raw.map((byte) => TRANSFORM[byte]));
  return decoded.readUInt32LE(0);
}

const ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-item-group-data-broadcast-packet-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_SetItemGroupData_Broadcast_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_factory_case_rva: '0xf0214f',
  evidence_constructor_rva: '0xebdd70',
  evidence_deserializer_rva: '0x10425b0',
  evidence_callback_rva: '0x350440',
  evidence_callback_lookup_rva: '0x5d3bd0',
  evidence_callback_transform_sha256: TRANSFORM_SHA256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays have 1229520 keyframe 0x013f packets in 15 observed shapes; one original Replay natively fully consumed 124080/124080 with one transformed +0x20 lookup key per packet',
  known_limits: Object.freeze([
    'The native callback lookup key is packet-local; its lookup is forced to miss because the captured module lacks live receiver state.',
    'The packet name does not identify a group, item, slot, owner, transaction, inventory state, or gameplay effect.',
    'Only exact KR 821 keyframe packets in the 15 observed length/selector shapes and ten raw parameter values are accepted.',
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
  return nativeRow && /^[0-9a-f]{8}$/.test(nativeRow.native_protected_lookup_bytes_hex)
    && Number.isInteger(nativeRow.native_callback_lookup_key_u32)
    && nativeRow.native_callback_lookup_key_u32 >= 0
    && nativeRow.native_callback_lookup_key_u32 <= 0xffffffff
    && nativeRow.native_callback_lookup_key_u32
      === decodeProtectedLookupU32(nativeRow.native_protected_lookup_bytes_hex)
    && nativeRow.raw_payload_sha256 === sha256(block.payload);
}

function decodeItemGroupDataBroadcastPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const profile = ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE_PROFILE_821;
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
    return fail('UNSUPPORTED', `item-group packet candidate supports only ${BUILD}`);
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
    return fail('UNSUPPORTED', `item-group input exceeds ${MAX_PACKETS} packets`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', 'item-group route scan returned incomplete rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) return fail('PROFILE_UNAVAILABLE', 'KR 0x013f packet route is absent', {
    input_count: 0, scanned_block_count: scannedBlockCount,
  });
  for (const { block, chunk } of rows) {
    if (!block || !chunk || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length
        || block.payload[0] !== 0x1e
        || !OBSERVED_SHAPES.has(`${block.payload.length}:${block.payload[1]}`)
        || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
        || !Number.isInteger(block.param) || block.param < RAW_PARAM_MIN
        || block.param > RAW_PARAM_MAX
        || !Number.isSafeInteger(block.offset) || block.offset < 0
        || !Number.isSafeInteger(block.payload_offset) || block.payload_offset < 0
        || !Number.isSafeInteger(chunk.index) || chunk.index < 0
        || !Number.isSafeInteger(chunk.offset) || chunk.offset < 0
        || !Number.isSafeInteger(chunk.chunk_id) || chunk.chunk_id < 0
        || chunk.stream_tag !== 2 || chunk.stream !== 'keyframe') {
      return fail('DECODE_FAILED', '0x013f packet has unobserved shape or invalid source', {
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
    'decode_item_group_data_broadcast_packet_16_19_821.py');
  const allInputHash = hashInput(rows);
  const outputHash = crypto.createHash('sha256');
  const events = [];
  let nativeRuns = 0;
  for (let start = 0; start < rows.length; start += MAX_NATIVE_BATCH) {
    const batch = rows.slice(start, start + MAX_NATIVE_BATCH);
    const request = JSON.stringify({ replay_version: BUILD, packet_id: PACKET_ID,
      stream_tag: 2,
      packets: batch.map(({ block }) => [block.param >>> 0, block.payload.toString('hex')]) });
    if (Buffer.byteLength(request) > 512 * 1024) {
      return fail('UNSUPPORTED', 'item-group native witness batch exceeds 512 KiB', {
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
        `item-group native witness failed: ${detail}`, {
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
        event_type: 'ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
        packet_name_candidate: profile.packet_name,
        native_protected_lookup_bytes_hex: nativeRow.native_protected_lookup_bytes_hex,
        native_callback_lookup_key_u32: nativeRow.native_callback_lookup_key_u32,
        native_receiver_lookup_status: 'NOT_OBSERVED',
        group_identity_status: 'UNKNOWN', item_identity_status: 'UNKNOWN',
        owner_status: 'UNKNOWN', participant_status: 'UNKNOWN',
        inventory_state_change_status: 'UNKNOWN',
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
  ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE_PROFILE_821,
  ITEM_GROUP_DATA_BROADCAST_OBSERVED_SHAPES_821: OBSERVED_SHAPES,
  decodeProtectedLookupU32,
  decodeItemGroupDataBroadcastPacketCandidates821,
};
