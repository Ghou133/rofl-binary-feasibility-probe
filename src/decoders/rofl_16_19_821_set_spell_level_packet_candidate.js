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
  opaque_u32_0x10: '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5',
  opaque_u32_0x14: 'b097f9ce648ac9593a43258eb81b7ee20dc37e7162a8bd584e768785c24ddbb3',
});
const CALLBACK_REGION_SHA256 = 'f365aa3bc45e3a21abc7a8039cb9402ce270539a863a49b9333138e8a93321ab';
const RECEIVER_WRITE_REGION_SHA256 = '550b1300a158e61bb8e7ee4502a0d823defcc9c694ab000198799d22f57d781e';
const CALLBACK_WITNESS_MODE = 'NATIVE_SYNTHETIC_RECEIVER';
const SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_ID_821 =
  'rofl-16.19.821.7343-kr-set-spell-level-packet-runtime-candidate-v1';
const SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_ID_821 =
  'rofl-16.19.821.7343-kr-set-spell-level-packet-runtime-candidate-v2';
const PACKET_ID = 0x025d;
const CAPABILITY = 'set_spell_level_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 10_000;
const MAX_TOTAL_PACKETS = 10_000;
const MAX_REQUEST_BYTES = 4_000_000;
const OBSERVED_PAYLOAD_LENGTHS = new Set([1, 2, 3]);

const SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_ID_821,
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_SetSpellLevel_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration/callback and 342/342 native full-consumption packet decodes across 11 KR Replays; 18,235,209 Replay blocks scanned with zero framing errors',
  known_limits: Object.freeze([
    'The packet class name and decoded fields do not establish a spell identity, actual level, owner or effect.',
    'Callback-transformed object offsets 0x10 and 0x14 remain anonymous.',
    'Only the observed game-stream 821 payload lengths are accepted.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});
const SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821 =
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821;
const SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821 = Object.freeze({
  ...SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821,
  id: SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_ID_821,
  evidence_callback_rva: '0x00998630',
  evidence_receiver_write_rva: '0x00947f20',
  evidence_callback_region_sha256: CALLBACK_REGION_SHA256,
  evidence_receiver_write_region_sha256: RECEIVER_WRITE_REGION_SHA256,
  evidence_callback_witness_mode: CALLBACK_WITNESS_MODE,
  evidence_scope: 'exact 821 native SetSpellLevel callback/receiver-write witness on each decoded packet; 342/342 source-bound packets across 11 KR Replays; synthetic receiver table does not identify a live receiver',
  known_limits: Object.freeze([
    ...SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821.known_limits,
    'Native callback witness uses a synthetic receiver table; no live receiver, spell identity, actual level change, or effect is established.',
    'V2 rejects signed-negative callback scalars; the observed KR values are 1 through 6.',
  ]),
});
const SET_SPELL_LEVEL_PACKET_CANDIDATE_FIELD_CONFIDENCE_V2_821 = Object.freeze({
  replay_time_ms: 'VERIFIED_DIRECT',
  raw_param: 'VERIFIED_DIRECT',
  opaque_u32_0x10: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  opaque_u32_0x14: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  native_receiver_slot_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
  native_receiver_selection_source: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
  native_clamped_scalar_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
  native_positive_flag_written: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function ror8(value, count) {
  return ((value >>> count) | (value << (8 - count))) & 0xff;
}

function swapBits(value) {
  return (((value & 0xd5) << 1) | ((value >>> 1) & 0x55)) & 0xff;
}

let callbackByteTables;
function exactCallbackByteTables() {
  if (callbackByteTables) return callbackByteTables;
  const at10 = Buffer.from(Array.from({ length: 256 }, (_, value) =>
    (ror8((~ror8((swapBits(value) + 0x68) & 0xff, 6)) & 0xff, 6) - 2) & 0xff));
  const at14 = Buffer.from(Array.from({ length: 256 }, (_, value) =>
    ((ror8(value, 6) + 0x41) & 0xff) ^ 8));
  if (sha256(at10) !== CALLBACK_TABLE_SHA256.opaque_u32_0x10
      || sha256(at14) !== CALLBACK_TABLE_SHA256.opaque_u32_0x14
      || new Set(at10).size !== 256 || new Set(at14).size !== 256) {
    throw new Error('exact 821 SetSpellLevel callback byte transforms differ');
  }
  callbackByteTables = { at10, at14 };
  return callbackByteTables;
}

function decodeRawU32(rawHex, table) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const raw = Buffer.from(rawHex, 'hex');
  for (let index = 0; index < raw.length; index += 1) raw[index] = table[raw[index]];
  return raw.readUInt32LE(0);
}

function decodeSetSpellLevelU32At10FromRaw821(rawHex) {
  return decodeRawU32(rawHex, exactCallbackByteTables().at10);
}

function decodeSetSpellLevelU32At14FromRaw821(rawHex) {
  return decodeRawU32(rawHex, exactCallbackByteTables().at14);
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

function decodeSetSpellLevelPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected, setSpellLevelProfile = 'v1',
} = {}) {
  const v2 = setSpellLevelProfile === 'v2';
  const profile = v2 ? SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821
    : SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
    ...(v2 ? {
      evidence_callback_rva: profile.evidence_callback_rva,
      evidence_receiver_write_rva: profile.evidence_receiver_write_rva,
      evidence_callback_region_sha256: CALLBACK_REGION_SHA256,
      evidence_receiver_write_region_sha256: RECEIVER_WRITE_REGION_SHA256,
      evidence_callback_witness_mode: CALLBACK_WITNESS_MODE,
    } : {}),
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (setSpellLevelProfile !== 'v1' && setSpellLevelProfile !== 'v2') {
    return fail('UNSUPPORTED', 'SetSpellLevel packet profile must be v1 or v2');
  }
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `SetSpellLevel packet candidate supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `SetSpellLevel runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: selected.observed_packet_count_minimum,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x025d SetSpellLevel route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  if (inputCount > MAX_TOTAL_PACKETS) {
    return failed('UNSUPPORTED', `SetSpellLevel runtime input exceeds ${MAX_TOTAL_PACKETS} packets`);
  }
  for (const { block, chunk } of rows) {
    const param = block.param >>> 0;
    if (chunk.stream_tag !== 1 || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || param === 0) {
      return failed('DECODE_FAILED', '0x025d packet framing differs from observed KR scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (!OBSERVED_PAYLOAD_LENGTHS.has(block.payload_length)) {
      return failed('DECODE_FAILED', '0x025d payload length differs from observed KR scope', {
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
    'decode_set_spell_level_packet_16_19_821.py');
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
      return failed('UNSUPPORTED', 'SetSpellLevel runtime request exceeds bounded input size', {
        runtime_image_used: start > 0,
      });
    }
    const run = childProcess.spawnSync(python, [
      '-B', script, '--image', imagePath,
      ...(v2 ? ['--callback-witness-v2'] : []),
    ], {
      input: request, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60000,
    });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `Python exited ${run.status}`).trim().slice(0, 1500);
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
      const wrongImage = /runtime image SHA-256 mismatch|record transform table differs|callback transform differs|callback region differs|receiver write region differs/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime SetSpellLevel packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime SetSpellLevel packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !callbackTablesMatch(decoded.callback_table_sha256)
        || (v2 && (decoded.callback_rva !== profile.evidence_callback_rva
          || decoded.receiver_write_rva !== profile.evidence_receiver_write_rva
          || decoded.callback_region_sha256 !== CALLBACK_REGION_SHA256
          || decoded.receiver_write_region_sha256 !== RECEIVER_WRITE_REGION_SHA256
          || decoded.callback_witness_mode !== CALLBACK_WITNESS_MODE))
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime SetSpellLevel output identity or packet count differs', {
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
          || !Number.isInteger(row.opaque_u32_0x10) || row.opaque_u32_0x10 < 0
          || row.opaque_u32_0x10 > 0xffffffff
          || !Number.isInteger(row.opaque_u32_0x14) || row.opaque_u32_0x14 < 0
          || row.opaque_u32_0x14 > 0xffffffff
          || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x10_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x14_hex)
          || (v2 && (!Number.isInteger(row.native_receiver_slot_candidate)
            || row.native_receiver_slot_candidate < 0
            || row.native_receiver_slot_candidate > 63
            || !['INDEXED', 'FALLBACK_0'].includes(row.native_receiver_selection_source)
            || !Number.isInteger(row.native_clamped_scalar_candidate)
            || row.native_clamped_scalar_candidate < 0
            || row.native_clamped_scalar_candidate > 6
            || typeof row.native_positive_flag_written !== 'boolean'
            || row.opaque_u32_0x10 !== decodeSetSpellLevelU32At10FromRaw821(row.raw_u32_0x10_hex)
            || row.opaque_u32_0x14 !== decodeSetSpellLevelU32At14FromRaw821(row.raw_u32_0x14_hex)
            || row.opaque_u32_0x14 > 0x7fffffff
            || row.native_receiver_slot_candidate !== (row.opaque_u32_0x10 <= 63 ? row.opaque_u32_0x10 : 0)
            || row.native_receiver_selection_source !== (row.opaque_u32_0x10 <= 63 ? 'INDEXED' : 'FALLBACK_0')
            || row.native_clamped_scalar_candidate !== Math.min(row.opaque_u32_0x14, 6)
            || row.native_positive_flag_written !== (row.native_clamped_scalar_candidate > 0)))) {
        return failed('DECODE_FAILED', `runtime SetSpellLevel packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'SET_SPELL_LEVEL_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        opaque_u32_0x10: row.opaque_u32_0x10,
        opaque_u32_0x14: row.opaque_u32_0x14,
        raw_object_u32_0x10_hex: row.raw_u32_0x10_hex,
        raw_object_u32_0x14_hex: row.raw_u32_0x14_hex,
        ...(v2 ? {
          native_receiver_slot_candidate: row.native_receiver_slot_candidate,
          native_receiver_selection_source: row.native_receiver_selection_source,
          native_clamped_scalar_candidate: row.native_clamped_scalar_candidate,
          native_positive_flag_written: row.native_positive_flag_written,
        } : {}),
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
    event_field_confidence: v2
      ? { ...SET_SPELL_LEVEL_PACKET_CANDIDATE_FIELD_CONFIDENCE_V2_821 }
      : Object.fromEntries(Object.entries(
        SET_SPELL_LEVEL_PACKET_CANDIDATE_FIELD_CONFIDENCE_V2_821)
        .filter(([field]) => !field.startsWith('native_'))),
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_ID_821,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_ID_821,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_FIELD_CONFIDENCE_V2_821,
  decodeSetSpellLevelU32At10FromRaw821,
  decodeSetSpellLevelU32At14FromRaw821,
  decodeSetSpellLevelPacketCandidates821,
};
