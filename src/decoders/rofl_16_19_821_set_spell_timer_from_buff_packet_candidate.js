'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { runtimeByteLookupTable821 } = require('./rofl_16_19_821_runtime_bytes');

const REPLAY_VERSION = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const CALLBACK_TABLE_SHA256 = Object.freeze({
  opaque_u8_0x10: '48a697d580affb9688308aa3f7a09ee24d87378dd299a5128a4447f1795c39a4',
  opaque_u8_0x11: 'cddd28e48f36e54efe3d10a70fd25121d665001654b661c121767c2ca23f2425',
  opaque_f32_0x14: '24206a5cc1586f42dd59c98818754f592a18e7ee3026115615e69e5814630c68',
  opaque_u32_0x18: 'b097f9ce648ac9593a43258eb81b7ee20dc37e7162a8bd584e768785c24ddbb3',
  opaque_u32_0x1c: 'a90f34d17c8715929574f708ea279badb13f527d6d025a6138fb179b7329c84b',
  opaque_u8_0x20: '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5',
});
const CALLBACK_REGION_SHA256 = '8aa6f881b0a6a05e5ba169da4d2521a390b947f214dbd587c946e00b0112b9c2';
const RECEIVER_LOOKUP_REGION_SHA256 = '88974afa23e856901f874805af9cb11670298ac9082f8bc4526e9a1a1c70a1d5';
const CALLBACK_WITNESS_MODE = 'NATIVE_SYNTHETIC_RECEIVER_CALL_ENTRY';
const SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_ID_821 =
  'rofl-16.19.821.7343-kr-set-spell-timer-from-buff-packet-runtime-candidate-v1';
const SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_ID_821 =
  'rofl-16.19.821.7343-kr-set-spell-timer-from-buff-packet-runtime-candidate-v2';
const SET_SPELL_TIMER_FROM_BUFF_V2_FIELD_CONFIDENCE_821 =
  'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS';
const PACKET_ID = 0x00fd;
const CAPABILITY = 'set_spell_timer_from_buff_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 10_000;
const MAX_TOTAL_PACKETS = 10_000;
const MAX_REQUEST_BYTES = 4_000_000;
const OBSERVED_PAYLOAD_LENGTHS = new Set([7, 8, 10, 11, 12]);

const SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_ID_821,
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_S2C_SetSpellTimerFromBuff_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 registration/callback; 5481/5481 native full packets across 11 KR Replays, with exact game-stream and observed-length gates',
  known_limits: Object.freeze([
    'The packet class name and decoded fields do not prove a spell timer change or buff effect.',
    'Object offsets 0x10, 0x11, 0x14, 0x18, 0x1c and 0x20 remain anonymous; no owner, spell or buff identity, timer effect or lifecycle is inferred.',
    'Only the observed game-stream 821 packet lengths are accepted.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});
const SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_821 =
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_821;
const SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_821 = Object.freeze({
  ...SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_821,
  id: SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_ID_821,
  evidence_callback_rva: '0x002c2760',
  evidence_receiver_lookup_rva: '0x0098a840',
  evidence_receiver_call_rva: '0x00946cf0',
  evidence_callback_region_sha256: CALLBACK_REGION_SHA256,
  evidence_receiver_lookup_region_sha256: RECEIVER_LOOKUP_REGION_SHA256,
  evidence_callback_witness_mode: CALLBACK_WITNESS_MODE,
  evidence_scope: 'exact 821 native SetSpellTimerFromBuff callback and receiver call-entry witness on each source-bound packet; 5481/5481 original packets across 11 KR Replays; synthetic receiver table cannot identify a live recipient',
  known_limits: Object.freeze([
    ...SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_821.known_limits,
    'V2 witnesses selector 0..5 or 63 and five forwarded fields at the native receiver call entry; it does not execute the live receiver or clock path.',
    'The synthetic receiver table does not establish a spell, Buff, owner, target, timer effect or lifecycle.',
  ]),
});
const SET_SPELL_TIMER_FROM_BUFF_V2_EVENT_FIELD_CONFIDENCE_821 = Object.freeze({
  replay_time_ms: 'VERIFIED_DIRECT',
  raw_param: 'VERIFIED_DIRECT',
  opaque_u8_0x10: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  opaque_u8_0x11: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  opaque_f32_0x14: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  opaque_u32_0x18: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  opaque_u32_0x1c: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  opaque_u8_0x20: 'CANDIDATE_EXACT_RUNTIME_FIELD',
  native_receiver_slot_candidate: SET_SPELL_TIMER_FROM_BUFF_V2_FIELD_CONFIDENCE_821,
  native_receiver_selection_path: SET_SPELL_TIMER_FROM_BUFF_V2_FIELD_CONFIDENCE_821,
  native_receiver_forwarded_fields_witnessed:
    SET_SPELL_TIMER_FROM_BUFF_V2_FIELD_CONFIDENCE_821,
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
  const lookup = runtimeByteLookupTable821();
  const transforms = {
    opaque_u8_0x10: (value) => lookup[(lookup[value] + 0x51) & 0xff],
    opaque_u8_0x11: (value) => (ror8((~value + 0x19) & 0xff, 1) - 0x29) & 0xff,
    opaque_f32_0x14: (value) =>
      ror8((ror8(swapBits((value - 0x6d) & 0xff), 5) + 9) & 0xff, 4),
    opaque_u32_0x18: (value) => ((ror8(value, 6) + 0x41) & 0xff) ^ 8,
    opaque_u32_0x1c: (value) => ror8(value, 1),
    opaque_u8_0x20: (value) =>
      (ror8((~ror8((swapBits(value) + 0x68) & 0xff, 6)) & 0xff, 6) - 2) & 0xff,
  };
  const tables = {};
  for (const [name, transform] of Object.entries(transforms)) {
    const table = Buffer.from(Array.from({ length: 256 }, (_, value) => transform(value)));
    if (new Set(table).size !== 256 || sha256(table) !== CALLBACK_TABLE_SHA256[name]) {
      throw new Error(`exact 821 SetSpellTimerFromBuff callback transform differs: ${name}`);
    }
    tables[name] = table;
  }
  callbackByteTables = tables;
  return tables;
}

function decodedBytes(rawHex, byteLength, table) {
  if (typeof rawHex !== 'string'
      || !new RegExp(`^[0-9a-f]{${byteLength * 2}}$`).test(rawHex)) return null;
  return Buffer.from(Buffer.from(rawHex, 'hex').map((byte) => table[byte]));
}

function decodeSetSpellTimerU8At20FromRaw821(rawHex) {
  const decoded = decodedBytes(rawHex, 1, exactCallbackByteTables().opaque_u8_0x20);
  return decoded ? decoded[0] : null;
}

function decodeSetSpellTimerRawFields821(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  const tables = exactCallbackByteTables();
  const specs = [
    ['opaque_u8_0x10', 'raw_object_u8_0x10_hex', 1],
    ['opaque_u8_0x11', 'raw_object_u8_0x11_hex', 1],
    ['opaque_f32_0x14', 'raw_object_f32_0x14_hex', 4],
    ['opaque_u32_0x18', 'raw_object_u32_0x18_hex', 4],
    ['opaque_u32_0x1c', 'raw_object_u32_0x1c_hex', 4],
    ['opaque_u8_0x20', 'raw_object_u8_0x20_hex', 1],
  ];
  const result = {};
  for (const [name, rawKey, byteLength] of specs) {
    const bytes = decodedBytes(row[rawKey], byteLength, tables[name]);
    if (!bytes) return null;
    const value = name.startsWith('opaque_f32') ? bytes.readFloatLE(0)
      : byteLength === 1 ? bytes[0] : bytes.readUInt32LE(0);
    if (!Number.isFinite(value)) return null;
    result[name] = value;
  }
  return result;
}

function v2WitnessMatches(row) {
  const decoded = decodeSetSpellTimerRawFields821({
    raw_object_u8_0x10_hex: row.raw_u8_0x10_hex,
    raw_object_u8_0x11_hex: row.raw_u8_0x11_hex,
    raw_object_f32_0x14_hex: row.raw_f32_0x14_hex,
    raw_object_u32_0x18_hex: row.raw_u32_0x18_hex,
    raw_object_u32_0x1c_hex: row.raw_u32_0x1c_hex,
    raw_object_u8_0x20_hex: row.raw_u8_0x20_hex,
  });
  if (!decoded || !Object.entries(decoded).every(([name, value]) => row[name] === value)) {
    return false;
  }
  const selector = row.opaque_u8_0x20;
  return (selector <= 5 || selector === 63)
    && row.native_receiver_slot_candidate === selector
    && row.native_receiver_selection_path ===
      (selector === 63 ? 'INDEX_63' : 'INDEX_0_TO_5')
    && row.native_receiver_forwarded_fields_witnessed === true;
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

function decodeSetSpellTimerFromBuffPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected, setSpellTimerProfile = 'v1',
} = {}) {
  const v2 = setSpellTimerProfile === 'v2';
  const profile = v2 ? SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_821
    : SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
    ...(v2 ? {
      evidence_callback_rva: profile.evidence_callback_rva,
      evidence_receiver_lookup_rva: profile.evidence_receiver_lookup_rva,
      evidence_receiver_call_rva: profile.evidence_receiver_call_rva,
      evidence_callback_region_sha256: CALLBACK_REGION_SHA256,
      evidence_receiver_lookup_region_sha256: RECEIVER_LOOKUP_REGION_SHA256,
      evidence_callback_witness_mode: CALLBACK_WITNESS_MODE,
    } : {}),
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (setSpellTimerProfile !== 'v1' && setSpellTimerProfile !== 'v2') {
    return fail('UNSUPPORTED', 'SetSpellTimerFromBuff packet profile must be v1 or v2');
  }
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `SetSpellTimerFromBuff packet candidate supports only ${REPLAY_VERSION}`);
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
    return fail('UNSUPPORTED', `SetSpellTimerFromBuff runtime input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      observed_packet_count_minimum: selected.observed_packet_count_minimum,
      scanned_block_count: scannedBlockCount,
    });
  }
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x00fd SetSpellTimerFromBuff route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  if (inputCount > MAX_TOTAL_PACKETS) {
    return failed('UNSUPPORTED', `SetSpellTimerFromBuff runtime input exceeds ${MAX_TOTAL_PACKETS} packets`);
  }
  for (const { block, chunk } of rows) {
    const param = block.param >>> 0;
    if (chunk.stream_tag !== 1 || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || param === 0) {
      return failed('DECODE_FAILED', '0x00fd packet framing differs from observed KR scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (!OBSERVED_PAYLOAD_LENGTHS.has(block.payload_length)) {
      return failed('DECODE_FAILED', '0x00fd payload length differs from observed KR scope', {
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
    'decode_set_spell_timer_from_buff_packet_16_19_821.py');
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
      return failed('UNSUPPORTED', 'SetSpellTimerFromBuff runtime request exceeds bounded input size', {
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
      const wrongImage = /runtime image SHA-256 mismatch|record transform table differs|callback transform differs|callback region differs|receiver lookup region differs/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime SetSpellTimerFromBuff packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime SetSpellTimerFromBuff packet output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0, runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || !callbackTablesMatch(decoded.callback_table_sha256)
        || (v2 && (decoded.callback_rva !== profile.evidence_callback_rva
          || decoded.receiver_lookup_rva !== profile.evidence_receiver_lookup_rva
          || decoded.receiver_call_rva !== profile.evidence_receiver_call_rva
          || decoded.callback_region_sha256 !== CALLBACK_REGION_SHA256
          || decoded.receiver_lookup_region_sha256 !== RECEIVER_LOOKUP_REGION_SHA256
          || decoded.callback_witness_mode !== CALLBACK_WITNESS_MODE))
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime SetSpellTimerFromBuff output identity or packet count differs', {
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
          || !Number.isFinite(row.opaque_f32_0x14)
          || !Number.isInteger(row.opaque_u32_0x18) || row.opaque_u32_0x18 < 0
          || row.opaque_u32_0x18 > 0xffffffff
          || !Number.isInteger(row.opaque_u32_0x1c) || row.opaque_u32_0x1c < 0
          || row.opaque_u32_0x1c > 0xffffffff
          || !Number.isInteger(row.opaque_u8_0x20) || row.opaque_u8_0x20 < 0
          || row.opaque_u8_0x20 > 0xff
          || !/^[0-9a-f]{2}$/.test(row.raw_u8_0x10_hex)
          || !/^[0-9a-f]{2}$/.test(row.raw_u8_0x11_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_f32_0x14_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x18_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x1c_hex)
          || !/^[0-9a-f]{2}$/.test(row.raw_u8_0x20_hex)
          || (v2 && !v2WitnessMatches(row))) {
        return failed('DECODE_FAILED', `runtime SetSpellTimerFromBuff packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        opaque_u8_0x10: row.opaque_u8_0x10,
        opaque_u8_0x11: row.opaque_u8_0x11,
        opaque_f32_0x14: row.opaque_f32_0x14,
        opaque_u32_0x18: row.opaque_u32_0x18,
        opaque_u32_0x1c: row.opaque_u32_0x1c,
        opaque_u8_0x20: row.opaque_u8_0x20,
        raw_object_u8_0x10_hex: row.raw_u8_0x10_hex,
        raw_object_u8_0x11_hex: row.raw_u8_0x11_hex,
        raw_object_f32_0x14_hex: row.raw_f32_0x14_hex,
        raw_object_u32_0x18_hex: row.raw_u32_0x18_hex,
        raw_object_u32_0x1c_hex: row.raw_u32_0x1c_hex,
        raw_object_u8_0x20_hex: row.raw_u8_0x20_hex,
        ...(v2 ? {
          native_receiver_slot_candidate: row.native_receiver_slot_candidate,
          native_receiver_selection_path: row.native_receiver_selection_path,
          native_receiver_forwarded_fields_witnessed:
            row.native_receiver_forwarded_fields_witnessed,
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
      ? SET_SPELL_TIMER_FROM_BUFF_V2_EVENT_FIELD_CONFIDENCE_821 : {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      opaque_u8_0x10: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_u8_0x11: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_f32_0x14: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_u32_0x18: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_u32_0x1c: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      opaque_u8_0x20: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, events,
  };
}

module.exports = {
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_821,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_ID_821,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_ID_821,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_821,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_821,
  SET_SPELL_TIMER_FROM_BUFF_V2_FIELD_CONFIDENCE_821,
  SET_SPELL_TIMER_FROM_BUFF_V2_EVENT_FIELD_CONFIDENCE_821,
  decodeSetSpellTimerU8At20FromRaw821,
  decodeSetSpellTimerRawFields821,
  decodeSetSpellTimerFromBuffPacketCandidates821,
};
