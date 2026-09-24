'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');

const REPLAY_VERSION = '16.19.820.7193';
const RUNTIME_IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const MAX_PACKETS = 50_000;
const MAX_INPUT_BYTES = 12_000_000;
const OBSERVED_LENGTHS = new Set([14, 15, ...Array.from({ length: 16 }, (_, index) => index + 17)]);
const FIELD_SPECS = Object.freeze([
  ['offset_0x10_u32', 0x10, 4, 'u32'],
  ['offset_0x14_f32', 0x14, 4, 'f32'],
  ['offset_0x1c_f32', 0x1c, 4, 'f32'],
  ['offset_0x24_u32', 0x24, 4, 'u32'],
  ['offset_0x28_u8', 0x28, 1, 'u8'],
  ['offset_0x30_u32', 0x30, 4, 'u32'],
]);

const NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-buff-add2-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'npc_buff_add_packet',
  status: 'CANDIDATE',
  enabled: true,
  stream_tags: Object.freeze([1, 2]),
  replay_block_packet_id: 0x03ed,
  packet_name: 'PKT_NPC_BuffAdd2_s',
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact HN callback/constructor/deserializer and 32434 fully consumed packets across game and keyframe streams in one HN Replay',
  known_limits: Object.freeze([
    'Only callback-transformed scalar positions observed in one exact HN Replay are emitted.',
    'The two floats have a bounded cross-stream additive correlation; no duration, elapsed-time, or lifecycle meaning is assigned.',
    'The four opaque grouping fields and raw param do not establish owner, participant, target, buff identity, or successful application.',
    'Two object vectors were empty in all observed packets; packets with nonempty vectors are outside this candidate profile.',
    'The exact captured runtime image and Python Unicorn are required for decoding.',
  ]),
});

function packetRef(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_stream_tag: chunk.stream_tag,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function fieldsAreValid(result) {
  const values = result?.decoded_scalar_fields;
  const raw = result?.raw_object_scalar_bytes_hex;
  if (!values || typeof values !== 'object' || Array.isArray(values)
      || !raw || typeof raw !== 'object' || Array.isArray(raw)
      || typeof result.raw_object_hex !== 'string'
      || !/^[0-9a-f]{192}$/.test(result.raw_object_hex)
      || Object.keys(values).length !== FIELD_SPECS.length
      || Object.keys(raw).length !== FIELD_SPECS.length) return false;
  for (const [name, offset, byteLength, kind] of FIELD_SPECS) {
    const value = values[name];
    if (kind === 'f32') {
      if (!Number.isFinite(value)) return false;
    } else if (!Number.isSafeInteger(value) || value < 0
      || value > (kind === 'u8' ? 0xff : 0xffffffff)) return false;
    if (typeof raw[name] !== 'string'
        || !new RegExp(`^[0-9a-f]{${byteLength * 2}}$`).test(raw[name])
        || raw[name] !== result.raw_object_hex.slice(offset * 2, (offset + byteLength) * 2)) {
      return false;
    }
  }
  for (const offset of [0x38, 0x48]) {
    if (result.raw_object_hex.slice(offset * 2, (offset + 16) * 2) !== '00'.repeat(16)) {
      return false;
    }
  }
  return true;
}

function decodeNpcBuffAddPacketCandidates(replay, _collected = null, options = {}) {
  const profile = NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE;
  const base = { profile_id: profile.id, input_packet_id: profile.replay_block_packet_id };
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { ...base, status: 'UNSUPPORTED', input_count: null, event_count: null,
      events: null, error: `BuffAdd2 candidate supports only ${REPLAY_VERSION}` };
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
      events: null, error: `Replay source integrity failed: ${sourceError}` };
  }
  const rows = [];
  const packetLimitError = new Error('BuffAdd2 packet limit reached');
  let walk;
  try {
    walk = walkBlocks(replay, (block, chunk) => {
      if (block.packet_id !== profile.replay_block_packet_id) return;
      if (rows.length === MAX_PACKETS) throw packetLimitError;
      rows.push({ block, chunk: { ...chunk } });
    }, { includeStreams: profile.stream_tags, strict: true });
  } catch (error) {
    if (error === packetLimitError) {
      return { ...base, status: 'UNSUPPORTED', input_count: null,
        observed_packet_count_minimum: MAX_PACKETS + 1,
        event_count: null, events: null, scanned_block_count: null,
        runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
        error: `BuffAdd2 route exceeds ${MAX_PACKETS} packets` };
    }
    return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
      events: null, error: `Replay framing failed: ${error.message}` };
  }
  const walkedSourceError = replaySourceError(replay);
  if (walkedSourceError) {
    return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
      events: null, runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
      error: `Replay source integrity failed after walk: ${walkedSourceError}` };
  }
  const inputCount = rows.length;
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: inputCount, event_count: null, events: null,
    scanned_block_count: walk.block_count, error, ...extra,
  });
  if (inputCount === 0) {
    return fail('PROFILE_UNAVAILABLE', 'HN BuffAdd2 route 0x03ed is absent from game and keyframe streams', {
      input_count: null, observed_raw_route_count: 0,
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  if (rows.some(({ block }) =>
    !OBSERVED_LENGTHS.has(block.payload_length))) {
    return fail('UNSUPPORTED', 'BuffAdd2 route has an unobserved payload length', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const imagePath = options.runtimeImagePath;
  if (typeof imagePath !== 'string' || !imagePath.trim()) {
    return fail('MISSING_INPUT', 'exact 16.19 HN runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING', runtime_image_used: false,
    });
  }
  const resolvedImage = path.resolve(imagePath);
  try {
    if (!fs.statSync(resolvedImage).isFile()) {
      return fail('MISSING_INPUT', 'runtime image path is not a file', {
        missing_input: 'runtime_image', runtime_image_status: 'MISSING', runtime_image_used: false,
      });
    }
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING', runtime_image_used: false,
    });
  }
  const request = {
    replay_version: REPLAY_VERSION,
    packets: rows.map(({ block, chunk }) => ({
      stream_tag: chunk.stream_tag,
      raw_param: block.param >>> 0,
      payload_hex: block.payload.toString('hex'),
    })),
  };
  const serialized = JSON.stringify(request);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_INPUT_BYTES) {
    return fail('UNSUPPORTED', 'BuffAdd2 runtime input exceeds its byte limit', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, 'decode_buff_add_16_19.py');
  const run = childProcess.spawnSync(python, ['-B', script, '--image', resolvedImage], {
    input: serialized, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    timeout: 180000,
  });
  if (run.error || run.status !== 0) {
    const detail = String(run.error?.message || run.stderr || run.stdout
      || `Python exited ${run.status}`).trim().slice(0, 1500);
    const missingPython = run.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    const imageMismatch = /runtime image SHA-256 mismatch|image hash mismatch/i.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `exact runtime BuffAdd2 decoder failed: ${detail}`, {
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        runtime_image_status: imageMismatch ? 'HASH_MISMATCH' : 'EXECUTION_FAILED',
        runtime_image_used: false,
      });
  }
  let decoded;
  try {
    decoded = JSON.parse(run.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `runtime BuffAdd2 output is not JSON: ${error.message}`, {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  if (decoded?.status !== 'PASS'
      || decoded.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || !Array.isArray(decoded.results) || decoded.results.length !== inputCount) {
    return fail('DECODE_FAILED', 'runtime BuffAdd2 output identity or packet count differs', {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  const refs = rows.map(({ block, chunk }) => packetRef(replay, block, chunk));
  const failures = [];
  for (let index = 0; index < inputCount; index += 1) {
    const result = decoded.results[index];
    const ref = refs[index];
    if (result?.input_index !== index || result.stream_tag !== ref.chunk_stream_tag
        || result.raw_param !== ref.raw_param
        || result.raw_payload_sha256 !== ref.raw_payload_sha256) {
      return fail('DECODE_FAILED', `runtime BuffAdd2 output does not match packet ${index}`, {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: decoded.runtime_image_sha256,
        first_failed_packet_ref: ref,
      });
    }
    const valid = result.status === 'DECODED'
      && result.deserialize_return_al === 1
      && result.bytes_consumed === rows[index].block.payload_length
      && fieldsAreValid(result);
    if (!valid) {
      failures.push({
        packet_index: index, raw_packet_ref: ref,
        runtime_status: result.status ?? null,
        deserialize_return_al: result.deserialize_return_al ?? null,
        bytes_consumed: result.bytes_consumed ?? null,
        error: String(result.error ?? 'invalid result').slice(0, 500),
      });
    }
  }
  if (failures.length) {
    return fail('DECODE_FAILED', `${failures.length} runtime BuffAdd2 packets did not fully decode`, {
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: decoded.runtime_image_sha256,
      first_failed_packet_ref: failures[0].raw_packet_ref,
      failed_packet_count: failures.length,
      failed_packet_results: failures.slice(0, 20),
      failed_packet_results_truncated: failures.length > 20,
    });
  }
  const fieldConfidence = Object.fromEntries(FIELD_SPECS.map(([name]) =>
    [name, 'CANDIDATE_EXACT_RUNTIME_CALLBACK_SCALAR']));
  const events = rows.map(({ block, chunk }, index) => {
    const result = decoded.results[index];
    return {
      event_type: 'NPC_BUFF_ADD_PACKET_CANDIDATE',
      game_version: REPLAY_VERSION, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      stream_tag: chunk.stream_tag,
      raw_param: block.param >>> 0,
      decoded_scalar_fields_candidate: result.decoded_scalar_fields,
      raw_object_scalar_bytes_hex: result.raw_object_scalar_bytes_hex,
      raw_object_hex: result.raw_object_hex,
      raw_payload_hex: block.payload.toString('hex'),
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_BUFF_ADD2_PACKET_ONE_REPLAY',
      raw_packet_ref: refs[index],
    };
  });
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_BUFF_ADD2_PACKET_ONE_REPLAY',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', stream_tag: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT', raw_payload_hex: 'VERIFIED_DIRECT',
      raw_object_hex: 'CANDIDATE_EXACT_RUNTIME_OBJECT_BYTES',
      decoded_scalar_fields_candidate: fieldConfidence,
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: walk.block_count,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: decoded.runtime_image_sha256,
    events,
  };
}

module.exports = {
  NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE,
  decodeNpcBuffAddPacketCandidates,
};
