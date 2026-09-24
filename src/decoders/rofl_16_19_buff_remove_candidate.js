'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { NPC_BUFF_REMOVE_PACKET_ID, candidateBuffPacketRowsForReplay } =
  require('./rofl_16_19_820_7193');
const { replaySourceError } = require('./replay_source_integrity');

const REPLAY_VERSION = '16.19.820.7193';
const RUNTIME_IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const MAX_PACKETS = 50_000;
const MAX_INPUT_BYTES = 12_000_000;
const MAX_PAYLOAD_BYTES = 64;

const NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-buff-remove2-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'npc_buff_remove_packet',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: NPC_BUFF_REMOVE_PACKET_ID,
  packet_name: 'PKT_NPC_BuffRemove2_s',
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact HN callback/factory/deserializer and all 11950 fully consumed route packets in one HN Replay',
  known_limits: Object.freeze([
    'Only observed BuffRemove2 packet fields are emitted; a decoded packet is not proof of a successful buff removal.',
    'The decoded byte is used as a BuffManager slot index and the decoded u32 is passed to a lookup; their external meanings remain candidates from one Replay.',
    'The decoded f32 is zero for most observed packets and matches Replay time in the eight nonzero observations; it is not a complete lifecycle clock.',
    'Raw param is preserved without assigning an owner, participant, buff name, buff type, duration, or target.',
    'The exact captured HN runtime image and Python Unicorn are required for decoding.',
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
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function decodeNpcBuffRemovePacketCandidates(replay, _collected = null, options = {}) {
  const profile = NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE;
  const base = { profile_id: profile.id, input_packet_id: profile.replay_block_packet_id };
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { ...base, status: 'UNSUPPORTED', input_count: null, event_count: null,
      events: null, error: `BuffRemove2 candidate supports only ${REPLAY_VERSION}` };
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
      events: null, error: `Replay source integrity failed: ${sourceError}` };
  }
  let rows = [];
  let walk;
  if (_collected !== null) {
    const selected = candidateBuffPacketRowsForReplay(replay, _collected,
      profile.replay_block_packet_id);
    if (selected.error) {
      return { ...base, status: 'DECODE_FAILED', input_count: null,
        event_count: null, events: null,
        error: `BuffRemove2 precollected scan failed: ${selected.error}` };
    }
    if (selected.observed_packet_count_minimum) {
      return { ...base, status: 'UNSUPPORTED', input_count: null,
        observed_packet_count_minimum: selected.observed_packet_count_minimum,
        event_count: null, events: null, scanned_block_count: null,
        runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
        error: `BuffRemove2 route exceeds ${MAX_PACKETS} packets` };
    }
    rows = selected.rows;
    walk = { block_count: selected.scanned_block_count };
  } else {
    const packetLimitError = new Error('BuffRemove2 packet limit reached');
    try {
      walk = walkBlocks(replay, (block, chunk) => {
        if (block.packet_id !== profile.replay_block_packet_id) return;
        if (rows.length === MAX_PACKETS) throw packetLimitError;
        rows.push({ block, chunk: { ...chunk } });
      }, { includeStreams: [profile.stream_tag], strict: true });
    } catch (error) {
      if (error === packetLimitError) {
        return { ...base, status: 'UNSUPPORTED', input_count: null,
          observed_packet_count_minimum: MAX_PACKETS + 1,
          event_count: null, events: null, scanned_block_count: null,
          runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
          error: `BuffRemove2 route exceeds ${MAX_PACKETS} packets` };
      }
      return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
        events: null, error: `Replay framing failed: ${error.message}` };
    }
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
    return fail('PROFILE_UNAVAILABLE', 'HN game-stream BuffRemove2 route 0x043c is absent', {
      input_count: null, observed_raw_route_count: 0,
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  if (rows.some(({ block }) =>
    block.payload_length < 1 || block.payload_length > MAX_PAYLOAD_BYTES)) {
    return fail('UNSUPPORTED', 'BuffRemove2 runtime payload exceeds its byte limit', {
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
    packets: rows.map(({ block }) => ({
      raw_param: block.param >>> 0,
      payload_hex: block.payload.toString('hex'),
    })),
  };
  const serialized = JSON.stringify(request);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_INPUT_BYTES) {
    return fail('UNSUPPORTED', 'BuffRemove2 runtime input exceeds its byte limit', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, 'decode_buff_remove_16_19.py');
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
      `exact runtime BuffRemove2 decoder failed: ${detail}`, {
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        runtime_image_status: imageMismatch ? 'HASH_MISMATCH' : 'EXECUTION_FAILED',
        runtime_image_used: false,
      });
  }
  let decoded;
  try {
    decoded = JSON.parse(run.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `runtime BuffRemove2 output is not JSON: ${error.message}`, {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  if (decoded?.status !== 'PASS'
      || decoded.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || !Array.isArray(decoded.results) || decoded.results.length !== inputCount) {
    return fail('DECODE_FAILED', 'runtime BuffRemove2 output identity or packet count differs', {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  const refs = rows.map(({ block, chunk }) => packetRef(replay, block, chunk));
  const failures = [];
  for (let index = 0; index < inputCount; index += 1) {
    const result = decoded.results[index];
    const ref = refs[index];
    if (result?.input_index !== index || result.raw_param !== ref.raw_param
        || result.raw_payload_sha256 !== ref.raw_payload_sha256) {
      return fail('DECODE_FAILED', `runtime BuffRemove2 output does not match packet ${index}`, {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: decoded.runtime_image_sha256,
        first_failed_packet_ref: ref,
      });
    }
    const valid = result.status === 'DECODED'
      && result.deserialize_return_al === 1
      && result.bytes_consumed === rows[index].block.payload_length
      && Number.isFinite(result.decoded_time_f32_seconds)
      && Number.isSafeInteger(result.slot_index_u8)
      && result.slot_index_u8 >= 0 && result.slot_index_u8 <= 0xff
      && Number.isSafeInteger(result.lookup_token_u32)
      && result.lookup_token_u32 >= 0 && result.lookup_token_u32 <= 0xffffffff
      && /^[0-9a-f]{8}$/.test(result.raw_object_time_bytes_hex)
      && /^[0-9a-f]{2}$/.test(result.raw_object_slot_byte_hex)
      && /^[0-9a-f]{8}$/.test(result.raw_object_lookup_bytes_hex);
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
    return fail('DECODE_FAILED', `${failures.length} runtime BuffRemove2 packets did not fully decode`, {
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: decoded.runtime_image_sha256,
      first_failed_packet_ref: failures[0].raw_packet_ref,
      failed_packet_count: failures.length,
      failed_packet_results: failures.slice(0, 20),
      failed_packet_results_truncated: failures.length > 20,
    });
  }
  const events = rows.map(({ block }, index) => {
    const result = decoded.results[index];
    return {
      event_type: 'NPC_BUFF_REMOVE_PACKET_CANDIDATE',
      game_version: REPLAY_VERSION, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      decoded_time_f32_seconds_candidate: result.decoded_time_f32_seconds,
      buff_slot_index_candidate: result.slot_index_u8,
      buff_lookup_token_u32_candidate: result.lookup_token_u32,
      raw_object_time_bytes_hex: result.raw_object_time_bytes_hex,
      raw_object_slot_byte_hex: result.raw_object_slot_byte_hex,
      raw_object_lookup_bytes_hex: result.raw_object_lookup_bytes_hex,
      raw_payload_hex: block.payload.toString('hex'),
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_BUFF_REMOVE2_ONE_REPLAY',
      raw_packet_ref: refs[index],
    };
  });
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_BUFF_REMOVE2_ONE_REPLAY',
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      raw_param: 'VERIFIED_DIRECT',
      decoded_time_f32_seconds_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      buff_slot_index_candidate: 'CANDIDATE_EXACT_RUNTIME_VECTOR_INDEX',
      buff_lookup_token_u32_candidate: 'CANDIDATE_EXACT_RUNTIME_LOOKUP_TOKEN',
      raw_payload_hex: 'VERIFIED_DIRECT',
    },
    input_count: inputCount, event_count: events.length,
    scanned_block_count: walk.block_count,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: decoded.runtime_image_sha256,
    events,
  };
}

module.exports = {
  NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE,
  decodeNpcBuffRemovePacketCandidates,
};
