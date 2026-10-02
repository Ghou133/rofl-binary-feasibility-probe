'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MEMSET_PREFIX_SHA256 = '961ec6b7a19ad835ada16a4cd076ebd87c7038c770e0ca8db6cf0aa6b04b3d38';
const CAPABILITY = 'anonymous_049c_packet';
const PROFILE_ID = 'rofl-16.19.821.7343-kr-anonymous-049c-native-byte-vector-candidate-v1';
const LENGTHS = Object.freeze({
  1: new Set([5, 6, ...Array.from({ length: 32 }, (_, index) => index + 9), 42, 48, 49, 52]),
  2: new Set([5, 6, ...Array.from({ length: 28 }, (_, index) => index + 10), 39, 49, 52]),
});
const ANONYMOUS_049C_PACKET_821_PROFILE = Object.freeze({
  id: PROFILE_ID, replay_version: BUILD, capability: CAPABILITY,
  status: 'CANDIDATE', enabled: true, replay_block_packet_id: 0x049c,
  evidence_status: 'CANDIDATE_EXACT_821_NATIVE_049C_BYTE_VECTOR',
  stream_tags: Object.freeze([1, 2]), evidence_runtime_image_sha256: IMAGE_SHA256,
  native_constructor_rva: '0xe9a6c0', native_deserializer_rva: '0x10d0d30',
  memory_compatibility_operation: 'MEMSET_ONLY',
  memory_compatibility_leaf_rva: '0x1a653c3',
  memory_compatibility_prefix_sha256: MEMSET_PREFIX_SHA256,
  known_limits: Object.freeze([
    'The exact native numeric 0x049c constructor/deserializer yields anonymous nested field bytes and a dynamic byte vector; field roles are not assigned.',
    'Printable ASCII is a reversible presentation of decoded vector bytes. A recognizable token does not prove a spell identity, slot, owner, successful change, cast or effect.',
    'Only a pinned AVX memset leaf is replaced with its host-memory fill semantics; no packet field decoder, receiver, game lookup or gameplay callback is stubbed.',
    'Game and keyframe packets retain their original timestamps and raw parameters; no participant mapping or lifecycle is inferred.',
    'The candidate is opt-in and bound to the complete 16.19.821.7343 build and pinned runtime image.',
  ]),
});

function sha(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function decodeAnonymous049cPacketCandidates821(replay, options = {}) {
  const profile = ANONYMOUS_049C_PACKET_821_PROFILE;
  const base = { profile_id: profile.id, input_packet_id: 0x049c,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    memory_compatibility_operation: profile.memory_compatibility_operation,
    memory_compatibility_leaf_rva: profile.memory_compatibility_leaf_rva,
    memory_compatibility_prefix_sha256: MEMSET_PREFIX_SHA256,
    known_limits: [...profile.known_limits] };
  const fail = (status, error, details = {}) => ({ ...base, status, input_count: null,
    event_count: null, events: null, runtime_image_used: false, error, ...details });
  if (replay?.header?.version !== BUILD) return fail('UNSUPPORTED', `requires exact ${BUILD}`);
  const integrity = replaySourceError(replay);
  if (integrity) return fail('DECODE_FAILED', integrity);
  if (!options.runtimeImagePath) return fail('MISSING_INPUT', 'exact runtime image is required', {
    runtime_image_status: 'MISSING', missing_input: 'exact_runtime_image' });
  let image;
  try {
    if (fs.statSync(options.runtimeImagePath).size !== 48_488_448) {
      return fail('INCONSISTENT', 'exact runtime image size differs', { runtime_image_status: 'SIZE_MISMATCH' });
    }
    image = fs.readFileSync(options.runtimeImagePath);
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      runtime_image_status: 'MISSING' });
  }
  const imageSha = sha(image);
  if (imageSha !== IMAGE_SHA256) return fail('INCONSISTENT', 'exact runtime image hash differs', {
    runtime_image_status: 'HASH_MISMATCH', runtime_image_sha256: imageSha });
  const packets = [];
  try {
    const observe = (block, chunk) => {
      if (block.packet_id !== 0x049c) return;
      if (!LENGTHS[chunk.stream_tag]?.has(block.payload.length)
          || !Number.isSafeInteger(block.param >>> 0) || (block.param >>> 0) === 0) {
        throw new Error('0x049c source packet is outside observed stream/length/raw-param scope');
      }
      if (packets.length >= 30_000) throw new Error('0x049c packet count exceeds bounded scope');
      packets.push({ packet_id: 0x049c, stream_tag: chunk.stream_tag,
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
        raw_packet_ref: { source_path: replay.source_path ?? null,
          replay_sha256: replay.source_sha256, chunk_index: chunk.index,
          chunk_id: chunk.chunk_id, chunk_stream: chunk.stream,
          chunk_file_offset: chunk.offset, decompressed_block_offset: block.offset,
          decompressed_payload_offset: block.payload_offset, packet_id: 0x049c,
          replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
          payload_length: block.payload.length, raw_payload_sha256: sha(block.payload) } });
    };
    if (options.precollected) {
      const source = rowsFor821Capability(replay, options.precollected, CAPABILITY);
      if (source.error) throw new Error(source.error);
      if (source.observed_packet_count_minimum) throw new Error('0x049c route exceeds bounded scope');
      for (const row of source.rows) observe(row.block, row.chunk);
    } else {
      walkBlocks(replay, observe, { strict: true });
    }
  } catch (error) { return fail('DECODE_FAILED', error.message); }
  if (!packets.length) return fail('PROFILE_UNAVAILABLE', 'no observed exact-821 0x049c route');
  const events = [];
  let printable = 0;
  const inputHash = crypto.createHash('sha256');
  for (let start = 0; start < packets.length; start += 10_000) {
    const batch = packets.slice(start, start + 10_000);
    const input = JSON.stringify({ replay_version: BUILD, packets: batch.map((packet) => ({
      packet_id: packet.packet_id, stream_tag: packet.stream_tag,
      raw_param: packet.raw_param, payload_hex: packet.payload_hex })) });
    inputHash.update(input);
    const run = childProcess.spawnSync(options.pythonExecutable ?? 'python',
      [path.resolve(__dirname, '../../scripts/decode_anonymous_049c_packet_16_19_821.py'),
        '--image', options.runtimeImagePath], {
        input, encoding: 'utf8', timeout: 120000, maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      });
    if (run.error || run.status !== 0) return fail('DECODE_FAILED',
      `native helper failed: ${run.error?.message ?? run.stderr ?? run.status}`);
    let result;
    try { result = JSON.parse(run.stdout); } catch {
      return fail('DECODE_FAILED', 'native helper returned invalid JSON');
    }
    if (result.replay_version !== BUILD || result.runtime_image_sha256 !== IMAGE_SHA256
        || result.memory_compatibility?.operation !== 'MEMSET_ONLY'
        || result.memory_compatibility?.leaf_rva !== profile.memory_compatibility_leaf_rva
        || result.memory_compatibility?.prefix_sha256 !== MEMSET_PREFIX_SHA256
        || !Array.isArray(result.rows) || result.rows.length !== batch.length) {
      return fail('INCONSISTENT', 'native helper identity/counts differ');
    }
    for (const [index, row] of result.rows.entries()) {
      const source = batch[index];
      if (row.index !== index || row.status !== 'NATIVE_ACCEPTED'
          || row.deserialize_return_al !== 1 || row.bytes_consumed !== source.payload_hex.length / 2
          || !Number.isSafeInteger(row.native_byte_vector_length)
          || row.native_byte_vector_length < 0 || row.native_byte_vector_length > 64
          || typeof row.native_byte_vector_hex !== 'string'
          || !/^(?:[0-9a-f]{2})*$/.test(row.native_byte_vector_hex)
          || row.native_byte_vector_hex.length !== row.native_byte_vector_length * 2) {
        return fail('DECODE_FAILED', `native 0x049c row ${start + index} failed: ${row.error ?? 'witness mismatch'}`);
      }
      const vector = Buffer.from(row.native_byte_vector_hex, 'hex');
      const terminalNul = vector.length > 0 && vector.at(-1) === 0;
      const visible = terminalNul ? vector.subarray(0, -1) : vector;
      const isPrintable = visible.length > 0 && visible.every((value) => value >= 32 && value <= 126);
      if (row.native_byte_vector_terminal_nul !== terminalNul
          || row.native_byte_vector_ascii_candidate !== (isPrintable ? visible.toString('ascii') : null)
          || row.native_byte_vector_text_status !== (isPrintable ? 'PRINTABLE_ASCII_CANDIDATE' : 'OPAQUE_BYTES')
          || !/^[0-9a-f]{2}$/.test(row.native_nested_field_bytes_hex?.['0x18'] ?? '')
          || !/^[0-9a-f]{8}$/.test(row.native_nested_field_bytes_hex?.['0x1c'] ?? '')
          || !/^[0-9a-f]{6}$/.test(row.native_nested_field_bytes_hex?.['0x20'] ?? '')) {
        return fail('INCONSISTENT', 'native 0x049c field bytes/text presentation differ');
      }
      if (isPrintable) printable += 1;
      const { index: _index, status: _status, ...fields } = row;
      events.push({ event_type: 'ANONYMOUS_049C_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: PROFILE_ID,
        replay_sha256: replay.source_sha256,
        replay_time_ms: source.raw_packet_ref.replay_time_ms,
        raw_param: source.raw_param, stream_tag: source.stream_tag,
        confidence: 'CANDIDATE', semantic_status: profile.evidence_status,
        semantic_effect_status: 'UNKNOWN',
        ...fields, raw_packet_ref: source.raw_packet_ref });
    }
  }
  return { ...base, status: 'CANDIDATE', evidence_status: profile.evidence_status,
    input_count: packets.length,
    event_count: events.length, native_full_success_count: events.length,
    native_printable_ascii_count: printable,
    native_opaque_vector_count: events.length - printable,
    ordered_native_input_sha256: inputHash.digest('hex'),
    runtime_image_used: true, runtime_image_status: 'MATCHED_USED',
    runtime_image_sha256: imageSha, events };
}

module.exports = { ANONYMOUS_049C_PACKET_821_PROFILE, decodeAnonymous049cPacketCandidates821 };
