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
const PROFILE_ID = 'rofl-16.19.821.7343-kr-049c-native-callback-request-candidate-v2';
const LENGTHS = Object.freeze({
  1: new Set([5, 6, ...Array.from({ length: 32 }, (_, index) => index + 9), 42, 48, 49, 52]),
  2: new Set([5, 6, ...Array.from({ length: 28 }, (_, index) => index + 10), 39, 49, 52]),
});
const CLASSES = Object.freeze({ 0x049c: 'PKT_ChangeSlotSpellData_s',
  0x028e: 'PKT_ChangeSlotSpellData_Summoner_s', 0x0375: 'PKT_ChangeSlotSpellData_OwnerOnly_s' });
const SIBLING_LENGTHS = { 0x028e: { 1: new Set([17,18,19,21,22,32,33,34,46]),
  2: new Set([17,18,19,21,22,32,33,34,46]) }, 0x0375: { 2: new Set([5,6,9,10]) } };
const ANONYMOUS_049C_PACKET_821_PROFILE = Object.freeze({
  id: PROFILE_ID, replay_version: BUILD, capability: CAPABILITY,
  status: 'CANDIDATE', enabled: true, replay_block_packet_id: 0x049c,
  evidence_status: 'CANDIDATE_EXACT_821_NATIVE_049C_CALLBACK_REQUEST',
  packet_name: 'PKT_ChangeSlotSpellData_s', registered_receiver_class: 'AIBaseClient',
  native_callback_rva: '0x24ebb0',
  stream_tags: Object.freeze([1, 2]), evidence_runtime_image_sha256: IMAGE_SHA256,
  native_constructor_rva: '0xe9a6c0', native_deserializer_rva: '0x10d0d30',
  memory_compatibility_operation: 'MEMSET_ONLY',
  memory_compatibility_leaf_rva: '0x1a653c3',
  memory_compatibility_prefix_sha256: MEMSET_PREFIX_SHA256,
  known_limits: Object.freeze([
    'Exact-image registration binds numeric 0x049c to AIBaseClient/PKT_ChangeSlotSpellData_s. Packet-only callback execution witnesses the slot index and arguments for the two observed operation branches.',
    'Selector 2 requests a name change; selector 1 requests a byte write to slot object +0x2f whose gameplay meaning remains unknown. Neither proves successful application, actor identity, cast or effect.',
    'Only a pinned AVX memset leaf is replaced with its host-memory fill semantics; no packet field decoder, receiver, game lookup or gameplay callback is stubbed.',
    'Game and keyframe packets retain their original timestamps and raw parameters; no participant mapping or lifecycle is inferred.',
    'The candidate is opt-in and bound to the complete 16.19.821.7343 build and pinned runtime image.',
  ]),
});
const SPELL_SLOT_CHANGE_REQUEST_821_PROFILE = Object.freeze({
  ...ANONYMOUS_049C_PACKET_821_PROFILE,
  id: 'rofl-16.19.821.7343-kr-spell-slot-change-request-native-candidate-v1',
  capability: 'spell_slot_change_request', packet_name: 'EXACT_821_SLOT_CHANGE_PACKET_FAMILY',
  replay_block_packet_id: null, replay_block_packet_ids: Object.freeze([0x049c, 0x028e, 0x0375]),
  native_constructor_rva: null, native_deserializer_rva: null,
  native_routes: Object.freeze([
    Object.freeze({packet_id:0x049c,packet_name:CLASSES[0x049c],constructor_rva:'0xe9a6c0',deserializer_rva:'0x10d0d30'}),
    Object.freeze({packet_id:0x028e,packet_name:CLASSES[0x028e],constructor_rva:'0xe9a670',deserializer_rva:'0x10d0bd0'}),
    Object.freeze({packet_id:0x0375,packet_name:CLASSES[0x0375],constructor_rva:'0xe9a620',deserializer_rva:'0x10d0a70'}),
  ]),
  evidence_status: 'CANDIDATE_EXACT_821_NATIVE_SLOT_CHANGE_REQUEST',
  known_limits: Object.freeze([
    ...ANONYMOUS_049C_PACKET_821_PROFILE.known_limits,
    'Exact Summoner 0x028e and OwnerOnly 0x0375 registrations/deserializers are independently pinned. Their class names do not prove current delivery audience or actor identity.',
    'OwnerOnly selector 6 requests a gated +0xe8 byte write; selector 7 requests a counted four-byte vector change. Field meanings, word type/units and applied state remain unknown.',
  ]),
});

function sha(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function isObservedSlotChangeShape821(packetId, streamTag, payloadLength) {
  const lengths = packetId === 0x049c ? LENGTHS : SIBLING_LENGTHS[packetId];
  return lengths?.[streamTag]?.has(payloadLength) === true;
}

function callbackRequestError(row) {
  const request = row.callback_request_candidate;
  const fields = row.native_nested_field_bytes_hex;
  if (!/^[0-9a-f]{8}$/.test(fields?.['0x1c'] ?? '') || !/^[0-9a-f]{2}$/.test(fields?.['0x18'] ?? '')
      || !/^(?:[0-9a-f]{2})*$/.test(row.native_byte_vector_hex ?? '')) return 'callback source fields differ';
  const operation = Buffer.from(fields['0x1c'], 'hex').readUInt32LE();
  const packetId = row.native_packet_id ?? 0x049c;
  const observed = { 0x049c: [1,2], 0x028e: [2], 0x0375: [6,7] }[packetId];
  if (!observed) return 'foreign slot-change packet route';
  if (!request || request.operation_selector !== operation || request.application_status !== 'NOT_OBSERVED') {
    return 'callback operation/application witness differs';
  }
  if (!observed.includes(operation)) {
    return request.status === 'UNOBSERVED_OPERATION' ? null : 'unobserved operation was claimed decoded';
  }
  const ror = (byte, count) => ((byte >>> count) | (byte << (8 - count))) & 255;
  const raw = parseInt(fields['0x18'], 16);
  const exchanged = (((raw & 0xd5) << 1) | ((raw >>> 1) & 0x55)) & 255;
  const slot = (ror(ror((exchanged + 0x68) & 255, 6) ^ 255, 6) - 2) & 255;
  if (request.status !== 'CANDIDATE_STATIC_RECEIVE_DATAFLOW'
      || request.registered_packet_class !== CLASSES[packetId]
      || request.registered_receiver_class !== 'AIBaseClient'
      || request.slot_index !== slot || request.receiver_entity_status !== 'UNKNOWN'
      || request.value_decode_witness !== 'NATIVE_PACKET_ONLY_CALLBACK_PREFIX') {
    return 'callback binding/index witness differs';
  }
  const vector = Buffer.from(row.native_byte_vector_hex, 'hex');
  if (operation === 1) {
    return vector.length === 1 && request.operation_kind === 'SLOT_BYTE_FIELD_WRITE_REQUEST'
      && request.callback_stop_rva === '0x24ec26' && request.requested_u8 === vector[0]
      && request.receiver_field_offset === '0x2f' && request.receiver_field_meaning === 'UNKNOWN'
      && request.native_lookup_index === (slot <= 63 ? slot : 0) ? null : 'callback byte-write witness differs';
  }
  if (operation === 6) {
    return vector.length === 1 && request.operation_kind === 'SLOT_GATED_BYTE_FIELD_WRITE_REQUEST'
      && request.callback_stop_rva === '0x24ed5e' && request.requested_u8 === vector[0]
      && request.receiver_field_offset === '0xe8' && request.receiver_field_meaning === 'UNKNOWN'
      && request.callee_has_state_gate === true ? null : 'callback gated byte-write witness differs';
  }
  if (operation === 7) {
    const words = request.requested_words_u32;
    return vector.length === 5 && vector[0] === 1
      && request.operation_kind === 'SLOT_DWORD_VECTOR_CHANGE_REQUEST' && request.callback_stop_rva === '0x24ed7b'
      && request.requested_word_count === vector[0] && Array.isArray(words) && words.length === vector[0]
      && words.every((word,i) => word === vector.readUInt32LE(1+i*4))
      && request.word_decode_witness === 'NATIVE_CALLEE_PACKET_ONLY_VECTOR_CONSTRUCTION'
      && request.nested_holder_vector_offset === '0x40' && request.word_meaning === 'UNKNOWN'
      && request.callee_has_state_gate === true ? null : 'callback counted word-vector witness differs';
  }
  const name = vector.subarray(0, -1);
  const ascii = name.length && name.every((byte) => byte >= 32 && byte <= 126) ? name.toString('ascii') : null;
  // Independent check against the pinned native comparison hash. Bytes above
  // 127 follow its sign-extended char addition; only ASCII A-Z are folded.
  let nameHash = 0;
  for (const byte of name) {
    const folded = byte >= 65 && byte <= 90 ? byte + 32 : byte;
    nameHash = ((nameHash << 4) + (folded < 128 ? folded : folded - 256)) >>> 0;
    const high = nameHash & 0xf0000000;
    if (high) nameHash = (nameHash ^ high ^ (high >>> 24)) >>> 0;
  }
  return vector.length >= 2 && vector.at(-1) === 0 && !name.includes(0)
    && request.operation_kind === 'SLOT_NAME_CHANGE_REQUEST' && request.callback_stop_rva === '0x24ecdf'
    && request.requested_name_bytes_hex === name.toString('hex') && request.requested_name_ascii === ascii
    && request.native_name_comparison_hash_u32 === nameHash
    && Array.isArray(request.anonymous_control_bytes) && request.anonymous_control_bytes.length === 3
    && request.anonymous_control_bytes.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    ? null : 'callback name-change witness differs';
}

function decodeAnonymous049cPacketCandidates821(replay, options = {}) {
  const includeSiblings = options.includeSlotSiblings === true;
  const profile = includeSiblings ? SPELL_SLOT_CHANGE_REQUEST_821_PROFILE : ANONYMOUS_049C_PACKET_821_PROFILE;
  const routes = includeSiblings ? [0x049c, 0x028e, 0x0375] : [0x049c];
  const base = { profile_id: profile.id, ...(includeSiblings ? {input_packet_ids:routes} : {input_packet_id:0x049c}),
    packet_name: profile.packet_name, registered_receiver_class: profile.registered_receiver_class,
    native_callback_rva: profile.native_callback_rva,
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
      if (!routes.includes(block.packet_id)) return;
      if (!isObservedSlotChangeShape821(block.packet_id, chunk.stream_tag, block.payload.length)
          || !Number.isSafeInteger(block.param >>> 0) || (block.param >>> 0) === 0) {
        throw new Error(`slot-change route 0x${block.packet_id.toString(16)} is outside observed stream/length/raw-param scope`);
      }
      if (packets.length >= 30_000) throw new Error('selected slot-change packet count exceeds bounded scope');
      packets.push({ packet_id: block.packet_id, stream_tag: chunk.stream_tag,
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
        raw_packet_ref: { source_path: replay.source_path ?? null,
          replay_sha256: replay.source_sha256, chunk_index: chunk.index,
          chunk_id: chunk.chunk_id, chunk_stream: chunk.stream,
          chunk_file_offset: chunk.offset, decompressed_block_offset: block.offset,
          decompressed_payload_offset: block.payload_offset, packet_id: block.packet_id,
          replay_time_ms: block.timestamp_ms, raw_param: block.param >>> 0,
          payload_length: block.payload.length, raw_payload_sha256: sha(block.payload) } });
    };
    if (options.precollected) {
      const source = rowsFor821Capability(replay, options.precollected, profile.capability);
      if (source.error) throw new Error(source.error);
      if (source.observed_packet_count_minimum) throw new Error('selected slot-change route exceeds bounded scope');
      for (const row of source.rows) observe(row.block, row.chunk);
    } else {
      walkBlocks(replay, observe, { strict: true });
    }
  } catch (error) { return fail('DECODE_FAILED', error.message); }
  if (!packets.length) return fail('PROFILE_UNAVAILABLE', 'no observed exact-821 selected slot-change route');
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
        '--image', options.runtimeImagePath, ...(includeSiblings ? ['--include-slot-siblings'] : [])], {
        input, encoding: 'utf8', timeout: 120000, maxBuffer: 32 * 1024 * 1024,
        windowsHide: true,
      });
    if (run.error || run.status !== 0) return fail('DECODE_FAILED',
      `native helper failed: ${run.error?.message ?? run.stderr ?? run.status}`);
    let result;
    try { result = JSON.parse(run.stdout); } catch {
      return fail('DECODE_FAILED', 'native helper returned invalid JSON');
    }
    if (result.replay_version !== BUILD || result.runtime_image_sha256 !== IMAGE_SHA256
        || result.callback_packet_class !== CLASSES[0x049c] || result.callback_body_rva !== profile.native_callback_rva
        || result.slot_siblings_enabled !== includeSiblings
        || result.memory_compatibility?.operation !== 'MEMSET_ONLY'
        || result.memory_compatibility?.leaf_rva !== profile.memory_compatibility_leaf_rva
        || result.memory_compatibility?.prefix_sha256 !== MEMSET_PREFIX_SHA256
        || !Array.isArray(result.rows) || result.rows.length !== batch.length) {
      return fail('INCONSISTENT', 'native helper identity/counts differ');
    }
    for (const [index, row] of result.rows.entries()) {
      const source = batch[index];
      if (row.index !== index || row.status !== 'NATIVE_ACCEPTED'
          || row.native_packet_id !== source.packet_id
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
      const callbackError = callbackRequestError(row);
      if (callbackError) return fail('INCONSISTENT', callbackError);
      const { index: _index, status: _status, ...fields } = row;
      events.push({ event_type: includeSiblings ? 'SPELL_SLOT_CHANGE_REQUEST_CANDIDATE' : 'ANONYMOUS_049C_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
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

function decodeSpellSlotChangeRequestCandidates821(replay, options = {}) {
  return decodeAnonymous049cPacketCandidates821(replay, {...options, includeSlotSiblings:true});
}
module.exports = { ANONYMOUS_049C_PACKET_821_PROFILE, SPELL_SLOT_CHANGE_REQUEST_821_PROFILE,
  decodeAnonymous049cPacketCandidates821, decodeSpellSlotChangeRequestCandidates821, callbackRequestError,
  isObservedSlotChangeShape821 };
