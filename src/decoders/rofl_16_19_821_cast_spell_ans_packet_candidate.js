'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { runtimeByteLookupTable821 } = require('./rofl_16_19_821_runtime_bytes');
const { BATCH_SIZE: V9_BATCH_SIZE, DIGEST_SCHEMA: V9_DIGEST_SCHEMA,
  batchDigest: v9BatchDigest, replayDigestStart: v9ReplayDigestStart,
  replayDigestBatch: v9ReplayDigestBatch } =
  require('./rofl_16_19_821_cast_spell_ans_native_digest');

const REPLAY_VERSION = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const CALLBACK_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const NESTED_U32_TRANSFORM_SHA256 = '5b858c9ef8d1393d05d867112316c3344ff777044719d839ad8cd64867d7f537';
const NESTED_U32_0X4C_TRANSFORM_SHA256 = 'ad5ff48a6d097a43b6880bcafd30d0f8ef7f30f3988c049e1add1261f626eb4c';
const NESTED_F32_0XA0_TRANSFORM_SHA256 = '38b9182f05f84284e1e6b877971aa4401ac0c3c3d98ea7f90f4768d90e1388ca';
const NESTED_F32_0XA0_INVERSE_SHA256 = '682d276b04d72c6400afd3e39c36074ece86577d5431950ff228c3faada64324';
const NESTED_U32_0X28_TRANSFORM_SHA256 = '8aa1a1d1b3c61b2717fbf3b7349dcc659f21d91cd0fe98404e4dc6b700214cb5';
const NESTED_U32_0X28_INVERSE_SHA256 = '442516bee22a1147d65334928ed5300c815deeab1ac6c92002960045590a4e71';
const NESTED_FLOAT_INVERSE_SHA256 = 'cce644f3775d31b6be55e5abc79ed029298be5110b8f81be8957bd3b066019f5';
const NESTED_BYTE_INVERSE_SHA256 = 'b5d220967c423848c278651d068786e3aaedf4994c6d30dd1d3d0c8fe6892516';
const PACKET_ID = 0x01da;
const CAPABILITY = 'cast_spell_ans_packet';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_BATCH_PACKETS = 8192;
const MAX_TOTAL_PACKETS = 100000;
const MAX_REQUEST_BYTES = 4_000_000;
const MIN_OBSERVED_PAYLOAD_BYTES = 97;
const MAX_OBSERVED_PAYLOAD_BYTES = 189;
const OBSERVED_SELECTORS = new Set([0x05, 0x11, 0x15, 0x17, 0x19, 0x1b]);
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V4_ID_821 =
  'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v4';
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_ID_821 =
  'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v5';
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_ID_821 =
  'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v6';
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_ID_821 =
  'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v7';
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_ID_821 =
  'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v8';
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_ID_821 =
  'rofl-16.19.821.7343-kr-cast-spell-ans-packet-runtime-candidate-v9';

const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V4_ID_821,
  replay_version: REPLAY_VERSION,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_NPC_CastSpellAns_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
  evidence_nested_float_inverse_sha256: NESTED_FLOAT_INVERSE_SHA256,
  evidence_nested_byte_inverse_sha256: NESTED_BYTE_INVERSE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'exact 821 native constructor/deserializer fully consumed 63496 route packets from 11 KR Replays; packet +0x148/+0x14c and nested +0xd0/+0x130/+0x14 callback fields remain opaque',
  known_limits: Object.freeze([
    'The packet class name does not prove a successful spell cast.',
    'Spell identity, slot, owner, target, cast action and gameplay meaning are unavailable.',
    'The nested float has no established position, timing or action meaning.',
    'The nested byte has no established spell, owner or action meaning.',
    'The nested +0x14 callback bit field has no established gameplay meaning.',
    'Only observed 821 packet selectors, payload lengths and stream tags are accepted.',
    'The pinned exact-build mapped runtime image and Python Unicorn are required.',
  ]),
});
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821 = Object.freeze({
  ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821,
  id: CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_ID_821,
  evidence_nested_u32_transform_sha256: NESTED_U32_TRANSFORM_SHA256,
  evidence_scope: '63496/63496 exact 821 CastSpellAns route packets in 11 original KR Replays natively fully consumed with protected +0x1c callback u32 and raw provenance',
  known_limits: Object.freeze([
    ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821.known_limits,
    'The nested +0x0c callback u32 is anonymous; its value proves no caster, spell, target or action.',
  ]),
});
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821 = Object.freeze({
  ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821,
  id: CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_ID_821,
  evidence_nested_u32_0x4c_transform_sha256: NESTED_U32_0X4C_TRANSFORM_SHA256,
  evidence_scope: '63496/63496 exact 821 native CastSpellAns packets in 11 original KR Replays fully consumed; V6 retains V5 fields and adds protected packet +0x4c anonymous callback u32',
  known_limits: Object.freeze([
    ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821.known_limits,
    'The nested +0x3c callback u32 is anonymous; its value proves no caster, spell, target or action.',
  ]),
});
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_821 = Object.freeze({
  ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821,
  id: CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_ID_821,
  evidence_nested_f32_0xa0_transform_sha256: NESTED_F32_0XA0_TRANSFORM_SHA256,
  evidence_nested_f32_0xa0_inverse_sha256: NESTED_F32_0XA0_INVERSE_SHA256,
  evidence_scope: '63496/63496 exact 821 CastSpellAns packets in 11 original KR Replays fully deserialized; exact image callback reads protected nested +0x90 and converts it for temporary +0x9c; V7 retains V5/V6 fields',
  known_limits: Object.freeze([
    ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821.known_limits,
    'The nested +0x90 callback f32 is anonymous; it proves no spell, actor, position, timing, or gameplay effect.',
    'Per-packet callback execution and its receiver state were not observed.',
  ]),
});
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_821 = Object.freeze({
  ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_821,
  id: CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_ID_821,
  evidence_nested_u32_0x28_transform_sha256: NESTED_U32_0X28_TRANSFORM_SHA256,
  evidence_nested_u32_0x28_inverse_sha256: NESTED_U32_0X28_INVERSE_SHA256,
  evidence_scope: '63496/63496 exact 821 CastSpellAns packets from 11 source-hash-matched KR Replays fully deserialized; callback converts packet +0x28 to an anonymous conditional runtime-tree lookup key; V8 retains V5/V6/V7 fields',
  known_limits: Object.freeze([
    ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_821.known_limits,
    'The packet +0x28 lookup key does not establish a lookup hit, receiver, actor, spell or cast effect.',
  ]),
});
const CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_821 = Object.freeze({
  ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_821,
  id: CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_ID_821,
  evidence_native_output_digest_schema: V9_DIGEST_SCHEMA,
  evidence_scope: 'exact 821 V8 packet fields plus native-produced ordered output digest bound to persisted native-derived fields, raw parameter, payload length and payload SHA; packet positions and receiver-tree result remain outside this witness',
  known_limits: Object.freeze([
    ...CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_821.known_limits,
    'The ordered digest binds persisted native packet fields, not receiver-tree lookup results or gameplay effects.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function ror8(value, count) {
  return ((value >>> count) | (value << (8 - count))) & 0xff;
}

function rol8(value, count) {
  return ((value << count) | (value >>> (8 - count))) & 0xff;
}

function swap(value) {
  return (((value & 0xd5) << 1) | ((value >>> 1) & 0x55)) & 0xff;
}

// Pin the exact 821 nested deserializer byte path at RVA 0x10bec00..0x10bec19.
const NESTED_FLOAT_INVERSE = (() => {
  const inverse = Buffer.alloc(256);
  const seen = new Set();
  for (let byte = 0; byte < 256; byte += 1) {
    const encoded = (swap(ror8((byte - 0x73) & 0xff, 2)) + 0x6c) & 0xff;
    inverse[encoded] = byte;
    seen.add(encoded);
  }
  if (seen.size !== 256 || sha256(inverse) !== NESTED_FLOAT_INVERSE_SHA256) {
    throw new Error('exact 821 nested float inverse differs');
  }
  return inverse;
})();

// Pin the exact 821 trailing nested byte path at RVA 0x10bf400..0x10bf422.
const NESTED_BYTE_INVERSE = (() => {
  const inverse = Buffer.alloc(256);
  const seen = new Set();
  for (let byte = 0; byte < 256; byte += 1) {
    let encoded = ror8((byte + 0x78) & 0xff, 7);
    encoded = (~((encoded + 0x44) & 0xff)) & 0xff;
    encoded = swap((ror8(encoded, 6) - 0x13) & 0xff);
    inverse[encoded] = byte;
    seen.add(encoded);
  }
  if (seen.size !== 256 || sha256(inverse) !== NESTED_BYTE_INVERSE_SHA256) {
    throw new Error('exact 821 nested byte inverse differs');
  }
  return inverse;
})();

function decodeNestedByte(rawHex) {
  if (!/^[0-9a-f]{2}$/.test(rawHex)) return null;
  return NESTED_BYTE_INVERSE[Number.parseInt(rawHex, 16)];
}

function decodeNestedFloat(rawHex) {
  const raw = Buffer.from(rawHex, 'hex');
  if (raw.length !== 4) return null;
  const bytes = Buffer.from(raw.map((value) => NESTED_FLOAT_INVERSE[value]));
  const value = bytes.readFloatLE(0);
  return Number.isFinite(value) ? value : null;
}

function decodeNestedBits(rawHex) {
  if (!/^[0-9a-f]{2}$/.test(rawHex)) return null;
  // Exact 821 callback conversion at RVA 0x8d7eb9..0x8d7f26.
  const value = swap(Number.parseInt(rawHex, 16));
  return ((((value - 0x54) & 0xff) ^ 0xcc) + 0x48) & 0xff;
}

// The callback at RVA 0x8d77ed..0x8d785a reads nested +0x0c (packet +0x1c)
// and writes its converted u32 to a temporary object at +0xa8. The image's
// r15-relative table copy at RVA 0x1b41db0 equals the SHA-gated shared table.
const NESTED_U32_CALLBACK_TABLE = runtimeByteLookupTable821();
const NESTED_U32_TRANSFORM = Buffer.from(Array.from({ length: 256 }, (_, byte) => {
  const looked = NESTED_U32_CALLBACK_TABLE[rol8(NESTED_U32_CALLBACK_TABLE[byte], 2)];
  return NESTED_U32_CALLBACK_TABLE[rol8((~((looked + 0x48) & 0xff)) & 0xff, 3)];
}));
if (new Set(NESTED_U32_TRANSFORM).size !== 256
    || sha256(NESTED_U32_TRANSFORM) !== NESTED_U32_TRANSFORM_SHA256) {
  throw new Error('exact 821 CastSpellAns nested u32 transform differs');
}

function decodeCastSpellAnsNestedU32FromRaw821(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  return Buffer.from(Buffer.from(rawHex, 'hex').map(
    (byte) => NESTED_U32_TRANSFORM[byte])).readUInt32LE(0);
}

// The callback at RVA 0x8d7860..0x8d78cb reads nested +0x3c (packet +0x4c)
// and writes its converted u32 to temporary +0xac. The nested deserializer
// protects the same word at RVA 0x10bb405..0x10bb744 with the inverse table.
const NESTED_U32_AT_4C_TRANSFORM = Buffer.from(Array.from({ length: 256 }, (_, byte) => {
  let value = swap(byte);
  value = swap((~value) & 0xff);
  value = swap((value + 0x30) & 0xff);
  return NESTED_U32_CALLBACK_TABLE[value];
}));
if (new Set(NESTED_U32_AT_4C_TRANSFORM).size !== 256
    || sha256(NESTED_U32_AT_4C_TRANSFORM) !== NESTED_U32_0X4C_TRANSFORM_SHA256) {
  throw new Error('exact 821 CastSpellAns nested +0x4c u32 transform differs');
}

function decodeCastSpellAnsNestedU32At4cFromRaw821(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  return Buffer.from(Buffer.from(rawHex, 'hex').map(
    (byte) => NESTED_U32_AT_4C_TRANSFORM[byte])).readUInt32LE(0);
}

// The nested deserializer at RVA 0x10bd7d4..0x10bd991 protects nested +0x90
// (packet object +0xa0). The callback at RVA 0x8d76da..0x8d7710 converts
// its four bytes directly to temporary +0x9c, without a receiver-heap lookup.
const NESTED_F32_AT_A0_TRANSFORM = Buffer.from(Array.from({ length: 256 }, (_, byte) =>
  (0x65 - (NESTED_U32_CALLBACK_TABLE[byte] ^ 0x2b)) & 0xff));
const NESTED_F32_AT_A0_INVERSE = Buffer.alloc(256);
for (let byte = 0; byte < 256; byte += 1) {
  NESTED_F32_AT_A0_INVERSE[NESTED_F32_AT_A0_TRANSFORM[byte]] = byte;
}
if (new Set(NESTED_F32_AT_A0_TRANSFORM).size !== 256
    || sha256(NESTED_F32_AT_A0_TRANSFORM) !== NESTED_F32_0XA0_TRANSFORM_SHA256
    || sha256(NESTED_F32_AT_A0_INVERSE) !== NESTED_F32_0XA0_INVERSE_SHA256) {
  throw new Error('exact 821 CastSpellAns nested +0xa0 f32 transform differs');
}

function decodeCastSpellAnsNestedF32AtA0FromRaw821(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  const raw = Buffer.from(rawHex, 'hex');
  const value = Buffer.from(raw.map((byte) => NESTED_F32_AT_A0_TRANSFORM[byte]))
    .readFloatLE(0);
  return Number.isFinite(value) ? value : null;
}

// Exact 821 callback RVA 0x8d75b3..0x8d75f5 converts nested +0x18
// (packet object +0x28). The decoded u32 is only a key for the conditional
// runtime-tree lookup at RVA 0x8d86c2..0x8d875a; the live heap is absent.
const NESTED_U32_AT_28_TRANSFORM = Buffer.from(Array.from({ length: 256 }, (_, byte) => {
  const value = ror8((swap(byte) + 0x68) & 0xff, 6);
  return (ror8((~value) & 0xff, 6) - 2) & 0xff;
}));
const NESTED_U32_AT_28_INVERSE = Buffer.from(Array.from({ length: 256 }, (_, byte) => {
  let value = ror8((byte + 2) & 0xff, 2);
  value = ror8((~value) & 0xff, 2);
  return swap((value - 0x68) & 0xff);
}));
if (new Set(NESTED_U32_AT_28_TRANSFORM).size !== 256
    || new Set(NESTED_U32_AT_28_INVERSE).size !== 256
    || sha256(NESTED_U32_AT_28_TRANSFORM) !== NESTED_U32_0X28_TRANSFORM_SHA256
    || sha256(NESTED_U32_AT_28_INVERSE) !== NESTED_U32_0X28_INVERSE_SHA256
    || NESTED_U32_AT_28_TRANSFORM.some((value, byte) =>
      NESTED_U32_AT_28_INVERSE[value] !== byte)) {
  throw new Error('exact 821 CastSpellAns nested +0x28 u32 transform differs');
}

function decodeCastSpellAnsNestedU32At28FromRaw821(rawHex) {
  if (typeof rawHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawHex)) return null;
  return Buffer.from(Buffer.from(rawHex, 'hex').map(
    (byte) => NESTED_U32_AT_28_TRANSFORM[byte])).readUInt32LE(0);
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
  const walked = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== PACKET_ID) return;
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
  return { rows, scanned_block_count: walked.block_count };
}

function decodeCastSpellAnsPacketCandidates821(replay, {
  runtimeImagePath, pythonExecutable, precollected, castPacketProfile = 'v4',
} = {}) {
  const useV9 = castPacketProfile === 'v9';
  const useV8 = castPacketProfile === 'v8' || useV9;
  const useV7 = castPacketProfile === 'v7' || useV8;
  const includeV6 = castPacketProfile === 'v6' || useV7;
  const includeV5 = castPacketProfile === 'v5' || includeV6;
  const profile = useV9 ? CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_821
    : useV8 ? CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_821
    : useV7 ? CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_821
    : includeV6 ? CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821
    : includeV5 ? CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821
      : CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_callback_table_sha256: CALLBACK_TABLE_SHA256,
    evidence_nested_float_inverse_sha256: NESTED_FLOAT_INVERSE_SHA256,
    evidence_nested_byte_inverse_sha256: NESTED_BYTE_INVERSE_SHA256,
    ...(includeV5 ? { evidence_nested_u32_transform_sha256: NESTED_U32_TRANSFORM_SHA256 } : {}),
    ...(includeV6 ? { evidence_nested_u32_0x4c_transform_sha256:
      NESTED_U32_0X4C_TRANSFORM_SHA256 } : {}),
    ...(useV7 ? {
      evidence_nested_f32_0xa0_transform_sha256: NESTED_F32_0XA0_TRANSFORM_SHA256,
      evidence_nested_f32_0xa0_inverse_sha256: NESTED_F32_0XA0_INVERSE_SHA256,
    } : {}),
    ...(useV8 ? {
      evidence_nested_u32_0x28_transform_sha256: NESTED_U32_0X28_TRANSFORM_SHA256,
      evidence_nested_u32_0x28_inverse_sha256: NESTED_U32_0X28_INVERSE_SHA256,
    } : {}),
    ...(useV9 ? { evidence_native_output_digest_schema: V9_DIGEST_SCHEMA } : {}),
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (castPacketProfile !== 'v4' && !includeV5) {
    return fail('UNSUPPORTED', 'CastSpellAns packet profile must be v4, v5, v6, v7, v8 or v9');
  }
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `cast packet candidate supports only ${REPLAY_VERSION}`);
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
  if (rows.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x01da CastSpellAns route is absent', {
      observed_raw_route_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  const inputCount = rows.length;
  const failed = (status, error, extra = {}) => fail(status, error, {
    input_count: inputCount, scanned_block_count: scannedBlockCount, ...extra,
  });
  if (inputCount > MAX_TOTAL_PACKETS) {
    return failed('UNSUPPORTED', `cast runtime input exceeds ${MAX_TOTAL_PACKETS} packets`);
  }
  for (const { block, chunk } of rows) {
    const param = block.param >>> 0;
    if (![1, 2].includes(chunk.stream_tag) || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload) || block.payload_length !== block.payload.length
        || !Number.isSafeInteger(block.timestamp_ms) || param === 0) {
      return failed('DECODE_FAILED', '0x01da packet framing differs from observed KR scope', {
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (block.payload_length < MIN_OBSERVED_PAYLOAD_BYTES
        || block.payload_length > MAX_OBSERVED_PAYLOAD_BYTES
        || !OBSERVED_SELECTORS.has(block.payload[0])) {
      return failed('DECODE_FAILED', '0x01da payload differs from observed KR scope', {
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
    'decode_cast_spell_ans_packet_16_19_821.py');
  const events = [];
  const v9ReplayHash = useV9 ? v9ReplayDigestStart(replay.source_sha256) : null;
  if (V9_BATCH_SIZE !== MAX_BATCH_PACKETS) {
    throw new Error('Cast V9 digest batch size differs from native batch size');
  }
  for (let start = 0; start < rows.length; start += MAX_BATCH_PACKETS) {
    const batch = rows.slice(start, start + MAX_BATCH_PACKETS);
    const request = JSON.stringify({
      replay_version: REPLAY_VERSION,
      packets: batch.map(({ block }) => ({
        raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
      })),
    });
    if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
      return failed('UNSUPPORTED', 'cast runtime request exceeds bounded input size', {
        runtime_image_used: start > 0,
      });
    }
    const nativeArgs = ['-B', script, '--image', imagePath];
    if (includeV5) nativeArgs.push('--nested-u32-0x1c');
    if (includeV6) nativeArgs.push('--nested-u32-0x4c');
    if (useV7) nativeArgs.push('--nested-f32-0xa0');
    if (useV8) nativeArgs.push('--nested-u32-0x28');
    if (useV9) nativeArgs.push('--native-output-digest-v9');
    const run = childProcess.spawnSync(python, nativeArgs, {
      input: request, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 60000,
    });
    if (run.error || run.status !== 0) {
      const detail = String(run.error?.message || run.stderr || run.stdout
        || `Python exited ${run.status}`).trim();
      const missingPython = run.error?.code === 'ENOENT'
        || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
      const wrongImage = /runtime image SHA-256 mismatch|record transform table differs|callback transform table differs/i.test(detail);
      return failed(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
        `exact runtime cast packet decoder failed: ${detail}`, {
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
      return failed('DECODE_FAILED', `runtime cast output is not JSON: ${error.message}`, {
        runtime_image_used: start > 0,
        runtime_image_status: 'EXECUTION_FAILED',
      });
    }
    if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
        || decoded.callback_table_sha256 !== CALLBACK_TABLE_SHA256
        || decoded.nested_float_inverse_sha256 !== NESTED_FLOAT_INVERSE_SHA256
        || decoded.nested_byte_inverse_sha256 !== NESTED_BYTE_INVERSE_SHA256
        || (includeV5 && decoded.nested_u32_transform_sha256 !== NESTED_U32_TRANSFORM_SHA256)
        || (includeV6 && decoded.nested_u32_0x4c_transform_sha256
          !== NESTED_U32_0X4C_TRANSFORM_SHA256)
        || (useV7 && (decoded.nested_f32_0xa0_transform_sha256
          !== NESTED_F32_0XA0_TRANSFORM_SHA256
          || decoded.nested_f32_0xa0_inverse_sha256
          !== NESTED_F32_0XA0_INVERSE_SHA256))
        || (useV8 && (decoded.nested_u32_0x28_transform_sha256
          !== NESTED_U32_0X28_TRANSFORM_SHA256
          || decoded.nested_u32_0x28_inverse_sha256
          !== NESTED_U32_0X28_INVERSE_SHA256))
        || (useV9 && (decoded.native_output_digest_schema !== V9_DIGEST_SCHEMA
          || !/^[0-9a-f]{64}$/.test(decoded.native_output_sha256 ?? '')))
        || !Array.isArray(decoded.results) || decoded.results.length !== batch.length) {
      return failed('DECODE_FAILED', 'runtime cast output identity or packet count differs', {
        runtime_image_used: start > 0,
        runtime_image_status: 'EXECUTION_FAILED',
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
          || !/^[0-9a-f]{2}$/.test(row.raw_flag_byte_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_i32_bytes_hex)
          || !/^[0-9a-f]{8}$/.test(row.raw_f32_bytes_hex)
          || !/^[0-9a-f]{2}$/.test(row.raw_u8_0x140_hex)
          || !/^[0-9a-f]{2}$/.test(row.raw_nested_bits_0x24_hex)
          || ![0, 1].includes(row.opaque_flag_0x148)
          || !Number.isInteger(row.opaque_i32_0x14c)
          || row.opaque_i32_0x14c < -0x80000000
          || row.opaque_i32_0x14c > 0x7fffffff
          || typeof row.opaque_f32_0xe0 !== 'number'
          || !Number.isFinite(row.opaque_f32_0xe0)
          || !Object.is(row.opaque_f32_0xe0, decodeNestedFloat(row.raw_f32_bytes_hex))
          || !Number.isInteger(row.opaque_u8_0x140)
          || row.opaque_u8_0x140 !== decodeNestedByte(row.raw_u8_0x140_hex)
          || !Number.isInteger(row.opaque_nested_bits_0x24)
          || row.opaque_nested_bits_0x24 !== decodeNestedBits(row.raw_nested_bits_0x24_hex)
          || (includeV5 && (typeof row.raw_u32_0x1c_hex !== 'string'
            || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x1c_hex)
            || !Number.isInteger(row.opaque_u32_0x1c)
            || row.opaque_u32_0x1c < 0 || row.opaque_u32_0x1c > 0xffffffff
            || row.opaque_u32_0x1c !== decodeCastSpellAnsNestedU32FromRaw821(
              row.raw_u32_0x1c_hex)))
          || (includeV6 && (typeof row.raw_u32_0x4c_hex !== 'string'
            || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x4c_hex)
            || !Number.isInteger(row.opaque_u32_0x4c)
            || row.opaque_u32_0x4c < 0 || row.opaque_u32_0x4c > 0xffffffff
            || row.opaque_u32_0x4c !== decodeCastSpellAnsNestedU32At4cFromRaw821(
              row.raw_u32_0x4c_hex)))
          || (useV7 && (typeof row.raw_f32_0xa0_hex !== 'string'
            || !/^[0-9a-f]{8}$/.test(row.raw_f32_0xa0_hex)
            || typeof row.opaque_f32_0xa0 !== 'number'
            || !Number.isFinite(row.opaque_f32_0xa0)
            || !Object.is(row.opaque_f32_0xa0,
              decodeCastSpellAnsNestedF32AtA0FromRaw821(row.raw_f32_0xa0_hex))))
          || (useV8 && (typeof row.raw_u32_0x28_hex !== 'string'
            || !/^[0-9a-f]{8}$/.test(row.raw_u32_0x28_hex)
            || !Number.isInteger(row.opaque_u32_0x28)
            || row.opaque_u32_0x28 < 0 || row.opaque_u32_0x28 > 0xffffffff
            || row.opaque_u32_0x28 !== decodeCastSpellAnsNestedU32At28FromRaw821(
              row.raw_u32_0x28_hex)))) {
        return failed('DECODE_FAILED', `runtime cast packet ${start + index} did not fully decode`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256, first_failed_packet_ref: ref,
          runtime_packet_result: row ?? null,
        });
      }
      events.push({
        event_type: 'NPC_CAST_SPELL_ANS_PACKET_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: block.timestamp_ms,
        raw_param: ref.raw_param,
        opaque_flag_0x148: row.opaque_flag_0x148,
        opaque_i32_0x14c: row.opaque_i32_0x14c,
        raw_f32_0xe0_bytes_hex: row.raw_f32_bytes_hex,
        opaque_f32_0xe0: row.opaque_f32_0xe0,
        raw_u8_0x140_hex: row.raw_u8_0x140_hex,
        opaque_u8_0x140: row.opaque_u8_0x140,
        raw_nested_bits_0x24_hex: row.raw_nested_bits_0x24_hex,
        opaque_nested_bits_0x24: row.opaque_nested_bits_0x24,
        ...(includeV5 ? { raw_u32_0x1c_hex: row.raw_u32_0x1c_hex,
          opaque_u32_0x1c: row.opaque_u32_0x1c } : {}),
        ...(includeV6 ? { raw_u32_0x4c_hex: row.raw_u32_0x4c_hex,
          opaque_u32_0x4c: row.opaque_u32_0x4c } : {}),
        ...(useV7 ? { raw_f32_0xa0_bytes_hex: row.raw_f32_0xa0_hex,
          opaque_f32_0xa0: row.opaque_f32_0xa0 } : {}),
        ...(useV8 ? { raw_u32_0x28_hex: row.raw_u32_0x28_hex,
          opaque_u32_0x28: row.opaque_u32_0x28,
          callback_tree_lookup_status: 'UNKNOWN' } : {}),
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
        raw_packet_ref: ref,
      });
    }
    if (useV9) {
      const outputSha = v9BatchDigest(decoded.results);
      if (decoded.native_output_sha256 !== outputSha) {
        return failed('DECODE_FAILED', `runtime cast V9 batch ${start} native output digest differs`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: IMAGE_SHA256,
        });
      }
      v9ReplayDigestBatch(v9ReplayHash, start, batch.length, outputSha);
    }
  }
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scannedBlockCount,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256,
    ...(useV9 ? { native_output_sha256: v9ReplayHash.digest('hex'),
      native_output_batch_size: V9_BATCH_SIZE } : {}),
    events,
  };
}

module.exports = {
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V4_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_821,
  decodeNestedBits,
  decodeNestedByte,
  decodeNestedFloat,
  decodeCastSpellAnsNestedU32FromRaw821,
  decodeCastSpellAnsNestedU32At4cFromRaw821,
  decodeCastSpellAnsNestedF32AtA0FromRaw821,
  decodeCastSpellAnsNestedU32At28FromRaw821,
  decodeCastSpellAnsPacketCandidates821,
};
