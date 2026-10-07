'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { runtimeByteLookupTable821 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'unit_apply_damage_packet';
const PACKET_ID = 0x005f;
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE_SIZE = 48_488_448;
const MAX_IMAGE_SIZE = 64 * 1024 * 1024;
const MAX_TOTAL_PACKETS = 100_000;
const TABLE_RVA = 0x1ab62d0;
const TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const CALLBACK_U32_0X10_TABLE_SHA256 =
  'd347ff60e28a7757cc3858fd550e5ced34e0ffccdfd5400248ae547b96e76453';
const CALLBACK_U32_0X1C_TABLE_SHA256 =
  '5acd891ce46e85484de06fa22f6cece25e6bfcc4c258094863c98d225ea3dc18';
const CALLBACK_F32_0X18_TABLE_SHA256 =
  '2a45ee14ca77f364f9f662dada6377ed01ef9e2e3b8fb074ee0c5ee3ae7d6d3d';
const LOOKUP_KEY_0X24_TABLE_SHA256 =
  'fdc699513c7ecb8b85f86b8420a6eb3d0a90005495c0ce2a5d19bdeb2be5fa1f';
const LOOKUP_KEY_0X2C_TABLE_SHA256 =
  'dde1767c7329b3624d423418742a52991a43e357a75a426c9d895e0d4d1b8eb1';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_821_UNIT_APPLY_DAMAGE_PACKET_FIELDS';
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821 =
  'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v1';
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821 =
  'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v2';
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821 =
  'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v3';
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821 =
  'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v4';
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V5_ID_821 =
  'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v5';
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_ID_821 =
  'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v6';
const CALLBACK_FLOAT_TABLE = runtimeByteLookupTable821();
// Exact 821 callback helper RVA 0x251be0, executed against the pinned image.
// These bytes decode the protected anonymous f32 at object offset +0x18.
const CALLBACK_F32_0X18_TABLE = Buffer.from([
  'd75382d986029e2c741024656ddac27f8fd62b4514973fb301277b704f171669',
  '4bd2e8ec38cc5b3bc5750525305f0baa0f9f1ad1925dea5c7e2edf23e1660055',
  '8bf94cb8e733262df8af13e9d841961d3d409a88fa4ef4cb1b4a4699220cbcb0',
  'dc60b2b57deb8d564283fda5eeb70ec8fefc44768179f7d4f2dd0df1842ade58',
  'ef9cca636f576b07e6ac47b14d203ea8f37172a094e5b65061649018e2b4cfa9',
  '52ba7c34e49dce06375459ab5e6ca4110a8e73db2135c6e331d5858919121ff6',
  'bdfba1eda24809c49b5a78f0390351d0a728ad0436b91c15ff32bfa38aaecdf5',
  '0891be62952f80938749bba67a3c1e8c6ae0c3c76867c9c19877c0436ed33a29',
].join(''), 'hex');
// Exact 821 callback helper RVA 0x251e40, executed against the pinned image.
// The table turns protected object bytes at +0x10 into an anonymous u32.
const CALLBACK_U32_0X10_TABLE = Buffer.from([
  'a6a4c7c5c2c0c3c1cac8dbd9bebcbfbdc6c4d7d5d2d0d3d1dad8bbb9cecccfcd',
  'd6d43735323033313a38ebe92e2c2f2d3634e7e5e2e0e3e1eae8cbc9dedcdfdd',
  'e6e44745424043414a485b593e3c3f3d46445755525053515a583b394e4c4f4d',
  '5654f7f5f2f0f3f1faf86b69eeecefedf6f46765626063616a684b495e5c5f5d',
  '66640705020003010a081b19fefcfffd06041715121013111a18fbf90e0c0f0d',
  '16147775727073717a782b296e6c6f6d76742725222023212a280b091e1c1f1d',
  '26248785828083818a889b997e7c7f7d86849795929093919a987b798e8c8f8d',
  '9694b7b5b2b0b3b1bab8aba9aeacafadb6b4a7a5a2a0a3a1aaa88b899e9c9f9d',
].join(''), 'hex');
// Exact 821 callback byte helpers at RVAs 0x251ba0 and 0x251c30. These
// complete 256-byte tables were obtained by executing the pinned image's
// helpers, and are checked independently before any saved-row use.
const LOOKUP_KEY_0X24_TABLE = Buffer.from([
  '14da85b179222a05fbb4e49610ffccebc877e0d06e12a05a4ef427fd18ec6049',
  '54357d5f0eed47c730408ea58f4fd82f5616ddf7591a7bae92ea6a872cc37186',
  'e5254842ca1c4b19a40088368bd78a78b55defcb159edf635328e7520306a399',
  'd21362f1c950b63f585bd3ced41d260d617e64b2685590db4311f3d9693a04c6',
  'fc0f31bbde325ec16d749baf3d98839f0295d6c023bf386fe8174cb9a176e92e',
  'f93bad0893a78029ba7ca29d8121aa41fe9a73bc51c56b077039d1be67d5b882',
  'ac09bd5c45f6b7abe1f5a6656c1ef02beee62d3c343e2072f2758db0570c8946',
  'e3cfb3a9cdc47a84e21b24c2010a334a9cfa974da8667f0b91f88cdc941f3744',
].join(''), 'hex');
const LOOKUP_KEY_0X2C_TABLE = Buffer.from([
  '195685bb00770f43d8ad947beb23654b2e68c8c6efd7d5550e0a8b8335b07eec',
  '4d8905ab3f8ae2db1c748f70c9e0f8a2da649fd2e11e4411989106b7a40cddb8',
  '457a844e03a7719e123926503c08485bc337b5157f978129dc5861ae098e9b95',
  'b48762a8a6a5ed4a6967f4b654c53404736c8c53880166906de3ba51c1ee3322',
  'b11747994c6a93ce28809a2da15df1b91d27fa2549c4a95c6b3663d6426e5e78',
  '72f0aa592b0daff775cf2cbcb2cb9df97d2abef3de31df6f078dd4d0d1f5d92f',
  'bde94f40e7cdb3ea30862132e6c75f161aac3813ffd314603efde8107ccc5aa0',
  'f6fc1f96fb46241bc0799282413a9c18f2e552bf3d0bfe57a376e40220ca3bc2',
].join(''), 'hex');
const LOOKUP_KEY_RELATIONS = Object.freeze([
  'EQUAL', 'RAW_PARAM_IS_LOOKUP_PLUS_0X100', 'OTHER',
]);
const NATIVE_FLOAT_SOURCES = Object.freeze([
  'RAW_READER', 'CONSTANT_0', 'CONSTANT_1', 'CONSTANT_2',
]);
const NATIVE_U32_0X10_SOURCES = Object.freeze(['RAW_READER', 'CONSTANT_0']);
const NATIVE_U32_0X1C_SOURCES = Object.freeze(['RAW_READER', 'CONSTANT_0']);
const U32_0X1C_RAW_CALL_RVA_BY_SELECTOR = Object.freeze({
  1: '0xf4a5cd', 2: '0xf4a742', 3: '0xf4a6b1',
  4: '0xf4a6fe', 5: '0xf4a661', 7: '0xf4a611',
});
const NATIVE_F32_0X18_SOURCES = Object.freeze(['RAW_READER', 'CONSTANT_0']);
const F32_0X18_RAW_SELECTORS = Object.freeze([0, 2, 3, 6]);
const F32_0X18_CONSTANT_ZERO_SELECTOR = 5;
const NATIVE_FLOAT_CONSTANTS = Object.freeze({
  3: Object.freeze({ source: 'CONSTANT_0', value: 0 }),
  5: Object.freeze({ source: 'CONSTANT_1', value: 1 }),
  7: Object.freeze({ source: 'CONSTANT_2', value: 2 }),
});

// Bit i encodes an observed (payload length 8..25, selector bits 24..26,
// selector bits 0..2, selector bits 3..5) tuple from the 11 exact-build KR
// Replays. The third selector steers the callback float deserializer. This
// is only an early rejection filter: a same-tuple byte change can alter a
// variable-length native read, so every selected packet is also natively
// checked for full consumption below.
const OBSERVED_SHAPES = Buffer.from(
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAggAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAIIAAIIAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAKCgCKAAAKAAAAAIAAAAAAAAAAgAAAgAAAAgCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCAACAAAAAAAAAAAAACAgACAAACAAAAACAAACAAAoKAIoAAIoACgoAigAAigAAAAAAAAAAAAAAAAAAAAAACgoAigAAigAAAAAAAAAAAAVVUAVQAAVQCgoAigAAigAKCgCKAACKAAoKAIoAAIoAAAAAAAAAAAAAAAAAAAAAAAoKAIoAAIoAAAAAAAAAAAAFVVAFUAAFUAoKAIoAAIoACgoACgAAigAKCgAKAACKAAAAAAAAAAAAAAAAAAAAAAAKCgAKAACKAAAAAAAAAAAABVVQBVAABVAKCgAKAACKAA1dUA1QAA1QDV1QBVAADVAAAAAAAAAAAAAAAAAAAAAABV1QDVAADVAAAAAAAAAAAAVVUAVQAAVQBVdQDVAABVAFVVAFUAAFUAVVUAVQAAVQAAAAAAAAAAAAAAAAAAAAAAVVUAVQAAVQAAAAAAAAAAAAFAAEAAAEAAVVUAVQAAVQB19QB1AAD1AHV1APUAAPUAAAAAAAAAAAAAAAAAAAAAAHV1AHUAAPUAAAAAAAAAAAAAAAABAAAQAPX1APUAAFUAVVUAVQAAVQBVVQBVAABVAAAAAAAAAAAAAAAAAAAAAABVVQBVAABVAAAAAAAAAAAAAAAAAAAAAABVVQBVAABVAFVVAFUAAFUAVVUAVQAAVQAAAAAAAAAAAAAAAAAAAAAAVVUAVQAAVQAAAAAAAAAAAAAAAAAAAAAAVVUAVQAAVQBVVQBVAABVAFVVAFUAAFUAAAAAAAAAAAAAAAAAAAAAAFVVAFUAAFUAAAAAAAAAAAAAAAAAAAAAAFVVAFUAAFUAVVUAVQAAVQBVVQBVAABVAAAAAAAAAAAAAAAAAAAAAABVVQBVAABVAAAAAAAAAAAAAAAAAAAAAABVVQBVAABVABBAAAAAAAAAQAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAQAAAAAAAAAAAAAAAAAAAAAAQQEAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAAQAAAQAABABFAAAAAAAAAAAAAAAAAAAAAAAAAAAEQAABAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB',
  'base64',
);
const SHAPES_SHA256 = 'd526eddcde8101c035b62b11faa0f619d4d6a1648423a5605ba9be65757d9c93';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

if (OBSERVED_SHAPES.length !== 1152 || sha256(OBSERVED_SHAPES) !== SHAPES_SHA256) {
  throw new Error('exact 821 UnitApplyDamage shape catalog differs');
}
if (LOOKUP_KEY_0X24_TABLE.length !== 256 || LOOKUP_KEY_0X2C_TABLE.length !== 256
    || new Set(LOOKUP_KEY_0X24_TABLE).size !== 256
    || new Set(LOOKUP_KEY_0X2C_TABLE).size !== 256
    || sha256(LOOKUP_KEY_0X24_TABLE) !== LOOKUP_KEY_0X24_TABLE_SHA256
    || sha256(LOOKUP_KEY_0X2C_TABLE) !== LOOKUP_KEY_0X2C_TABLE_SHA256) {
  throw new Error('exact 821 UnitApplyDamage callback lookup tables differ');
}
if (CALLBACK_U32_0X10_TABLE.length !== 256
    || new Set(CALLBACK_U32_0X10_TABLE).size !== 256
    || sha256(CALLBACK_U32_0X10_TABLE) !== CALLBACK_U32_0X10_TABLE_SHA256) {
  throw new Error('exact 821 UnitApplyDamage +0x10 callback table differs');
}
// Exact pinned helper RVA 0x251df0 reverses the deserializer byte transform.
// Generate the complete table from those native instructions, then pin its hash.
const CALLBACK_U32_0X1C_TABLE = Buffer.from(Array.from({ length: 256 }, (_, byte) => {
  const minusSeven = (byte - 7) & 0xff;
  const rotated = ((minusSeven << 1) | (minusSeven >>> 7)) & 0xff;
  return (((rotated - 0x4b) & 0xff) ^ 0xee) - 0x5c & 0xff;
}));
if (new Set(CALLBACK_U32_0X1C_TABLE).size !== 256
    || sha256(CALLBACK_U32_0X1C_TABLE) !== CALLBACK_U32_0X1C_TABLE_SHA256) {
  throw new Error('exact 821 UnitApplyDamage +0x1c callback table differs');
}
if (CALLBACK_F32_0X18_TABLE.length !== 256
    || new Set(CALLBACK_F32_0X18_TABLE).size !== 256
    || sha256(CALLBACK_F32_0X18_TABLE) !== CALLBACK_F32_0X18_TABLE_SHA256) {
  throw new Error('exact 821 UnitApplyDamage +0x18 callback table differs');
}

const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821 = Object.freeze({
  id: UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V5_ID_821,
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  packet_name: 'PKT_UnitApplyDamage_s',
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scalar_table_sha256: TABLE_SHA256,
  evidence_callback_u32_0x10_table_sha256: CALLBACK_U32_0X10_TABLE_SHA256,
  evidence_callback_f32_0x18_table_sha256: CALLBACK_F32_0X18_TABLE_SHA256,
  evidence_lookup_key_0x24_table_sha256: LOOKUP_KEY_0X24_TABLE_SHA256,
  evidence_lookup_key_0x2c_table_sha256: LOOKUP_KEY_0X2C_TABLE_SHA256,
  evidence_shape_catalog_sha256: SHAPES_SHA256,
  evidence_registration_rva: '0x26efbc',
  evidence_callback_rva: '0x2ce150',
  evidence_constructor_rva: '0xecec40',
  evidence_deserializer_rva: '0xf49dd0',
  runtime_image_required: true,
  evidence_scope: '628909/628909 game-stream 0x005f packets in 11 KR Replays natively fully consumed with explicit +0x10, +0x18, +0x20, +0x24, and +0x2c writes; all +0x18 values match the exact pinned callback transform, with 828 raw-reader and 628081 constant-zero branches',
  known_limits: Object.freeze([
    'The packet name and callback-read float do not establish effective damage or health loss.',
    'The +0x24 FLOAT_RECEIVER_LOOKUP_CANDIDATE and +0x2c SECOND_LOOKUP_OBJECT_CANDIDATE are numeric lookup keys, not proof that lookup or runtime type conversion succeeded.',
    'Source, target, actual damage, and health effects remain UNKNOWN; the callback can conditionally add another float to +0x20 before dispatch.',
    'The raw_param relation is local to this packet and must not normalize aliases across other routes.',
    'The legacy callback_f32 fields remain limited to one native-calibrated 15-byte shape; new native_callback_f32 fields cover all accepted rows and label raw-reader or constant-write provenance.',
    'The runtime parser reports three exact header selectors but does not reproduce all native object fields.',
    'The +0x10 callback u32 is anonymous; it does not identify damage type, amount, actor, source, target, or effect.',
    'The +0x18 callback f32 is anonymous and conditionally read by the callback; neither it nor its combination with +0x20 identifies actual damage or a health effect.',
    'Every selected packet needs native full-consumption witness; an unseen shape, excess packet count, wrong image or damaged Replay fails the whole capability.',
  ]),
});
const UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821 = Object.freeze({
  ...UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821,
  id: UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_ID_821,
  evidence_callback_u32_0x1c_table_sha256: CALLBACK_U32_0X1C_TABLE_SHA256,
  evidence_scope: '125182/125182 0x005f packets in two original KR Replays natively fully consumed with exact +0x1c branch/full-write, callback transform and variable-length raw-reader span; selector 6 was absent from all 11 KR inputs',
  known_limits: Object.freeze([
    ...UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821.known_limits,
    'The +0x1c callback u32 is anonymous. Its numeric value, including zero, proves no actor, type, source, target, amount, or gameplay effect.',
    'Selector 6 has an image-level constant 0xffffffff branch but no observed packet in the 11 KR Replays, so V6 rejects that selector.',
    'V6 is an opt-in packet-local decoder; active CLI/API and saved-query profile remain V5 until downstream profiles migrate.',
  ]),
});

function swapBits(byte) {
  return (((byte & 0xd5) << 1) | ((byte >>> 1) & 0x55)) & 0xff;
}

function ror4(byte) {
  return ((byte >>> 4) | (byte << 4)) & 0xff;
}

// Exact 821 callback byte helper at RVA 0x251c60. The final 256-byte table
// is read from the matching mapped image and independently SHA-256 checked.
function decodeCallbackFloatByte(byte, table = CALLBACK_FLOAT_TABLE) {
  return table[swapBits(ror4((swapBits(byte) + 0x64) & 0xff))];
}

// A saved JSONL query can rederive the same packet-local value without an
// image. The table was copied and hash-checked by runtime_bytes.js at load.
function decodeUnitApplyDamageCallbackF32FromRaw821(rawBytesHex) {
  if (typeof rawBytesHex !== 'string' || !/^[0-9a-f]{8}$/.test(rawBytesHex)) return null;
  const raw = Buffer.from(rawBytesHex, 'hex');
  const decoded = Buffer.from(Array.from(raw, (byte) => decodeCallbackFloatByte(byte)));
  const value = decoded.readFloatLE(0);
  return Number.isFinite(value) ? value : null;
}

function decodeUnitApplyDamageCallbackU32FromRaw821(encodedBytesHex) {
  if (typeof encodedBytesHex !== 'string' || !/^[0-9a-f]{8}$/.test(encodedBytesHex)) {
    return null;
  }
  const encoded = Buffer.from(encodedBytesHex, 'hex');
  const decoded = Buffer.from(Array.from(encoded,
    (byte) => CALLBACK_U32_0X10_TABLE[byte]));
  return decoded.readUInt32LE(0);
}

function decodeUnitApplyDamageCallbackU32At1cFromEncoded821(encodedBytesHex) {
  if (typeof encodedBytesHex !== 'string' || !/^[0-9a-f]{8}$/.test(encodedBytesHex)) {
    return null;
  }
  const encoded = Buffer.from(encodedBytesHex, 'hex');
  const decoded = Buffer.from(Array.from(encoded,
    (byte) => CALLBACK_U32_0X1C_TABLE[byte]));
  return decoded.readUInt32LE(0);
}

// Exact 821 reader RVA 0xe81ec0 decodes protected variable-length bytes,
// assembles seven bits per byte, then conditionally toggles bit 30. Only the
// two- and three-byte spans seen in the original KR Replays are supported.
function decodeUnitApplyDamageU32At1cFromRawSpan821(rawBytesHex) {
  if (typeof rawBytesHex !== 'string' || !/^(?:[0-9a-f]{4}|[0-9a-f]{6})$/.test(rawBytesHex)) {
    return null;
  }
  const rawBytes = Buffer.from(rawBytesHex, 'hex');
  let value = 0;
  for (const [index, rawByte] of rawBytes.entries()) {
    const decodedByte = CALLBACK_U32_0X1C_TABLE[rawByte];
    if (Boolean(decodedByte & 0x80) !== (index < rawBytes.length - 1)) return null;
    value |= (decodedByte & 0x7f) << (index * 7);
  }
  if (value & 0xffffff) value ^= 0x40000000;
  return value >>> 0;
}

function checkedNativeU32At1cRow821(row, index, payload) {
  const selector = (payload[1] >>> 4) & 7;
  const callRva = U32_0X1C_RAW_CALL_RVA_BY_SELECTOR[selector] ?? null;
  const source = selector === 0 ? 'CONSTANT_0' : callRva ? 'RAW_READER' : null;
  if (source === null || !Array.isArray(row) || row.length !== 7
      || row[0] !== index || typeof row[1] !== 'string'
      || !/^[0-9a-f]{8}$/.test(row[1])
      || !Number.isSafeInteger(row[2]) || row[2] < 0 || row[2] > 0xffffffff
      || row[3] !== source
      || decodeUnitApplyDamageCallbackU32At1cFromEncoded821(row[1]) !== row[2]) {
    return null;
  }
  if (source === 'CONSTANT_0') {
    return row[1] === '05050505' && row[2] === 0
      && row[4] === null && row[5] === null && row[6] === null
      ? { selector, source, callRva: null, rawOffset: null, rawBytesHex: null }
      : null;
  }
  if (row[4] !== callRva || !Number.isSafeInteger(row[5])
      || row[5] < 0 || typeof row[6] !== 'string'
      || !/^(?:[0-9a-f]{4}|[0-9a-f]{6})$/.test(row[6])
      || row[5] + row[6].length / 2 > payload.length
      || payload.subarray(row[5], row[5] + row[6].length / 2).toString('hex')
        !== row[6]
      || decodeUnitApplyDamageU32At1cFromRawSpan821(row[6]) !== row[2]) {
    return null;
  }
  return { selector, source, callRva, rawOffset: row[5], rawBytesHex: row[6] };
}

function decodeUnitApplyDamageCallbackF32At18FromEncoded821(encodedBytesHex) {
  if (typeof encodedBytesHex !== 'string' || !/^[0-9a-f]{8}$/.test(encodedBytesHex)) {
    return null;
  }
  const encoded = Buffer.from(encodedBytesHex, 'hex');
  const decoded = Buffer.from(Array.from(encoded,
    (byte) => CALLBACK_F32_0X18_TABLE[byte]));
  const value = decoded.readFloatLE(0);
  return Number.isFinite(value) ? value : null;
}

function decodeUnitApplyDamageLookupKeyFromRaw821(encodedBytesHex, objectOffset) {
  const table = objectOffset === 0x24 ? LOOKUP_KEY_0X24_TABLE
    : objectOffset === 0x2c ? LOOKUP_KEY_0X2C_TABLE : null;
  if (!table || typeof encodedBytesHex !== 'string'
      || !/^[0-9a-f]{8}$/.test(encodedBytesHex)) return null;
  const encoded = Buffer.from(encodedBytesHex, 'hex');
  const decoded = Buffer.from(Array.from(encoded, (byte) => table[byte]));
  const value = decoded.readUInt32LE(0);
  return value === 0 ? null : value;
}

function lookupKey24RawParamRelation(rawParam, key24) {
  if (rawParam === key24) return 'EQUAL';
  if (rawParam - key24 === 0x100) return 'RAW_PARAM_IS_LOOKUP_PLUS_0X100';
  return 'OTHER';
}

function shapeTuple(payload) {
  return {
    header_selector_bits_24_26: payload[3] & 7,
    header_selector_bits_0_2: payload[0] & 7,
    header_selector_bits_3_5: (payload[0] >>> 3) & 7,
    header_selector_bits_6_8: ((payload[0] >>> 6) | (payload[1] << 2)) & 7,
  };
}

function isObservedShape(length, selector24, selector0, selector3) {
  if (length < 8 || length > 25) return false;
  const index = (length - 8) * 512 + selector24 * 64 + selector0 * 8 + selector3;
  return Boolean(OBSERVED_SHAPES[index >>> 3] & (1 << (index & 7)));
}

function hasCallbackFloatShape(payload) {
  return payload.length === 15 && (payload[3] & 7) === 6
    && (payload[0] & 7) === 1 && ((payload[0] >>> 3) & 7) === 6;
}

// The digest binds the witness response to the exact ordered Replay rows.
// Each tuple is u32 raw_param LE, u32 byte length LE, then payload bytes.
function nativeInputSha256(rows) {
  const hash = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const { block } of rows) {
    header.writeUInt32LE(block.param >>> 0, 0);
    header.writeUInt32LE(block.payload.length, 4);
    hash.update(header);
    hash.update(block.payload);
  }
  return hash.digest('hex');
}

function packetRef(replay, block, chunk) {
  const payload = Buffer.isBuffer(block.payload) ? block.payload : null;
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
    raw_payload_hex: payload?.toString('hex') ?? null,
    raw_payload_sha256: payload ? sha256(payload) : null,
  };
}

function collectRows(replay, precollected) {
  if (precollected) return rowsFor821Capability(replay, precollected, CAPABILITY);
  const rows = [];
  let observedPacketCount = 0;
  const walked = walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== PACKET_ID) return;
    observedPacketCount += 1;
    if (rows.length >= MAX_TOTAL_PACKETS) return;
    rows.push({
      block: {
        offset: block.offset, payload_offset: block.payload_offset,
        payload_length: block.payload_length, payload: Buffer.from(block.payload),
        timestamp_ms: block.timestamp_ms, packet_id: block.packet_id, param: block.param,
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

function decodeUnitApplyDamagePacketCandidates821WithProfile(replay, profile, {
  runtimeImagePath, pythonExecutable, precollected,
} = {}) {
  const v6 = profile === UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: PACKET_ID,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_scalar_table_sha256: TABLE_SHA256,
    evidence_callback_u32_0x10_table_sha256: CALLBACK_U32_0X10_TABLE_SHA256,
    evidence_callback_f32_0x18_table_sha256: CALLBACK_F32_0X18_TABLE_SHA256,
    ...(v6 ? { evidence_callback_u32_0x1c_table_sha256:
      CALLBACK_U32_0X1C_TABLE_SHA256 } : {}),
    evidence_lookup_key_0x24_table_sha256: LOOKUP_KEY_0X24_TABLE_SHA256,
    evidence_lookup_key_0x2c_table_sha256: LOOKUP_KEY_0X2C_TABLE_SHA256,
    evidence_shape_catalog_sha256: SHAPES_SHA256,
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `UnitApplyDamage packet candidate supports only ${BUILD}`);
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
  const scannedBlockCount = selected.scanned_block_count;
  const observedCount = selected.observed_packet_count_minimum
    ?? selected.observed_packet_count ?? selected.rows?.length;
  if (observedCount > MAX_TOTAL_PACKETS) {
    return fail('UNSUPPORTED', `UnitApplyDamage input exceeds ${MAX_TOTAL_PACKETS} packets`, {
      input_count: observedCount, observed_packet_count_minimum: observedCount,
      scanned_block_count: scannedBlockCount,
    });
  }
  const { rows } = selected;
  if (!Array.isArray(rows) || rows.length !== observedCount) {
    return fail('DECODE_FAILED', '821 UnitApplyDamage route scan returned incomplete packet rows', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
    });
  }
  if (!rows.length) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x005f UnitApplyDamage route is absent', {
      input_count: 0, observed_raw_shape_count: 0, scanned_block_count: scannedBlockCount,
    });
  }
  for (const { block, chunk } of rows) {
    if (chunk.stream_tag !== 1 || chunk.stream !== 'game_chunk'
        || block.packet_id !== PACKET_ID
        || !Buffer.isBuffer(block.payload)
        || block.payload.length !== block.payload_length
        || !Number.isSafeInteger(block.timestamp_ms)
        || !Number.isInteger(block.param) || block.param <= 0 || block.param > 0xffffffff
        || block.payload.length < 8) {
      return fail('DECODE_FAILED', '0x005f framing differs from observed KR scope', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    const selectors = shapeTuple(block.payload);
    if (!isObservedShape(block.payload_length, selectors.header_selector_bits_24_26,
      selectors.header_selector_bits_0_2, selectors.header_selector_bits_3_5)) {
      return fail('DECODE_FAILED', '0x005f payload shape is outside native-witnessed KR scope', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (v6 && ((block.payload[1] >>> 4) & 7) === 6) {
      return fail('DECODE_FAILED', '+0x1c selector 6 is outside observed KR Replay scope', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return fail('MISSING_INPUT', 'exact 16.19.821.7343 mapped runtime image is required', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  let image;
  try {
    const imagePath = path.resolve(runtimeImagePath);
    const stat = fs.statSync(imagePath);
    if (!stat.isFile() || stat.size > MAX_IMAGE_SIZE) throw new Error('not a bounded file');
    image = fs.readFileSync(imagePath);
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const imageSha = sha256(image);
  if (image.length !== IMAGE_SIZE || imageSha !== IMAGE_SHA256) {
    return fail('DECODE_FAILED', 'exact 821 runtime image SHA-256 mismatch', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'HASH_MISMATCH', runtime_image_sha256: imageSha,
    });
  }
  const table = image.subarray(TABLE_RVA, TABLE_RVA + 256);
  if (sha256(table) !== TABLE_SHA256 || !table.equals(CALLBACK_FLOAT_TABLE)) {
    return fail('DECODE_FAILED', 'exact 821 callback table differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'TABLE_MISMATCH', runtime_image_sha256: imageSha,
    });
  }
  const inputSha = nativeInputSha256(rows);
  const nativeRequest = JSON.stringify({
    replay_version: BUILD,
    packet_id: PACKET_ID,
    packets: rows.map(({ block }) => [
      block.param >>> 0, block.payload.toString('hex'), hasCallbackFloatShape(block.payload),
    ]),
  });
  if (Buffer.byteLength(nativeRequest) > 16 * 1024 * 1024) {
    return fail('UNSUPPORTED', '0x005f native witness request exceeds 16 MiB', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    });
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_unit_apply_damage_packet_16_19_821.py');
  const nativeRun = childProcess.spawnSync(python,
    ['-B', script, '--image', path.resolve(runtimeImagePath), '--batch',
      ...(v6 ? ['--u32-0x1c'] : [])], {
      input: nativeRequest, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
      timeout: 120_000, windowsHide: true,
    });
  if (nativeRun.error || nativeRun.status !== 0) {
    const detail = String(nativeRun.error?.message || nativeRun.stderr
      || nativeRun.stdout || `exit ${nativeRun.status}`).trim().slice(0, 1500);
    const missingPython = nativeRun.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `0x005f native witness unavailable or failed: ${detail}`, {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: missingPython ? 'UNAVAILABLE' : 'FAILED',
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
      });
  }
  let native;
  try {
    native = JSON.parse(nativeRun.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `0x005f native witness output is invalid JSON: ${error.message}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native?.replay_version !== BUILD || native.runtime_image_sha256 !== IMAGE_SHA256
      || native.packet_id !== PACKET_ID || native.packet_count !== observedCount
      || native.input_sha256 !== inputSha
      || !Number.isInteger(native.native_full_success_count)
      || !Array.isArray(native.float_rows)
      || !Array.isArray(native.native_float_rows)
      || !Array.isArray(native.native_u32_0x10_rows)
      || !Array.isArray(native.native_f32_0x18_rows)
      || !Array.isArray(native.lookup_rows)
      || !Number.isSafeInteger(native.native_u32_0x10_full_write_count)
      || !Number.isSafeInteger(native.native_f32_0x18_full_write_count)
      || native.callback_u32_0x10_table_sha256 !== CALLBACK_U32_0X10_TABLE_SHA256
      || native.callback_f32_0x18_table_sha256 !== CALLBACK_F32_0X18_TABLE_SHA256
      || !Number.isSafeInteger(native.native_lookup_full_write_count)
      || native.lookup_table_sha256?.['0x24'] !== LOOKUP_KEY_0X24_TABLE_SHA256
      || native.lookup_table_sha256?.['0x2c'] !== LOOKUP_KEY_0X2C_TABLE_SHA256
      || Object.keys(native.lookup_table_sha256).sort().join(',') !== '0x24,0x2c'
      || native.native_float_source_counts === null
      || typeof native.native_float_source_counts !== 'object'
      || Array.isArray(native.native_float_source_counts)
      || Object.keys(native.native_float_source_counts).sort().join(',')
        !== [...NATIVE_FLOAT_SOURCES].sort().join(',')
      || NATIVE_FLOAT_SOURCES.some((source) =>
        !Number.isSafeInteger(native.native_float_source_counts[source])
        || native.native_float_source_counts[source] < 0)
      || native.native_u32_0x10_source_counts === null
      || typeof native.native_u32_0x10_source_counts !== 'object'
      || Array.isArray(native.native_u32_0x10_source_counts)
      || Object.keys(native.native_u32_0x10_source_counts).sort().join(',')
        !== [...NATIVE_U32_0X10_SOURCES].sort().join(',')
      || NATIVE_U32_0X10_SOURCES.some((source) =>
        !Number.isSafeInteger(native.native_u32_0x10_source_counts[source])
        || native.native_u32_0x10_source_counts[source] < 0)
      || native.native_f32_0x18_source_counts === null
      || typeof native.native_f32_0x18_source_counts !== 'object'
      || Array.isArray(native.native_f32_0x18_source_counts)
      || Object.keys(native.native_f32_0x18_source_counts).sort().join(',')
        !== [...NATIVE_F32_0X18_SOURCES].sort().join(',')
      || NATIVE_F32_0X18_SOURCES.some((source) =>
        !Number.isSafeInteger(native.native_f32_0x18_source_counts[source])
        || native.native_f32_0x18_source_counts[source] < 0)
      || (v6 && (!Array.isArray(native.native_u32_0x1c_rows)
        || !Number.isSafeInteger(native.native_u32_0x1c_full_write_count)
        || native.callback_u32_0x1c_table_sha256 !== CALLBACK_U32_0X1C_TABLE_SHA256
        || native.native_u32_0x1c_source_counts === null
        || typeof native.native_u32_0x1c_source_counts !== 'object'
        || Array.isArray(native.native_u32_0x1c_source_counts)
        || Object.keys(native.native_u32_0x1c_source_counts).sort().join(',')
          !== [...NATIVE_U32_0X1C_SOURCES].sort().join(',')
        || NATIVE_U32_0X1C_SOURCES.some((source) =>
          !Number.isSafeInteger(native.native_u32_0x1c_source_counts[source])
          || native.native_u32_0x1c_source_counts[source] < 0)))) {
    return fail('DECODE_FAILED', '0x005f native witness identity or input digest differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native.native_full_success_count !== observedCount || native.first_failure !== null) {
    const failedIndex = native.first_failure?.index;
    return fail('DECODE_FAILED', `0x005f native packet did not fully deserialize: ${native.first_failure?.reason || 'count mismatch'}`, {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
      native_full_success_count: native.native_full_success_count,
      first_failed_packet_ref: Number.isInteger(failedIndex)
        && failedIndex >= 0 && failedIndex < rows.length
        ? packetRef(replay, rows[failedIndex].block, rows[failedIndex].chunk) : null,
    });
  }
  const expectedFloatCount = rows.reduce((count, row) =>
    count + Number(hasCallbackFloatShape(row.block.payload)), 0);
  if (native.float_rows.length !== expectedFloatCount) {
    return fail('DECODE_FAILED', '0x005f native callback float count differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native.native_float_rows.length !== observedCount
      || NATIVE_FLOAT_SOURCES.reduce((total, source) =>
        total + native.native_float_source_counts[source], 0) !== observedCount) {
    return fail('DECODE_FAILED', '0x005f native callback float row or source count differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native.lookup_rows.length !== observedCount
      || native.native_lookup_full_write_count !== observedCount) {
    return fail('DECODE_FAILED', '0x005f native callback lookup row or write count differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native.native_u32_0x10_rows.length !== observedCount
      || native.native_u32_0x10_full_write_count !== observedCount
      || NATIVE_U32_0X10_SOURCES.reduce((total, source) =>
        total + native.native_u32_0x10_source_counts[source], 0) !== observedCount) {
    return fail('DECODE_FAILED', '0x005f native +0x10 callback row or write count differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (native.native_f32_0x18_rows.length !== observedCount
      || native.native_f32_0x18_full_write_count !== observedCount
      || NATIVE_F32_0X18_SOURCES.reduce((total, source) =>
        total + native.native_f32_0x18_source_counts[source], 0) !== observedCount) {
    return fail('DECODE_FAILED', '0x005f native +0x18 callback row or write count differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (v6 && (native.native_u32_0x1c_rows.length !== observedCount
      || native.native_u32_0x1c_full_write_count !== observedCount
      || NATIVE_U32_0X1C_SOURCES.reduce((total, source) =>
        total + native.native_u32_0x1c_source_counts[source], 0) !== observedCount)) {
    return fail('DECODE_FAILED', '0x005f native +0x1c callback row or write count differs', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  const events = [];
  const shapeCounts = new Map();
  let callbackF32AvailableCount = 0;
  let nativeFloatIndex = 0;
  const nativeFloatSourceCounts = Object.fromEntries(
    NATIVE_FLOAT_SOURCES.map((source) => [source, 0]));
  const lookupKey24RelationCounts = Object.fromEntries(
    LOOKUP_KEY_RELATIONS.map((relation) => [relation, 0]));
  const nativeU32SourceCounts = Object.fromEntries(
    NATIVE_U32_0X10_SOURCES.map((source) => [source, 0]));
  const nativeU32At1cSourceCounts = v6 ? Object.fromEntries(
    NATIVE_U32_0X1C_SOURCES.map((source) => [source, 0])) : null;
  const nativeF32At18SourceCounts = Object.fromEntries(
    NATIVE_F32_0X18_SOURCES.map((source) => [source, 0]));
  for (const [rowIndex, { block, chunk }] of rows.entries()) {
    const payload = block.payload;
    const selectors = shapeTuple(payload);
    const shapeKey = `${payload.length}:${selectors.header_selector_bits_24_26}:${selectors.header_selector_bits_0_2}:${selectors.header_selector_bits_3_5}`;
    shapeCounts.set(shapeKey, (shapeCounts.get(shapeKey) ?? 0) + 1);
    const hasFloat = hasCallbackFloatShape(payload);
    const nativeFloatRow = native.native_float_rows[rowIndex];
    const nativeU32Row = native.native_u32_0x10_rows[rowIndex];
    const nativeU32At1cRow = v6 ? native.native_u32_0x1c_rows[rowIndex] : null;
    const nativeF32At18Row = native.native_f32_0x18_rows[rowIndex];
    const lookupRow = native.lookup_rows[rowIndex];
    if (!Array.isArray(lookupRow) || lookupRow.length !== 5
        || lookupRow[0] !== rowIndex
        || typeof lookupRow[1] !== 'string' || !/^[0-9a-f]{8}$/.test(lookupRow[1])
        || typeof lookupRow[3] !== 'string' || !/^[0-9a-f]{8}$/.test(lookupRow[3])
        || !Number.isSafeInteger(lookupRow[2]) || lookupRow[2] <= 0
        || lookupRow[2] > 0xffffffff
        || !Number.isSafeInteger(lookupRow[4]) || lookupRow[4] <= 0
        || lookupRow[4] > 0xffffffff
        || decodeUnitApplyDamageLookupKeyFromRaw821(lookupRow[1], 0x24) !== lookupRow[2]
        || decodeUnitApplyDamageLookupKeyFromRaw821(lookupRow[3], 0x2c) !== lookupRow[4]) {
      return fail('DECODE_FAILED', '0x005f native callback lookup-key identity or transform differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: 'FAILED',
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    const lookupKey24Relation = lookupKey24RawParamRelation(block.param >>> 0, lookupRow[2]);
    lookupKey24RelationCounts[lookupKey24Relation] += 1;
    const expectedU32Source = selectors.header_selector_bits_24_26 === 6
      ? 'CONSTANT_0' : 'RAW_READER';
    if (!Array.isArray(nativeU32Row) || nativeU32Row.length !== 4
        || nativeU32Row[0] !== rowIndex
        || typeof nativeU32Row[1] !== 'string' || !/^[0-9a-f]{8}$/.test(nativeU32Row[1])
        || !Number.isSafeInteger(nativeU32Row[2]) || nativeU32Row[2] < 0
        || nativeU32Row[2] > 0xffffffff
        || nativeU32Row[3] !== expectedU32Source
        || decodeUnitApplyDamageCallbackU32FromRaw821(nativeU32Row[1]) !== nativeU32Row[2]
        || (expectedU32Source === 'CONSTANT_0'
          && (nativeU32Row[1] !== '85858585' || nativeU32Row[2] !== 0))) {
      return fail('DECODE_FAILED', '0x005f native +0x10 callback identity or transform differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: 'FAILED',
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    nativeU32SourceCounts[expectedU32Source] += 1;
    const nativeU32At1c = v6
      ? checkedNativeU32At1cRow821(nativeU32At1cRow, rowIndex, payload) : null;
    if (v6 && !nativeU32At1c) {
      return fail('DECODE_FAILED', '0x005f native +0x1c callback identity or raw span differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: 'FAILED',
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    if (v6) nativeU32At1cSourceCounts[nativeU32At1c.source] += 1;
    const selectorAt18 = selectors.header_selector_bits_6_8;
    const expectedF32At18Source = selectorAt18 === F32_0X18_CONSTANT_ZERO_SELECTOR
      ? 'CONSTANT_0' : F32_0X18_RAW_SELECTORS.includes(selectorAt18)
        ? 'RAW_READER' : null;
    if (expectedF32At18Source === null
        || !Array.isArray(nativeF32At18Row) || nativeF32At18Row.length !== 5
        || nativeF32At18Row[0] !== rowIndex
        || typeof nativeF32At18Row[1] !== 'string'
        || !/^[0-9a-f]{8}$/.test(nativeF32At18Row[1])
        || !Number.isFinite(nativeF32At18Row[2])
        || nativeF32At18Row[3] !== expectedF32At18Source
        || !Object.is(decodeUnitApplyDamageCallbackF32At18FromEncoded821(
          nativeF32At18Row[1]), nativeF32At18Row[2])) {
      return fail('DECODE_FAILED', '0x005f native +0x18 callback identity or transform differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: 'FAILED',
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    let nativeF32At18RawBytes = null;
    if (expectedF32At18Source === 'CONSTANT_0') {
      if (nativeF32At18Row[1] !== '3e3e3e3e'
          || !Object.is(nativeF32At18Row[2], 0)
          || nativeF32At18Row[4] !== null) {
        return fail('DECODE_FAILED', '0x005f native +0x18 callback constant differs', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
    } else {
      const rawOffset = nativeF32At18Row[4];
      if (!Number.isSafeInteger(rawOffset) || rawOffset < 0
          || rawOffset + 4 > payload.length) {
        return fail('DECODE_FAILED', '0x005f native +0x18 raw offset differs', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      nativeF32At18RawBytes = payload.subarray(rawOffset, rawOffset + 4);
      if (Buffer.from(nativeF32At18RawBytes).reverse().toString('hex')
          !== nativeF32At18Row[1]) {
        return fail('DECODE_FAILED', '0x005f native +0x18 raw bytes differ', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
    }
    nativeF32At18SourceCounts[expectedF32At18Source] += 1;
    const selector = selectors.header_selector_bits_3_5;
    const constant = NATIVE_FLOAT_CONSTANTS[selector];
    const expectedSource = constant?.source ?? 'RAW_READER';
    if (!Array.isArray(nativeFloatRow) || nativeFloatRow.length !== 4
        || nativeFloatRow[0] !== rowIndex
        || !Number.isFinite(nativeFloatRow[1])
        || nativeFloatRow[2] !== expectedSource) {
      return fail('DECODE_FAILED', '0x005f native callback float identity or source differs', {
        input_count: observedCount, scanned_block_count: scannedBlockCount,
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        native_witness_status: 'FAILED',
        first_failed_packet_ref: packetRef(replay, block, chunk),
      });
    }
    let nativeCallbackF32 = nativeFloatRow[1];
    let nativeRawOffset = null;
    let nativeRawBytes = null;
    if (constant) {
      if (nativeFloatRow[3] !== null || !Object.is(nativeCallbackF32, constant.value)) {
        return fail('DECODE_FAILED', '0x005f native callback constant differs', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
    } else {
      nativeRawOffset = nativeFloatRow[3];
      if (!Number.isSafeInteger(nativeRawOffset)
          || nativeRawOffset < 0 || nativeRawOffset + 4 > payload.length) {
        return fail('DECODE_FAILED', '0x005f native callback raw offset differs', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      nativeRawBytes = payload.subarray(nativeRawOffset, nativeRawOffset + 4);
      const redecoded = decodeUnitApplyDamageCallbackF32FromRaw821(
        nativeRawBytes.toString('hex'));
      if (redecoded === null || !Object.is(redecoded, nativeCallbackF32)) {
        return fail('DECODE_FAILED', '0x005f native callback raw transform differs', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      nativeCallbackF32 = redecoded;
    }
    nativeFloatSourceCounts[expectedSource] += 1;
    let callbackF32 = null;
    let rawFloatBytes = null;
    if (hasFloat) {
      rawFloatBytes = payload.subarray(5, 9);
      callbackF32 = decodeUnitApplyDamageCallbackF32FromRaw821(rawFloatBytes.toString('hex'));
      if (callbackF32 === null) {
        return fail('DECODE_FAILED', '0x005f callback float is nonfinite', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      const nativeFloatRow = native.float_rows[nativeFloatIndex++];
      if (!Array.isArray(nativeFloatRow) || nativeFloatRow.length !== 2
          || nativeFloatRow[0] !== rowIndex || !Number.isFinite(nativeFloatRow[1])
          || !Object.is(nativeFloatRow[1], callbackF32)
          || expectedSource !== 'RAW_READER' || nativeRawOffset !== 5
          || !Object.is(nativeCallbackF32, callbackF32)) {
        return fail('DECODE_FAILED', '0x005f callback float differs from native witness', {
          input_count: observedCount, scanned_block_count: scannedBlockCount,
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          native_witness_status: 'FAILED',
          first_failed_packet_ref: packetRef(replay, block, chunk),
        });
      }
      callbackF32AvailableCount += 1;
    }
    events.push({
      event_type: 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      packet_name_candidate: profile.packet_name,
      ...selectors,
      ...(v6 ? { header_selector_bits_12_14: nativeU32At1c.selector } : {}),
      native_callback_u32_0x10_candidate: nativeU32Row[2],
      native_callback_u32_0x10_encoded_bytes_hex: nativeU32Row[1],
      native_callback_u32_0x10_source: expectedU32Source,
      ...(v6 ? {
        native_callback_u32_0x1c_candidate: nativeU32At1cRow[2],
        native_callback_u32_0x1c_encoded_bytes_hex: nativeU32At1cRow[1],
        native_callback_u32_0x1c_source: nativeU32At1c.source,
        native_callback_u32_0x1c_raw_call_rva: nativeU32At1c.callRva,
        native_callback_u32_0x1c_raw_offset: nativeU32At1c.rawOffset,
        native_callback_u32_0x1c_raw_bytes_hex: nativeU32At1c.rawBytesHex,
      } : {}),
      native_callback_f32_0x18_candidate: nativeF32At18Row[2],
      native_callback_f32_0x18_encoded_bytes_hex: nativeF32At18Row[1],
      native_callback_f32_0x18_source: expectedF32At18Source,
      native_callback_f32_0x18_raw_offset: nativeF32At18Row[4],
      native_callback_f32_0x18_raw_bytes_hex:
        nativeF32At18RawBytes?.toString('hex') ?? null,
      callback_f32_0x20_candidate: callbackF32,
      callback_f32_0x20_status: hasFloat ? 'NATIVE_MATCHED_SHAPE' : 'UNAVAILABLE_SHAPE',
      callback_f32_0x20_raw_bytes_hex: rawFloatBytes?.toString('hex') ?? null,
      native_callback_f32_0x20_candidate: nativeCallbackF32,
      native_callback_f32_0x20_source: expectedSource,
      native_callback_f32_0x20_raw_offset: nativeRawOffset,
      native_callback_f32_0x20_raw_bytes_hex: nativeRawBytes?.toString('hex') ?? null,
      native_callback_lookup_key_u32_0x24_candidate: lookupRow[2],
      native_callback_lookup_key_0x24_encoded_bytes_hex: lookupRow[1],
      native_callback_lookup_key_u32_0x2c_candidate: lookupRow[4],
      native_callback_lookup_key_0x2c_encoded_bytes_hex: lookupRow[3],
      native_callback_lookup_key_0x24_raw_param_relation: lookupKey24Relation,
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      raw_packet_ref: packetRef(replay, block, chunk),
    });
  }
  if (NATIVE_FLOAT_SOURCES.some((source) =>
    nativeFloatSourceCounts[source] !== native.native_float_source_counts[source])) {
    return fail('DECODE_FAILED', '0x005f native callback float source counts differ', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (NATIVE_U32_0X10_SOURCES.some((source) =>
    nativeU32SourceCounts[source] !== native.native_u32_0x10_source_counts[source])) {
    return fail('DECODE_FAILED', '0x005f native +0x10 callback source counts differ', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (v6 && NATIVE_U32_0X1C_SOURCES.some((source) =>
    nativeU32At1cSourceCounts[source] !== native.native_u32_0x1c_source_counts[source])) {
    return fail('DECODE_FAILED', '0x005f native +0x1c callback source counts differ', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  if (NATIVE_F32_0X18_SOURCES.some((source) =>
    nativeF32At18SourceCounts[source] !== native.native_f32_0x18_source_counts[source])) {
    return fail('DECODE_FAILED', '0x005f native +0x18 callback source counts differ', {
      input_count: observedCount, scanned_block_count: scannedBlockCount,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      native_witness_status: 'FAILED',
    });
  }
  return {
    ...base,
    status: 'CANDIDATE', input_count: observedCount, event_count: events.length,
    events, scanned_block_count: scannedBlockCount,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      header_selector_bits_24_26: 'CANDIDATE_EXACT_RUNTIME_BIT_READER',
      header_selector_bits_0_2: 'CANDIDATE_EXACT_RUNTIME_BIT_READER',
      header_selector_bits_3_5: 'CANDIDATE_EXACT_RUNTIME_BIT_READER',
      header_selector_bits_6_8: 'CANDIDATE_EXACT_RUNTIME_BIT_READER',
      ...(v6 ? { header_selector_bits_12_14:
        'CANDIDATE_EXACT_RUNTIME_BIT_READER' } : {}),
      callback_f32_0x20_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      native_callback_f32_0x20_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      native_callback_u32_0x10_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      ...(v6 ? { native_callback_u32_0x1c_candidate:
        'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM' } : {}),
      native_callback_f32_0x18_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      native_callback_lookup_key_u32_0x24_candidate: 'FLOAT_RECEIVER_LOOKUP_CANDIDATE',
      native_callback_lookup_key_u32_0x2c_candidate: 'SECOND_LOOKUP_OBJECT_CANDIDATE',
      native_callback_lookup_key_0x24_raw_param_relation: 'CANDIDATE_EXACT_RUNTIME_LOOKUP_KEY_RELATION',
    },
    observed_shape_family_count: shapeCounts.size,
    callback_f32_available_count: callbackF32AvailableCount,
    callback_f32_unavailable_count: events.length - callbackF32AvailableCount,
    native_callback_f32_available_count: events.length,
    native_callback_f32_source_counts: nativeFloatSourceCounts,
    native_callback_u32_0x10_full_write_count: native.native_u32_0x10_full_write_count,
    native_callback_u32_0x10_source_counts: nativeU32SourceCounts,
    ...(v6 ? {
      native_callback_u32_0x1c_full_write_count: native.native_u32_0x1c_full_write_count,
      native_callback_u32_0x1c_source_counts: nativeU32At1cSourceCounts,
    } : {}),
    native_callback_f32_0x18_full_write_count: native.native_f32_0x18_full_write_count,
    native_callback_f32_0x18_source_counts: nativeF32At18SourceCounts,
    native_callback_lookup_full_write_count: native.native_lookup_full_write_count,
    native_callback_lookup_key_0x24_raw_param_relation_counts: lookupKey24RelationCounts,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: native.native_full_success_count,
    native_input_sha256: inputSha,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: imageSha,
  };
}

function decodeUnitApplyDamagePacketCandidates821(replay, options) {
  return decodeUnitApplyDamagePacketCandidates821WithProfile(
    replay, UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821, options);
}

function decodeUnitApplyDamagePacketCandidates821V6(replay, options) {
  return decodeUnitApplyDamagePacketCandidates821WithProfile(
    replay, UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821, options);
}

module.exports = {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V5_ID_821,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_ID_821,
  decodeUnitApplyDamagePacketCandidates821,
  decodeUnitApplyDamagePacketCandidates821V6,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageCallbackU32FromRaw821,
  decodeUnitApplyDamageCallbackU32At1cFromEncoded821,
  decodeUnitApplyDamageU32At1cFromRawSpan821,
  UNIT_APPLY_DAMAGE_U32_0X1C_RAW_CALL_RVA_BY_SELECTOR_821:
    U32_0X1C_RAW_CALL_RVA_BY_SELECTOR,
  decodeUnitApplyDamageCallbackF32At18FromEncoded821,
  decodeUnitApplyDamageLookupKeyFromRaw821,
  decodeCallbackFloatByte,
  isObservedShape,
};
