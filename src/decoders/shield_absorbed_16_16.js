'use strict';

const crypto = require('node:crypto');

const REPLAY_VERSION = '16.16.805.0442';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const CALLBACK_LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const CALLBACK_DISASSEMBLY_SHA256 = '22a9b546c56737a6cd43dc273b92bf645bdcc24be9e79968c4d312ed5548b39e';

const SHIELD_ABSORBED_PROFILE = Object.freeze({
  id: 'rofl-16.16.805.0442-unit-apply-shield-damage-callback-inverse-v1',
  neutral_decoder_profile: 'rofl-16.16.805.0442-unit-apply-shield-damage-neutral-v1',
  capability: 'SHIELD_ABSORBED',
  replay_version: REPLAY_VERSION,
  runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  status: 'SEMANTIC_VERIFIED_DIRECT',
  enabled: true,
  replay_block_packet_id: 0x01e1,
  client_opcode: 0x01e1,
  runtime_type_name: 'PKT_UnitApplyShieldDamage_s',
  constructor_rva: 0x00eac9b0,
  object_vtable_rva: 0x01b109e8,
  deserialize_rva: 0x00f22400,
  callback_rva: 0x002a77b0,
  callback_lookup_table_rva: 0x01a27950,
  callback_lookup_table_sha256: CALLBACK_LOOKUP_TABLE_SHA256,
  callback_inverse_instruction_ranges: Object.freeze({
    target_field_18: '0x002a77c5..0x002a7811',
    target_field_1c: '0x002a7820..0x002a7850',
    neutral_field_14: '0x002a7896..0x002a78b8',
    absorbed_amount_field_10: '0x002a7934..0x002a795d',
  }),
  object_size: 0x20,
  validation_artifact: '.omo/evidence/quant_combat_closure/packet_01e1_shield_absorbed_direct.jsonl',
  evidence: '12_EXACT_RUNTIME_FULL_CONSUME_ROWS_PLUS_CALLBACK_INVERSE_AND_DUPLICATE_TARGET_GATES',
  semantic_boundary: 'Direct target-total absorbed amount only; source, shield instance and remaining amount unavailable.',
});

function rotateRight8(value, count) {
  return ((value >>> count) | (value << (8 - count))) & 0xff;
}

function rotateLeft8(value, count) {
  return ((value << count) | (value >>> (8 - count))) & 0xff;
}

function decodeShieldCallbackObject(objectHex, table) {
  const object = Buffer.from(objectHex, 'hex');
  if (object.length !== 0x20 || !Buffer.isBuffer(table) || table.length !== 0x100) {
    throw new Error('invalid 0x01e1 object/table size');
  }
  if (crypto.createHash('sha256').update(table).digest('hex') !== CALLBACK_LOOKUP_TABLE_SHA256) {
    throw new Error('0x01e1 callback lookup table SHA mismatch');
  }
  const transform = (offset, fn) => Buffer.from([...object.subarray(offset, offset + 4)].map(fn));
  const amountBytes = transform(0x10, (byte) => {
    let value = rotateRight8(byte, 6) ^ 0x9f;
    value = rotateRight8(value, 6) ^ 0xe0;
    return (value + 0x51) & 0xff;
  });
  const field14 = transform(0x14, (byte) => rotateRight8((byte - 0x1d) & 0xff, 6) ^ 0xcc);
  const target18 = transform(0x18, (byte) =>
    (table[rotateLeft8((byte - 0x3d) & 0xff, 3)] - 0x40) & 0xff);
  const target1c = transform(0x1c, (byte) => {
    let value = (~byte) & 0xff;
    value = (value - 0x77) & 0xff;
    value = rotateRight8(value, 4);
    value = (~value) & 0xff;
    return (value - 0x58) & 0xff;
  });
  return Object.freeze({
    shield_absorbed_amount: amountBytes.readFloatLE(0),
    shield_absorbed_amount_bits_hex: amountBytes.toString('hex'),
    field_14_plain_u32: field14.readUInt32LE(0),
    target_network_id_from_field_18: target18.readUInt32LE(0),
    target_network_id_from_field_1c: target1c.readUInt32LE(0),
  });
}

function shieldAbsorbedFromFullyConsumedRow(row, callbackLookupTable) {
  if (!row || row.replay_version !== REPLAY_VERSION
      || typeof row.replay_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(row.replay_sha256)
      || !Number.isInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || typeof row.raw_payload_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(row.raw_payload_sha256)
      || !Number.isInteger(row.raw_param)
      || row.packet_type !== '0x01e1' || row.packet_id !== 0x01e1
      || row.decoded_opcode !== 0x01e1 || row.opcode_matches_profile !== true
      || row.decoder_profile !== SHIELD_ABSORBED_PROFILE.neutral_decoder_profile
      || row.decoder_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || row.deserialize_return_al === 0 || row.fully_consumed !== true
      || row.payload_length !== 10 || typeof row.object_hex !== 'string') return null;
  if (typeof row.raw_payload_hex === 'string'
      && crypto.createHash('sha256').update(Buffer.from(row.raw_payload_hex, 'hex')).digest('hex')
        !== row.raw_payload_sha256) return null;
  const decoded = decodeShieldCallbackObject(row.object_hex, callbackLookupTable);
  const target = decoded.target_network_id_from_field_18;
  const canonicalRawTarget = 0x40000000 | (row.raw_param & 0xff);
  if (!Number.isFinite(decoded.shield_absorbed_amount) || decoded.shield_absorbed_amount < 0
      || decoded.field_14_plain_u32 !== 0
      || target !== decoded.target_network_id_from_field_1c
      || target !== canonicalRawTarget) return null;
  return Object.freeze({
    semantic: 'SHIELD_ABSORBED',
    evidence: 'VERIFIED_DIRECT',
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    target_network_id: target,
    absorbed_amount: decoded.shield_absorbed_amount,
    amount_bits_hex: decoded.shield_absorbed_amount_bits_hex,
    source_network_id: null,
    shield_instance_id: null,
    remaining_amount: null,
    attribution_status: 'UNATTRIBUTED_TARGET_TOTAL',
    decoder_profile: SHIELD_ABSORBED_PROFILE.id,
    protocol_route: '0x01e1',
    raw_payload_sha256: row.raw_payload_sha256,
  });
}

function validateShieldCallbackDisassembly(disassemblyBytes, runtimeImage) {
  if (!Buffer.isBuffer(disassemblyBytes) || !Buffer.isBuffer(runtimeImage)
      || crypto.createHash('sha256').update(disassemblyBytes).digest('hex') !== CALLBACK_DISASSEMBLY_SHA256
      || crypto.createHash('sha256').update(runtimeImage).digest('hex') !== RUNTIME_IMAGE_SHA256) {
    throw new Error('0x01e1 callback disassembly/runtime identity mismatch');
  }
  const document = JSON.parse(disassemblyBytes.toString('utf8'));
  const instructions = document.disassembly?.flatMap((row) => row.instructions || []) || [];
  for (const instruction of instructions) {
    const bytes = Buffer.from(instruction.bytes, 'hex');
    if (!bytes.length || !bytes.equals(runtimeImage.subarray(instruction.rva, instruction.rva + bytes.length))) {
      throw new Error(`0x01e1 callback instruction bytes mismatch at ${instruction.rva}`);
    }
  }
  const ranges = [
    [0x002a77c5, 0x002a7811, ['sub', 'shl', 'shr', 'or', 'movzx']],
    [0x002a7820, 0x002a7850, ['not', 'sub', 'ror']],
    [0x002a7896, 0x002a78b8, ['sub', 'ror', 'xor']],
    [0x002a7934, 0x002a795d, ['ror', 'xor', 'add']],
  ];
  for (const [start, end, operations] of ranges) {
    const slice = instructions.filter((row) => row.rva >= start && row.rva <= end);
    const mnemonics = new Set(slice.map((row) => row.mnemonic));
    if (!slice.length || operations.some((operation) => !mnemonics.has(operation))) {
      throw new Error(`0x01e1 callback inverse operation evidence mismatch at ${start}`);
    }
  }
  if (SHIELD_ABSORBED_PROFILE.callback_lookup_table_rva !== 0x01a27950) {
    throw new Error('0x01e1 callback lookup-table RVA mismatch');
  }
  return true;
}

module.exports = {
  REPLAY_VERSION,
  RUNTIME_IMAGE_SHA256,
  CALLBACK_LOOKUP_TABLE_SHA256,
  CALLBACK_DISASSEMBLY_SHA256,
  SHIELD_ABSORBED_PROFILE,
  decodeShieldCallbackObject,
  shieldAbsorbedFromFullyConsumedRow,
  validateShieldCallbackDisassembly,
};
