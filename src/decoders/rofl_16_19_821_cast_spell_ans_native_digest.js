'use strict';

const crypto = require('node:crypto');

const BATCH_SIZE = 8192;
const DIGEST_SCHEMA = 'CAST_SPELL_ANS_821_V9_NATIVE_OUTPUT_V1';
const BATCH_DOMAIN = Buffer.from(`${DIGEST_SCHEMA}\0`, 'ascii');
const REPLAY_DOMAIN = Buffer.from('CAST_SPELL_ANS_821_V9_REPLAY_V1\0', 'ascii');

function u32(value) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32LE(value >>> 0);
  return bytes;
}

function i32(value) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeInt32LE(value);
  return bytes;
}

function raw(hex, length) {
  if (typeof hex !== 'string' || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(hex)) {
    throw new TypeError(`Cast V9 digest requires ${length} raw bytes`);
  }
  return Buffer.from(hex, 'hex');
}

// The V9 digest covers only fields retained in candidate JSONL. Float values
// are pinned by their protected bytes and the existing exact-build transforms.
function updateBatchRow(hash, row, index, saved = false) {
  const ref = saved ? row.raw_packet_ref : null;
  const payloadLength = saved ? ref?.payload_length : row.bytes_consumed;
  const payloadSha = saved ? ref?.raw_payload_sha256 : row.raw_payload_sha256;
  hash.update(u32(index));
  hash.update(u32(row.raw_param));
  hash.update(u32(payloadLength));
  hash.update(raw(payloadSha, 32));
  hash.update(Buffer.from([row.opaque_flag_0x148]));
  hash.update(i32(row.opaque_i32_0x14c));
  hash.update(raw(saved ? row.raw_f32_0xe0_bytes_hex : row.raw_f32_bytes_hex, 4));
  hash.update(raw(row.raw_u8_0x140_hex, 1));
  hash.update(Buffer.from([row.opaque_u8_0x140]));
  hash.update(raw(row.raw_nested_bits_0x24_hex, 1));
  hash.update(Buffer.from([row.opaque_nested_bits_0x24]));
  hash.update(raw(row.raw_u32_0x1c_hex, 4));
  hash.update(u32(row.opaque_u32_0x1c));
  hash.update(raw(row.raw_u32_0x4c_hex, 4));
  hash.update(u32(row.opaque_u32_0x4c));
  hash.update(raw(saved ? row.raw_f32_0xa0_bytes_hex : row.raw_f32_0xa0_hex, 4));
  hash.update(raw(row.raw_u32_0x28_hex, 4));
  hash.update(u32(row.opaque_u32_0x28));
}

function batchDigest(rows, saved = false) {
  const hash = crypto.createHash('sha256').update(BATCH_DOMAIN);
  rows.forEach((row, index) => updateBatchRow(hash, row, index, saved));
  return hash.digest('hex');
}

function replayDigestStart(replaySha) {
  return crypto.createHash('sha256').update(REPLAY_DOMAIN).update(raw(replaySha, 32));
}

function replayDigestBatch(hash, start, count, digest) {
  hash.update(u32(start)).update(u32(count)).update(raw(digest, 32));
}

module.exports = {
  BATCH_SIZE, DIGEST_SCHEMA, batchDigest, replayDigestStart, replayDigestBatch,
};
