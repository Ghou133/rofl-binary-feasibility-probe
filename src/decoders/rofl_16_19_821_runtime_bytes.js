'use strict';

const crypto = require('node:crypto');

const RUNTIME_IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';

// Independently extracted from RVA 0x01ba1560 of the captured 821 module.
// The LevelUp and HeroStats runtime routines use this same table with
// different byte arithmetic. With the Replay raw_param supplied to its base
// reader, exact 821 native 0x0089 decoding fully consumes observed keyframes;
// the semantic labels of individual vector offsets remain candidates.
const LOOKUP_TABLE = Buffer.from([
  'd75682dc83028f2935042171799e927fcb976a5105c76fe640637e345b470778',
  '5a96b8b92c995e6ed1754161245f4aaa4bcf0ed4865dba1d3f2bdf62f0330055',
  'cafc19acf3662369bceb46f89c50874d6d108e88be1bb5da4e1a13cc2209ada4',
  '9d30a6e57dfac91712c2fde1bbe70b98bfbd1137c07cf795b6dd49f4812a9f1c',
  'fb8d9a727b577a43b3a953e459202fa8f67436a085f1a7147031840cb2a5dbe8',
  '16ae3d25b1cd9b0367155cea1f39a1440a8b76de606593f264d5c1c84c064fb7',
  'edfee0f9a2184891ce1e3cb46c425494e328e90127ec0d45ff26efe28aabd9f5',
  '08c4af32c56b80c6c358eea33e2d0f893ab0d2d33873d8d08c7790523bd62e68',
].join(''), 'hex');
if (LOOKUP_TABLE.length !== 256 || new Set(LOOKUP_TABLE).size !== 256
  || crypto.createHash('sha256').update(LOOKUP_TABLE).digest('hex') !== LOOKUP_TABLE_SHA256) {
  throw new Error('exact 821 byte lookup table identity mismatch');
}

function runtimeByteLookupTable821() {
  return Buffer.from(LOOKUP_TABLE);
}

function rotateRight8(value, bits) {
  return ((value >>> bits) | (value << (8 - bits))) & 0xff;
}

function rotateLeft8(value, bits) {
  return ((value << bits) | (value >>> (8 - bits))) & 0xff;
}

function decodeRuntimeLevelByte(encoded) {
  const rotated = rotateRight8(encoded, 6) ^ 0x18;
  const index = rotateRight8((rotated + 0x3b) & 0xff, 1) ^ 0xa3;
  return LOOKUP_TABLE[index];
}

function decodeRuntimeCountByte(encoded) {
  const rotated = rotateRight8((encoded + 0x11) & 0xff, 2);
  const index = (((rotated & 0xd5) << 1) | ((rotated >>> 1) & 0x55)) & 0xff;
  return (LOOKUP_TABLE[index] + 0x39) & 0xff;
}

// Exact 821 PKT_NPC_Hero_Die_s wire path at RVA 0xf1ce16/e81d40. In every
// observed 0x0438 payload, the source ID occupies the final two bytes.
function decodeHeroDieSourceByte821(encoded) {
  const looked = LOOKUP_TABLE[LOOKUP_TABLE[rotateRight8(encoded, 7)]];
  const permuted = (((looked & 0xd5) << 1) | ((looked >>> 1) & 0x55)) & 0xff;
  return (~rotateRight8(permuted, 4)) & 0xff;
}

function decodeHeroDieSourceId821(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 2) return null;
  const first = decodeHeroDieSourceByte821(payload[payload.length - 2]);
  const second = decodeHeroDieSourceByte821(payload[payload.length - 1]);
  if ((first & 0x80) === 0 || (second & 0x80) !== 0) return null;
  const value = (first & 0x7f) | ((second & 0x7f) << 7);
  return (value & 0xffffff) === 0 ? value : (value ^ 0x40000000);
}

// Exact 821 PKT_HeroReincarnateAlive_s constructor and callback byte inverses.
// Field meanings remain unknown; the callback reads two f32 and one optional
// f32 from these object positions before calling actor virtual functions.
function decodeHeroReincarnateAlivePayload821(payload) {
  if (!Buffer.isBuffer(payload) || ![9, 13].includes(payload.length)) return null;
  const pair = Buffer.alloc(8);
  for (let field = 0; field < 2; field += 1) {
    for (let byte = 0; byte < 4; byte += 1) {
      const encoded = payload[1 + field * 4 + (3 - byte)];
      const swapped = (((encoded ^ 0xa6) & 0x55) << 1)
        | (((encoded ^ 0xa6) & 0xaa) >>> 1);
      pair[field * 4 + byte] = ((swapped ^ 0x9c) - 0x72) & 0xff;
    }
  }
  const optional = Buffer.alloc(4);
  for (let byte = 0; byte < 4; byte += 1) {
    const encoded = payload.length === 13 ? payload[9 + byte] : 0x1e;
    optional[byte] = rotateLeft8(
      (LOOKUP_TABLE[(encoded - 0x3d) & 0xff] + 0x3c) & 0xff, 3);
  }
  const first = pair.readFloatLE(0);
  const second = pair.readFloatLE(4);
  const scalar = optional.readFloatLE(0);
  if (![first, second, scalar].every(Number.isFinite)) return null;
  return {
    pair_f32: [first, second],
    optional_f32: scalar,
    optional_field_present: payload.length === 13,
  };
}

module.exports = {
  RUNTIME_IMAGE_SHA256,
  LOOKUP_TABLE_SHA256,
  runtimeByteLookupTable821,
  decodeRuntimeLevelByte,
  decodeRuntimeCountByte,
  decodeHeroDieSourceId821,
  decodeHeroReincarnateAlivePayload821,
};
