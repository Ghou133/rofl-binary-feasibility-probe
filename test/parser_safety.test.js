'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const zlib = require('node:zlib');
const { decompressChunk, walkBlocks } = require('../src/rofl');
const { packet, replayFromChunks } = require('./helpers/synthetic_replay');

function compressed(bytes, declared = bytes.length) {
  const buffer = zlib.zstdCompressSync(bytes);
  return {
    buffer,
    chunk: {
      chunk_id: 1, body_offset: 0, body_length: buffer.length,
      body_end: buffer.length, is_compressed: true, uncompressed_length: declared,
    },
  };
}

function decode(fixture) {
  return decompressChunk(fixture.buffer, fixture.chunk);
}

test('native Zstd is available in the supported Node runtime', () => {
  assert.equal(typeof zlib.zstdDecompressSync, 'function');
  assert.equal(typeof zlib.zstdCompressSync, 'function');
});

test('a valid compressed chunk round trips exactly', () => {
  const input = Buffer.from('synthetic chunk content');
  assert.deepEqual(decode(compressed(input)), input);
});

test('actual decompression is capped by the declared length', () => {
  const fixture = compressed(Buffer.alloc(1024 * 1024, 65), 8);
  assert.throws(() => decode(fixture), (error) => {
    assert.equal(error.code, 'ZSTD_DECOMPRESSION_ERROR');
    assert.match(error.details.cause, /larger than|output length/i);
    return true;
  });
});

test('the runtime receives an output limit before decompression', (t) => {
  const fixture = compressed(Buffer.from('abc'));
  const native = zlib.zstdDecompressSync;
  const limits = [];
  t.mock.method(zlib, 'zstdDecompressSync', (bytes, options) => {
    limits.push(options.maxOutputLength);
    return native(bytes, options);
  });
  assert.deepEqual(decode(fixture), Buffer.from('abc'));
  assert.deepEqual(limits, [3]);
});

test('a larger declared length still fails exact-length verification', () => {
  assert.throws(() => decode(compressed(Buffer.from('abc'), 4)), {
    code: 'DECOMPRESSED_LENGTH_MISMATCH',
  });
});

test('a declared empty compressed frame is accepted only when actually empty', () => {
  assert.equal(decode(compressed(Buffer.alloc(0), 0)).length, 0);
  assert.throws(() => decode(compressed(Buffer.from('x'), 0)), {
    code: 'DECOMPRESSED_LENGTH_MISMATCH',
  });
  assert.throws(() => decode(compressed(Buffer.alloc(1024, 65), 0)), {
    code: 'ZSTD_DECOMPRESSION_ERROR',
  });
});

test('an oversized declaration is rejected before invoking Zstd', (t) => {
  const fixture = compressed(Buffer.from('abc'), 128 * 1024 * 1024 + 1);
  const spy = t.mock.method(zlib, 'zstdDecompressSync', () => {
    throw new Error('must not be called');
  });
  assert.throws(() => decode(fixture), { code: 'CHUNK_TOO_LARGE' });
  assert.equal(spy.mock.callCount(), 0);
});

test('truncated and corrupt compressed frames are rejected', () => {
  const fixture = compressed(Buffer.from('abc'));
  fixture.buffer = fixture.buffer.subarray(0, -1);
  fixture.chunk.body_length = fixture.buffer.length;
  fixture.chunk.body_end = fixture.buffer.length;
  // Some Node/Zstd versions return a short output for this truncation. Both
  // decoder rejection and the mandatory exact-length rejection are valid.
  assert.throws(() => decode(fixture), (error) => (
    ['ZSTD_DECOMPRESSION_ERROR', 'DECOMPRESSED_LENGTH_MISMATCH'].includes(error.code)
  ));
  fixture.buffer = Buffer.from('not a Zstd frame');
  fixture.chunk.body_length = fixture.buffer.length;
  fixture.chunk.body_end = fixture.buffer.length;
  assert.throws(() => decode(fixture), { code: 'ZSTD_DECOMPRESSION_ERROR' });
});

test('uncompressed chunks preserve their existing exact-length check', () => {
  const fixture = { buffer: Buffer.from('abc'), chunk: {
    chunk_id: 1, body_offset: 0, body_length: 3, body_end: 3,
    is_compressed: false, uncompressed_length: 3,
  } };
  assert.deepEqual(decode(fixture), fixture.buffer);
  fixture.chunk.uncompressed_length = 4;
  assert.throws(() => decode(fixture), { code: 'RAW_CHUNK_LENGTH_MISMATCH' });
});

test('framing receives no bytes from an oversized compressed output', () => {
  const replay = replayFromChunks([
    { body: packet(1), compressed: true, declaredLength: 1 },
    { body: packet(2), compressed: true },
  ]);
  const seen = [];
  const result = walkBlocks(replay, (block) => seen.push(block.packet_id));
  assert.deepEqual(seen, [2]);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0].code, 'ZSTD_DECOMPRESSION_ERROR');
  assert.throws(() => walkBlocks(replay, () => {}, { strict: true }), {
    code: 'ZSTD_DECOMPRESSION_ERROR',
  });
});
