'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { replaySourceError } = require('../src/decoders/replay_source_integrity');

function fixture() {
  return replayFromChunks([{ stream: 1, body: Buffer.from('100000000000000000000000', 'hex') }],
    '16.19.821.7343');
}

test('a previously verified Replay still rejects changed bytes and a rewritten hash', () => {
  const replay = fixture();
  const originalHash = replay.source_sha256;
  const offset = replay.chunks[0].body_offset + 5;
  const originalByte = replay.buffer[offset];
  assert.equal(replaySourceError(replay), null);
  replay.buffer[offset] ^= 1;
  replay.source_sha256 = crypto.createHash('sha256').update(replay.buffer).digest('hex');
  assert.match(replaySourceError(replay), /bytes differ/);
  replay.buffer[offset] = originalByte;
  replay.source_sha256 = originalHash;
  assert.equal(replaySourceError(replay), null);
});

test('a previously verified Replay still rejects changed header and chunk metadata', () => {
  const replay = fixture();
  assert.equal(replaySourceError(replay), null);
  replay.header.version = '16.19.820.7193';
  assert.match(replaySourceError(replay), /header or chunk layout/);
  replay.header.version = '16.19.821.7343';
  replay.chunks[0].body_offset += 1;
  assert.match(replaySourceError(replay), /header or chunk layout/);
  replay.chunks[0].body_offset -= 1;
  assert.equal(replaySourceError(replay), null);
});

test('first source check rejects a byte change triggered by metadata access', () => {
  const replay = fixture();
  const chunks = replay.chunks;
  Object.defineProperty(replay, 'chunks', { configurable: true, get() {
    replay.buffer[chunks[0].body_offset + 5] ^= 1;
    return chunks;
  } });
  assert.match(replaySourceError(replay), /bytes differ/);
});
