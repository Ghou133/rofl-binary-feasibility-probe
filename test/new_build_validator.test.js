'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  assertGameChunkChronology,
  boundedGameWalk,
} = require('../scripts/validate_new_build_compatibility');

function absoluteBlock(timestamp) {
  const body = Buffer.alloc(1 + 4 + 4 + 2 + 4);
  body[0] = 0;
  body.writeFloatLE(timestamp, 1);
  body.writeUInt32LE(0, 5);
  body.writeUInt16LE(1, 9);
  body.writeUInt32LE(0, 11);
  return body;
}

function replayWithTimestamps(timestamps) {
  const bodies = timestamps.map(absoluteBlock);
  const buffer = Buffer.concat(bodies);
  let cursor = 0;
  const chunks = bodies.map((body, index) => {
    const chunk = {
      chunk_id: index + 1,
      index,
      offset: cursor,
      body_offset: cursor,
      body_end: cursor + body.length,
      body_length: body.length,
      uncompressed_length: body.length,
      is_compressed: false,
      stream_tag: 1,
    };
    cursor += body.length;
    return chunk;
  });
  return { buffer, chunks };
}

test('bounded fastpath rejects non-monotonic game chunk ordering', () => {
  const replay = replayWithTimestamps([10, 5]);
  assert.throws(() => assertGameChunkChronology(replay), /non-monotonic game-chunk timestamp/);
  assert.throws(() => boundedGameWalk(replay, 130_000), /non-monotonic game-chunk timestamp/);
});

test('bounded fastpath includes raw game chunks after chronology validation', () => {
  const result = boundedGameWalk(replayWithTimestamps([10, 20]), 15_000);
  assert.equal(result.blockCount, 1);
  assert.equal(result.gameChunksDecompressed ?? result.chunkCount, 2);
  assert.equal(result.maximumTimestampMs, 10_000);
});
