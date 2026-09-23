'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const rofl = require('../src/rofl');
const { analyzeReplay } = require('../src/analysis');
const { packet, replayFromChunks } = require('./helpers/synthetic_replay');

function makeReplay(count) {
  return replayFromChunks([{
    body: Buffer.concat(Array.from({ length: count }, (_, index) => packet(index + 1))),
    compressed: true,
  }]);
}

test('timeline preserves the frozen prefix-only contract and hard row budget', () => {
  for (const stride of [1, 2, 10000]) {
    const analysis = analyzeReplay(makeReplay(10), { timelineLimit: 3, sampleStride: stride });
    assert.equal(analysis.packet_count, 10);
    assert.deepEqual(analysis.packet_timeline_sample.map((row) => row.packet_id), [1, 2, 3]);
  }
});

test('a zero timeline budget still emits meaningful independent anchors', () => {
  const analysis = analyzeReplay(makeReplay(10), { timelineLimit: 0 });
  assert.deepEqual(analysis.packet_timeline_sample, []);
  assert.ok(analysis.raw_anchors.some((row) => row.anchor_kind === 'last_raw_block'));
});

test('invalid public API budgets are rejected instead of creating unbounded samples', () => {
  for (const timelineLimit of [-1, 1.5, Infinity, NaN, '3']) {
    assert.throws(() => analyzeReplay(makeReplay(1), { timelineLimit }), RangeError);
  }
});

test('no block means no last-block anchor', () => {
  const analysis = analyzeReplay(replayFromChunks([]));
  assert.equal(analysis.packet_count, 0);
  assert.deepEqual(analysis.packet_timeline_sample, []);
  assert.deepEqual(analysis.raw_anchors, []);
});

test('last-block hash, offsets, time and anchor order survive multiple compressed chunks', () => {
  const replay = replayFromChunks([
    { body: packet(1), compressed: true },
    { body: Buffer.concat([packet(2), packet(3)]), compressed: true },
    { body: packet(4), stream: 2, compressed: true },
  ]);
  const expected = [];
  rofl.walkBlocks(replay, (block, chunk) => expected.push({ block, chunk }), { strict: true });
  const { block, chunk } = expected.at(-1);
  const analysis = analyzeReplay(replay, { timelineLimit: 2 });
  const last = analysis.raw_anchors.at(-1);
  assert.equal(last.anchor_kind, 'last_raw_block');
  assert.equal(last.raw_payload_sha256, rofl.sha256(block.payload));
  assert.equal(last.replay_time_ms, block.timestamp_ms);
  assert.equal(last.raw_packet_ref.chunk_index, chunk.index);
  assert.equal(last.raw_packet_ref.decompressed_block_offset, block.offset);
  assert.equal(last.raw_packet_ref.decompressed_payload_offset, block.payload_offset);
  assert.deepEqual(analysis.raw_anchors.map((row) => row.anchor_kind), [
    'first_game_chunk', 'first_nonzero_timestamp', 'first_keyframe',
    'largest_raw_payload', 'last_raw_block',
  ]);
});

test('malformed later data does not replace the last successfully parsed block', () => {
  const replay = replayFromChunks([{ body: Buffer.concat([packet(1), Buffer.from([0])]) }]);
  const analysis = analyzeReplay(replay, { strict: false });
  assert.equal(analysis.block_errors.length, 1);
  assert.equal(analysis.raw_anchors.at(-1).packet_id, 1);
});

test('discarded timeline and last-block candidates are no longer hashed per packet', (t) => {
  const replay = makeReplay(1000);
  const native = rofl.sha256;
  const spy = t.mock.method(rofl, 'sha256', (value) => native(value));
  const modulePath = require.resolve('../src/analysis');
  const previous = require.cache[modulePath];
  delete require.cache[modulePath];
  t.after(() => { require.cache[modulePath] = previous; });
  const instrumented = require('../src/analysis');
  const result = instrumented.analyzeReplay(replay, { timelineLimit: 3, sampleStride: 1 });
  assert.equal(result.packet_count, 1000);
  // Three timeline rows; first-stream, first-positive-time, largest, and last anchors.
  assert.equal(spy.mock.callCount(), 7);
});
