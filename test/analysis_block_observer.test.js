'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { analyzeReplay } = require('../src/analysis');
const { packet, replayFromChunks } = require('./helpers/synthetic_replay');

function twoStreamReplay() {
  return replayFromChunks([
    { stream: 1, compressed: true, body: Buffer.concat([
      packet(1, Buffer.from('a1', 'hex')),
      packet(2, Buffer.from('b2', 'hex')),
    ]) },
    { stream: 2, compressed: true, body: packet(3, Buffer.from('c3', 'hex')) },
  ], '16.19.820.7193');
}

test('optional raw-block observer sees each framed block without changing analysis output', () => {
  const replay = twoStreamReplay();
  const baseline = analyzeReplay(replay, { timelineLimit: 2, strict: true });
  const observed = [];
  const withObserver = analyzeReplay(replay, {
    timelineLimit: 2,
    strict: true,
    onBlock(block, chunk) {
      observed.push({
        packet_id: block.packet_id,
        stream: chunk.stream,
        payload_hex: block.payload.toString('hex'),
        chunk_index: chunk.index,
      });
    },
  });
  assert.deepEqual(observed, [
    { packet_id: 1, stream: 'game_chunk', payload_hex: 'a1', chunk_index: 0 },
    { packet_id: 2, stream: 'game_chunk', payload_hex: 'b2', chunk_index: 0 },
    { packet_id: 3, stream: 'keyframe', payload_hex: 'c3', chunk_index: 1 },
  ]);
  assert.equal(withObserver.packet_count, 3);
  for (const key of ['packet_type_inventory', 'packet_timeline_sample',
    'raw_anchors', 'chunk_inventory', 'block_errors', 'events', 'event_counts']) {
    assert.deepEqual(withObserver[key], baseline[key], key);
  }
  assert.equal(Object.hasOwn(withObserver, 'onBlock'), false);
  assert.equal(Object.hasOwn(withObserver, 'observed_blocks'), false);
});

test('observer receives valid preceding blocks while a malformed block remains a framing error', () => {
  const replay = replayFromChunks([{ body: Buffer.concat([
    packet(1), Buffer.from([0x10]),
  ]) }]);
  const seen = [];
  const result = analyzeReplay(replay, { onBlock(block) { seen.push(block.packet_id); } });
  assert.deepEqual(seen, [1]);
  assert.equal(result.packet_count, 1);
  assert.equal(result.block_errors.length, 1);
});

test('observer exceptions propagate instead of appearing as replay framing failures', () => {
  const marker = new Error('raw observer failed');
  const replay = twoStreamReplay();
  assert.throws(() => analyzeReplay(replay, {
    strict: false,
    onBlock() { throw marker; },
  }), (error) => error === marker);
});

test('observer option must be a function when supplied', () => {
  assert.throws(() => analyzeReplay(twoStreamReplay(), { onBlock: 1 }),
    /onBlock must be a function/);
});
