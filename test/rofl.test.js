const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  CHUNK_HEADER_SIZE,
  RoflError,
  parseBlockAt,
  parseChunks,
  parseHeader,
  parseReplayFile,
  walkBlocks,
} = require('../src/rofl');
const { analyzeReplay } = require('../src/analysis');
const { parseArgs, parseTestSummary } = require('../src/cli');
const { EntityRegistry } = require('../src/entity');
const {
  buildAdcDeathRecord,
  buildCombatWindow,
  damageEvent,
  deathEvent,
  positionEvent,
  spellCastEvent,
} = require('../src/events');
const { outputHashes, writeJsonl } = require('../src/io');

test('Match Details input is accepted only by validate', () => {
  const validation = parseArgs(['validate', 'replay', '--details-dir', 'details']);
  assert.equal(validation.options.detailsDir, 'details');
  for (const command of ['decode', 'analyze', 'batch', 'inspect']) {
    assert.throws(
      () => parseArgs([command, 'replay', '--details-dir', 'details']),
      /only valid with validate/,
    );
  }
});

function syntheticHeader(version = '16.15.801.3452') {
  const versionBytes = Buffer.from(version, 'ascii');
  const buffer = Buffer.alloc(15 + versionBytes.length);
  Buffer.from('RIOT').copy(buffer, 0);
  buffer.writeUInt16LE(2, 4);
  buffer.writeUInt16LE(217, 6);
  Buffer.from([1, 2, 3, 4, 5, 6]).copy(buffer, 8);
  buffer[14] = versionBytes.length;
  versionBytes.copy(buffer, 15);
  return buffer;
}

function absoluteBlock(timestamp, packetId, param, payload) {
  const body = Buffer.alloc(1 + 4 + 4 + 2 + 4 + payload.length);
  let cursor = 0;
  body[cursor++] = 0;
  body.writeFloatLE(timestamp, cursor); cursor += 4;
  body.writeUInt32LE(payload.length, cursor); cursor += 4;
  body.writeUInt16LE(packetId, cursor); cursor += 2;
  body.writeUInt32LE(param, cursor); cursor += 4;
  Buffer.from(payload).copy(body, cursor);
  return body;
}

test('header parser reads the variable-length version', () => {
  const header = parseHeader(syntheticHeader());
  assert.equal(header.format_version, 2);
  assert.equal(header.field_u16_0x06, 217);
  assert.equal(header.version, '16.15.801.3452');
  assert.equal(header.patch, '16.15');
  assert.equal(header.size, 29);
});

test('header parser rejects a wrong magic', () => {
  const bytes = syntheticHeader();
  bytes[0] = 0;
  assert.throws(() => parseHeader(bytes), (error) => error instanceof RoflError && error.code === 'INVALID_MAGIC');
});

test('chunk parser enforces body bounds', () => {
  const bytes = Buffer.alloc(CHUNK_HEADER_SIZE + 2);
  bytes.writeUInt32LE(1, 0);
  bytes[4] = 2;
  bytes.writeUInt32LE(0x03000000, 5);
  bytes.writeUInt32LE(100, 9);
  bytes.writeUInt32LE(0, 13);
  assert.throws(() => parseChunks(bytes, 0, bytes.length), (error) => error.code === 'CHUNK_BOUNDS_ERROR');
});

test('block parser handles absolute and relative framing', () => {
  const first = absoluteBlock(1.5, 0x1234, 9, [1, 2, 3]);
  const second = Buffer.from([0xf0, 250, 0, 7]);
  const body = Buffer.concat([first, second]);
  const state = { timestamp: 0, packet_id: 0, param: 0 };
  const one = parseBlockAt(body, 0, state);
  const two = parseBlockAt(body, one.next_offset, state);
  assert.equal(one.packet_id, 0x1234);
  assert.equal(one.payload_length, 3);
  assert.equal(two.timestamp_ms, 1750);
  assert.equal(two.packet_id, 0x1234);
  assert.equal(two.param, 16);
});

test('block parser rejects truncated payloads', () => {
  const body = Buffer.alloc(1 + 4 + 4 + 2 + 4);
  body[0] = 0;
  body.writeFloatLE(0, 1);
  body.writeUInt32LE(10, 5);
  assert.throws(() => parseBlockAt(body, 0, { timestamp: 0, packet_id: 0, param: 0 }), (error) => error.code === 'BOUNDS_ERROR');
});

test('block walker validates uncompressed chunks in included streams', () => {
  const body = absoluteBlock(2.5, 0x1234, 7, [1, 2]);
  const replay = {
    buffer: body,
    chunks: [{
      chunk_id: 1,
      index: 0,
      offset: 0,
      body_offset: 0,
      body_end: body.length,
      body_length: body.length,
      uncompressed_length: body.length,
      is_compressed: false,
      stream_tag: 1,
    }],
  };
  const blocks = [];
  const result = walkBlocks(replay, (block) => blocks.push(block), { strict: true });
  assert.equal(result.block_count, 1);
  assert.equal(result.errors.length, 0);
  assert.equal(blocks[0].packet_id, 0x1234);
});

test('entity registry keeps raw entity and attribution separate', () => {
  const registry = new EntityRegistry();
  registry.register(42, { entity_type: 'pet', champion: null, attributed_champion: 'Lulu', confidence: 'INFERRED' });
  const resolved = registry.attributeSource(42);
  assert.equal(resolved.raw_source_entity.entity_type, 'pet');
  assert.equal(resolved.attributed_champion, 'Lulu');
  assert.equal(resolved.status, 'INFERRED');
  assert.equal(registry.resolve(99), null);
});

test('combat window emits fixed and heuristic windows', () => {
  const death = deathEvent({ replay_time_ms: 10000, victim_network_id: 7 });
  const damage = [
    damageEvent({ replay_time_ms: 7000, target_network_id: 7, amount: 10 }),
    damageEvent({ replay_time_ms: 8500, target_network_id: 7, amount: 20 }),
    damageEvent({ replay_time_ms: 9900, target_network_id: 7, amount: 30 }),
    damageEvent({ replay_time_ms: 9950, target_network_id: 8, amount: 999 }),
  ];
  const spells = [spellCastEvent({ replay_time_ms: 9000 })];
  const positions = [positionEvent({ replay_time_ms: 9500, network_id: 7, x: 1, y: 2 })];
  const window = buildCombatWindow(death, damage, spells, positions, { damageGapMs: 2000 });
  assert.equal(window.victim_network_id, 7);
  assert.equal(window.fixed.fixed_5s.damage_events.length, 3);
  assert.equal(window.heuristic.damage_events.length, 3);
  assert.ok(window.heuristic.damage_events.every((event) => event.target_network_id === 7));
  assert.equal(window.heuristic.start_ms, 7000);
  assert.equal(window.heuristic.duration_ms, 3000);
});

test('combat window leaves timing fields null without a verified death time', () => {
  const window = buildCombatWindow(deathEvent(), [damageEvent({ replay_time_ms: 100 })], [], []);
  assert.equal(window.death_time_ms, null);
  assert.equal(window.heuristic.start_ms, null);
  assert.equal(window.heuristic.duration_ms, null);
  assert.deepEqual(window.fixed.fixed_5s.damage_events, []);
});

test('ADC schema preserves unknown fields as null', () => {
  const record = buildAdcDeathRecord({ adc: 'Jinx' });
  assert.equal(record.adc, 'Jinx');
  assert.equal(record.death_time_ms, null);
  assert.deepEqual(record.attackers, []);
});

test('real Replay samples parse and expose packet blocks', { timeout: 120000 }, () => {
  const replayDir = path.resolve(__dirname, '..', 'replay');
  const files = fs.readdirSync(replayDir).filter((name) => name.endsWith('.rofl')).sort();
  assert.ok(files.length >= 1);
  for (const name of files) {
    const replay = parseReplayFile(path.join(replayDir, name));
    assert.equal(replay.header.version, '16.15.801.3452');
    assert.ok(replay.chunks.length > 0);
    let firstBlock = null;
    const result = walkBlocks(replay, (block) => {
      if (!firstBlock) firstBlock = block;
    });
    assert.ok(result.block_count > 0, name);
    assert.equal(result.errors.length, 0, name);
    assert.ok(firstBlock);
  }
});

test('real Replay golden anchor remains stable', { timeout: 120000 }, () => {
  const golden = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'real-replay-golden.json'), 'utf8'));
  const replay = parseReplayFile(path.resolve(__dirname, '..', golden.relative_path));
  assert.equal(replay.file_size, golden.file_size);
  assert.equal(replay.source_sha256, golden.sha256);
  assert.equal(replay.header.version, golden.version);
  assert.equal(replay.tail.metadata_length, golden.metadata_length);
  assert.equal(replay.chunks.length, golden.chunk_count);
  assert.deepEqual(replay.stream_counts, golden.stream_counts);
  let firstBlock = null;
  const result = walkBlocks(replay, (block, chunk) => {
    if (!firstBlock) {
      firstBlock = {
        chunk_index: chunk.index,
        chunk_id: chunk.chunk_id,
        stream: chunk.stream,
        block_offset: block.offset,
        payload_offset: block.payload_offset,
        packet_id: block.packet_id,
        timestamp_ms: block.timestamp_ms,
        payload_length: block.payload_length,
        payload_sha256: require('../src/rofl').sha256(block.payload),
      };
    }
  });
  assert.equal(result.block_count, golden.block_count);
  assert.equal(result.errors.length, 0);
  assert.deepEqual(firstBlock, golden.first_block);
});

test('analysis output is honest when no decoder profile exists', { timeout: 120000 }, () => {
  const file = path.join(path.resolve(__dirname, '..', 'replay'), fs.readdirSync(path.resolve(__dirname, '..', 'replay')).find((name) => name.endsWith('.rofl')));
  const analysis = analyzeReplay(parseReplayFile(file), { timelineLimit: 10, sampleStride: 1000 });
  assert.ok(analysis.packet_count > 0);
  assert.equal(analysis.decoded_packet_count, 0);
  assert.equal(analysis.events.death_events.length, 0);
  assert.equal(analysis.capabilities.find((row) => row.capability === 'hero death').status, 'UNVERIFIED');
  assert.ok(analysis.raw_anchors.length > 0);
});

test('JSONL serialization has one JSON object per line', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-test-'));
  const file = path.join(directory, 'rows.jsonl');
  writeJsonl(file, [{ a: 1 }, { a: 2 }]);
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
  assert.deepEqual(lines.map((line) => JSON.parse(line)), [{ a: 1 }, { a: 2 }]);
});

test('test summary parser reads Node test output', () => {
  const summary = parseTestSummary('\u001b[32mℹ tests 11\u001b[39m\nℹ pass 10\nℹ fail 1\n', 1);
  assert.equal(summary.total, 11);
  assert.equal(summary.passed, 10);
  assert.equal(summary.failed, 1);
  assert.equal(summary.exit_code, 1);
});

test('output hash manifest can exclude its self-reference', async () => {
  const directory = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'rofl-hash-'));
  fs.writeFileSync(path.join(directory, 'data.txt'), 'data', 'utf8');
  fs.writeFileSync(path.join(directory, 'manifest.json'), 'old', 'utf8');
  const hashes = await outputHashes(directory, { exclude: ['manifest.json'] });
  assert.deepEqual(Object.keys(hashes), ['data.txt']);
});
