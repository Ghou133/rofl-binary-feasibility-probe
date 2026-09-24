'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');

const { parseReplayFile } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { parseOne } = require('../src/cli');
const {
  collectCandidateRoutes,
  decodeHeroLevelStateCandidates,
} = require('../src/decoders/rofl_16_19_820_7193');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_deaths_snapshot';
const OUTPUT = 'hero_deaths_snapshot_candidates';

// In the exact HN HeroStats byte inverse, f6 decodes to 0 and c6 to 3.
function heroStatsPayload(deaths) {
  if (deaths !== 0 && deaths !== 3) throw new RangeError('fixture supports 0 or 3');
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  if (deaths === 3) encodedBlob[1260 - 1 - 0x50] = 0xc6;
  return Buffer.concat([Buffer.from('1ca6e8', 'hex'), encodedBlob]);
}

function packetFor(participantId, deaths) {
  const payload = heroStatsPayload(deaths);
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function levelPacketFor(participantId) {
  const payload = Buffer.from('5b', 'hex');
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x02b3, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function compressedReplay({ malformed = false } = {}) {
  const replay = replayFromChunks([{
    stream: 2,
    compressed: true,
    body: Buffer.concat([
      ...Array.from({ length: 10 }, (_, index) =>
        packetFor(index + 1, index === 0 ? 3 : 0)),
      ...(malformed ? [Buffer.from([0x10])] : []),
    ]),
  }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 ? 4 : 0),
  }));
  replay.tail.metadata.gameLength = 2000;
  return replay;
}

function combinedCompressedReplay({ heroStats = true, malformedGame = false } = {}) {
  const gameBody = Buffer.concat([
    ...Array.from({ length: 10 }, (_, index) => levelPacketFor(index + 1)),
    ...(malformedGame ? [Buffer.from([0x10])] : []),
  ]);
  const chunks = [{ stream: 1, compressed: true, body: gameBody }];
  if (heroStats) chunks.push({ stream: 2, compressed: true, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) => packetFor(index + 1, index === 0 ? 3 : 0)),
  ) });
  const replay = replayFromChunks(chunks, BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    LEVEL: '1', NUM_DEATHS: String(index === 0 ? 4 : 0),
  }));
  replay.tail.metadata.gameLength = 2000;
  return replay;
}

function writeReplayWithTailStats(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    ...replay.tail.metadata,
    statsJson: JSON.stringify(replay.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

function countDecompressions(t) {
  const original = zlib.zstdDecompressSync;
  let calls = 0;
  t.mock.method(zlib, 'zstdDecompressSync', (...args) => {
    calls += 1;
    return original(...args);
  });
  return () => calls;
}

test('16.19 CLI analysis reuses its compressed keyframe scan for selected death snapshots', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-scan-reuse-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  writeReplayWithTailStats(compressedReplay(), input);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(input, {
    events: [CAPABILITY], semantic: true, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  const { analysis } = parsed;
  assert.equal(analysis.block_errors.length, 0);
  assert.equal(analysis.packet_count, 10);
  assert.equal(analysis.decoder.status, 'CANDIDATE');
  assert.equal(analysis.semantic.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(analysis.semantic.capability_results[CAPABILITY].event_count, 10);
  assert.deepEqual(Object.keys(analysis.events), [OUTPUT]);
  assert.deepEqual(analysis.events[OUTPUT].map((row) => row.deaths_candidate),
    [3, ...Array(9).fill(0)]);
  assert.equal(analysis.events[OUTPUT][0].confidence, 'CANDIDATE');
  assert.equal(analysis.events[OUTPUT][0].raw_packet_ref.packet_id, 0x0276);
  assert.equal(analysis.events[OUTPUT][0].raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(analysis.events[OUTPUT][0].raw_packet_ref.replay_sha256,
    analysis.replay_sha256);
  assert.equal(analysis.events[OUTPUT][0].raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(heroStatsPayload(3)).digest('hex'));
  assert.equal(decompressions(), 1);
});

test('standalone semantic API still scans a compressed replay without the CLI collector', (t) => {
  const replay = compressedReplay();
  const decompressions = countDecompressions(t);
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 10);
  assert.deepEqual(decoded.events[OUTPUT].map((row) => row.deaths_candidate),
    [3, ...Array(9).fill(0)]);
  assert.equal(decoded.events[OUTPUT][0].raw_packet_ref.replay_sha256,
    replay.source_sha256);
  assert.equal(decompressions(), 1);
});

test('a damaged keyframe never turns precollected rows into candidate output', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-scan-damaged-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'damaged-16.19.rofl');
  writeReplayWithTailStats(compressedReplay({ malformed: true }), input);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(input, {
    events: [CAPABILITY], semantic: true, strict: false, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.block_errors.length, 1);
  assert.equal(parsed.analysis.decoder.status, 'FRAMING_FAILED');
  assert.equal(parsed.analysis.semantic.capability_results[CAPABILITY].status, 'DECODE_FAILED');
  assert.deepEqual(parsed.analysis.events, {});
  assert.equal(decompressions(), 1);
});

test('16.19 CLI reuses one compressed game scan for selected level state', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-game-reuse-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  writeReplayWithTailStats(combinedCompressedReplay({ heroStats: false }), input);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(input, {
    events: ['hero_level_state'], semantic: true, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.decoder.status, 'CANDIDATE');
  assert.equal(parsed.analysis.semantic.capability_results.hero_level_state.event_count, 10);
  assert.equal(parsed.analysis.events.hero_level_state_candidates.length, 10);
  assert.equal(parsed.analysis.events.hero_level_state_candidates[0].raw_packet_ref.replay_sha256,
    parsed.analysis.replay_sha256);
  assert.equal(decompressions(), 1);
});

test('mixed 16.19 CLI selection reuses both game and HeroStats compressed chunks', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-mixed-reuse-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  writeReplayWithTailStats(combinedCompressedReplay(), input);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(input, {
    events: ['hero_level_state', CAPABILITY],
    semantic: true, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.decoder.status, 'CANDIDATE');
  assert.equal(parsed.analysis.semantic.capability_results.hero_level_state.event_count, 10);
  assert.equal(parsed.analysis.semantic.capability_results[CAPABILITY].event_count, 10);
  assert.equal(decompressions(), 2);
});

test('damaged game framing cannot publish precollected level candidates', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-game-damaged-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'damaged-16.19.rofl');
  writeReplayWithTailStats(combinedCompressedReplay({
    heroStats: false, malformedGame: true,
  }), input);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(input, {
    events: ['hero_level_state'], semantic: true, strict: false, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.block_errors.length, 1);
  assert.equal(parsed.analysis.decoder.status, 'FRAMING_FAILED');
  assert.deepEqual(parsed.analysis.events, {});
  assert.equal(decompressions(), 1);
});

test('candidate route scan exposes only a replay-bound opaque token', () => {
  const replay = combinedCompressedReplay({ heroStats: false });
  const token = collectCandidateRoutes(replay);
  assert.equal(token.error, null);
  assert.equal(Object.isFrozen(token), true);
  assert.equal(Object.hasOwn(token, 'routes'), false);
  assert.equal(decodeHeroLevelStateCandidates(replay, token).status, 'CANDIDATE');
  const forged = { ...token, routes: new Map([[0x02b3, []]]) };
  const rejected = decodeHeroLevelStateCandidates(replay, forged);
  assert.equal(rejected.status, 'DECODE_FAILED');
  assert.equal(rejected.events, null);
});

test('standalone route token retains original bytes and chunk offsets after Replay mutation', () => {
  const replay = replayFromChunks([{
    stream: 1, compressed: false, body: levelPacketFor(1),
  }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, () => ({ LEVEL: '2' }));
  const token = collectCandidateRoutes(replay);
  const baseline = decodeHeroLevelStateCandidates(replay, token);
  assert.equal(baseline.status, 'CANDIDATE');
  assert.equal(baseline.events[0].level_after_candidate, 1);
  const originalChunkOffset = replay.chunks[0].offset;
  replay.buffer[replay.chunks[0].body_offset + 15] = 0x6d;
  replay.chunks[0].offset = originalChunkOffset + 42;
  const afterMutation = decodeHeroLevelStateCandidates(replay, token);
  assert.equal(afterMutation.status, 'CANDIDATE');
  assert.deepEqual(afterMutation.events, baseline.events);
  assert.equal(afterMutation.events[0].raw_packet_ref.chunk_file_offset,
    originalChunkOffset);
});
