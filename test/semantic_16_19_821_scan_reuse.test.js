'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { decodeHeroDeathCandidates821 } = require('../src/decoders/rofl_16_19_821_7343');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const CAPABILITIES = ['hero_death', 'hero_deaths_snapshot', 'hero_level_state'];

function shortPacket(id, param, payload) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(1, 1);
  header[5] = payload.length;
  header.writeUInt16LE(id, 6);
  header.writeUInt32LE(param >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function snapshotPacket(participant, deaths, timeMs) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  payload[1182] = deaths === 0 ? 0x97 : 0xcc;
  payload[374] = deaths === 0 ? 0x97 : 0xcc;
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ unknownLevel = false, damagedStart = false, damagedGame = false } = {}) {
  const game = Buffer.concat([
    shortPacket(0x0259, 0x400000ae, Buffer.from('121017d7d7', 'hex')),
    shortPacket(0x0438, 0x400000ae, Buffer.alloc(13)),
    shortPacket(0x031b, 0, Buffer.alloc(12)),
    shortPacket(0x03d4, 0, Buffer.alloc(3)),
    ...Array.from({ length: 10 }, (_, index) => shortPacket(
      0x0197, 0x400000ae + index,
      unknownLevel && index === 0 ? Buffer.from([0xfa, 0x70]) : Buffer.from([0xe5]))),
  ]);
  const chunks = [
    { stream: 1, compressed: true, body: game },
    ...[0, 1].map((frame) => ({ stream: 2, compressed: true,
      body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
        snapshotPacket(index + 1, frame === 1 && index === 0 ? 1 : 0,
          frame * 1000))),
    })),
    ...(damagedStart ? [{ stream: 3, compressed: true, body: Buffer.from([0x10]) }] : []),
    ...(damagedGame ? [{ stream: 1, compressed: true, body: Buffer.from([0x10]) }] : []),
  ];
  const replay = replayFromChunks(chunks, BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
    Missions_MinionsKilled: index === 0 ? '1' : '0',
    LEVEL: unknownLevel && index === 0 ? '20' : '2',
  }));
  return replay;
}

function writeWithTail(replay, filePath) {
  const source = replay.buffer;
  const originalMetadataLength = source.readUInt32LE(source.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    ...replay.tail.metadata, statsJson: JSON.stringify(replay.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(filePath, Buffer.concat([
    source.subarray(0, source.length - originalMetadataLength - 4), metadata, trailer,
  ]));
}

function countDecompressions(t) {
  const original = zlib.zstdDecompressSync;
  let count = 0;
  t.mock.method(zlib, 'zstdDecompressSync', (...args) => {
    count += 1;
    return original(...args);
  });
  return () => count;
}

test('821 standalone combined API scans each compressed chunk once', (t) => {
  const replay = fixture();
  const decompressions = countDecompressions(t);
  const decoded = decodeSemanticReplay(replay, { capabilities: CAPABILITIES });
  assert.equal(decompressions(), 3);
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.deepEqual(CAPABILITIES.map((name) => decoded.capability_results[name].status),
    ['CANDIDATE', 'CANDIDATE', 'CANDIDATE']);
  assert.deepEqual(CAPABILITIES.map((name) => decoded.capability_results[name].event_count),
    [1, 20, 10]);
  assert.equal(decoded.events.hero_death_candidates[0].raw_packet_ref.replay_sha256,
    replay.source_sha256);
  assert.equal(decoded.events.hero_deaths_snapshot_candidates[10].deaths_candidate, 1);
});

test('821 timer and mission snapshots reuse the same bounded route scan', (t) => {
  const replay = fixture();
  const decompressions = countDecompressions(t);
  const selected = ['hero_death', 'hero_death_timer',
    'hero_deaths_snapshot', 'hero_missions_minions_killed_snapshot'];
  const decoded = decodeSemanticReplay(replay, { capabilities: selected });
  assert.equal(decompressions(), 3);
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.deepEqual(selected.map((name) => decoded.capability_results[name].event_count),
    [1, 1, 20, 20]);
  assert.equal(decoded.events.hero_death_timer_candidates[0].timer_seconds_candidate, 12);
  assert.equal(decoded.events.hero_missions_minions_killed_snapshot_candidates[10]
    .missions_minions_killed_candidate, 1);
});

test('821 CLI reuses its analyzer walk for all selected candidates', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-scan-reuse-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  writeWithTail(fixture(), filePath);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(filePath, {
    semantic: true, events: CAPABILITIES, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(decompressions(), 3);
  assert.equal(parsed.analysis.block_errors.length, 0);
  assert.equal(parsed.analysis.decoder.status, 'CANDIDATE');
  assert.deepEqual(CAPABILITIES.map((name) =>
    parsed.analysis.semantic.capability_results[name].event_count), [1, 20, 10]);
});

test('821 single-capability CLI retains only selected rows and still walks once', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-single-scan-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  writeWithTail(fixture(), filePath);
  const decompressions = countDecompressions(t);
  const parsed = parseOne(filePath, {
    semantic: true, events: ['hero_level_state'], strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(decompressions(), 3);
  assert.deepEqual(Object.keys(parsed.analysis.events), ['hero_level_state_candidates']);
});

test('821 selected-only token stays bound to its Replay and copied packet rows', () => {
  const replay = fixture();
  const token = collect821Routes(replay, ['hero_death']);
  const first = rowsFor821Capability(replay, token, 'hero_death');
  assert.equal(first.rows.length, 4);
  const originalByte = first.rows[0].block.payload[0];
  first.rows[0].block.payload[0] ^= 1;
  assert.equal(rowsFor821Capability(replay, token, 'hero_death').rows[0].block.payload[0],
    originalByte);
  assert.match(rowsFor821Capability(replay, token, 'hero_deaths_snapshot').error,
    /not selected/);
  assert.match(rowsFor821Capability(fixture(), token, 'hero_death').error,
    /different Replay/);
  replay.buffer[0] ^= 1;
  assert.match(rowsFor821Capability(replay, token, 'hero_death').error,
    /Replay source integrity failed/);
  const rejected = decodeHeroDeathCandidates821(replay, token);
  assert.equal(rejected.status, 'DECODE_FAILED');
  assert.match(rejected.error, /Replay source integrity failed/);
});

test('821 OnEvent packet shapes stay separate in the shared scan', () => {
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat([17, 29, 44, 60, 104, 116].map((length) =>
      shortPacket(0x040a, 0x400000ae, Buffer.alloc(length)))) },
    { stream: 2, body: Buffer.concat([17, 29, 60, 104, 116].map((length) =>
      shortPacket(0x040a, 0x400000ae, Buffer.alloc(length)))) },
  ], BUILD);
  const token = collect821Routes(replay, [
    'hero_assist', 'params_heal_packet', 'shielding_params_packet_pair',
    'stealth_event_packet',
    'champion_die_event_packet',
    'champion_kill_event_packet',
  ]);
  assert.deepEqual(rowsFor821Capability(replay, token, 'hero_assist').rows
    .map(({ block }) => block.payload_length), [44]);
  assert.deepEqual(rowsFor821Capability(replay, token, 'params_heal_packet').rows
    .map(({ block }) => block.payload_length), [60, 60]);
  assert.deepEqual(rowsFor821Capability(replay, token, 'shielding_params_packet_pair').rows
    .map(({ block }) => block.payload_length), [29, 29]);
  assert.deepEqual(rowsFor821Capability(replay, token, 'stealth_event_packet').rows
    .map(({ block }) => block.payload_length), [17, 17]);
  assert.deepEqual(rowsFor821Capability(replay, token, 'champion_die_event_packet').rows
    .map(({ block }) => block.payload_length), [116, 116]);
  assert.deepEqual(rowsFor821Capability(replay, token, 'champion_kill_event_packet').rows
    .map(({ block }) => block.payload_length), [104, 104]);
});

test('821 out-of-range level retains independent results and a bad start chunk blocks all', (t) => {
  const unknown = fixture({ unknownLevel: true });
  const decompressions = countDecompressions(t);
  const partial = decodeSemanticReplay(unknown, { capabilities: CAPABILITIES });
  assert.equal(decompressions(), 3);
  assert.equal(partial.status, 'PARTIAL');
  assert.equal(partial.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(partial.capability_results.hero_deaths_snapshot.status, 'CANDIDATE');
  assert.equal(partial.capability_results.hero_level_state.status, 'DECODE_FAILED');
  assert.equal(partial.capability_results.hero_level_state.rejected_packet_ref.raw_payload_hex,
    'fa70');

  const damaged = fixture({ damagedStart: true });
  const failed = decodeSemanticReplay(damaged, { capabilities: CAPABILITIES });
  assert.deepEqual(CAPABILITIES.map((name) => failed.capability_results[name].status),
    ['DECODE_FAILED', 'DECODE_FAILED', 'DECODE_FAILED']);
  assert.equal(failed.events, null);
});

test('821 standalone API retains valid snapshots after damaged game framing', () => {
  const damaged = fixture({ damagedGame: true });
  const decoded = decodeSemanticReplay(damaged, { capabilities: CAPABILITIES });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_death.status, 'DECODE_FAILED');
  assert.equal(decoded.capability_results.hero_level_state.status, 'DECODE_FAILED');
  assert.equal(decoded.capability_results.hero_deaths_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.events.hero_deaths_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_death_candidates, undefined);
  assert.equal(decoded.events.hero_level_state_candidates, undefined);
});

test('821 CLI framing gate rejects candidate rows before using an analyzer token', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-framing-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'damaged.rofl');
  writeWithTail(fixture({ damagedStart: true }), filePath);
  const parsed = parseOne(filePath, {
    semantic: true, events: CAPABILITIES, strict: false, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.block_errors.length, 1);
  assert.equal(parsed.analysis.decoder.status, 'FRAMING_FAILED');
  assert.deepEqual(parsed.analysis.events, {});
});
