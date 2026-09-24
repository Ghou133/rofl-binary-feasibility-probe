'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeSemanticReplay,
  getHeroChampionKillsSnapshotCandidates,
} = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_champion_kills_snapshot';
const OUTPUT = 'hero_champion_kills_snapshot_candidates';
const HERO_PARAM_FIRST = 0x400000ae;

// Exact-image byte anchors: f6 decodes to 0 and c6 decodes to 3.
// The wire blob is reversed before the two mirrored u32LE fields are read.
function payloadFor(kills) {
  if (kills !== 0 && kills !== 3) throw new RangeError('fixture supports 0 or 3');
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  if (kills === 3) {
    for (const offset of [0x4c, 0x33c]) {
      encodedBlob[1260 - 1 - offset] = 0xc6;
    }
  }
  return Buffer.concat([Buffer.from('1ca6e8', 'hex'), encodedBlob]);
}

function keyframePacket(participantId, kills) {
  const payload = payloadFor(kills);
  const header = Buffer.alloc(15);
  header[0] = 0x00;
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(HERO_PARAM_FIRST + participantId - 1, 11);
  return Buffer.concat([header, payload]);
}

function fixture() {
  const replay = replayFromChunks([{
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      keyframePacket(index + 1, index === 0 ? 3 : 0))),
  }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    CHAMPIONS_KILLED: String(index === 0 ? 4 : 0),
    MINIONS_KILLED: '0',
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

test('API exposes mirrored observed champion-kill snapshots as candidates only', () => {
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 10);
  assert.equal(decoded.capability_results[CAPABILITY].tail_gap_total, 1);
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  const events = getHeroChampionKillsSnapshotCandidates(decoded);
  assert.deepEqual(events.map((row) => row.champion_kills_candidate),
    [3, ...Array(9).fill(0)]);
  assert.ok(events.every((row) => row.confidence === 'CANDIDATE'
    && row.raw_packet_ref.packet_id === 0x0276
    && row.raw_packet_ref.replay_sha256 === replay.source_sha256));
  assert.equal(decoded.events.hero_kill_events, undefined);
});

test('capability query preflights CHAMPIONS_KILLED without packet decoding', () => {
  const replay = fixture();
  const { capabilityQuery } = require('../src/cli');
  const query = capabilityQuery(replay);
  const row = query.capabilities.find((entry) => entry.capability === CAPABILITY);
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, OUTPUT);
  assert.deepEqual(row.missing_inputs, []);
  delete replay.tail.stats[3].CHAMPIONS_KILLED;
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === CAPABILITY).missing_inputs,
  ['replay_tail_CHAMPIONS_KILLED']);
  replay.tail.stats[3].CHAMPIONS_KILLED = '-1';
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === CAPABILITY).invalid_inputs,
  ['replay_tail_CHAMPIONS_KILLED']);
});

test('missing kills tail leaves selected CS candidate usable after one keyframe scan', () => {
  const replay = fixture();
  delete replay.tail.stats[0].CHAMPIONS_KILLED;
  const chunks = replay.chunks;
  let traversalCount = 0;
  Object.defineProperty(replay, 'chunks', { get() {
    traversalCount += 1;
    return chunks;
  } });
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY, 'hero_minions_killed_snapshot'],
  });
  assert.equal(traversalCount, 1);
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.capability_results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), ['hero_minions_killed_snapshot_candidates']);
});

test('selected CLI writes candidate JSONL without confirmed kill events', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-champion-kills-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await require('../src/cli').main([
    'decode', input, '--events', CAPABILITY, '--out-dir', output,
  ]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 10);
  const events = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [OUTPUT]);
  const jsonl = fs.readFileSync(path.join(replayDirectory, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(jsonl.length, 10);
  assert.equal(jsonl[0].champion_kills_candidate, 3);
});
