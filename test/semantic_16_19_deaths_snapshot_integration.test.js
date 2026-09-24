'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeSemanticReplay,
  getHeroDeathsSnapshotCandidates,
} = require('../src/semantic_api');
const { capabilityQuery, main } = require('../src/cli');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const CAPABILITY = 'hero_deaths_snapshot';
const OUTPUT = 'hero_deaths_snapshot_candidates';

// Exact-image byte anchors: f6 decodes to 0; c6 decodes to 3.
function packet(participantId, deaths) {
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  if (deaths === 3) encodedBlob[1260 - 1 - 0x50] = 0xc6;
  else if (deaths !== 0) throw new RangeError('fixture supports 0 or 3');
  const payload = Buffer.concat([Buffer.from('1ca6e8', 'hex'), encodedBlob]);
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture() {
  const replay = replayFromChunks([{
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(index + 1, index === 0 ? 3 : 0))),
  }], '16.19.820.7193');
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 ? 4 : 0),
    MINIONS_KILLED: '0',
  }));
  replay.tail.metadata.gameLength = 2000;
  return replay;
}

function writeReplay(replay, outputPath) {
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

test('API exposes only observed HN death-count snapshots as candidates', () => {
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].tail_gap_total, 1);
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  const rows = getHeroDeathsSnapshotCandidates(decoded);
  assert.deepEqual(rows.map((row) => row.deaths_candidate), [3, ...Array(9).fill(0)]);
  assert.ok(rows.every((row) => row.confidence === 'CANDIDATE'
    && row.raw_packet_ref.packet_id === 0x0276
    && row.raw_packet_ref.replay_sha256 === replay.source_sha256));
  assert.equal(decoded.events.hero_death_events, undefined);
});

test('capability query preflights NUM_DEATHS without decoding packets', () => {
  const replay = fixture();
  const query = capabilityQuery(replay);
  const row = query.capabilities.find((item) => item.capability === CAPABILITY);
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.equal(row.output, OUTPUT);
  assert.deepEqual(row.missing_inputs, []);
  delete replay.tail.stats[3].NUM_DEATHS;
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((item) => item.capability === CAPABILITY).missing_inputs,
  ['replay_tail_NUM_DEATHS']);
  replay.tail.stats[3].NUM_DEATHS = '-1';
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((item) => item.capability === CAPABILITY).invalid_inputs,
  ['replay_tail_NUM_DEATHS']);
});

test('missing death tail preserves an independently selected CS snapshot', () => {
  const replay = fixture();
  delete replay.tail.stats[0].NUM_DEATHS;
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY, 'hero_minions_killed_snapshot'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.capability_results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), ['hero_minions_killed_snapshot_candidates']);
});

test('selected CLI writes candidate JSONL with no derived death events', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-deaths-snapshot-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplay(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 10);
  const events = JSON.parse(fs.readFileSync(path.join(replayDir, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [OUTPUT]);
  const jsonl = fs.readFileSync(path.join(replayDir, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(jsonl.length, 10);
  assert.equal(jsonl[0].deaths_candidate, 3);
});
