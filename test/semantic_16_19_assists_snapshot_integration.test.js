'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { decodeSemanticReplay, getHeroAssistsSnapshotCandidates } = require('../src/semantic_api');
const { capabilityQuery, main } = require('../src/cli');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const CAPABILITY = 'hero_assists_snapshot';
const OUTPUT = 'hero_assists_snapshot_candidates';

// Exact-image byte anchors: f6 decodes to 0; c6 decodes to 3.
function packet(participantId, assists) {
  if (assists !== 0 && assists !== 3) throw new RangeError('fixture supports 0 or 3');
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  if (assists === 3) encodedBlob[1260 - 1 - 0x54] = 0xc6;
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
    ASSISTS: String(index === 0 ? 4 : 0),
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

test('API exposes observed assist-count keyframes without assist events', () => {
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].tail_gap_total, 1);
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  const rows = getHeroAssistsSnapshotCandidates(decoded);
  assert.deepEqual(rows.map((row) => row.assists_candidate), [3, ...Array(9).fill(0)]);
  assert.ok(rows.every((row) => row.confidence === 'CANDIDATE'
    && row.raw_packet_ref.packet_id === 0x0276
    && row.raw_packet_ref.replay_sha256 === replay.source_sha256));
  assert.equal(decoded.events.hero_assist_events, undefined);
});

test('capability query preflights ASSISTS and leaves packet framing unexecuted', () => {
  const replay = fixture();
  const row = capabilityQuery(replay).capabilities.find((item) => item.capability === CAPABILITY);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, OUTPUT);
  assert.deepEqual(row.missing_inputs, []);
  delete replay.tail.stats[3].ASSISTS;
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((item) => item.capability === CAPABILITY).missing_inputs,
  ['replay_tail_ASSISTS']);
});

test('selected CLI writes only assist snapshot candidates', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-16-19-assists-snapshot-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplay(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const events = JSON.parse(fs.readFileSync(path.join(replayDir, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [OUTPUT]);
  const jsonl = fs.readFileSync(path.join(replayDir, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(jsonl.length, 10);
  assert.equal(jsonl[0].assists_candidate, 3);
});
