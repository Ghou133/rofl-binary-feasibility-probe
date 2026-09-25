'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';
const SELECTED = ['hero_ward_stats_snapshot', 'hero_inventory_broadcast_packet'];
const ASSOCIATION = 'ward_inventory_keyframe_pair';
const PAIR_EVENTS = 'ward_inventory_keyframe_pair_candidates';
const WARD_EVENTS = 'hero_ward_stats_snapshot_candidates';

function packet(packetId, rawParam, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(0, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayBytes() {
  const ward = Buffer.alloc(1263, 0x97);
  ward.set([0x67, 0x00, 0xde]);
  const broadcast = Buffer.alloc(79);
  broadcast[0] = 0x1e;
  const keyframe = Buffer.concat([
    ...Array.from({ length: 10 }, (_, index) =>
      packet(0x0357, 0x400000ae + index, broadcast)),
    ...Array.from({ length: 10 }, (_, index) =>
      packet(0x0089, 0x400000ae + index, ward)),
  ]);
  const generated = replayFromChunks([{ stream: 2, body: keyframe }], BUILD);
  const original = generated.buffer;
  const trailerOffset = original.length - 4;
  const metadataOffset = trailerOffset - original.readUInt32LE(trailerOffset);
  const stats = Array.from({ length: 10 }, () => ({
    WARD_PLACED_DETECTOR: '0', WARD_KILLED: '0', WARD_PLACED: '0',
  }));
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000, statsJson: JSON.stringify(stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return Buffer.concat([original.subarray(0, metadataOffset), metadata, trailer]);
}

test('selected API preserves exact-821 ward rows when Broadcast needs the runtime image', () => {
  const { decodeSemanticReplay } = require('../src/semantic_api');
  const replay = parseReplayBuffer(replayBytes(),
    path.resolve('synthetic-821-ward-broadcast-pair.rofl'));
  const decoded = decodeSemanticReplay(replay, { capabilities: SELECTED });

  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_ward_stats_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_ward_stats_snapshot.event_count, 10);
  assert.equal(decoded.events[WARD_EVENTS].length, 10);
  assert.ok(decoded.events[WARD_EVENTS].every((row) =>
    row.confidence === 'CANDIDATE' && row.raw_packet_ref.packet_id === 0x0089));
  assert.equal(decoded.capability_results.hero_inventory_broadcast_packet.status,
    'MISSING_INPUT');
  assert.equal(decoded.capability_results.hero_inventory_broadcast_packet.missing_input,
    'runtime_image');
  assert.equal(decoded.events.hero_inventory_broadcast_packet_candidates, undefined);
  assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(decoded.candidate_associations[ASSOCIATION].event_count, null);
  assert.equal(decoded.events[PAIR_EVENTS], undefined);
});

test('selected CLI records a partial run and writes only the independent ward JSONL', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-ward-pair-partial-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, 'sample.rofl');
  const output = path.join(directory, 'output');
  fs.writeFileSync(inputPath, replayBytes());

  const exitCode = await require('../src/cli').main([
    'decode', inputPath, '--events', SELECTED.join(','), '--event-jsonl-only',
    '--out-dir', output,
  ]);
  assert.equal(exitCode, 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'PARTIAL');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results.hero_ward_stats_snapshot.status, 'CANDIDATE');
  assert.equal(semantic.capability_results.hero_inventory_broadcast_packet.status,
    'MISSING_INPUT');
  assert.equal(semantic.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(semantic.events?.[PAIR_EVENTS], undefined);
  assert.equal(fs.existsSync(path.join(replayDirectory, `${PAIR_EVENTS}.jsonl`)), false);
  const wardRows = fs.readFileSync(path.join(replayDirectory, `${WARD_EVENTS}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(wardRows.length, 10);
  assert.ok(wardRows.every((row) => row.confidence === 'CANDIDATE'));
});
