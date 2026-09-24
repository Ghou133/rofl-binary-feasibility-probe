'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeSemanticReplay,
  getHeroGoldEarnedSnapshotCandidates,
} = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_gold_earned_snapshot';
const OUTPUT = 'hero_gold_earned_snapshot_candidates';
const HERO_PARAM_FIRST = 0x400000ae;

// Exact-image inverse anchors: f6f620cc decodes to f32LE 500, and
// f63c2ecc decodes to f32LE 503.25. The encoded blob is reversed.
function heroStatsPayload(goldEarned) {
  const encodedFloat = {
    500: 'f6f620cc',
    503.25: 'f63c2ecc',
  }[goldEarned];
  if (!encodedFloat) throw new RangeError('synthetic fixture supports only 500 or 503.25');
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  const bytes = Buffer.from(encodedFloat, 'hex');
  for (let index = 0; index < bytes.length; index += 1) {
    encodedBlob[1260 - 1 - (0x38 + index)] = bytes[index];
  }
  return Buffer.concat([Buffer.from('1ca6e8', 'hex'), encodedBlob]);
}

function keyframePacket(timestampMs, participantId, goldEarned) {
  const payload = heroStatsPayload(goldEarned);
  const header = Buffer.alloc(15);
  header[0] = 0x00;
  header.writeFloatLE(timestampMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(HERO_PARAM_FIRST + participantId - 1, 11);
  return Buffer.concat([header, payload]);
}

function replayWithKeyframe() {
  const replay = replayFromChunks([{
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      keyframePacket(1000, index + 1, index === 0 ? 503.25 : 500))),
    stream: 2,
  }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    GOLD_EARNED: String(index === 0 ? 505 : 500),
    MINIONS_KILLED: '0',
    EXP: '0',
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

test('selected API exposes observed raw f32 gold snapshots with replay-bound refs only', () => {
  const replay = replayWithKeyframe();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.runtime_image_used, false);
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 10);
  assert.equal(decoded.capability_results[CAPABILITY].keyframe_timestamp_count, 1);
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  const events = getHeroGoldEarnedSnapshotCandidates(decoded);
  assert.equal(events.length, 10);
  assert.deepEqual(events.map((row) => row.gold_earned_candidate),
    [503.25, ...Array(9).fill(500)]);
  assert.deepEqual(events.map((row) => row.participant_id_candidate),
    Array.from({ length: 10 }, (_, index) => index + 1));
  assert.ok(events.every((row) => row.confidence === 'CANDIDATE'
    && row.observation_kind === 'KEYFRAME_SNAPSHOT'
    && row.raw_packet_ref.packet_id === 0x0276
    && row.raw_packet_ref.replay_sha256 === replay.source_sha256
    && row.raw_packet_ref.raw_payload_sha256));
  assert.equal(decoded.events.hero_gold_earned_events, undefined);
  assert.equal(decoded.events.gold_income_events, undefined);
});

test('CLI capabilities checks GOLD_EARNED tail without reading packet framing', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-gold-earned-capabilities-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const replay = replayWithKeyframe();
  writeReplayWithTailStats(replay, input);
  let output = '';
  t.mock.method(process.stdout, 'write', (chunk) => { output += String(chunk); return true; });
  const cli = require('../src/cli');
  assert.equal(await cli.main(['capabilities', input, '--json']), 0);
  const query = JSON.parse(output);
  const row = query.capabilities.find((capability) => capability.capability === CAPABILITY);
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, OUTPUT);
  assert.equal(row.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(row.missing_inputs, []);
  assert.deepEqual(row.invalid_inputs, []);
  assert.equal(row.required_inputs.find((inputRow) => inputRow.name === 'replay_tail_GOLD_EARNED').status,
    'PRESENT_UNVALIDATED');
  delete replay.tail.stats[3].GOLD_EARNED;
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((capability) => capability.capability === CAPABILITY).missing_inputs,
  ['replay_tail_GOLD_EARNED']);
  replay.tail.stats[3].GOLD_EARNED = '-1';
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((capability) => capability.capability === CAPABILITY).invalid_inputs,
  ['replay_tail_GOLD_EARNED']);
});

test('selected CLI writes candidate-only gold JSONL', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-gold-earned-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(replayWithKeyframe(), input);
  assert.equal(await require('../src/cli').main([
    'decode', input, '--events', CAPABILITY, '--out-dir', output,
  ]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.capability_runs[0].capability_results[CAPABILITY].status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.runtime_image_used, false);
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 10);
  const events = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [OUTPUT]);
  assert.equal(events[OUTPUT].length, 10);
  const jsonl = fs.readFileSync(path.join(replayDirectory, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(jsonl.length, 10);
  assert.equal(jsonl[0].gold_earned_candidate, 503.25);
  assert.equal(jsonl[0].confidence, 'CANDIDATE');
  assert.equal(jsonl[0].raw_packet_ref.packet_id, 0x0276);
});

test('missing gold tail leaves independently selected CS and XP candidates usable', () => {
  const replay = replayWithKeyframe();
  delete replay.tail.stats[0].GOLD_EARNED;
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY, 'hero_minions_killed_snapshot', 'hero_experience_snapshot'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(getHeroGoldEarnedSnapshotCandidates(decoded), null);
  assert.equal(decoded.capability_results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_experience_snapshot.status, 'CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events),
    ['hero_minions_killed_snapshot_candidates', 'hero_experience_snapshot_candidates']);
  assert.equal(decoded.events.hero_minions_killed_snapshot_candidates.length, 10);
  assert.equal(decoded.events.hero_experience_snapshot_candidates.length, 10);
});

test('three selected HeroStats fields share one keyframe traversal', () => {
  const replay = replayWithKeyframe();
  const chunks = replay.chunks;
  let chunkTraversalCount = 0;
  Object.defineProperty(replay, 'chunks', { get() {
    chunkTraversalCount += 1;
    return chunks;
  } });
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['hero_minions_killed_snapshot', 'hero_experience_snapshot', CAPABILITY],
  });
  assert.equal(chunkTraversalCount, 1);
  assert.equal(decoded.capability_results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_experience_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.events.hero_minions_killed_snapshot_candidates.length, 10);
  assert.equal(decoded.events.hero_experience_snapshot_candidates.length, 10);
  assert.equal(decoded.events[OUTPUT].length, 10);
});
