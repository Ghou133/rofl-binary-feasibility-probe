'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeSemanticReplay,
  getHeroGoldSpentSnapshotCandidates,
} = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_gold_spent_snapshot';
const OUTPUT = 'hero_gold_spent_snapshot_candidates';
const HERO_PARAM_FIRST = 0x400000ae;

// Exact-image inverse anchors: f6f676cc decodes to f32LE 200 and f6f60075
// to f32LE 100. The encoded HeroStats blob is reversed before field reads.
function heroStatsPayload(goldSpent) {
  const encodedSpent = {
    0: 'f6f6f6f6',
    100: 'f6f60075',
    200: 'f6f676cc',
  }[goldSpent];
  if (!encodedSpent) throw new RangeError('synthetic fixture supports only 0, 100 or 200');
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  for (const [offset, encoded] of [[0x34, encodedSpent], [0x38, 'f6f620cc']]) {
    const bytes = Buffer.from(encoded, 'hex');
    for (let index = 0; index < bytes.length; index += 1) {
      encodedBlob[1260 - 1 - (offset + index)] = bytes[index];
    }
  }
  return Buffer.concat([Buffer.from('1ca6e8', 'hex'), encodedBlob]);
}

function keyframePacket(timestampMs, participantId, goldSpent) {
  const payload = heroStatsPayload(goldSpent);
  const header = Buffer.alloc(15);
  header[0] = 0x00;
  header.writeFloatLE(timestampMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(HERO_PARAM_FIRST + participantId - 1, 11);
  return Buffer.concat([header, payload]);
}

function replayWithDecrease() {
  const body = Buffer.concat([1000, 2000].flatMap((time, timeIndex) =>
    Array.from({ length: 10 }, (_, index) => keyframePacket(time, index + 1,
      index === 0 ? (timeIndex === 0 ? 200 : 100) : 0))));
  const replay = replayFromChunks([{ body, stream: 2 }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    GOLD_SPENT: String(index === 0 ? 90 : 0),
    GOLD_EARNED: '500',
    MINIONS_KILLED: '0',
    EXP: '0',
  }));
  replay.tail.metadata.gameLength = 3000;
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

test('selected API preserves observed gold-spent decrease and negative terminal difference', () => {
  const replay = replayWithDecrease();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.runtime_image_used, false);
  const result = decoded.capability_results[CAPABILITY];
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.tail_differences[0].tail_minus_last_snapshot_candidate, -10);
  assert.equal(result.tail_difference_total, -10);
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  const events = getHeroGoldSpentSnapshotCandidates(decoded);
  assert.equal(events.length, 20);
  assert.equal(events[0].gold_spent_candidate, 200);
  assert.equal(events[10].gold_spent_candidate, 100);
  assert.deepEqual(events.map((row) => row.participant_id_candidate),
    [
      ...Array.from({ length: 10 }, (_, index) => index + 1),
      ...Array.from({ length: 10 }, (_, index) => index + 1),
    ]);
  assert.ok(events.every((row) => row.confidence === 'CANDIDATE'
    && row.observation_kind === 'KEYFRAME_SNAPSHOT'
    && row.raw_packet_ref.packet_id === 0x0276
    && row.raw_packet_ref.replay_sha256 === replay.source_sha256
    && row.raw_packet_ref.raw_payload_sha256));
  assert.equal(decoded.events.gold_spent_events, undefined);
  assert.equal(decoded.events.gold_transaction_events, undefined);
  assert.equal(decoded.events.item_purchase_events, undefined);
});

test('CLI capabilities checks GOLD_SPENT tail without packet decoding', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-gold-spent-capabilities-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const replay = replayWithDecrease();
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
  assert.equal(row.required_inputs.find((inputRow) => inputRow.name === 'replay_tail_GOLD_SPENT').status,
    'PRESENT_UNVALIDATED');
  delete replay.tail.stats[3].GOLD_SPENT;
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((capability) => capability.capability === CAPABILITY).missing_inputs,
  ['replay_tail_GOLD_SPENT']);
  replay.tail.stats[3].GOLD_SPENT = '-1';
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((capability) => capability.capability === CAPABILITY).invalid_inputs,
  ['replay_tail_GOLD_SPENT']);
});

test('selected CLI writes candidate snapshots without transaction events', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-gold-spent-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(replayWithDecrease(), input);
  assert.equal(await require('../src/cli').main([
    'decode', input, '--events', CAPABILITY, '--out-dir', output,
  ]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.capability_runs[0].capability_results[CAPABILITY].status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.runtime_image_used, false);
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 20);
  assert.equal(semantic.capability_results[CAPABILITY].tail_difference_total, -10);
  const events = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [OUTPUT]);
  const jsonl = fs.readFileSync(path.join(replayDirectory, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(jsonl.length, 20);
  assert.equal(jsonl[0].gold_spent_candidate, 200);
  assert.equal(jsonl[10].gold_spent_candidate, 100);
  assert.equal(jsonl[10].confidence, 'CANDIDATE');
  assert.equal(jsonl[10].raw_packet_ref.packet_id, 0x0276);
});

test('missing spent tail does not suppress independent HeroStats candidates', () => {
  const replay = replayWithDecrease();
  delete replay.tail.stats[0].GOLD_SPENT;
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY, 'hero_minions_killed_snapshot',
      'hero_experience_snapshot', 'hero_gold_earned_snapshot'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(getHeroGoldSpentSnapshotCandidates(decoded), null);
  for (const other of ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
    'hero_gold_earned_snapshot']) {
    assert.equal(decoded.capability_results[other].status, 'CANDIDATE');
  }
  assert.deepEqual(Object.keys(decoded.events), [
    'hero_minions_killed_snapshot_candidates',
    'hero_experience_snapshot_candidates',
    'hero_gold_earned_snapshot_candidates',
  ]);
});

test('all four selected HeroStats capabilities share one keyframe scan', () => {
  const replay = replayWithDecrease();
  const chunks = replay.chunks;
  let chunkTraversalCount = 0;
  Object.defineProperty(replay, 'chunks', { get() {
    chunkTraversalCount += 1;
    return chunks;
  } });
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', CAPABILITY],
  });
  assert.equal(chunkTraversalCount, 1);
  for (const capability of ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
    'hero_gold_earned_snapshot', CAPABILITY]) {
    assert.equal(decoded.capability_results[capability].status, 'CANDIDATE');
  }
  assert.equal(decoded.events.hero_minions_killed_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_experience_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_gold_earned_snapshot_candidates.length, 20);
  assert.equal(decoded.events[OUTPUT].length, 20);
});
