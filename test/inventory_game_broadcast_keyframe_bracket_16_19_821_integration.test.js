'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseReplayFile } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'hero_inventory_broadcast_packet';
const INTERVAL = 'inventory_keyframe_interval_difference';
const BRACKET = 'inventory_game_broadcast_keyframe_bracket';
const SOURCE_EVENTS = 'hero_inventory_broadcast_packet_candidates';
const INTERVAL_EVENTS = 'inventory_keyframe_interval_difference_candidates';
const BRACKET_EVENTS = 'inventory_game_broadcast_keyframe_bracket_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

function broadcastPacket(rawParam, timeMs) {
  const payload = Buffer.alloc(79);
  payload[0] = 0x1e;
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0357, 9);
  header.writeUInt32LE(rawParam, 11);
  return Buffer.concat([header, payload]);
}

function syntheticReplay() {
  return replayFromChunks([1000, 2000].map((timeMs) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      broadcastPacket(0x400000ae + index, timeMs))),
  })), BUILD);
}

function artifactDirectory(output) {
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  return { acceptance, replayDirectory: path.join(output,
    acceptance.replay_artifacts[0].artifact_directory) };
}

test('selected API and CLI report both dependent associations missing without the exact image', (t) => {
  const replay = syntheticReplay();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.candidate_associations[INTERVAL].status, 'MISSING_INPUT');
  assert.equal(decoded.candidate_associations[BRACKET].status, 'MISSING_INPUT');
  assert.equal(decoded.events?.[BRACKET_EVENTS], undefined);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-broadcast-bracket-missing-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = path.join(directory, 'synthetic.rofl');
  const output = path.join(directory, 'output');
  fs.writeFileSync(input, replay.buffer);
  const run = spawnSync(process.execPath, [CLI, 'decode', input,
    '--events', CAPABILITY, '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 30000,
  });
  assert.equal(run.status, 2, run.stderr || run.stdout);
  const { replayDirectory } = artifactDirectory(output);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(semantic.candidate_associations[INTERVAL].status, 'MISSING_INPUT');
  assert.equal(semantic.candidate_associations[BRACKET].status, 'MISSING_INPUT');
  assert.equal(fs.existsSync(path.join(replayDirectory, `${BRACKET_EVENTS}.jsonl`)), false);
});

test('selected API and CLI expose exact-image game Broadcast bracket candidates', (t) => {
  if (!fs.existsSync(REPLAY) || !fs.existsSync(IMAGE)) {
    t.skip('supplied KR 821 replay or matching local runtime image absent');
    return;
  }
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: [CAPABILITY], runtimeImagePath: IMAGE,
  });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(decoded.candidate_associations[INTERVAL].status, 'CANDIDATE');
  const summary = decoded.candidate_associations[BRACKET];
  assert.equal(summary.status, 'CANDIDATE', summary.error);
  assert.equal(summary.evidence_status,
    'CANDIDATE_821_GAME_BROADCAST_BETWEEN_ADJACENT_KEYFRAMES');
  assert.equal(summary.runtime_image_status, 'MATCHED_USED');
  assert.equal(summary.runtime_image_used, true);
  assert.equal(summary.event_count, decoded.events[BRACKET_EVENTS].length);
  assert.equal(summary.event_count, summary.bracketed_game_broadcast_count);
  assert.ok(summary.event_count > 0);
  assert.equal(summary.record_comparison_count,
    decoded.events[BRACKET_EVENTS].reduce((sum, row) =>
      sum + row.record_comparisons_candidate.length, 0));
  assert.ok(decoded.events[BRACKET_EVENTS].every((row) =>
    row.event_type === 'INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_CANDIDATE'
      && row.confidence === 'CANDIDATE'
      && row.previous_observation_time_ms < row.game_observation_time_ms
      && row.game_observation_time_ms < row.next_observation_time_ms));
  for (const row of decoded.events[BRACKET_EVENTS]) {
    assert.deepEqual(row.raw_packet_ref, row.game_raw_packet_ref);
    assert.deepEqual(row.raw_packet_refs,
      [row.previous_raw_packet_ref, row.game_raw_packet_ref, row.next_raw_packet_ref]);
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-broadcast-bracket-real-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'output');
  const run = spawnSync(process.execPath, [CLI, 'decode', REPLAY,
    '--events', CAPABILITY, '--runtime-image', IMAGE,
    '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 120000,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const { replayDirectory } = artifactDirectory(output);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  const bracketRows = fs.readFileSync(path.join(replayDirectory,
    `${BRACKET_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(semantic.candidate_associations[BRACKET], summary);
  assert.deepEqual(bracketRows, decoded.events[BRACKET_EVENTS]);
  assert.equal(semantic.runtime_image_used, true);
  assert.equal(fs.existsSync(path.join(replayDirectory, `${SOURCE_EVENTS}.jsonl`)), true);
  assert.equal(fs.existsSync(path.join(replayDirectory, `${INTERVAL_EVENTS}.jsonl`)), true);
});

test('association throw is PARTIAL while selected source and interval rows survive', () => {
  const broadcastModule = require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
  const intervalModule = require('../src/decoders/rofl_16_19_821_inventory_keyframe_interval_difference_candidate');
  const bracketModule = require('../src/decoders/rofl_16_19_821_inventory_game_broadcast_keyframe_bracket_candidate');
  const originalBroadcast = broadcastModule.decodeHeroInventoryBroadcastPacketCandidates821;
  const originalInterval = intervalModule.deriveInventoryKeyframeIntervalDifferenceCandidates821;
  const originalBracket = bracketModule.associateInventoryGameBroadcastKeyframeBracketCandidates821;
  const semanticPath = require.resolve('../src/semantic_api');
  const previousSemanticModule = require.cache[semanticPath];
  const sourceEvent = { event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE',
    game_version: BUILD, replay_time_ms: 1000, confidence: 'CANDIDATE' };
  const intervalEvent = { event_type: 'INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE',
    game_version: BUILD, replay_time_ms: 2000, confidence: 'CANDIDATE' };
  broadcastModule.decodeHeroInventoryBroadcastPacketCandidates821 = () => ({
    status: 'CANDIDATE', input_count: 1, event_count: 1,
    input_packet_id: 0x0357, events: [sourceEvent],
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
  });
  intervalModule.deriveInventoryKeyframeIntervalDifferenceCandidates821 = () => ({
    status: 'CANDIDATE', input_count: 1, event_count: 1, events: [intervalEvent],
  });
  bracketModule.associateInventoryGameBroadcastKeyframeBracketCandidates821 =
    (_replay, { inventoryBroadcastOutcome, inventoryIntervalOutcome }) => {
      assert.deepEqual(inventoryBroadcastOutcome.events, [sourceEvent]);
      assert.deepEqual(inventoryIntervalOutcome.events, [intervalEvent]);
      throw new Error('injected Broadcast bracket failure');
    };
  delete require.cache[semanticPath];
  try {
    const freshApi = require('../src/semantic_api');
    const decoded = freshApi.decodeSemanticReplay(syntheticReplay(), {
      capabilities: [CAPABILITY],
    });
    assert.equal(decoded.status, 'PARTIAL');
    assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
    assert.deepEqual(decoded.events[SOURCE_EVENTS], [sourceEvent]);
    assert.deepEqual(decoded.events[INTERVAL_EVENTS], [intervalEvent]);
    assert.equal(decoded.candidate_associations[BRACKET].status, 'DECODE_FAILED');
    assert.match(decoded.candidate_associations[BRACKET].error,
      /injected Broadcast bracket failure/);
    assert.equal(decoded.events[BRACKET_EVENTS], undefined);
  } finally {
    broadcastModule.decodeHeroInventoryBroadcastPacketCandidates821 = originalBroadcast;
    intervalModule.deriveInventoryKeyframeIntervalDifferenceCandidates821 = originalInterval;
    bracketModule.associateInventoryGameBroadcastKeyframeBracketCandidates821 = originalBracket;
    if (previousSemanticModule) require.cache[semanticPath] = previousSemanticModule;
    else delete require.cache[semanticPath];
  }
});
