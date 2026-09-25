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
const ASSOCIATION = 'inventory_keyframe_interval_difference';
const INTERVAL_EVENTS = 'inventory_keyframe_interval_difference_candidates';
const SOURCE_EVENTS = 'hero_inventory_broadcast_packet_candidates';
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

test('selected API marks the interval association missing when Broadcast lacks the exact image', () => {
  const decoded = decodeSemanticReplay(syntheticReplay(), {
    capabilities: [CAPABILITY],
  });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.capability_results[CAPABILITY].missing_input, 'runtime_image');
  assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(decoded.events?.[SOURCE_EVENTS], undefined);
  assert.equal(decoded.events?.[INTERVAL_EVENTS], undefined);
});

test('selected CLI saves missing-image association without an interval JSONL', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-inventory-interval-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = path.join(directory, 'synthetic.rofl');
  const output = path.join(directory, 'output');
  fs.writeFileSync(input, syntheticReplay().buffer);
  const run = spawnSync(process.execPath, [CLI, 'decode', input,
    '--events', CAPABILITY, '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 30000,
  });
  assert.equal(run.status, 2, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(semantic.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(fs.existsSync(path.join(replayDirectory,
    `${INTERVAL_EVENTS}.jsonl`)), false);
});

test('one exact KR replay exposes observed interval candidates through API and CLI', (t) => {
  if (!fs.existsSync(REPLAY) || !fs.existsSync(IMAGE)) {
    t.skip('supplied KR 821 replay or matching local runtime image absent');
    return;
  }
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: [CAPABILITY], runtimeImagePath: IMAGE,
  });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  const summary = decoded.candidate_associations[ASSOCIATION];
  assert.equal(summary.status, 'CANDIDATE', summary.error);
  assert.equal(summary.event_count, decoded.events[INTERVAL_EVENTS].length);
  assert.ok(summary.event_count > 0);
  assert.equal(summary.observed_interval_count,
    summary.changed_interval_count + summary.unchanged_interval_count);
  assert.ok(decoded.events[INTERVAL_EVENTS].every((row) =>
    row.event_type === 'INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE'
      && row.confidence === 'CANDIDATE'
      && row.previous_observation_time_ms < row.current_observation_time_ms));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-inventory-interval-real-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'output');
  const run = spawnSync(process.execPath, [CLI, 'decode', REPLAY,
    '--events', CAPABILITY, '--runtime-image', IMAGE,
    '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 120000,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  const intervalRows = fs.readFileSync(path.join(replayDirectory,
    `${INTERVAL_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const sourceRows = fs.readFileSync(path.join(replayDirectory,
    `${SOURCE_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(semantic.candidate_associations[ASSOCIATION], summary);
  assert.deepEqual(intervalRows, decoded.events[INTERVAL_EVENTS]);
  assert.equal(sourceRows.length, decoded.events[SOURCE_EVENTS].length);
});

test('an injected interval failure is PARTIAL in API and CLI while source rows survive', async (t) => {
  const broadcastModule = require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
  const intervalModule = require('../src/decoders/rofl_16_19_821_inventory_keyframe_interval_difference_candidate');
  const originalBroadcast = broadcastModule.decodeHeroInventoryBroadcastPacketCandidates821;
  const originalInterval = intervalModule.deriveInventoryKeyframeIntervalDifferenceCandidates821;
  const semanticPath = require.resolve('../src/semantic_api');
  const cliPath = require.resolve('../src/cli');
  const previousSemanticModule = require.cache[semanticPath];
  const previousCliModule = require.cache[cliPath];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-inventory-interval-fail-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = path.join(directory, 'synthetic.rofl');
  const output = path.join(directory, 'output');
  const sourceEvent = {
    event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE',
    game_version: BUILD,
    replay_time_ms: 1000,
    participant_id_candidate: 1,
    confidence: 'CANDIDATE',
  };
  broadcastModule.decodeHeroInventoryBroadcastPacketCandidates821 = () => ({
    status: 'CANDIDATE', input_count: 20, event_count: 1,
    input_packet_id: 0x0357, events: [sourceEvent],
    runtime_image_status: 'NOT_REQUIRED', runtime_image_used: false,
  });
  intervalModule.deriveInventoryKeyframeIntervalDifferenceCandidates821 = () => {
    throw new Error('injected interval association failure');
  };
  delete require.cache[semanticPath];
  delete require.cache[cliPath];
  try {
    const freshApi = require('../src/semantic_api');
    const freshCli = require('../src/cli');
    const decoded = freshApi.decodeSemanticReplay(syntheticReplay(), {
      capabilities: [CAPABILITY],
    });
    assert.equal(decoded.status, 'PARTIAL');
    assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
    assert.deepEqual(decoded.events[SOURCE_EVENTS], [sourceEvent]);
    assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'DECODE_FAILED');
    assert.match(decoded.candidate_associations[ASSOCIATION].error,
      /injected interval association failure/);
    assert.equal(decoded.events[INTERVAL_EVENTS], undefined);

    fs.writeFileSync(input, syntheticReplay().buffer);
    const exitCode = await freshCli.main(['decode', input, '--events', CAPABILITY,
      '--event-jsonl-only', '--out-dir', output]);
    assert.equal(exitCode, 2);
    const acceptance = JSON.parse(fs.readFileSync(path.join(output,
      'acceptance_summary.json'), 'utf8'));
    assert.equal(acceptance.status, 'PARTIAL');
    const replayDirectory = path.join(output,
      acceptance.replay_artifacts[0].artifact_directory);
    const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
      'semantic_run.json'), 'utf8'));
    assert.equal(semantic.status, 'PARTIAL');
    assert.equal(semantic.api_status, 'PARTIAL');
    assert.equal(semantic.capability_results[CAPABILITY].status, 'CANDIDATE');
    assert.equal(semantic.candidate_associations[ASSOCIATION].status, 'DECODE_FAILED');
    assert.equal(fs.existsSync(path.join(replayDirectory,
      `${INTERVAL_EVENTS}.jsonl`)), false);
    const sourceRows = fs.readFileSync(path.join(replayDirectory,
      `${SOURCE_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
    assert.deepEqual(sourceRows, [sourceEvent]);
  } finally {
    broadcastModule.decodeHeroInventoryBroadcastPacketCandidates821 = originalBroadcast;
    intervalModule.deriveInventoryKeyframeIntervalDifferenceCandidates821 = originalInterval;
    if (previousSemanticModule) require.cache[semanticPath] = previousSemanticModule;
    else delete require.cache[semanticPath];
    if (previousCliModule) require.cache[cliPath] = previousCliModule;
    else delete require.cache[cliPath];
  }
});
