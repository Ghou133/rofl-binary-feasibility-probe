'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveBuildProfile, resolveCapability } = require('../src/build_registry');
const { capabilityQuery, parseOne } = require('../src/cli');
const { decodeSemanticReplay, getHeroDeathCandidates, getHeroDeaths } =
  require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';

function packet(packetId, rawParam, payloadLength, timestampMs = 1000) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payloadLength;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, Buffer.alloc(payloadLength)]);
}

function keyframeDeathsPacket(participantId, count, timeMs,
  killCode = 0x97, assistCode = 0x97) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  payload[1182] = count === 0 ? 0x97 : 0xcc;
  payload[434] = killCode;
  payload[1186] = killCode;
  payload[1178] = assistCode;
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function replay({ unknownLevel = false, runtimeLevel20 = false, observedReturn = false,
  runtimeHighCounts = false, aboveTailKill = false, aboveTailAssist = false } = {}) {
  const levelPackets = Array.from({ length: 10 }, (_, index) => {
    const row = packet(0x0197, 0x400000ae + index,
      (unknownLevel || runtimeLevel20) && index === 0 ? 2 : 1);
    if (unknownLevel && index === 0) row.set([0xfa, 0x70], 12);
    else if (runtimeLevel20 && index === 0) row.set([0xfa, 0x4d], 12);
    else row[12] = 0xe5;
    return row;
  });
  const game = { body: Buffer.concat([
    packet(0x0259, 0x400000ae, 5),
    packet(0x0438, 0x400000ae, 13),
    packet(0x031b, 0, 12),
    packet(0x03d4, 0, 3),
    ...levelPackets,
    ...(observedReturn ? [
      packet(0x018d, 0x400000ae, 55, 10000),
      packet(0x0048, 0x400000ae, 13, 10000),
    ] : []),
  ]) };
  const snapshots = [0, 1].map((frame) => ({ stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      keyframeDeathsPacket(index + 1, frame && index === 0 ? 1 : 0, frame * 1000,
        frame && index === 0 ? aboveTailKill ? 0x3d : runtimeHighCounts ? 0x4d : 0xcc : 0x97,
        frame && index === 0 ? aboveTailAssist ? 0x3d : runtimeHighCounts ? 0x9d : 0xcc : 0x97))),
  }));
  const input = replayFromChunks([game, ...snapshots], BUILD);
  input.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
    TOTAL_TIME_SPENT_DEAD: observedReturn && index === 0 ? '9' : '0',
    CHAMPIONS_KILLED: index === 0 ? aboveTailKill || runtimeHighCounts ? '28' : '1' : '0',
    ASSISTS: index === 0 ? aboveTailAssist || runtimeHighCounts ? '28' : '1' : '0',
    LEVEL: (unknownLevel || runtimeLevel20) && index === 0 ? '20' : '2',
  }));
  return input;
}

test('821 build exposes only its exact candidate and tail-only preflight', () => {
  const input = replay();
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'hero_death').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_respawn').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_deaths_snapshot').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_champion_kills_snapshot').status,
    'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_assists_snapshot').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_level_state').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_death_timer').status, 'UNAVAILABLE');
  const query = capabilityQuery(input);
  assert.equal(query.profile_release_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.deepEqual(query.capabilities.map((row) => row.capability),
    ['hero_death', 'hero_respawn', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_level_state']);
  assert.equal(query.capabilities[0].runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(query.capabilities[0].output, 'hero_death_candidates');
  assert.deepEqual(query.capabilities[0].missing_inputs, []);
  assert.equal(query.capabilities[1].runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(query.capabilities[1].output, 'hero_respawn_candidates');
  assert.deepEqual(query.capabilities[1].missing_inputs, []);
  assert.deepEqual(query.capabilities[1].required_inputs.map((row) => row.name),
    ['replay', 'replay_tail_statsJson', 'replay_tail_NUM_DEATHS',
      'replay_tail_TOTAL_TIME_SPENT_DEAD',
      'replay_tail_gameLength']);
  assert.equal(query.capabilities[2].output, 'hero_deaths_snapshot_candidates');
  assert.deepEqual(query.capabilities[2].missing_inputs, []);
  assert.equal(query.capabilities[3].output, 'hero_champion_kills_snapshot_candidates');
  assert.deepEqual(query.capabilities[3].missing_inputs, []);
  assert.equal(query.capabilities[4].output, 'hero_assists_snapshot_candidates');
  assert.deepEqual(query.capabilities[4].missing_inputs, []);
  assert.equal(query.capabilities[5].output, 'hero_level_state_candidates');
  assert.deepEqual(query.capabilities[5].missing_inputs, []);
  input.tail.stats[0].NUM_DEATHS = null;
  for (const row of capabilityQuery(input).capabilities.slice(0, 3)) {
    assert.deepEqual(row.missing_inputs, ['replay_tail_NUM_DEATHS']);
  }
  input.tail.stats[0].TOTAL_TIME_SPENT_DEAD = null;
  assert.deepEqual(capabilityQuery(input).capabilities[1].missing_inputs,
    ['replay_tail_NUM_DEATHS', 'replay_tail_TOTAL_TIME_SPENT_DEAD']);
  input.tail.stats[0].LEVEL = null;
  assert.deepEqual(capabilityQuery(input).capabilities[5].missing_inputs,
    ['replay_tail_LEVEL']);
  input.tail.stats[0].CHAMPIONS_KILLED = null;
  assert.deepEqual(capabilityQuery(input).capabilities[3].missing_inputs,
    ['replay_tail_CHAMPIONS_KILLED']);
  input.tail.stats[0].ASSISTS = null;
  assert.deepEqual(capabilityQuery(input).capabilities[4].missing_inputs,
    ['replay_tail_ASSISTS']);
});

test('821 API exposes only observed return candidates and retains the death dependency', () => {
  const input = replay({ observedReturn: true });
  const result = decodeSemanticReplay(input, {
    capabilities: ['hero_death', 'hero_respawn'],
  });
  assert.equal(result.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(result.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(result.capability_results.hero_respawn.status, 'CANDIDATE');
  assert.equal(result.capability_results.hero_respawn.event_count, 1);
  assert.equal(result.events.hero_respawn_candidates[0].replay_time_ms, 10000);
  assert.equal(result.events.hero_respawn_candidates[0].matched_death_replay_time_ms_candidate,
    1000);
  assert.equal(result.events.hero_respawn_candidates[0].observed_death_to_return_ms_candidate,
    9000);
  assert.equal(result.events.respawn_events, undefined);

  input.tail.stats[0].TOTAL_TIME_SPENT_DEAD = '10';
  const failed = decodeSemanticReplay(input, {
    capabilities: ['hero_death', 'hero_respawn'],
  });
  assert.equal(failed.status, 'PARTIAL');
  assert.equal(failed.capability_results.hero_respawn.status, 'DECODE_FAILED');
  assert.equal(failed.events.hero_death_candidates.length, 1);
  assert.equal(failed.events.hero_respawn_candidates, undefined);
});

test('821 return preflight distinguishes a missing game length from present dead-time totals', () => {
  const input = replay({ observedReturn: true });
  input.tail.metadata.gameLength = null;
  const row = capabilityQuery(input).capabilities.find((capability) =>
    capability.capability === 'hero_respawn');
  assert.deepEqual(row.missing_inputs, ['replay_tail_gameLength']);
  assert.deepEqual(row.invalid_inputs, []);
  assert.equal(row.required_inputs.find((item) =>
    item.name === 'replay_tail_TOTAL_TIME_SPENT_DEAD').status, 'PRESENT_UNVALIDATED');
});

test('821 API dispatch emits separate candidate records and no confirmed deaths', () => {
  const input = replay();
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['hero_death'], runtimeImagePath: 'unused-image.bin',
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.game_version, BUILD);
  assert.equal(decoded.runtime_image_used, false);
  assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_death.runtime_image_status,
    'PROVIDED_NOT_USED');
  assert.equal(decoded.events.death_events, undefined);
  assert.deepEqual(getHeroDeaths(decoded), []);
  assert.equal(getHeroDeathCandidates(decoded).length, 1);
  assert.equal(getHeroDeathCandidates(decoded)[0].victim_participant_id, 1);

  const combined = decodeSemanticReplay(input, {
    capabilities: ['hero_death', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_level_state'],
  });
  assert.equal(combined.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(combined.capability_results.hero_deaths_snapshot.status, 'CANDIDATE');
  assert.equal(combined.capability_results.hero_deaths_snapshot.event_count, 20);
  assert.equal(combined.events.hero_deaths_snapshot_candidates.length, 20);
  assert.equal(combined.events.hero_deaths_snapshot_candidates[10].deaths_candidate, 1);
  assert.equal(combined.capability_results.hero_champion_kills_snapshot.status, 'CANDIDATE');
  assert.equal(combined.events.hero_champion_kills_snapshot_candidates.length, 20);
  assert.equal(combined.events.hero_champion_kills_snapshot_candidates[10].champion_kills_candidate,
    1);
  assert.equal(combined.capability_results.hero_assists_snapshot.status, 'CANDIDATE');
  assert.equal(combined.events.hero_assists_snapshot_candidates.length, 20);
  assert.equal(combined.events.hero_assists_snapshot_candidates[10].assists_candidate, 1);
  assert.equal(combined.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(combined.events.hero_level_state_candidates.length, 10);
  assert.equal(combined.events.hero_level_state_candidates[0].level_after_candidate, 2);
  assert.equal(combined.events.death_events, undefined);

  const unavailable = decodeSemanticReplay(input, { capabilities: ['hero_death_timer'] });
  assert.equal(unavailable.status, 'UNSUPPORTED');
  assert.equal(unavailable.events, null);
  assert.equal(unavailable.capability_results.hero_death_timer.status, 'UNSUPPORTED');
});

test('exact 821 runtime level 20 reaches the combined API candidate output', () => {
  const decoded = decodeSemanticReplay(replay({ runtimeLevel20: true }), {
    capabilities: ['hero_level_state'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(decoded.events.hero_level_state_candidates[0].level_after_candidate, 20);
  assert.equal(decoded.events.hero_level_state_candidates[0].raw_packet_ref.raw_payload_hex, 'fa4d');
});

test('out-of-range 821 level code leaves independent death candidates available', () => {
  const decoded = decodeSemanticReplay(replay({ unknownLevel: true }), {
    capabilities: ['hero_death', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_deaths_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_champion_kills_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_assists_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_level_state.status, 'DECODE_FAILED');
  assert.equal(decoded.capability_results.hero_level_state.event_count, null);
  assert.equal(decoded.capability_results.hero_level_state.rejected_packet_ref.raw_payload_hex,
    'fa70');
  assert.equal(decoded.events.hero_death_candidates.length, 1);
  assert.equal(decoded.events.hero_deaths_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_champion_kills_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_assists_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_level_state_candidates, undefined);
});

test('821 runtime high kill and assist counts reach combined API candidate output', () => {
  const decoded = decodeSemanticReplay(replay({ runtimeHighCounts: true }), {
    capabilities: ['hero_champion_kills_snapshot', 'hero_assists_snapshot'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_champion_kills_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.events.hero_champion_kills_snapshot_candidates[10].champion_kills_candidate,
    26);
  assert.equal(decoded.capability_results.hero_assists_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.events.hero_assists_snapshot_candidates[10].assists_candidate, 19);
});

test('821 kill count above tail leaves death, return, and level candidates available', () => {
  const decoded = decodeSemanticReplay(replay({ aboveTailKill: true, observedReturn: true }), {
    capabilities: ['hero_death', 'hero_respawn', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_champion_kills_snapshot.status, 'DECODE_FAILED');
  assert.match(decoded.capability_results.hero_champion_kills_snapshot.error,
    /exceeds Replay tail CHAMPIONS_KILLED/);
  assert.equal(decoded.capability_results.hero_champion_kills_snapshot.event_count, null);
  assert.equal(decoded.events.hero_champion_kills_snapshot_candidates, undefined);
  assert.equal(decoded.events.hero_death_candidates.length, 1);
  assert.equal(decoded.events.hero_respawn_candidates.length, 1);
  assert.equal(decoded.events.hero_deaths_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_assists_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_level_state_candidates.length, 10);
});

test('821 assist count above tail leaves the other candidate capabilities available', () => {
  const decoded = decodeSemanticReplay(replay({ aboveTailAssist: true }), {
    capabilities: ['hero_death', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_assists_snapshot.status, 'DECODE_FAILED');
  assert.match(decoded.capability_results.hero_assists_snapshot.error,
    /exceeds Replay tail ASSISTS/);
  assert.equal(decoded.events.hero_assists_snapshot_candidates, undefined);
  assert.equal(decoded.events.hero_death_candidates.length, 1);
  assert.equal(decoded.events.hero_deaths_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_champion_kills_snapshot_candidates.length, 20);
  assert.equal(decoded.events.hero_level_state_candidates.length, 10);
});

test('821 CLI dispatch reads a replay file and labels selected output candidate', (t) => {
  const input = replay();
  const original = input.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000,
    statsJson: JSON.stringify(input.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  const bytes = Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-cli-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'sample.rofl');
  fs.writeFileSync(file, bytes);
  const result = parseOne(file, {
    semantic: true, events: ['hero_death', 'hero_deaths_snapshot',
      'hero_champion_kills_snapshot', 'hero_assists_snapshot',
      'hero_level_state'],
    strict: true, timelineLimit: 0,
  });
  assert.equal(result.ok, true);
  assert.equal(result.analysis.decoder.status, 'CANDIDATE');
  assert.equal(result.analysis.packet_count, 34);
  assert.equal(result.analysis.block_errors.length, 0);
  assert.equal(result.analysis.event_counts.hero_death_candidates, 1);
  assert.equal(result.analysis.event_counts.hero_deaths_snapshot_candidates, 20);
  assert.equal(result.analysis.event_counts.hero_champion_kills_snapshot_candidates, 20);
  assert.equal(result.analysis.event_counts.hero_assists_snapshot_candidates, 20);
  assert.equal(result.analysis.event_counts.hero_level_state_candidates, 10);
  assert.deepEqual(result.analysis.events.death_events, undefined);
});
