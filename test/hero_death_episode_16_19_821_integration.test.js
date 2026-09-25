'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const SELECTED = ['hero_assist', 'hero_death_timer', 'hero_respawn'];
const VICTIM_RAW = 0x400000ae;
const KILLER_RAW = 0x400000b3;
const TIMER = Buffer.from('121017d7d7', 'hex'); // exact 821 12-second timer wire
const RETURN = Buffer.from('64b0f17b7bb06e3b7b1e3aaaf9', 'hex');

function packet(packetId, rawParam, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function assistPair(timeMs) {
  const first = Buffer.alloc(44, 0xa5);
  const second = Buffer.from(first);
  first[0] = second[0] = 0xf0;
  Buffer.from('35b94b3d', 'hex').copy(first, 1);
  Buffer.from('350b4bb3', 'hex').copy(second, 1);
  first[43] = 0x14;
  second[43] = 0xd4;
  const assistantRaw = 0x400000b0;
  return [
    packet(0x040a, assistantRaw, first, timeMs),
    packet(0x040a, assistantRaw, second, timeMs),
  ];
}

function deathCore(timeMs, { assisted = false } = {}) {
  const heroDie = Buffer.alloc(37, 0x43);
  heroDie.set(Buffer.from('3678', 'hex'), heroDie.length - 2);
  return [
    packet(0x03d4, 0, Buffer.alloc(3, 0xd4), timeMs),
    packet(0x031b, 0, Buffer.alloc(12, 0x31), timeMs),
    ...(assisted ? assistPair(timeMs) : []),
    packet(0x0259, VICTIM_RAW, TIMER, timeMs),
    packet(0x0438, VICTIM_RAW, heroDie, timeMs),
  ];
}

function replayBytes({ includeDeadTime = true } = {}) {
  const body = Buffer.concat([
    ...deathCore(1000, { assisted: true }),
    packet(0x018d, VICTIM_RAW, Buffer.alloc(55, 0x18), 10000),
    packet(0x0048, VICTIM_RAW, RETURN, 10000),
    ...deathCore(20000),
  ]);
  const generated = replayFromChunks([{ stream: 1, body }], BUILD);
  const stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '2' : '0',
    CHAMPIONS_KILLED: index === 5 ? '2' : '0',
    ASSISTS: index === 2 ? '1' : '0',
    ...(includeDeadTime ? { TOTAL_TIME_SPENT_DEAD: index === 0 ? '9' : '0' } : {}),
  }));
  const trailerOffset = generated.buffer.length - 4;
  const metadataOffset = trailerOffset - generated.buffer.readUInt32LE(trailerOffset);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000, statsJson: JSON.stringify(stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return Buffer.concat([generated.buffer.subarray(0, metadataOffset), metadata, trailer]);
}

function replay(options) {
  return parseReplayBuffer(replayBytes(options), 'synthetic-death-episode.rofl');
}

test('821 selected source candidates derive each death episode in API and CLI', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-death-episode-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, 'sample.rofl');
  const bytes = replayBytes();
  fs.writeFileSync(inputPath, bytes);

  const decoded = decodeSemanticReplay(replay(), { capabilities: SELECTED });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  for (const capability of SELECTED) {
    assert.equal(decoded.capability_results[capability].status, 'CANDIDATE');
  }
  assert.equal(decoded.events.hero_assist_candidates.length, 2);
  assert.equal(decoded.events.hero_death_timer_candidates.length, 2);
  assert.equal(decoded.events.hero_respawn_candidates.length, 1);
  const summary = decoded.candidate_associations.hero_death_episode;
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.death_count, 2);
  assert.equal(summary.timer_count, 2);
  assert.equal(summary.observed_return_count, 1);
  assert.equal(summary.terminal_unobserved_count, 1);
  assert.equal(summary.event_count, 2);
  const [returned, finalDeath] = decoded.events.hero_death_episode_candidates;
  assert.deepEqual([returned.replay_time_ms, finalDeath.replay_time_ms], [1000, 20000]);
  assert.deepEqual([returned.return_observation_status, finalDeath.return_observation_status],
    ['OBSERVED_RETURN', 'UNOBSERVED_BEFORE_REPLAY_END']);
  assert.deepEqual([returned.return_replay_time_ms_candidate,
    finalDeath.return_replay_time_ms_candidate], [10000, null]);
  assert.deepEqual([returned.observed_death_to_return_ms_candidate,
    finalDeath.observed_death_to_return_ms_candidate], [9000, null]);
  for (const [index, row] of [returned, finalDeath].entries()) {
    assert.equal(row.event_type, 'HERO_DEATH_EPISODE_CANDIDATE');
    assert.equal(row.confidence, 'CANDIDATE');
    assert.equal(row.victim_participant_id_candidate, 1);
    assert.equal(row.killer_participant_id_candidate, 6);
    assert.deepEqual(row.assisting_participant_ids_candidate, index === 0 ? [3] : []);
    assert.equal(row.timer_seconds_candidate, 12);
    assert.equal(row.raw_packet_ref.packet_id, 0x0259);
    assert.equal(row.raw_packet_ref.raw_payload_sha256,
      decoded.events.hero_death_timer_candidates[index].raw_packet_ref.raw_payload_sha256);
    assert.ok(row.raw_packet_refs.some((ref) => ref.packet_id === 0x0438));
  }
  assert.equal(returned.return_raw_packet_ref.packet_id, 0x0048);
  assert.equal(returned.raw_packet_refs.filter((ref) => ref.packet_id === 0x040a).length,
    2);
  assert.equal(finalDeath.return_raw_packet_ref, null);

  const parsed = parseOne(inputPath, {
    semantic: true, events: SELECTED, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.candidate_associations.hero_death_episode.status,
    'CANDIDATE');
  assert.equal(parsed.analysis.event_counts.hero_death_episode_candidates, 2);
  assert.equal(parsed.analysis.events.hero_death_episode_candidates[1]
    .return_observation_status, 'UNOBSERVED_BEFORE_REPLAY_END');

  const onlyTwo = decodeSemanticReplay(replay(), {
    capabilities: ['hero_assist', 'hero_death_timer'],
  });
  assert.equal(onlyTwo.candidate_associations.hero_death_episode, undefined);
  assert.equal(onlyTwo.events.hero_death_episode_candidates, undefined);
});

test('821 missing respawn tail leaves independent assist and timer streams available', (t) => {
  const decoded = decodeSemanticReplay(replay({ includeDeadTime: false }), {
    capabilities: SELECTED,
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_assist.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_death_timer.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_respawn.status, 'MISSING_INPUT');
  assert.equal(decoded.events.hero_assist_candidates.length, 2);
  assert.equal(decoded.events.hero_death_timer_candidates.length, 2);
  assert.equal(decoded.events.hero_respawn_candidates, undefined);
  assert.equal(decoded.candidate_associations.hero_death_episode.status, 'MISSING_INPUT');
  assert.equal(decoded.events.hero_death_episode_candidates, undefined);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-episode-partial-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const inputPath = path.join(directory, 'sample.rofl');
  fs.writeFileSync(inputPath, replayBytes({ includeDeadTime: false }));
  const parsed = parseOne(inputPath, {
    semantic: true, events: SELECTED, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.status, 'PARTIAL');
  assert.equal(parsed.analysis.semantic.candidate_associations.hero_death_episode.status,
    'MISSING_INPUT');
  assert.equal(parsed.analysis.event_counts.hero_assist_candidates, 2);
  assert.equal(parsed.analysis.event_counts.hero_death_timer_candidates, 2);
  assert.equal(parsed.analysis.events.hero_death_episode_candidates, undefined);
});
