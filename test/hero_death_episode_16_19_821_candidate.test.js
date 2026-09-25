'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { HERO_ASSIST_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_assist_candidate');
const { HERO_DEATH_TIMER_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_death_timer_candidate');
const { HERO_RESPAWN_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_respawn_candidate');
const { RUNTIME_IMAGE_SHA256 } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { HERO_DEATH_EPISODE_821_PROFILE,
  associateHeroDeathEpisodeCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_hero_death_episode_candidate');

const BUILD = '16.19.821.7343';

function packet(packetId, rawParam, timeMs, fill, length = 5) {
  const payload = Buffer.alloc(length, fill);
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function ref(replay, block, chunk) {
  return {
    role: 'candidate_primary',
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function fixture() {
  const replay = replayFromChunks([{ stream: 1, body: Buffer.concat([
    packet(0x0259, 0x400000ae, 1000, 0x11),
    packet(0x0048, 0x400000ae, 1500, 0x48, 9),
    packet(0x0259, 0x400000af, 2000, 0x22),
  ]) }], BUILD);
  const blocks = [];
  walkBlocks(replay, (block, chunk) => blocks.push({ block, chunk }), { strict: true });
  const first = ref(replay, blocks[0].block, blocks[0].chunk);
  const returned = ref(replay, blocks[1].block, blocks[1].chunk);
  const second = ref(replay, blocks[2].block, blocks[2].chunk);
  const deathRows = [
    { primary: first, victim: 1, killer: 6, assists: [] },
    { primary: second, victim: 2, killer: null, assists: null },
  ];
  const heroAssistOutcome = {
    status: 'CANDIDATE', profile_id: HERO_ASSIST_CANDIDATE_PROFILE_821.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_used: false, native_child_identity_status: 'NOT_CHECKED',
    input_packet_id: 0x040a, input_count: 0,
    event_count: 2, matched_death_count: 2,
    events: deathRows.map(({ primary, victim, killer, assists }) => ({
      event_type: 'HERO_ASSIST_ATTRIBUTION_CANDIDATE', game_version: BUILD,
      build_profile: HERO_ASSIST_CANDIDATE_PROFILE_821.id,
      replay_sha256: replay.source_sha256,
      confidence: 'CANDIDATE', replay_time_ms: primary.replay_time_ms,
      victim_participant_id_candidate: victim,
      killer_participant_id_candidate: killer,
      assisting_participant_ids_candidate: assists,
      assist_pair_count: assists?.length ?? null,
      assist_observation_status: assists === null
        ? 'UNAVAILABLE_NONHERO_SOURCE'
        : 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT',
      field_confidence: {},
      raw_packet_ref: primary, raw_packet_refs: [primary],
    })),
  };
  const heroDeathTimerOutcome = {
    status: 'CANDIDATE', profile_id: HERO_DEATH_TIMER_CANDIDATE_PROFILE_821.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_used: false, input_packet_id: 0x0259,
    input_count: 2, event_count: 2, matched_death_core_count: 2,
    events: deathRows.map(({ primary, victim }, index) => ({
      event_type: 'HERO_DEATH_TIMER_CANDIDATE', game_version: BUILD,
      build_profile: HERO_DEATH_TIMER_CANDIDATE_PROFILE_821.id,
      replay_sha256: replay.source_sha256, confidence: 'CANDIDATE',
      replay_time_ms: primary.replay_time_ms,
      victim_participant_id_candidate: victim,
      victim_raw_param: primary.raw_param,
      timer_seconds_candidate: index === 0 ? 12 : 21,
      raw_packet_ref: primary, raw_packet_refs: [primary],
    })),
  };
  const heroRespawnOutcome = {
    status: 'CANDIDATE', profile_id: HERO_RESPAWN_CANDIDATE_PROFILE_821.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_used: false, input_packet_id: 0x0048,
    input_count: 1, event_count: 1, matched_death_core_count: 2,
    unpaired_final_death_count: 1,
    unpaired_final_deaths: [{
      participant_id_candidate: 2,
      death_replay_time_ms_candidate: second.replay_time_ms,
      replay_remaining_ms: 598000,
      raw_packet_refs: [second],
    }],
    events: [{
      event_type: 'HERO_RESPAWN_CANDIDATE', game_version: BUILD,
      build_profile: HERO_RESPAWN_CANDIDATE_PROFILE_821.id,
      replay_sha256: replay.source_sha256, confidence: 'CANDIDATE',
      replay_time_ms: returned.replay_time_ms,
      participant_id_candidate: 1,
      matched_death_replay_time_ms_candidate: first.replay_time_ms,
      observed_death_to_return_ms_candidate: 500,
      raw_packet_ref: returned, raw_packet_refs: [returned, first],
    }],
  };
  return { replay, heroAssistOutcome, heroDeathTimerOutcome, heroRespawnOutcome };
}

test('exact 821 episode joins observed and terminal deaths without timer prediction', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(HERO_DEATH_EPISODE_821_PROFILE.capability, 'hero_death_episode');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 2);
  assert.equal(result.observed_return_count, 1);
  assert.equal(result.terminal_unobserved_count, 1);
  assert.equal(result.verified_raw_packet_count, 3);
  const [returned, terminal] = result.events;
  assert.equal(returned.event_type, 'HERO_DEATH_EPISODE_CANDIDATE');
  assert.equal(returned.return_observation_status, 'OBSERVED_RETURN');
  assert.equal(returned.return_replay_time_ms_candidate, 1500);
  assert.equal(returned.observed_death_to_return_ms_candidate, 500);
  assert.equal(returned.timer_seconds_candidate, 12);
  assert.deepEqual(returned.assisting_participant_ids_candidate, []);
  assert.equal(returned.raw_packet_refs.length, 2);
  assert.equal(terminal.return_observation_status, 'UNOBSERVED_BEFORE_REPLAY_END');
  assert.equal(terminal.return_replay_time_ms_candidate, null);
  assert.equal(terminal.observed_death_to_return_ms_candidate, null);
  assert.equal(terminal.replay_remaining_ms, 598000);
  assert.equal(terminal.killer_participant_id_candidate, null);
  assert.equal(terminal.assisting_participant_ids_candidate, null);
  for (const row of result.events) {
    assert.equal(row.confidence, 'CANDIDATE');
    assert.equal('predicted_return_time_ms' in row, false);
    assert.equal('actual_death' in row, false);
  }
});

test('exact 821 episode rejects unavailable, wrong-build, and wrong-profile outcomes', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {
    heroAssistOutcome: values.heroAssistOutcome,
    heroDeathTimerOutcome: values.heroDeathTimerOutcome,
  }).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.heroRespawnOutcome.status = 'PROFILE_UNAVAILABLE';
  assert.equal(associate(unavailable.replay, unavailable).status, 'MISSING_INPUT');
  const wrongProfile = fixture();
  wrongProfile.heroAssistOutcome.profile_id = 'wrong-profile';
  assert.equal(associate(wrongProfile.replay, wrongProfile).status, 'INCONSISTENT');
  const wrongImage = fixture();
  wrongImage.heroDeathTimerOutcome.evidence_runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
});

test('exact 821 episode fails all rows on duplicate, missing, and conflicting matches', () => {
  const duplicate = fixture();
  duplicate.heroAssistOutcome.events[1] = duplicate.heroAssistOutcome.events[0];
  let result = associate(duplicate.replay, duplicate);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  const missingTimer = fixture();
  missingTimer.heroDeathTimerOutcome.events.pop();
  missingTimer.heroDeathTimerOutcome.event_count = 1;
  result = associate(missingTimer.replay, missingTimer);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  const missingTerminal = fixture();
  missingTerminal.heroRespawnOutcome.unpaired_final_deaths = [];
  result = associate(missingTerminal.replay, missingTerminal);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  const wrongParticipant = fixture();
  wrongParticipant.heroRespawnOutcome.events[0].participant_id_candidate = 2;
  assert.equal(associate(wrongParticipant.replay, wrongParticipant).status, 'INCONSISTENT');
});

test('exact 821 episode checks source-bound bytes, including identical forged refs', () => {
  const wrongSha = fixture();
  wrongSha.heroAssistOutcome.events[0].replay_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongSha.replay, wrongSha).status, 'INCONSISTENT');
  const alteredSource = fixture();
  alteredSource.replay.buffer[0] ^= 1;
  assert.equal(associate(alteredSource.replay, alteredSource).status, 'DECODE_FAILED');
  const forged = fixture();
  // The same ref object is intentionally shared across all three outcomes.
  // Cross-outcome equality alone would accept this stale payload fingerprint.
  forged.heroAssistOutcome.events[0].raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  const result = associate(forged.replay, forged);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  assert.match(result.error, /Replay block/);
});

test('one supplied KR Replay joins three independent candidate outcomes', (t) => {
  const replayPath = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
    'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
  const artifactRoot = path.resolve(__dirname, '..', 'artifacts', '16_19_development');
  const source = (directory, capability, stream) => ({
    run: path.join(artifactRoot, directory, 'replays', 'KR_8392938200', 'semantic_run.json'),
    rows: path.join(artifactRoot, directory, 'replays', 'KR_8392938200', `${stream}.jsonl`),
    capability,
  });
  const assist = source('assist_native_field_join_cli_batch_11',
    'hero_assist', 'hero_assist_candidates');
  const timer = source('kr_821_runtime_timer_11',
    'hero_death_timer', 'hero_death_timer_candidates');
  const respawn = source('kr_821_all_current_11',
    'hero_respawn', 'hero_respawn_candidates');
  if (![replayPath, assist.run, assist.rows, timer.run, timer.rows,
    respawn.run, respawn.rows].every(fs.existsSync)) {
    t.skip('supplied private Replay or independently decoded local outputs absent');
    return;
  }
  const outcomeFromFiles = ({ run, rows, capability }) => ({
    ...JSON.parse(fs.readFileSync(run, 'utf8')).capability_results[capability],
    events: fs.readFileSync(rows, 'utf8').trim().split(/\r?\n/).map(JSON.parse),
  });
  const result = associate(parseReplayFile(replayPath), {
    heroAssistOutcome: outcomeFromFiles(assist),
    heroDeathTimerOutcome: outcomeFromFiles(timer),
    heroRespawnOutcome: outcomeFromFiles(respawn),
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 71);
  assert.equal(result.observed_return_count, 66);
  assert.equal(result.terminal_unobserved_count, 5);
  assert.ok(result.verified_raw_packet_count > result.event_count);
  assert.ok(result.events.some((row) => row.return_observation_status
    === 'UNOBSERVED_BEFORE_REPLAY_END'));
});
