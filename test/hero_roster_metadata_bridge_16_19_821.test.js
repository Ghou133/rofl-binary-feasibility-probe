'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { parseReplayBuffer } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE,
  associateHeroRosterMetadataBridge821,
} = require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const ROLES = ['TOP', 'JUNGLE', 'MIDDLE', 'BOTTOM', 'UTILITY'];

function players() {
  return Array.from({ length: 10 }, (_, index) => ({
    SKIN: `Champion${index + 1}`,
    TEAM: index < 5 ? '100' : '200',
    INDIVIDUAL_POSITION: ROLES[index % 5],
    CHAMPIONS_KILLED: String(index + 1),
    NUM_DEATHS: String(index + 2),
    ASSISTS: String(index + 3),
    PUUID: `private-puuid-${index}`,
    RIOT_ID_GAME_NAME: `private-name-${index}`,
  }));
}

function replayWithPlayers(stats) {
  const base = replayFromChunks([], BUILD);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000,
    statsJson: JSON.stringify(stats),
  }));
  const length = Buffer.alloc(4);
  length.writeUInt32LE(metadata.length);
  return parseReplayBuffer(Buffer.concat([
    base.buffer.subarray(0, base.tail.metadata_start), metadata, length,
  ]), 'synthetic-roster-bridge.rofl');
}

function sourceOutcomes(replay, counts = players()) {
  const death = counts.map((row) => Number(row.NUM_DEATHS));
  const kills = counts.map((row) => Number(row.CHAMPIONS_KILLED));
  const assists = counts.map((row) => Number(row.ASSISTS));
  const refs = Array.from({ length: 10 }, (_, index) => ({
    replay_sha256: replay.source_sha256,
    chunk_stream: 'keyframe',
    packet_id: 0x0089,
    raw_param: 0x400000ae + index,
    replay_time_ms: 500000,
    chunk_index: 1,
    decompressed_block_offset: index * 1280,
    raw_payload_sha256: crypto.createHash('sha256')
      .update(`hero-${index}`).digest('hex'),
  }));
  const snapshot = (field, values) => ({
    status: 'CANDIDATE', input_count: 10, event_count: 10,
    events: values.map((value, index) => ({
      participant_id_candidate: index + 1,
      hero_raw_param: 0x400000ae + index,
      replay_time_ms: 500000,
      [field]: value,
      raw_packet_ref: refs[index],
    })),
  });
  return {
    hero_death: {
      status: 'CANDIDATE', event_count: death.reduce((sum, n) => sum + n, 0),
      champion_kills_tail_alignment_status: 'CANDIDATE_ALIGNED',
      observed_death_counts: death,
      observed_champion_kills_by_source: kills,
    },
    hero_assist: {
      status: 'CANDIDATE', assist_pair_count: assists.reduce((sum, n) => sum + n, 0),
      observed_assists_by_participant: assists,
    },
    hero_deaths_snapshot: snapshot('deaths_candidate', death),
    hero_champion_kills_snapshot: snapshot('champion_kills_candidate', kills),
    hero_assists_snapshot: snapshot('assists_candidate', assists),
  };
}

test('unique ten-player K/D/A bridge keeps metadata labels direct and network identity candidate', () => {
  const stats = players();
  const replay = replayWithPlayers(stats);
  const result = associateHeroRosterMetadataBridge821(replay,
    sourceOutcomes(replay, stats));
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 10);
  assert.equal(result.unique_kda_match_count, 10);
  assert.equal(result.events[0].champion_metadata, 'Champion1');
  assert.equal(result.events[0].team_metadata, 'blue');
  assert.equal(result.events[0].role_metadata, 'top');
  assert.equal(result.events[0].per_packet_actor_status, 'UNKNOWN');
  assert.equal(result.events[0].field_confidence.champion_metadata,
    'VERIFIED_FROM_METADATA');
  assert.equal(result.events[0].field_confidence.participant_id_candidate,
    HERO_ROSTER_METADATA_BRIDGE_821_PROFILE.evidence_status);
  assert.equal(result.events[0].raw_packet_ref.raw_param, 0x400000ae);
  assert.equal(result.stats_json_sha256,
    crypto.createHash('sha256').update(replay.tail.metadata.statsJson).digest('hex'));
  const text = JSON.stringify(result.events);
  assert.doesNotMatch(text, /private-puuid|private-name|metadata_player_id|riot_id|puuid/i);
});

test('permuted metadata rows contradict the raw-key alignment and emit no bridge', () => {
  const canonical = players();
  const permuted = [...canonical];
  [permuted[0], permuted[1]] = [permuted[1], permuted[0]];
  const replay = replayWithPlayers(permuted);
  const result = associateHeroRosterMetadataBridge821(replay,
    sourceOutcomes(replay, canonical));
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /contradicts/);
  assert.equal(result.events, null);
});

test('ambiguous K/D/A, missing labels and a missing source remain unavailable', () => {
  const duplicate = players();
  duplicate[1].CHAMPIONS_KILLED = duplicate[0].CHAMPIONS_KILLED;
  duplicate[1].NUM_DEATHS = duplicate[0].NUM_DEATHS;
  duplicate[1].ASSISTS = duplicate[0].ASSISTS;
  const ambiguousReplay = replayWithPlayers(duplicate);
  const ambiguous = associateHeroRosterMetadataBridge821(ambiguousReplay,
    sourceOutcomes(ambiguousReplay, duplicate));
  assert.equal(ambiguous.status, 'PROFILE_UNAVAILABLE');
  assert.match(ambiguous.error, /uniquely/);
  assert.equal(ambiguous.events, null);

  const missing = players();
  delete missing[4].SKIN;
  const missingReplay = replayWithPlayers(missing);
  const noLabel = associateHeroRosterMetadataBridge821(missingReplay,
    sourceOutcomes(missingReplay, missing));
  assert.equal(noLabel.status, 'MISSING_INPUT');
  assert.equal(noLabel.events, null);

  const replay = replayWithPlayers(players());
  const inputs = sourceOutcomes(replay);
  inputs.hero_assist = { status: 'MISSING_INPUT' };
  const noAssists = associateHeroRosterMetadataBridge821(replay, inputs);
  assert.equal(noAssists.status, 'MISSING_INPUT');
  assert.equal(noAssists.events, null);
});

test('altered parsed metadata or mismatched HeroStats references fail closed', () => {
  const replay = replayWithPlayers(players());
  const inputs = sourceOutcomes(replay);
  inputs.hero_assists_snapshot.events[0].raw_packet_ref = {
    ...inputs.hero_assists_snapshot.events[0].raw_packet_ref,
    raw_payload_sha256: '0'.repeat(64),
  };
  const badRef = associateHeroRosterMetadataBridge821(replay, inputs);
  assert.equal(badRef.status, 'DECODE_FAILED');
  assert.equal(badRef.events, null);

  const parsed = replayWithPlayers(players());
  parsed.tail.stats[0].SKIN = 'Injected';
  const changed = associateHeroRosterMetadataBridge821(parsed,
    sourceOutcomes(parsed));
  assert.equal(changed.status, 'DECODE_FAILED');
  assert.match(changed.error, /physical source bytes/);
  assert.equal(changed.events, null);
});
