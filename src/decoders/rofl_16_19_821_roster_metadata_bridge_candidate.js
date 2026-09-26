'use strict';

const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { normalizePlayers, parseMetadataTail } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { RUNTIME_IMAGE_SHA256 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const FIRST_HERO_PARAM = 0x400000ae;
const EVIDENCE_STATUS = 'CANDIDATE_821_UNIQUE_EVENT_KDA_TO_METADATA_ROSTER';
const DEPENDENCIES = Object.freeze([
  'hero_death', 'hero_assist', 'hero_deaths_snapshot',
  'hero_champion_kills_snapshot', 'hero_assists_snapshot',
]);

const HERO_ROSTER_METADATA_BRIDGE_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-roster-metadata-bridge-candidate-v1',
  replay_version: BUILD,
  capability: 'hero_roster_metadata_bridge',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: DEPENDENCIES,
  packet_ids: Object.freeze([0x0089, 0x0259, 0x0438, 0x040a]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; all 110 raw roster keys have an internally consistent unique death/source-kill/assist count triplet aligned with one Replay metadata player row',
  known_limits: Object.freeze([
    'Champion, team, and role labels are direct Replay metadata fields; their association with a 0x0089 raw roster key remains a candidate.',
    'The join requires a unique ten-way K/D/A match from death, source-kill, and paired-assist candidates; those upstream decoders already use Replay tail gates, so this is not independent identity confirmation.',
    'The latest 0x0089 keyframe packet is an observed roster reference, not a live packet actor or a continuous game-state observation.',
    'HeroStats K/D/A values can lag the Replay tail; this join does not require or fabricate final keyframe equality.',
    'Other packets sharing a raw parameter are not assigned this champion, team, role, or participant identity.',
  ]),
});

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function tenCounts(value) {
  return Array.isArray(value) && value.length === 10 && value.every(nonnegative);
}

function signature(kills, deaths, assists) {
  return `${kills}/${deaths}/${assists}`;
}

function latestRosterRefs(outcome, field) {
  if (!Array.isArray(outcome?.events)
      || !nonnegative(outcome.event_count)
      || outcome.events.length !== outcome.event_count
      || outcome.events.length === 0
      || outcome.events.length % 10 !== 0) return null;
  const latest = Array(10).fill(null);
  for (const row of outcome.events) {
    const participant = row?.participant_id_candidate;
    const ref = row?.raw_packet_ref;
    if (!Number.isInteger(participant) || participant < 1 || participant > 10
        || row.hero_raw_param !== FIRST_HERO_PARAM + participant - 1
        || ref?.packet_id !== 0x0089 || ref.raw_param !== row.hero_raw_param
        || ref.chunk_stream !== 'keyframe'
        || row.replay_time_ms !== ref.replay_time_ms
        || !nonnegative(row[field])) return null;
    latest[participant - 1] = ref;
  }
  return latest.every(Boolean) ? latest : null;
}

function sameRef(a, b) {
  return a?.replay_sha256 === b?.replay_sha256
    && a?.chunk_index === b?.chunk_index
    && a?.decompressed_block_offset === b?.decompressed_block_offset
    && a?.raw_payload_sha256 === b?.raw_payload_sha256;
}

function associateHeroRosterMetadataBridge821(replay, outcomes) {
  const profile = HERO_ROSTER_METADATA_BRIDGE_821_PROFILE;
  const dependencyStatuses = Object.fromEntries(DEPENDENCIES.map((name) =>
    [name, outcomes?.[name]?.status ?? 'UNEXECUTED']));
  const base = {
    profile_id: profile.id,
    evidence_status: EVIDENCE_STATUS,
    input_packet_id: 0x0089,
    runtime_image_used: false,
    runtime_image_status: 'NOT_REQUIRED',
    dependency_statuses: dependencyStatuses,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error) => ({
    ...base, status, input_count: null, event_count: null, events: null, error,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `hero_roster_metadata_bridge requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  let physicalTail;
  try {
    physicalTail = parseMetadataTail(replay.buffer, replay.header.size);
  } catch (error) {
    return fail('DECODE_FAILED', `Replay metadata failed: ${error.message}`);
  }
  if (!isDeepStrictEqual(physicalTail.stats, replay.tail?.stats)
      || !isDeepStrictEqual(physicalTail.metadata, replay.tail?.metadata)) {
    return fail('DECODE_FAILED', 'Replay metadata rows differ from physical source bytes');
  }
  const unavailable = DEPENDENCIES.find((name) => dependencyStatuses[name] !== 'CANDIDATE');
  if (unavailable) {
    const status = dependencyStatuses[unavailable];
    return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
      `hero_roster_metadata_bridge requires ${unavailable}: ${status}`);
  }
  const death = outcomes.hero_death;
  const assist = outcomes.hero_assist;
  const deathCounts = death.observed_death_counts;
  const killCounts = death.observed_champion_kills_by_source;
  const assistCounts = assist.observed_assists_by_participant;
  if (death.champion_kills_tail_alignment_status !== 'CANDIDATE_ALIGNED'
      || !tenCounts(deathCounts) || !tenCounts(killCounts)
      || !tenCounts(assistCounts)) {
    return fail('DECODE_FAILED', 'Complete exact-build death, source-kill, and assist counts are required');
  }
  const players = normalizePlayers(replay);
  if (players.length !== 10) {
    return fail('MISSING_INPUT', 'Replay metadata must contain exactly ten player rows');
  }
  if (players.some((row, index) => row.metadata_index !== index
      || typeof row.champion !== 'string' || row.champion.length === 0
      || ![100, 200].includes(row.team_id)
      || row.role_status !== 'VERIFIED_FROM_METADATA'
      || !['top', 'jungle', 'mid', 'adc', 'support'].includes(row.role)
      || !nonnegative(row.aggregate_stats.kills)
      || !nonnegative(row.aggregate_stats.deaths)
      || !nonnegative(row.aggregate_stats.assists))) {
    return fail('MISSING_INPUT', 'Replay metadata has missing or invalid champion, team, role, or K/D/A');
  }
  if (players.filter((row) => row.team_id === 100).length !== 5
      || players.filter((row) => row.team_id === 200).length !== 5) {
    return fail('DECODE_FAILED', 'Replay metadata does not form two five-player teams');
  }
  const metadataSignatures = players.map((row) => signature(
    row.aggregate_stats.kills, row.aggregate_stats.deaths, row.aggregate_stats.assists));
  const matches = deathCounts.map((count, index) => {
    const candidate = signature(killCounts[index], count, assistCounts[index]);
    return metadataSignatures.flatMap((value, metadataIndex) =>
      value === candidate ? [metadataIndex] : []);
  });
  if (matches.some((indices) => indices.length !== 1)
      || new Set(matches.map((indices) => indices[0])).size !== 10) {
    return fail('PROFILE_UNAVAILABLE', 'K/D/A signatures do not uniquely match all ten metadata rows');
  }
  if (matches.some((indices, index) => indices[0] !== index)) {
    return fail('DECODE_FAILED', 'K/D/A match contradicts the existing exact-821 raw-key and tail-row alignment');
  }
  const snapshots = [
    latestRosterRefs(outcomes.hero_deaths_snapshot, 'deaths_candidate'),
    latestRosterRefs(outcomes.hero_champion_kills_snapshot, 'champion_kills_candidate'),
    latestRosterRefs(outcomes.hero_assists_snapshot, 'assists_candidate'),
  ];
  if (snapshots.some((refs) => refs === null)
      || snapshots[0].some((ref, index) =>
        !sameRef(ref, snapshots[1][index]) || !sameRef(ref, snapshots[2][index])
        || ref.replay_sha256 !== replay.source_sha256)) {
    return fail('DECODE_FAILED', 'Three K/D/A snapshots lack matching ten-key HeroStats packet references');
  }
  const metadataSha256 = crypto.createHash('sha256')
    .update(JSON.stringify(physicalTail.metadata), 'utf8').digest('hex');
  const statsJsonSha256 = crypto.createHash('sha256')
    .update(physicalTail.metadata.statsJson, 'utf8').digest('hex');
  const events = players.map((player, index) => ({
    event_type: 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
    game_version: BUILD,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: snapshots[0][index].replay_time_ms,
    hero_raw_param: FIRST_HERO_PARAM + index,
    participant_id_candidate: index + 1,
    metadata_index_candidate: index,
    champion_metadata: player.champion,
    team_id_metadata: player.team_id,
    team_metadata: player.team,
    role_metadata: player.role,
    observed_deaths_candidate: deathCounts[index],
    observed_source_kills_candidate: killCounts[index],
    observed_assists_candidate: assistCounts[index],
    metadata_kills: player.aggregate_stats.kills,
    metadata_deaths: player.aggregate_stats.deaths,
    metadata_assists: player.aggregate_stats.assists,
    metadata_sha256: metadataSha256,
    stats_json_sha256: statsJsonSha256,
    observation_kind: 'LATEST_KEYFRAME_ROSTER_AND_REPLAY_METADATA_JOIN',
    confidence: 'CANDIDATE',
    semantic_status: EVIDENCE_STATUS,
    roster_to_metadata_status: EVIDENCE_STATUS,
    per_packet_actor_status: 'UNKNOWN',
    field_confidence: {
      hero_raw_param: 'VERIFIED_DIRECT',
      champion_metadata: 'VERIFIED_FROM_METADATA',
      team_metadata: 'VERIFIED_FROM_METADATA',
      role_metadata: 'VERIFIED_FROM_METADATA',
      participant_id_candidate: EVIDENCE_STATUS,
      metadata_index_candidate: EVIDENCE_STATUS,
      per_packet_actor_status: 'UNKNOWN',
    },
    raw_packet_ref: snapshots[0][index],
    known_limits: [...profile.known_limits],
  }));
  return {
    ...base,
    status: 'CANDIDATE',
    input_count: outcomes.hero_deaths_snapshot.input_count,
    event_count: events.length,
    metadata_player_count: players.length,
    unique_kda_match_count: 10,
    metadata_sha256: metadataSha256,
    stats_json_sha256: statsJsonSha256,
    observed_hero_death_count: death.event_count,
    observed_assist_pair_count: assist.assist_pair_count,
    events,
  };
}

module.exports = {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE,
  associateHeroRosterMetadataBridge821,
};
