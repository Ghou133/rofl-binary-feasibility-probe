'use strict';

// Sampled cumulative counters bound a change window, never a single attack.
const { PROFILES, decodeHeroDamageSnapshotCandidates821 } =
  require('./rofl_16_19_821_damage_float_candidate');

const {buildDamageKeyframeIntervals} = require('./damage_keyframe_intervals');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'hero_damage_keyframe_intervals';
const SOURCE_CAPABILITIES = Object.freeze([
  'hero_damage_totals_snapshot', 'hero_damage_taken_from_champions_snapshot',
]);
const FIELDS = Object.freeze(SOURCE_CAPABILITIES.flatMap((name) =>
  PROFILES[name].fields));
const EVIDENCE_STATUS = 'CANDIDATE_821_SAMPLED_DAMAGE_COUNTER_ENDPOINT_DIFFERENCE';
const DAMAGE_KEYFRAME_INTERVALS_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-damage-keyframe-intervals-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  depends_on: SOURCE_CAPABILITIES,
  replay_block_packet_id: 0x0089,
  stream_tags: Object.freeze([2]),
  fields: FIELDS,
  evidence_runtime_image_sha256:
    PROFILES.hero_damage_totals_snapshot.evidence_runtime_image_sha256,
  lookup_table_sha256: PROFILES.hero_damage_totals_snapshot.lookup_table_sha256,
  evidence_scope: 'Adjacent complete exact-821 HeroStats keyframes; four existing runtime-byte/Replay-tail-correlated cumulative counter candidates.',
  known_limits: Object.freeze([
    'Damage labels and participant mapping inherit the existing exact-821 snapshot candidate evidence; endpoint subtraction does not confirm those semantic labels.',
    'Rows describe sampled counter differences over a time window, not individual attacks, applied damage, health loss, attacker, victim, mitigation or fatal damage.',
    'replay_time_ms is the current keyframe endpoint, not the time of an intervening event. No value is interpolated.',
    'Every adjacent sampled participant pair is emitted, including unchanged counters; unchanged endpoints do not prove the absence of activity.',
    'No interval from the last keyframe to the final Replay tail is fabricated. Unobserved tail gaps are reported separately.',
    'The f32 endpoint difference and the difference of integer endpoint floors are separate quantities; neither is a count of damage events.',
  ]),
});

function decodeHeroDamageKeyframeIntervalsCandidates821(replay, precollected = null) {
  const profile = DAMAGE_KEYFRAME_INTERVALS_821_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    depends_on: [...SOURCE_CAPABILITIES],
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    lookup_table_sha256: profile.lookup_table_sha256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, details = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...details,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `${CAPABILITY} supports only ${BUILD}`);
  }

  // These dependencies are decoded here from the original Replay, not accepted
  // as caller-supplied summaries. The shared API route scan avoids rescanning.
  const sources = SOURCE_CAPABILITIES.map((name) =>
    decodeHeroDamageSnapshotCandidates821(replay, name, precollected));
  const statuses = Object.fromEntries(SOURCE_CAPABILITIES.map((name, index) =>
    [name, sources[index].status]));
  const failedIndex = sources.findIndex((source) => source.status !== 'CANDIDATE');
  if (failedIndex !== -1) {
    const source = sources[failedIndex];
    return fail(source.status, `${SOURCE_CAPABILITIES[failedIndex]}: ${source.error}`, {
      dependency_statuses: statuses,
    });
  }
  return buildDamageKeyframeIntervals(replay,profile,sources,base,EVIDENCE_STATUS);
}

module.exports = {
  DAMAGE_KEYFRAME_INTERVALS_821_PROFILE,
  decodeHeroDamageKeyframeIntervalsCandidates821,
};
