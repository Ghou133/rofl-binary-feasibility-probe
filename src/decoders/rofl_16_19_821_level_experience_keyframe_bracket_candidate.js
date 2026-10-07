'use strict';

// A packet-time bracket over sampled cumulative EXP candidate endpoints. The
// level packet does not locate an EXP gain or establish an experience threshold.
const { isDeepStrictEqual } = require('node:util');
const {
  HERO_LEVEL_CANDIDATE_PROFILE_821,
  decodeHeroLevelCandidates821,
} = require('./rofl_16_19_821_level_candidate');
const { PROFILES: FLOAT_PROFILES } =
  require('./rofl_16_19_821_float_stats_candidate');
const {
  deriveExperienceKeyframeIntervalDifferenceCandidates821,
} = require('./rofl_16_19_821_experience_keyframe_interval_difference_candidate');

const BUILD = '16.19.821.7343';
const LEVEL = HERO_LEVEL_CANDIDATE_PROFILE_821;
const EXPERIENCE = FLOAT_PROFILES.hero_experience_snapshot;
const EVIDENCE_STATUS = 'CANDIDATE_821_LEVEL_PACKET_WITHIN_EXPERIENCE_KEYFRAME_ENDPOINTS';

const LEVEL_EXPERIENCE_KEYFRAME_BRACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-level-experience-keyframe-bracket-candidate-v1',
  replay_version: BUILD,
  capability: 'level_experience_keyframe_bracket',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['hero_level_state', 'hero_experience_snapshot']),
  evidence_runtime_image_sha256: LEVEL.evidence_runtime_image_sha256,
  lookup_table_sha256: LEVEL.lookup_table_sha256,
  evidence_scope: 'exact 821 level packets strictly between two adjacent complete EXP candidate keyframes for the same candidate participant',
  known_limits: Object.freeze([
    'The relation is temporal and uses candidate participant alignment; it does not identify an experience gain, its source, or a level threshold.',
    'EXP is a Replay-tail-correlated cumulative candidate field; the exact runtime byte transform does not prove its semantic label.',
    'A sampled endpoint difference belongs to the whole keyframe interval and is not apportioned among its level packets.',
    'Positive and unchanged endpoint summary counts count bracket rows; involved_interval_count counts distinct participant intervals.',
    'Repeated same-level and level-one packets are counted but excluded; missing intermediate levels are retained as sequence gaps.',
    'Packets after the final keyframe, before the first, or on a keyframe time have no strict adjacent-endpoint bracket.',
    'Participant alignment between the two packet routes and Replay tail remains candidate-only.',
  ]),
});

function propagatedStatus(status) {
  return ['MISSING_INPUT', 'PROFILE_UNAVAILABLE', 'UNSUPPORTED',
    'DECODE_FAILED', 'INCONSISTENT'].includes(status) ? status : 'INCONSISTENT';
}

function associateLevelExperienceKeyframeBracketCandidates821(replay, {
  levelOutcome,
  experienceSnapshotOutcome,
} = {}) {
  const profile = LEVEL_EXPERIENCE_KEYFRAME_BRACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    replay_sha256: replay?.source_sha256 ?? null,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    lookup_table_sha256: profile.lookup_table_sha256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, evidence_status: null, event_count: null, events: null,
    level_packet_count: null, experience_snapshot_count: null,
    keyframe_count: null, error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `level/EXP bracket candidate supports only ${BUILD}`);
  }
  if (!levelOutcome || !experienceSnapshotOutcome) {
    return fail('MISSING_INPUT', 'both exact-build source outcomes are required', {
      missing_inputs: [
        ...(!levelOutcome ? ['hero_level_state'] : []),
        ...(!experienceSnapshotOutcome ? ['hero_experience_snapshot'] : []),
      ],
    });
  }
  if (LEVEL.evidence_runtime_image_sha256 !== EXPERIENCE.evidence_runtime_image_sha256
      || LEVEL.lookup_table_sha256 !== EXPERIENCE.lookup_table_sha256
      || levelOutcome.profile_id !== LEVEL.id
      || levelOutcome.input_packet_id !== LEVEL.replay_block_packet_id
      || levelOutcome.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || experienceSnapshotOutcome.profile_id !== EXPERIENCE.id
      || experienceSnapshotOutcome.input_packet_id !== EXPERIENCE.replay_block_packet_id
      || experienceSnapshotOutcome.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || experienceSnapshotOutcome.lookup_table_sha256 !== profile.lookup_table_sha256) {
    return fail('INCONSISTENT', 'source profile, route, runtime image, or lookup table differs');
  }
  if (levelOutcome.status !== 'CANDIDATE') {
    return fail(propagatedStatus(levelOutcome.status), 'level candidate decoder is unavailable', {
      dependency_status: { hero_level_state: levelOutcome.status ?? null },
    });
  }
  if (experienceSnapshotOutcome.status !== 'CANDIDATE') {
    return fail(propagatedStatus(experienceSnapshotOutcome.status),
      'experience snapshot candidate decoder is unavailable', {
        dependency_status: { hero_experience_snapshot: experienceSnapshotOutcome.status ?? null },
      });
  }
  if (levelOutcome.evidence_status !== 'CANDIDATE_821_RUNTIME_LEVEL_BYTE_AND_REPLAY_TAIL'
      || levelOutcome.runtime_image_used !== false
      || levelOutcome.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
      || !Number.isSafeInteger(levelOutcome.input_count)
      || levelOutcome.input_count < 0
      || levelOutcome.event_count !== levelOutcome.input_count
      || !Array.isArray(levelOutcome.events)
      || levelOutcome.events.length !== levelOutcome.event_count) {
    return fail('INCONSISTENT', 'level source identity or event counts differ');
  }

  // Both dependencies are checked against physical Replay bytes. The fresh
  // level decode also catches omitted route packets; the EXP validator checks
  // every complete keyframe roster, packet ref, transformed f32 and Replay tail.
  const physicalLevel = decodeHeroLevelCandidates821(replay);
  if (physicalLevel.status !== 'CANDIDATE') {
    return fail(propagatedStatus(physicalLevel.status),
      `physical level Replay check failed: ${physicalLevel.error ?? physicalLevel.status}`);
  }
  if (levelOutcome.input_count !== physicalLevel.input_count
      || levelOutcome.event_count !== physicalLevel.event_count
      || levelOutcome.repeated_level_observation_count
        !== physicalLevel.repeated_level_observation_count
      || levelOutcome.level_one_packet_count !== physicalLevel.level_one_packet_count
      || levelOutcome.missing_level_update_count !== physicalLevel.missing_level_update_count
      || !isDeepStrictEqual(levelOutcome.final_levels, physicalLevel.final_levels)
      || !isDeepStrictEqual(levelOutcome.missing_level_updates,
        physicalLevel.missing_level_updates)
      || levelOutcome.unclassified_adjacent_prefix_count
        !== physicalLevel.unclassified_adjacent_prefix_count
      || !isDeepStrictEqual(levelOutcome.unclassified_adjacent_prefix_refs,
        physicalLevel.unclassified_adjacent_prefix_refs)
      || !isDeepStrictEqual(levelOutcome.events, physicalLevel.events)) {
    return fail('INCONSISTENT', 'level source differs from physical Replay packets');
  }
  const physicalExperience = deriveExperienceKeyframeIntervalDifferenceCandidates821(replay, {
    experienceSnapshotOutcome,
  });
  if (physicalExperience.status !== 'CANDIDATE') {
    return fail(propagatedStatus(physicalExperience.status),
      `physical experience Replay check failed: ${physicalExperience.error ?? physicalExperience.status}`,
      { dependency_status: { hero_experience_snapshot: experienceSnapshotOutcome.status } });
  }

  const frames = new Map();
  for (const row of experienceSnapshotOutcome.events) {
    const ref = row.raw_packet_ref;
    const frame = frames.get(ref.chunk_index) ?? {
      chunk_index: ref.chunk_index,
      replay_time_ms: row.replay_time_ms,
      participants: new Map(),
    };
    frame.participants.set(row.participant_id_candidate, row);
    frames.set(ref.chunk_index, frame);
  }
  const orderedFrames = replay.chunks.filter((chunk) => chunk.stream === 'keyframe')
    .map((chunk) => frames.get(chunk.index));
  // The EXP dependency already proved these frames are complete and ordered.
  if (orderedFrames.length !== physicalExperience.keyframe_count
      || orderedFrames.some((frame) => !frame || frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'experience source keyframe roster differs');
  }

  let excludedLevelOne = 0;
  let excludedRepeated = 0;
  let beforeFirst = 0;
  let afterLast = 0;
  let exactBoundary = 0;
  let observedLevelGap = 0;
  let positiveEndpoint = 0;
  let unchangedEndpoint = 0;
  const positiveIntervals = new Set();
  const unchangedIntervals = new Set();
  const lastLevel = new Map();
  const intervalCounts = new Map();
  const events = [];
  for (const level of physicalLevel.events) {
    const participant = level.participant_id_candidate;
    const priorLevel = lastLevel.get(participant) ?? null;
    lastLevel.set(participant, level.level_after_candidate);
    if (level.level_after_candidate === 1) {
      excludedLevelOne += 1;
      continue;
    }
    if (level.observation_kind === 'REPEATED_LEVEL_OBSERVATION') {
      excludedRepeated += 1;
      continue;
    }
    const sequenceGap = priorLevel !== null
      && level.level_after_candidate > priorLevel + 1;
    if (sequenceGap) observedLevelGap += 1;
    const time = level.replay_time_ms;
    const firstTime = orderedFrames[0].replay_time_ms;
    const lastTime = orderedFrames[orderedFrames.length - 1].replay_time_ms;
    if (time < firstTime) { beforeFirst += 1; continue; }
    if (time > lastTime) { afterLast += 1; continue; }
    if (time === firstTime || time === lastTime) { exactBoundary += 1; continue; }
    let previous = null;
    let current = null;
    for (let index = 1; index < orderedFrames.length; index += 1) {
      const left = orderedFrames[index - 1];
      const right = orderedFrames[index];
      if (time === left.replay_time_ms || time === right.replay_time_ms) {
        exactBoundary += 1;
        break;
      }
      if (left.replay_time_ms < time && time < right.replay_time_ms) {
        previous = left;
        current = right;
        break;
      }
    }
    if (!previous || !current) {
      if (orderedFrames.some((frame) => frame.replay_time_ms === time)) continue;
      return fail('INCONSISTENT', 'level packet has no adjacent experience keyframe bracket');
    }
    const left = previous.participants.get(participant);
    const right = current.participants.get(participant);
    if (!left || !right) return fail('INCONSISTENT', 'candidate participant is missing from EXP keyframe');
    const delta = right.experience_raw_f32_candidate - left.experience_raw_f32_candidate;
    if (delta < 0) return fail('INCONSISTENT', 'sampled EXP candidate decreased');
    const intervalKey = `${participant}/${previous.chunk_index}/${current.chunk_index}`;
    if (delta > 0) {
      positiveEndpoint += 1;
      positiveIntervals.add(intervalKey);
    } else {
      unchangedEndpoint += 1;
      unchangedIntervals.add(intervalKey);
    }
    intervalCounts.set(intervalKey, (intervalCounts.get(intervalKey) ?? 0) + 1);
    const levelRef = structuredClone(level.raw_packet_ref);
    const previousRef = structuredClone(left.raw_packet_ref);
    const currentRef = structuredClone(right.raw_packet_ref);
    events.push({
      event_type: 'LEVEL_EXPERIENCE_KEYFRAME_BRACKET_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: time,
      hero_raw_param: level.hero_raw_param,
      participant_id_candidate: participant,
      level_after_candidate: level.level_after_candidate,
      level_observation_kind: level.observation_kind,
      prior_observed_level_candidate: priorLevel,
      observed_level_sequence_gap: sequenceGap,
      raw_level_payload_code_hex: level.raw_payload_code_hex,
      previous_observation_time_ms: previous.replay_time_ms,
      current_observation_time_ms: current.replay_time_ms,
      observation_interval_ms: current.replay_time_ms - previous.replay_time_ms,
      previous_keyframe_chunk_index: previous.chunk_index,
      current_keyframe_chunk_index: current.chunk_index,
      experience_hero_raw_param: left.hero_raw_param,
      previous_experience_raw_f32_candidate: left.experience_raw_f32_candidate,
      current_experience_raw_f32_candidate: right.experience_raw_f32_candidate,
      previous_experience_floor_candidate: left.experience_floor_candidate,
      current_experience_floor_candidate: right.experience_floor_candidate,
      previous_experience_raw_payload_field_bytes_hex: left.raw_payload_field_bytes_hex,
      current_experience_raw_payload_field_bytes_hex: right.raw_payload_field_bytes_hex,
      experience_endpoint_delta_f32_candidate: delta,
      experience_endpoint_delta_floor_candidate:
        right.experience_floor_candidate - left.experience_floor_candidate,
      level_packet_count_in_same_interval: null,
      observation_kind: 'LEVEL_PACKET_WITHIN_ADJACENT_EXPERIENCE_KEYFRAMES',
      observation_scope: 'TEMPORAL_AND_CANDIDATE_PARTICIPANT_ONLY',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        previous_observation_time_ms: 'VERIFIED_DIRECT',
        current_observation_time_ms: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        level_after_candidate: physicalLevel.evidence_status,
        raw_level_payload_code_hex: 'VERIFIED_DIRECT',
        previous_experience_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
        current_experience_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
        previous_experience_raw_f32_candidate: experienceSnapshotOutcome.evidence_status,
        current_experience_raw_f32_candidate: experienceSnapshotOutcome.evidence_status,
        experience_endpoint_delta_f32_candidate: physicalExperience.evidence_status,
        level_packet_count_in_same_interval: EVIDENCE_STATUS,
      },
      raw_packet_ref: levelRef,
      level_raw_packet_ref: levelRef,
      previous_experience_raw_packet_ref: previousRef,
      current_experience_raw_packet_ref: currentRef,
      raw_packet_refs: [previousRef, levelRef, currentRef],
      known_limits: [...profile.known_limits],
    });
  }
  for (const event of events) {
    const key = `${event.participant_id_candidate}/${event.previous_keyframe_chunk_index}/${event.current_keyframe_chunk_index}`;
    event.level_packet_count_in_same_interval = intervalCounts.get(key);
  }
  return {
    ...base,
    status: 'CANDIDATE',
    evidence_status: EVIDENCE_STATUS,
    level_packet_count: physicalLevel.event_count,
    experience_snapshot_count: experienceSnapshotOutcome.event_count,
    keyframe_count: orderedFrames.length,
    higher_level_observation_count: physicalLevel.event_count
      - excludedLevelOne - excludedRepeated,
    excluded_level_one_count: excludedLevelOne,
    excluded_repeated_level_count: excludedRepeated,
    outside_first_keyframe_count: beforeFirst,
    outside_last_keyframe_count: afterLast,
    exact_keyframe_boundary_count: exactBoundary,
    observed_level_sequence_gap_count: observedLevelGap,
    positive_endpoint_count: positiveEndpoint,
    unchanged_endpoint_count: unchangedEndpoint,
    involved_interval_count: intervalCounts.size,
    positive_involved_interval_count: positiveIntervals.size,
    unchanged_involved_interval_count: unchangedIntervals.size,
    multi_level_interval_count: [...intervalCounts.values()].filter((count) => count > 1).length,
    max_level_packets_per_interval: [...intervalCounts.values()]
      .reduce((maximum, count) => Math.max(maximum, count), 0),
    verified_level_raw_packet_count: physicalLevel.event_count,
    verified_experience_raw_packet_count: physicalExperience.verified_raw_packet_count,
    event_count: events.length,
    events,
  };
}

module.exports = {
  LEVEL_EXPERIENCE_KEYFRAME_BRACKET_821_PROFILE,
  associateLevelExperienceKeyframeBracketCandidates821,
};
