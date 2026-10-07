'use strict';

// Arithmetic over exact-build decoded snapshots; no protocol or identity inference.
function buildDamageKeyframeIntervals(replay, profile, sources, base, evidenceStatus) {
  const FIELDS = profile.fields, BUILD = profile.replay_version, EVIDENCE_STATUS = evidenceStatus;
  const statuses = Object.fromEntries(profile.depends_on.map((name,index)=>[name,sources[index].status]));
  const fail = (status,error,details={}) => ({...base,status,input_count:null,event_count:null,events:null,error,...details});
  const [totals, fromChampions] = sources;
  if (totals.event_count !== fromChampions.event_count
      || totals.keyframe_count !== fromChampions.keyframe_count) {
    return fail('INCONSISTENT', 'damage snapshot dependencies have different keyframes');
  }
  const previousByParticipant = new Map();
  const changedByField = Object.fromEntries(FIELDS.map((field) =>
    [field.replay_tail_field, 0]));
  const events = [];
  let changed = 0;
  for (let index = 0; index < totals.events.length; index += 1) {
    const total = totals.events[index];
    const other = fromChampions.events[index];
    if (total.participant_id_candidate !== other.participant_id_candidate
        || total.replay_time_ms !== other.replay_time_ms
        || total.raw_packet_ref.chunk_index !== other.raw_packet_ref.chunk_index
        || total.raw_packet_ref.decompressed_block_offset
          !== other.raw_packet_ref.decompressed_block_offset) {
      return fail('INCONSISTENT', 'damage snapshot endpoints refer to different packets');
    }
    const current = {
      replay_time_ms: total.replay_time_ms,
      raw_packet_ref: total.raw_packet_ref,
      values: Object.fromEntries(FIELDS.map((field) => [field.replay_tail_field,
        (total[field.value_key] ?? other[field.value_key])])),
      raw_bytes: { ...total.raw_payload_field_bytes_hex,
        ...other.raw_payload_field_bytes_hex },
    };
    const participant = total.participant_id_candidate;
    const previous = previousByParticipant.get(participant);
    previousByParticipant.set(participant, current);
    if (!previous) continue;
    if (current.replay_time_ms <= previous.replay_time_ms) {
      return fail('INCONSISTENT', 'damage keyframe times must be strictly increasing', {
        participant_id_candidate: participant,
        previous_observation_time_ms: previous.replay_time_ms,
        current_observation_time_ms: current.replay_time_ms,
      });
    }
    const counters = {};
    let anyChanged = false;
    for (const field of FIELDS) {
      const name = field.replay_tail_field;
      const start = previous.values[name];
      const end = current.values[name];
      const difference = end - start;
      if (!Number.isFinite(difference) || difference < 0) {
        return fail('DECODE_FAILED', `invalid sampled damage counter difference: ${name}`);
      }
      counters[name] = {
        previous_raw_f32_candidate: start,
        current_raw_f32_candidate: end,
        endpoint_delta_f32_candidate: difference,
        endpoint_floor_difference_candidate: Math.floor(end) - Math.floor(start),
      };
      if (difference > 0) {
        anyChanged = true;
        changedByField[name] += 1;
      }
    }
    if (anyChanged) changed += 1;
    events.push({
      event_type: 'HERO_DAMAGE_KEYFRAME_INTERVAL_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: current.replay_time_ms,
      participant_id_candidate: participant,
      hero_raw_param: total.hero_raw_param,
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      observation_scope: 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY',
      change_time_status: 'UNRESOLVED_WITHIN_INTERVAL',
      previous_observation_time_ms: previous.replay_time_ms,
      current_observation_time_ms: current.replay_time_ms,
      interval_duration_ms: current.replay_time_ms - previous.replay_time_ms,
      any_counter_changed: anyChanged,
      counters,
      previous_raw_payload_field_bytes_hex: previous.raw_bytes,
      current_raw_payload_field_bytes_hex: current.raw_bytes,
      previous_raw_packet_ref: previous.raw_packet_ref,
      current_raw_packet_ref: current.raw_packet_ref,
      raw_packet_ref: current.raw_packet_ref,
      raw_packet_refs: [previous.raw_packet_ref, current.raw_packet_ref],
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    dependency_statuses: statuses,
    input_count: totals.input_count,
    keyframe_count: totals.keyframe_count,
    observed_participant_count: 10,
    observed_interval_count: events.length,
    changed_interval_count: changed,
    unchanged_interval_count: events.length - changed,
    changed_interval_counts_by_field: changedByField,
    tail_gaps: sources.flatMap((source) => source.tail_gaps),
    event_count: events.length,
    events,
  };
}

module.exports = {buildDamageKeyframeIntervals};
