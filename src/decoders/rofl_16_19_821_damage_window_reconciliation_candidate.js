'use strict';

// Internal calculator over fresh decoder outcomes. The semantic API owns raw
// decoding/image witnesses; this calculator cannot authenticate saved artifacts.
const { DAMAGE_KEYFRAME_INTERVALS_821_PROFILE: INTERVAL_PROFILE } =
  require('./rofl_16_19_821_damage_keyframe_intervals_candidate');
const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821: DAMAGE_V6_PROFILE } =
  require('./rofl_16_19_821_unit_apply_damage_packet_candidate');

const BUILD = '16.19.821.7343';
const PROFILE_ID = 'rofl-16.19.821.7343-kr-damage-packet-keyframe-window-comparison-candidate-v1';
const KEYS = Object.freeze({
  lookup_0x24: 'native_callback_lookup_key_u32_0x24_candidate',
  lookup_0x2c: 'native_callback_lookup_key_u32_0x2c_candidate',
});
const LIMITS = Object.freeze([
  'Full-key packet groups and anonymous +0x20 sums are compared with sampled cumulative counter differences; correlations do not confirm a combat role or an effective-damage amount.',
  'Only strict open time windows are grouped. Packets exactly at a sampled endpoint are counted separately because game/keyframe observation ordering is unresolved.',
  'The two lookup keys remain independently named by native offsets; object lookup/type-cast success, source, target, health effect and fatal damage remain UNKNOWN.',
  'A fixed 0.1 absolute-error comparison is an evidence screen, not semantic acceptance. Rotated participant keys are a negative control.',
  'Detailed original packet streams and both keyframe endpoint refs remain available; no tail gap or event time is interpolated.',
]);

function lowerBound(times, value) {
  let low = 0;
  let high = times.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (times[middle] < value) low = middle + 1;
    else high = middle;
  }
  return low;
}

function compareDamagePacketKeyframeWindows821(replay, damage, intervals) {
  const base = { profile_id: PROFILE_ID, replay_sha256: replay.source_sha256,
    required_capabilities: ['unit_apply_damage_packet', 'hero_damage_keyframe_intervals'],
    known_limits: [...LIMITS] };
  const fail = (status, error) => ({ ...base, status, event_count: null, events: null, error });
  if (replay?.header?.version !== BUILD) return fail('UNSUPPORTED', `requires ${BUILD}`);
  if (damage?.status !== 'CANDIDATE' || intervals?.status !== 'CANDIDATE') {
    return { ...fail('UNAVAILABLE', 'fresh candidate dependencies are unavailable'),
      dependency_statuses: { unit_apply_damage_packet: damage?.status ?? 'UNEXECUTED',
        hero_damage_keyframe_intervals: intervals?.status ?? 'UNEXECUTED' } };
  }
  if (![DAMAGE_PROFILE.id, DAMAGE_V6_PROFILE.id].includes(damage.profile_id)
      || intervals.profile_id !== INTERVAL_PROFILE.id
      || damage.runtime_image_used !== true || damage.runtime_image_status !== 'MATCHED_USED'
      || damage.runtime_image_sha256 !== DAMAGE_PROFILE.evidence_runtime_image_sha256
      || damage.native_full_success_count !== damage.event_count
      || damage.native_callback_f32_available_count !== damage.event_count
      || damage.native_callback_lookup_full_write_count !== damage.event_count
      || !Array.isArray(damage.events) || damage.events.length !== damage.event_count
      || !Array.isArray(intervals.events) || intervals.events.length !== intervals.event_count) {
    return fail('INCONSISTENT', 'fresh exact-image dependency identity or complete native counts differ');
  }
  const windows = intervals.events;
  const times = windows.length ? [windows[0].previous_observation_time_ms,
    ...[...new Set(windows.map((row) => row.current_observation_time_ms))].sort((a, b) => a - b)] : [];
  const groups = new Map();
  const getGroup = (endTime, rawKey, name) => groups.get(`${endTime}/${rawKey}/${name}`);
  let endpointPackets = 0;
  let outsidePackets = 0;
  for (const packet of damage.events) {
    const value = packet.native_callback_f32_0x20_candidate;
    if (packet.game_version !== BUILD || packet.replay_sha256 !== replay.source_sha256
        || !Number.isFinite(value) || !Number.isFinite(packet.replay_time_ms)) {
      return fail('INCONSISTENT', 'fresh packet identity or anonymous float differs');
    }
    const at = lowerBound(times, packet.replay_time_ms);
    if (at < times.length && times[at] === packet.replay_time_ms) {
      endpointPackets += 1;
      continue;
    }
    if (at === 0 || at === times.length) {
      outsidePackets += 1;
      continue;
    }
    for (const [name, field] of Object.entries(KEYS)) {
      const rawKey = packet[field];
      if (!Number.isSafeInteger(rawKey) || rawKey < 0 || rawKey > 0xffffffff) {
        return fail('INCONSISTENT', 'fresh packet lookup key is not a uint32');
      }
      if (rawKey < 0x400000ae || rawKey > 0x400000b7) continue;
      const bucket = `${times[at]}/${rawKey}/${name}`;
      let group = groups.get(bucket);
      if (!group) {
        group = { packet_count: 0, summed_callback_f32_0x20_candidate: 0,
          first_raw_packet_ref: packet.raw_packet_ref, last_raw_packet_ref: packet.raw_packet_ref };
        groups.set(bucket, group);
      }
      group.packet_count += 1;
      group.summed_callback_f32_0x20_candidate += value;
      group.last_raw_packet_ref = packet.raw_packet_ref;
    }
  }
  const positiveMatches = {};
  const events = windows.map((window) => {
    if (window.replay_sha256 !== replay.source_sha256 || window.game_version !== BUILD
        || window.hero_raw_param !== 0x400000ad + window.participant_id_candidate) {
      throw new Error('fresh sampled window identity differs');
    }
    const comparisons = {};
    for (const name of Object.keys(KEYS)) {
      const group = getGroup(window.current_observation_time_ms, window.hero_raw_param, name)
        ?? { packet_count: 0, summed_callback_f32_0x20_candidate: 0,
          first_raw_packet_ref: null, last_raw_packet_ref: null };
      const rotatedKey = 0x400000ae + window.participant_id_candidate % 10;
      const control = getGroup(window.current_observation_time_ms, rotatedKey, name)
        ?? { packet_count: 0, summed_callback_f32_0x20_candidate: 0 };
      const counterDifferences = {};
      for (const [field, counter] of Object.entries(window.counters)) {
        const delta = counter.endpoint_delta_f32_candidate;
        const error = group.summed_callback_f32_0x20_candidate - delta;
        const controlError = control.summed_callback_f32_0x20_candidate - delta;
        counterDifferences[field] = { counter_endpoint_delta_f32_candidate: delta,
          anonymous_sum_minus_counter_delta: error,
          rotated_key_sum_minus_counter_delta: controlError };
        const metric = positiveMatches[`${name}/${field}`] ??= {
          positive_counter_windows: 0, absolute_error_at_most_0_1: 0,
          rotated_key_control_matches: 0 };
        if (delta > 0) {
          metric.positive_counter_windows += 1;
          metric.absolute_error_at_most_0_1 += Math.abs(error) <= 0.1 ? 1 : 0;
          metric.rotated_key_control_matches += Math.abs(controlError) <= 0.1 ? 1 : 0;
        }
      }
      comparisons[name] = { ...group, raw_lookup_key: window.hero_raw_param,
        key_role_status: 'UNKNOWN', counter_differences: counterDifferences,
        rotated_key_control: { raw_lookup_key: rotatedKey, ...control } };
    }
    return { event_type: 'HERO_DAMAGE_PACKET_KEYFRAME_WINDOW_COMPARISON_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: PROFILE_ID,
      replay_sha256: replay.source_sha256, replay_time_ms: window.replay_time_ms,
      participant_id_candidate: window.participant_id_candidate,
      previous_observation_time_ms: window.previous_observation_time_ms,
      current_observation_time_ms: window.current_observation_time_ms,
      packet_time_window: 'STRICT_OPEN_ENDPOINTS', confidence: 'CANDIDATE',
      semantic_effect_status: 'UNKNOWN', comparisons,
      raw_packet_ref: window.current_raw_packet_ref,
      raw_packet_refs: window.raw_packet_refs };
  });
  return { ...base, status: 'CANDIDATE',
    native_packet_count: damage.event_count, sampled_counter_window_count: windows.length,
    exact_endpoint_time_packets_excluded: endpointPackets,
    packets_outside_sampled_windows: outsidePackets,
    positive_counter_comparisons: positiveMatches,
    event_count: events.length, events };
}

module.exports = { compareDamagePacketKeyframeWindows821 };
