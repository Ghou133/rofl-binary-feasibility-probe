'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const readline = require('node:readline');

const EXACT_BUILD = '16.16.805.0442';
const REPORT_SCHEMA = 'UNKNOWN_ROUTE_DEEP_MINING_V2';
const ANALYZER_VERSION = 'unknown-route-deep-miner-v2';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 8) {
  if (!Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function percentile(sorted, fraction) {
  if (sorted.length === 0) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.floor((sorted.length - 1) * fraction)));
  return sorted[index];
}

function entropy(counts, total) {
  if (!total) return 0;
  let result = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / total;
    result -= probability * Math.log2(probability);
  }
  return result;
}

function mapRows(map, keyName, valueName = 'count', limit = null) {
  const rows = [...map.entries()]
    .map(([key, value]) => ({ [keyName]: key, [valueName]: value }))
    .sort((left, right) => right[valueName] - left[valueName]
      || String(left[keyName]).localeCompare(String(right[keyName])));
  return limit === null ? rows : rows.slice(0, limit);
}

function sha256Text(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function exactParticipant(value) {
  const low = value & 0xff;
  const participant = low - 0xad;
  return participant >= 1 && participant <= 10 ? participant : null;
}

function fullChampionEntity(value) {
  return value >= 0x400000ae && value <= 0x400000b7;
}

function broadNetworkEntity(value) {
  return value >= 0x40000000 && value <= 0x4fffffff;
}

function newNumericAccumulator() {
  return { count: 0, finite_count: 0, min: Infinity, max: -Infinity, mean: 0, m2: 0 };
}

function addNumeric(accumulator, value) {
  accumulator.count += 1;
  if (!Number.isFinite(value)) return;
  accumulator.finite_count += 1;
  accumulator.min = Math.min(accumulator.min, value);
  accumulator.max = Math.max(accumulator.max, value);
  const delta = value - accumulator.mean;
  accumulator.mean += delta / accumulator.finite_count;
  accumulator.m2 += delta * (value - accumulator.mean);
}

function numericSummary(accumulator) {
  return {
    count: accumulator.count,
    finite_count: accumulator.finite_count,
    finite_rate: round(accumulator.finite_count / Math.max(1, accumulator.count)),
    min: accumulator.finite_count ? round(accumulator.min) : null,
    max: accumulator.finite_count ? round(accumulator.max) : null,
    mean: accumulator.finite_count ? round(accumulator.mean) : null,
    variance: accumulator.finite_count > 1
      ? round(accumulator.m2 / accumulator.finite_count)
      : 0,
  };
}

function newRouteAccumulator(packetId, packetDiscriminator, maxScanBytes) {
  return {
    packet_id: packetId,
    packet_discriminator: packetDiscriminator,
    count: 0,
    replay_counts: new Map(),
    length_counts: new Map(),
    payload_hashes: new Set(),
    prefix2_counts: new Map(),
    prefix4_counts: new Map(),
    suffix2_counts: new Map(),
    byte_counts: Array.from({ length: maxScanBytes }, () => new Uint32Array(256)),
    byte_observations: new Uint32Array(maxScanBytes),
    total_scanned_bytes: 0,
    scanned_byte_counts: new Uint32Array(256),
    printable_scanned_bytes: 0,
    zlib_signature_count: 0,
    gzip_signature_count: 0,
    raw_param_counts: new Map(),
    raw_param_zero_count: 0,
    raw_param_full_champion_count: 0,
    raw_param_participant_low_byte_count: 0,
    raw_param_broad_network_count: 0,
    u32_offsets: Array.from({ length: Math.max(0, maxScanBytes - 3) }, () => ({
      count: 0,
      full_champion_count: 0,
      participant_low_byte_count: 0,
      broad_network_count: 0,
      distinct: new Set(),
    })),
    f32_offsets: Array.from({ length: Math.max(0, maxScanBytes - 3) }, () => ({
      numeric: newNumericAccumulator(),
      plausible_stat_count: 0,
      plausible_coordinate_count: 0,
      zero_count: 0,
    })),
    times_by_replay: new Map(),
    exact_key_counts: new Map(),
    time_key_counts: new Map(),
    anchor: {
      available_count: 0,
      exact_time_count: 0,
      within_1ms_count: 0,
      within_10ms_count: 0,
      within_50ms_count: 0,
      within_100ms_count: 0,
      within_500ms_count: 0,
      raw_param_matches_damage_source_count: 0,
      raw_param_matches_damage_target_count: 0,
      raw_param_matches_either_within_10ms_count: 0,
      shifted_137ms_within_10ms_count: 0,
      shifted_997ms_within_10ms_count: 0,
      nearest_deltas: [],
    },
  };
}

function nearestAnchor(anchors, timestamp) {
  if (!anchors || anchors.length === 0) return null;
  let low = 0;
  let high = anchors.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (anchors[middle].time_ms < timestamp) low = middle + 1;
    else high = middle;
  }
  const candidates = [];
  if (low < anchors.length) candidates.push(anchors[low]);
  if (low > 0) candidates.push(anchors[low - 1]);
  return candidates.sort((left, right) =>
    Math.abs(left.time_ms - timestamp) - Math.abs(right.time_ms - timestamp))[0];
}

function addRow(accumulator, row, anchorsByReplay, maxScanBytes) {
  invariant(row.replay_version === EXACT_BUILD, `row has wrong build ${row.replay_version}`);
  invariant(Number(row.packet_id) === accumulator.packet_id, 'row packet_id mismatch');
  invariant(typeof row.raw_payload_hex === 'string' && row.raw_payload_hex.length % 2 === 0,
    'raw_payload_hex must contain complete bytes');
  const payload = Buffer.from(row.raw_payload_hex, 'hex');
  invariant(payload.length === Number(row.payload_length), 'payload length mismatch');
  const replay = row.replay_sha256;
  const rawParam = Number(row.raw_param) >>> 0;
  accumulator.count += 1;
  accumulator.replay_counts.set(replay, (accumulator.replay_counts.get(replay) ?? 0) + 1);
  accumulator.length_counts.set(payload.length, (accumulator.length_counts.get(payload.length) ?? 0) + 1);
  accumulator.payload_hashes.add(row.raw_payload_sha256 ?? sha256Text(payload));
  const prefix2 = payload.subarray(0, Math.min(2, payload.length)).toString('hex');
  const prefix4 = payload.subarray(0, Math.min(4, payload.length)).toString('hex');
  const suffix2 = payload.subarray(Math.max(0, payload.length - 2)).toString('hex');
  accumulator.prefix2_counts.set(prefix2, (accumulator.prefix2_counts.get(prefix2) ?? 0) + 1);
  accumulator.prefix4_counts.set(prefix4, (accumulator.prefix4_counts.get(prefix4) ?? 0) + 1);
  accumulator.suffix2_counts.set(suffix2, (accumulator.suffix2_counts.get(suffix2) ?? 0) + 1);
  if (payload.length >= 2 && payload[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(payload[1])) {
    accumulator.zlib_signature_count += 1;
  }
  if (payload.length >= 2 && payload[0] === 0x1f && payload[1] === 0x8b) {
    accumulator.gzip_signature_count += 1;
  }
  const scanLength = Math.min(maxScanBytes, payload.length);
  for (let offset = 0; offset < scanLength; offset += 1) {
    const value = payload[offset];
    accumulator.byte_counts[offset][value] += 1;
    accumulator.byte_observations[offset] += 1;
    accumulator.scanned_byte_counts[value] += 1;
    accumulator.total_scanned_bytes += 1;
    if ((value >= 0x20 && value <= 0x7e) || value === 0x09 || value === 0x0a || value === 0x0d) {
      accumulator.printable_scanned_bytes += 1;
    }
  }
  for (let offset = 0; offset + 4 <= scanLength; offset += 1) {
    const u32 = payload.readUInt32LE(offset);
    const u32Row = accumulator.u32_offsets[offset];
    u32Row.count += 1;
    if (u32Row.distinct.size < 50000) u32Row.distinct.add(u32);
    if (fullChampionEntity(u32)) u32Row.full_champion_count += 1;
    if (exactParticipant(u32) !== null) u32Row.participant_low_byte_count += 1;
    if (broadNetworkEntity(u32)) u32Row.broad_network_count += 1;
    const f32 = payload.readFloatLE(offset);
    const f32Row = accumulator.f32_offsets[offset];
    addNumeric(f32Row.numeric, f32);
    if (Number.isFinite(f32) && f32 >= 0 && f32 <= 100000) f32Row.plausible_stat_count += 1;
    if (Number.isFinite(f32) && f32 >= -20000 && f32 <= 20000) f32Row.plausible_coordinate_count += 1;
    if (Object.is(f32, 0) || Object.is(f32, -0)) f32Row.zero_count += 1;
  }
  accumulator.raw_param_counts.set(rawParam, (accumulator.raw_param_counts.get(rawParam) ?? 0) + 1);
  if (rawParam === 0) accumulator.raw_param_zero_count += 1;
  if (fullChampionEntity(rawParam)) accumulator.raw_param_full_champion_count += 1;
  if (exactParticipant(rawParam) !== null) accumulator.raw_param_participant_low_byte_count += 1;
  if (broadNetworkEntity(rawParam)) accumulator.raw_param_broad_network_count += 1;
  if (!accumulator.times_by_replay.has(replay)) accumulator.times_by_replay.set(replay, []);
  accumulator.times_by_replay.get(replay).push(Number(row.replay_time_ms));
  const timeKey = `${replay}:${Number(row.replay_time_ms)}`;
  const exactKey = `${timeKey}:${rawParam}`;
  accumulator.time_key_counts.set(timeKey, (accumulator.time_key_counts.get(timeKey) ?? 0) + 1);
  accumulator.exact_key_counts.set(exactKey, (accumulator.exact_key_counts.get(exactKey) ?? 0) + 1);

  const replayAnchors = anchorsByReplay.get(replay);
  const timestamp = Number(row.replay_time_ms);
  const nearest = nearestAnchor(replayAnchors, timestamp);
  if (nearest) {
    const delta = Math.abs(nearest.time_ms - Number(row.replay_time_ms));
    accumulator.anchor.available_count += 1;
    accumulator.anchor.nearest_deltas.push(delta);
    if (delta === 0) accumulator.anchor.exact_time_count += 1;
    if (delta <= 1) accumulator.anchor.within_1ms_count += 1;
    if (delta <= 10) accumulator.anchor.within_10ms_count += 1;
    if (delta <= 50) accumulator.anchor.within_50ms_count += 1;
    if (delta <= 100) accumulator.anchor.within_100ms_count += 1;
    if (delta <= 500) accumulator.anchor.within_500ms_count += 1;
    if (rawParam === nearest.source) accumulator.anchor.raw_param_matches_damage_source_count += 1;
    if (rawParam === nearest.target) accumulator.anchor.raw_param_matches_damage_target_count += 1;
    if (delta <= 10 && (rawParam === nearest.source || rawParam === nearest.target)) {
      accumulator.anchor.raw_param_matches_either_within_10ms_count += 1;
    }
    const shifted137 = nearestAnchor(replayAnchors, timestamp + 137);
    const shifted997 = nearestAnchor(replayAnchors, timestamp + 997);
    if (shifted137 && Math.abs(shifted137.time_ms - (timestamp + 137)) <= 10) {
      accumulator.anchor.shifted_137ms_within_10ms_count += 1;
    }
    if (shifted997 && Math.abs(shifted997.time_ms - (timestamp + 997)) <= 10) {
      accumulator.anchor.shifted_997ms_within_10ms_count += 1;
    }
  }
}

function finishRoute(accumulator, runtimeRow = null) {
  const count = accumulator.count;
  const byteOffsets = [];
  for (let offset = 0; offset < accumulator.byte_counts.length; offset += 1) {
    const observations = accumulator.byte_observations[offset];
    if (!observations) continue;
    const counts = accumulator.byte_counts[offset];
    const distinct = counts.reduce((sum, value) => sum + Number(value > 0), 0);
    let mode = 0;
    for (let value = 1; value < counts.length; value += 1) {
      if (counts[value] > counts[mode]) mode = value;
    }
    byteOffsets.push({
      offset,
      observation_count: observations,
      distinct_value_count: distinct,
      entropy_bits: round(entropy(counts, observations)),
      mode_u8: mode,
      mode_hex: `0x${mode.toString(16).padStart(2, '0')}`,
      mode_rate: round(counts[mode] / observations),
    });
  }
  const identifiers = accumulator.u32_offsets
    .map((row, offset) => ({
      offset,
      observation_count: row.count,
      distinct_value_count_capped: row.distinct.size,
      full_champion_rate: round(row.full_champion_count / Math.max(1, row.count)),
      participant_low_byte_rate: round(row.participant_low_byte_count / Math.max(1, row.count)),
      broad_network_rate: round(row.broad_network_count / Math.max(1, row.count)),
    }))
    .filter((row) => row.observation_count >= 50
      && Math.max(row.full_champion_rate, row.broad_network_rate) >= 0.05)
    .sort((left, right) => Math.max(right.full_champion_rate, right.broad_network_rate)
      - Math.max(left.full_champion_rate, left.broad_network_rate)
      || left.offset - right.offset)
    .slice(0, 32);
  const floats = accumulator.f32_offsets
    .map((row, offset) => {
      const summary = numericSummary(row.numeric);
      return {
        offset,
        ...summary,
        plausible_stat_rate: round(row.plausible_stat_count / Math.max(1, row.numeric.count)),
        plausible_coordinate_rate: round(row.plausible_coordinate_count / Math.max(1, row.numeric.count)),
        zero_rate: round(row.zero_count / Math.max(1, row.numeric.count)),
      };
    })
    .filter((row) => row.count >= 50 && row.finite_rate >= 0.98
      && row.plausible_coordinate_rate >= 0.95 && row.variance > 0)
    .sort((left, right) => right.plausible_stat_rate - left.plausible_stat_rate
      || left.offset - right.offset)
    .slice(0, 32);
  const vectors = [];
  const floatByOffset = new Map(floats.map((row) => [row.offset, row]));
  for (const row of floats) {
    const adjacent = floatByOffset.get(row.offset + 4);
    if (!adjacent) continue;
    vectors.push({
      offset: row.offset,
      kind: 'FLOAT32_PAIR_STRUCTURAL_CANDIDATE',
      component_offsets: [row.offset, adjacent.offset],
      component_ranges: [[row.min, row.max], [adjacent.min, adjacent.max]],
      semantic_claim: null,
    });
  }
  const replayTemporal = [];
  const allDeltas = [];
  let sameTimestampTransitions = 0;
  let transitionCount = 0;
  for (const [replaySha256, times] of accumulator.times_by_replay) {
    times.sort((left, right) => left - right);
    const deltas = [];
    for (let index = 1; index < times.length; index += 1) {
      const delta = times[index] - times[index - 1];
      deltas.push(delta);
      allDeltas.push(delta);
      transitionCount += 1;
      if (delta === 0) sameTimestampTransitions += 1;
    }
    deltas.sort((left, right) => left - right);
    replayTemporal.push({
      replay_sha256: replaySha256,
      observation_count: times.length,
      first_time_ms: times[0] ?? null,
      last_time_ms: times[times.length - 1] ?? null,
      delta_p50_ms: percentile(deltas, 0.5),
      delta_p90_ms: percentile(deltas, 0.9),
      delta_p99_ms: percentile(deltas, 0.99),
    });
  }
  allDeltas.sort((left, right) => left - right);
  accumulator.anchor.nearest_deltas.sort((left, right) => left - right);
  const anchorCount = accumulator.anchor.available_count;
  const globalEntropy = entropy(accumulator.scanned_byte_counts, accumulator.total_scanned_bytes);
  const rawParticipantRate = accumulator.raw_param_participant_low_byte_count / Math.max(1, count);
  const opaqueBulkSignal = globalEntropy >= 7.5
    && mapRows(accumulator.length_counts, 'payload_length').some((row) => Number(row.payload_length) >= 64);
  const constantPayloadSignal = accumulator.payload_hashes.size === 1;
  const decision = opaqueBulkSignal
    ? 'REPURPOSE'
    : 'KEEP_CANDIDATE';
  const hypothesis = opaqueBulkSignal
    ? 'OPAQUE_OR_CONTAINERIZED_BULK_UPDATE_FAMILY'
    : constantPayloadSignal && rawParticipantRate > 0.5
      ? 'ENTITY_SCOPED_OPERATION_MARKER_WITH_CONSTANT_PAYLOAD'
      : rawParticipantRate > 0.5
        ? 'ENTITY_SCOPED_UPDATE_FAMILY'
        : 'UNRESOLVED_PROTOCOL_FAMILY';
  return {
    packet_id: accumulator.packet_id,
    packet_discriminator: accumulator.packet_discriminator,
    sample_count: count,
    replay_count: accumulator.replay_counts.size,
    sample_policy_warning: 'Every-fifth game-stream sampling; counts and correlations are sample-scoped and cannot promote semantics.',
    cross_replay: {
      per_replay_counts: mapRows(accumulator.replay_counts, 'replay_sha256'),
      observed_in_all_four_replays: accumulator.replay_counts.size === 4,
    },
    payload: {
      length_distribution: mapRows(accumulator.length_counts, 'payload_length'),
      distinct_payload_hash_count: accumulator.payload_hashes.size,
      payload_repetition_rate: round(1 - (accumulator.payload_hashes.size / Math.max(1, count))),
      top_prefix2: mapRows(accumulator.prefix2_counts, 'hex', 'count', 16),
      top_prefix4: mapRows(accumulator.prefix4_counts, 'hex', 'count', 16),
      top_suffix2: mapRows(accumulator.suffix2_counts, 'hex', 'count', 16),
      scanned_global_byte_entropy_bits: round(globalEntropy),
      scanned_printable_byte_rate: round(accumulator.printable_scanned_bytes / Math.max(1, accumulator.total_scanned_bytes)),
      zlib_signature_rate: round(accumulator.zlib_signature_count / Math.max(1, count)),
      gzip_signature_rate: round(accumulator.gzip_signature_count / Math.max(1, count)),
      byte_offset_profiles: byteOffsets,
    },
    entity_identifier_mining: {
      raw_param: {
        distinct_count: accumulator.raw_param_counts.size,
        zero_rate: round(accumulator.raw_param_zero_count / Math.max(1, count)),
        full_champion_entity_rate: round(accumulator.raw_param_full_champion_count / Math.max(1, count)),
        participant_low_byte_rate: round(rawParticipantRate),
        broad_network_entity_rate: round(accumulator.raw_param_broad_network_count / Math.max(1, count)),
        top_values: mapRows(accumulator.raw_param_counts, 'value_u32', 'count', 20),
      },
      payload_u32_candidates: identifiers,
      semantic_claim: null,
    },
    numeric_structure_mining: {
      float32_candidates: floats,
      vector_candidates: vectors.slice(0, 16),
      semantic_claim: null,
    },
    temporal_behavior: {
      per_replay: replayTemporal,
      delta_p50_ms: percentile(allDeltas, 0.5),
      delta_p90_ms: percentile(allDeltas, 0.9),
      delta_p99_ms: percentile(allDeltas, 0.99),
      same_timestamp_transition_rate: round(sameTimestampTransitions / Math.max(1, transitionCount)),
    },
    damage_neighborhood: {
      anchor_kind: 'VERIFIED_0x017f_DAMAGE_PACKET_TIME_AND_SOURCE_TARGET',
      candidate_sample_count_with_anchor_replay: anchorCount,
      exact_time_rate: round(accumulator.anchor.exact_time_count / Math.max(1, anchorCount)),
      within_1ms_rate: round(accumulator.anchor.within_1ms_count / Math.max(1, anchorCount)),
      within_10ms_rate: round(accumulator.anchor.within_10ms_count / Math.max(1, anchorCount)),
      within_50ms_rate: round(accumulator.anchor.within_50ms_count / Math.max(1, anchorCount)),
      within_100ms_rate: round(accumulator.anchor.within_100ms_count / Math.max(1, anchorCount)),
      within_500ms_rate: round(accumulator.anchor.within_500ms_count / Math.max(1, anchorCount)),
      nearest_delta_p50_ms: percentile(accumulator.anchor.nearest_deltas, 0.5),
      nearest_delta_p90_ms: percentile(accumulator.anchor.nearest_deltas, 0.9),
      raw_param_matches_nearest_damage_source_rate: round(accumulator.anchor.raw_param_matches_damage_source_count / Math.max(1, anchorCount)),
      raw_param_matches_nearest_damage_target_rate: round(accumulator.anchor.raw_param_matches_damage_target_count / Math.max(1, anchorCount)),
      raw_param_matches_either_within_10ms_rate: round(accumulator.anchor.raw_param_matches_either_within_10ms_count / Math.max(1, anchorCount)),
      shifted_137ms_control_within_10ms_rate: round(accumulator.anchor.shifted_137ms_within_10ms_count / Math.max(1, anchorCount)),
      shifted_997ms_control_within_10ms_rate: round(accumulator.anchor.shifted_997ms_within_10ms_count / Math.max(1, anchorCount)),
      exact_time_enrichment_over_137ms_control: round(
        (accumulator.anchor.within_10ms_count + 1)
        / (accumulator.anchor.shifted_137ms_within_10ms_count + 1),
      ),
      exact_time_enrichment_over_997ms_control: round(
        (accumulator.anchor.within_10ms_count + 1)
        / (accumulator.anchor.shifted_997ms_within_10ms_count + 1),
      ),
      semantic_claim: null,
    },
    runtime_join: runtimeRow ? {
      callback_mapping_status: runtimeRow.runtime_registration?.callback_mapping_status ?? null,
      callback_names: runtimeRow.runtime_registration?.callback_names ?? [],
      factory_status: runtimeRow.runtime_registration?.factory_status ?? null,
      factory_packet_count: runtimeRow.runtime_registration?.factory_packets?.length ?? 0,
    } : null,
    research_decision: {
      decision,
      hypothesis,
      evidence_grade: 'CANDIDATE',
      semantic_claim: null,
      evidence_exhausted: false,
      next_required_evidence: [
        'Recover exact callback/registration/factory/deserializer identity for this currently unmapped route.',
        'Decode bounded fields or container structure, then repeat anchor and counterexample analysis without sampling bias.',
      ],
    },
  };
}

function multisetIntersection(left, right) {
  let intersection = 0;
  const smaller = left.size <= right.size ? left : right;
  const larger = smaller === left ? right : left;
  for (const [key, count] of smaller) {
    intersection += Math.min(count, larger.get(key) ?? 0);
  }
  return intersection;
}

function crossRouteRelationships(accumulators) {
  const rows = [];
  const values = [...accumulators.values()].sort((left, right) => left.packet_id - right.packet_id);
  for (let leftIndex = 0; leftIndex < values.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < values.length; rightIndex += 1) {
      const left = values[leftIndex];
      const right = values[rightIndex];
      const sameTime = multisetIntersection(left.time_key_counts, right.time_key_counts);
      const sameExact = multisetIntersection(left.exact_key_counts, right.exact_key_counts);
      const minimumCount = Math.max(1, Math.min(left.count, right.count));
      const unionTime = Math.max(1, left.count + right.count - sameTime);
      const unionExact = Math.max(1, left.count + right.count - sameExact);
      const timeContainment = sameTime / minimumCount;
      const exactContainment = sameExact / minimumCount;
      if (timeContainment < 0.01 && exactContainment < 0.01) continue;
      rows.push({
        left_packet_discriminator: left.packet_discriminator,
        right_packet_discriminator: right.packet_discriminator,
        sampled_left_count: left.count,
        sampled_right_count: right.count,
        same_replay_time_multiset_intersection: sameTime,
        same_replay_time_containment: round(timeContainment),
        same_replay_time_jaccard: round(sameTime / unionTime),
        same_replay_time_raw_param_multiset_intersection: sameExact,
        same_replay_time_raw_param_containment: round(exactContainment),
        same_replay_time_raw_param_jaccard: round(sameExact / unionExact),
        semantic_claim: null,
      });
    }
  }
  return rows.sort((left, right) =>
    right.same_replay_time_raw_param_containment - left.same_replay_time_raw_param_containment
    || right.same_replay_time_containment - left.same_replay_time_containment
    || left.left_packet_discriminator.localeCompare(right.left_packet_discriminator)
    || left.right_packet_discriminator.localeCompare(right.right_packet_discriminator));
}

function loadDamageAnchorLine(row, anchorsByReplay) {
  if (row.replay_version !== EXACT_BUILD || row.packet_id !== 0x017f || row.fully_consumed !== true) return;
  const source = Number(row.decoded_fields?.field_10_u32);
  const target = Number(row.decoded_fields?.field_14_u32);
  if (!Number.isInteger(source) || !Number.isInteger(target)) return;
  if (!anchorsByReplay.has(row.replay_sha256)) anchorsByReplay.set(row.replay_sha256, []);
  anchorsByReplay.get(row.replay_sha256).push({
    time_ms: Number(row.replay_time_ms),
    source: source >>> 0,
    target: target >>> 0,
  });
}

async function streamJsonl(filePath, visitor) {
  invariant(!filePath.toLowerCase().includes('holdout'), `protected Holdout path is forbidden: ${filePath}`);
  const hash = crypto.createHash('sha256');
  const input = fs.createReadStream(filePath);
  input.on('data', (chunk) => hash.update(chunk));
  const reader = readline.createInterface({ input, crlfDelay: Infinity });
  let lineNumber = 0;
  for await (const line of reader) {
    lineNumber += 1;
    if (!line.trim()) continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch (error) {
      throw new Error(`${filePath}:${lineNumber}: ${error.message}`);
    }
    visitor(row, lineNumber);
  }
  return { line_count: lineNumber, sha256: hash.digest('hex') };
}

async function mineUnknownRoutes({
  samplePath,
  damageAnchorPath,
  observedRegistry,
  maxScanBytes = 64,
}) {
  invariant(Number.isInteger(maxScanBytes) && maxScanBytes >= 4 && maxScanBytes <= 256,
    'maxScanBytes must be an integer from 4 to 256');
  const anchorsByReplay = new Map();
  const damageSource = await streamJsonl(damageAnchorPath,
    (row) => loadDamageAnchorLine(row, anchorsByReplay));
  for (const anchors of anchorsByReplay.values()) {
    anchors.sort((left, right) => left.time_ms - right.time_ms);
  }
  const runtimeByPacket = new Map((observedRegistry.routes ?? []).map((row) => [Number(row.packet_id), row]));
  const accumulators = new Map();
  const sampleSource = await streamJsonl(samplePath, (row) => {
    const packetId = Number(row.packet_id);
    if (!accumulators.has(packetId)) {
      accumulators.set(packetId,
        newRouteAccumulator(packetId, row.packet_type ?? `0x${packetId.toString(16).padStart(4, '0')}`, maxScanBytes));
    }
    addRow(accumulators.get(packetId), row, anchorsByReplay, maxScanBytes);
  });
  const routes = [...accumulators.values()]
    .map((accumulator) => finishRoute(accumulator, runtimeByPacket.get(accumulator.packet_id)))
    .sort((left, right) => right.sample_count - left.sample_count || left.packet_id - right.packet_id);
  const routeRelationships = crossRouteRelationships(accumulators);
  return {
    schema: REPORT_SCHEMA,
    schema_version: 2,
    analyzer_version: ANALYZER_VERSION,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    semantic_claim: null,
    promotion_authority: 'NONE',
    input: {
      sample_jsonl: { path: samplePath, ...sampleSource },
      damage_anchor_jsonl: { path: damageAnchorPath, ...damageSource },
      max_scan_bytes: maxScanBytes,
      sampling_policy: 'EVERY_FIFTH_GAME_STREAM_PACKET_WITH_PER_ROUTE_PER_REPLAY_CAP_4000',
    },
    route_count: routes.length,
    sampled_packet_count: routes.reduce((sum, row) => sum + row.sample_count, 0),
    routes,
    cross_route_relationships: routeRelationships,
    route_decisions: routes.map((row) => ({
      packet_id: row.packet_id,
      decision: row.research_decision.decision,
      evidence_grade: row.research_decision.evidence_grade,
      evidence_exhausted: row.research_decision.evidence_exhausted,
      next_required_evidence: row.research_decision.next_required_evidence,
      positive_anchor_count: 0,
      counterexample_count: 0,
    })),
    limitations: [
      'Sampling is deterministic but not exhaustive; observed rates are sample-scoped.',
      'Payload primitive plausibility, entropy, identifiers, and timing correlations do not establish semantics.',
      'Damage neighborhood uses the nearest verified 0x017f timestamp and source/target only; near-time association is not causality.',
      '137 ms and 997 ms shifted-time controls estimate dense-anchor coincidence but do not establish independence.',
      'Cross-route co-occurrence is computed over independently every-fifth sampled streams and is structural candidate evidence only.',
      'Currently unmapped runtime routes require callback/factory/deserializer recovery before field semantics can be published.',
    ],
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

module.exports = {
  ANALYZER_VERSION,
  EXACT_BUILD,
  REPORT_SCHEMA,
  addRow,
  exactParticipant,
  finishRoute,
  mineUnknownRoutes,
  nearestAnchor,
  newRouteAccumulator,
  crossRouteRelationships,
  streamJsonl,
};
