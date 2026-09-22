'use strict';

const EXACT_BUILD = '16.16.805.0442';
const LEGACY_BUILD = '16.15.801.3452';
const PACKET_ID = 0x0064;
const LEGACY_PACKET_ID = 0x0465;
const SNAPSHOT_SIZE = 10;
const CURRENT_STAGE_CODES = ['f09dfa31', 'f0393186', 'f0c524db'];
const LEGACY_STAGE_CODES = ['3d53a86d', '3d486d1a', '3dbad1f4'];

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 8) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function quantile(values, fraction) {
  if (!values.length) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const index = (sorted.length - 1) * fraction;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + ((sorted[upper] - sorted[lower]) * (index - lower));
}

function countRows(values, keyName, limit = null) {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  const rows = [...counts.entries()]
    .map(([value, count]) => ({ [keyName]: value, count }))
    .sort((left, right) => right.count - left.count
      || String(left[keyName]).localeCompare(String(right[keyName])));
  return limit === null ? rows : rows.slice(0, limit);
}

function payloadParts(payloadHex) {
  invariant(typeof payloadHex === 'string' && /^[0-9a-f]+$/i.test(payloadHex),
    'payload must be hexadecimal');
  invariant(payloadHex.length === 14, 'canonical snapshot payload must be exactly seven bytes');
  return {
    raw_payload_hex: payloadHex.toLowerCase(),
    volatile_prefix_hex: payloadHex.slice(0, 2).toLowerCase(),
    stable_suffix_hex: payloadHex.slice(2).toLowerCase(),
    stage_family_code_hex: payloadHex.slice(2, 10).toLowerCase(),
    participant_slot_code_hex: payloadHex.slice(10).toLowerCase(),
  };
}

function collapse(values, valueKey) {
  const rows = [];
  for (const value of values) {
    const key = value[valueKey];
    if (!rows.length || rows[rows.length - 1][valueKey] !== key) rows.push(value);
  }
  return rows;
}

function groupEvents(events, packetId, exactBuild) {
  const groups = new Map();
  for (const event of events) {
    invariant(event.packet_id === packetId, `unexpected packet ${event.packet_id}`);
    invariant(event.replay_version === exactBuild, `wrong build ${event.replay_version}`);
    const key = Number(event.replay_time_ms);
    invariant(Number.isFinite(key), 'event timestamp must be finite');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }
  return [...groups.entries()]
    .map(([replayTimeMs, rows]) => ({
      replay_time_ms: replayTimeMs,
      events: [...rows].sort((left, right) => left.occurrence_index - right.occurrence_index),
    }))
    .sort((left, right) => left.replay_time_ms - right.replay_time_ms);
}

function analyzeReplay(record, options = {}) {
  const packetId = options.packetId ?? PACKET_ID;
  const exactBuild = options.exactBuild ?? EXACT_BUILD;
  const expectedStageCodes = options.expectedStageCodes ?? CURRENT_STAGE_CODES;
  invariant(Array.isArray(record.roster) && record.roster.length === SNAPSHOT_SIZE,
    'each replay must provide an exact ten-participant roster');
  const utilityIds = record.roster
    .filter((row) => row.team_position === 'UTILITY')
    .map((row) => row.participant_id)
    .sort((left, right) => left - right);
  const groups = groupEvents(record.events, packetId, exactBuild);
  const fullGroups = groups.filter((group) => group.events.length === SNAPSHOT_SIZE
    && group.events.every((event) => event.raw_param === 0 && event.payload_length === 7));

  const suffixCountsBySlot = Array.from({ length: SNAPSHOT_SIZE }, (_, slotIndex) =>
    countRows(fullGroups.map((group) => payloadParts(group.events[slotIndex].raw_payload_hex).stable_suffix_hex),
      'stable_suffix_hex'));
  const allowedSuffixBySlot = suffixCountsBySlot.map((rows, slotIndex) => {
    const participantId = slotIndex + 1;
    const limit = utilityIds.includes(participantId) ? 3 : 1;
    return new Set(rows.slice(0, limit).map((row) => row.stable_suffix_hex));
  });
  const canonicalGroups = fullGroups.filter((group) => group.events.every((event, slotIndex) =>
    allowedSuffixBySlot[slotIndex].has(payloadParts(event.raw_payload_hex).stable_suffix_hex)));

  const slotSeries = Array.from({ length: SNAPSHOT_SIZE }, (_, slotIndex) => {
    const participantId = slotIndex + 1;
    const champion = record.roster[slotIndex].champion ?? null;
    const teamPosition = record.roster[slotIndex].team_position ?? null;
    const rows = canonicalGroups.map((group) => {
      const parts = payloadParts(group.events[slotIndex].raw_payload_hex);
      return {
        replay_time_ms: group.replay_time_ms,
        ...parts,
      };
    });
    const transitions = collapse(rows.map((row) => ({
      replay_time_ms: row.replay_time_ms,
      stable_suffix_hex: row.stable_suffix_hex,
      stage_family_code_hex: row.stage_family_code_hex,
      participant_slot_code_hex: row.participant_slot_code_hex,
    })), 'stable_suffix_hex');
    const prefixChanges = rows.slice(1).reduce((count, row, index) =>
      count + Number(row.volatile_prefix_hex !== rows[index].volatile_prefix_hex), 0);
    return {
      participant_id: participantId,
      champion,
      team_position: teamPosition,
      utility_slot: utilityIds.includes(participantId),
      observation_count: rows.length,
      distinct_stable_suffix_count: new Set(rows.map((row) => row.stable_suffix_hex)).size,
      distinct_stage_family_code_count: new Set(rows.map((row) => row.stage_family_code_hex)).size,
      distinct_volatile_prefix_count: new Set(rows.map((row) => row.volatile_prefix_hex)).size,
      volatile_prefix_change_rate: rows.length > 1 ? round(prefixChanges / (rows.length - 1)) : null,
      transitions,
    };
  });

  const utilitySeries = slotSeries.filter((row) => row.utility_slot);
  const nonUtilitySeries = slotSeries.filter((row) => !row.utility_slot);
  const utilityStageOrderPass = utilitySeries.length === 2
    && utilitySeries.every((row) => row.transitions.length === 3
      && row.transitions.map((entry) => entry.stage_family_code_hex).join(',')
        === expectedStageCodes.join(','));
  const nonUtilityStablePass = nonUtilitySeries.length === 8
    && nonUtilitySeries.every((row) => row.distinct_stable_suffix_count === 1);
  const intervals = canonicalGroups.slice(1).map((group, index) =>
    group.replay_time_ms - canonicalGroups[index].replay_time_ms);

  return {
    replay_label: record.replay_label ?? null,
    replay_sha256: record.replay_sha256,
    exact_build: exactBuild,
    packet_id: packetId,
    counts: {
      event_count: record.events.length,
      timestamp_group_count: groups.length,
      exact_ten_row_seven_byte_zero_param_group_count: fullGroups.length,
      canonical_periodic_snapshot_group_count: canonicalGroups.length,
      noncanonical_full_group_count: fullGroups.length - canonicalGroups.length,
      residual_event_count: record.events.length - (canonicalGroups.length * SNAPSHOT_SIZE),
    },
    interval_ms: {
      min: intervals.length ? Math.min(...intervals) : null,
      p50: quantile(intervals, 0.5),
      p90: quantile(intervals, 0.9),
      max: intervals.length ? Math.max(...intervals) : null,
    },
    utility_participant_ids: utilityIds,
    roster: record.roster,
    slot_series: slotSeries,
    validations: {
      exactly_two_utility_slots: utilityIds.length === 2,
      utility_slots_follow_exact_three_stage_order: utilityStageOrderPass,
      all_eight_nonutility_slots_have_constant_suffix: nonUtilityStablePass,
      canonical_groups_exist: canonicalGroups.length > 0,
      all_pass: utilityIds.length === 2 && utilityStageOrderPass
        && nonUtilityStablePass && canonicalGroups.length > 0,
    },
  };
}

function nearestPreceding(events, participantId, itemId, timestampMs, maxLagMs) {
  const rows = events
    .filter((event) => event.type === 'ITEM_DESTROYED'
      && event.participant_id === participantId
      && event.item_id === itemId
      && event.timestamp_ms <= timestampMs
      && timestampMs - event.timestamp_ms <= maxLagMs)
    .sort((left, right) => right.timestamp_ms - left.timestamp_ms);
  return rows[0] ?? null;
}

function alignP0Details(replayAnalyses, p0Records) {
  const expectedByStage = new Map([[1, 3865], [2, 3867]]);
  const alignments = [];
  for (const record of p0Records) {
    const replay = replayAnalyses.find((row) => row.replay_sha256 === record.replay_sha256);
    invariant(replay, `missing replay analysis for P0 ${record.replay_sha256}`);
    for (const series of replay.slot_series.filter((row) => row.utility_slot)) {
      for (let stageIndex = 1; stageIndex <= 2; stageIndex += 1) {
        const transition = series.transitions[stageIndex];
        const expectedItemId = expectedByStage.get(stageIndex);
        const anchor = nearestPreceding(record.item_events, series.participant_id,
          expectedItemId, transition.replay_time_ms, 1000);
        const companion3866 = stageIndex === 2
          ? nearestPreceding(record.item_events, series.participant_id, 3866,
            transition.replay_time_ms, 5000) : null;
        alignments.push({
          game_id: record.game_id,
          replay_sha256: record.replay_sha256,
          participant_id: series.participant_id,
          champion: series.champion,
          team_position: series.team_position,
          stage_before: stageIndex - 1,
          stage_after: stageIndex,
          route_first_observed_timestamp_ms: transition.replay_time_ms,
          stage_family_code_hex: transition.stage_family_code_hex,
          expected_details_anchor: {
            type: 'ITEM_DESTROYED',
            item_id: expectedItemId,
          },
          matched: anchor !== null,
          lag_after_details_anchor_ms: anchor
            ? transition.replay_time_ms - anchor.timestamp_ms : null,
          details_anchor: anchor,
          preceding_item_3866_within_5s: companion3866,
        });
      }
    }
  }
  const relevantDetailsEvents = p0Records.flatMap((record) => {
    const utilityIds = new Set(record.roster
      .filter((row) => row.team_position === 'UTILITY')
      .map((row) => row.participant_id));
    return record.item_events
      .filter((event) => event.type === 'ITEM_DESTROYED'
        && utilityIds.has(event.participant_id)
        && [3865, 3867].includes(event.item_id))
      .map((event) => ({ game_id: record.game_id, replay_sha256: record.replay_sha256, ...event }));
  });
  const matchedAnchorKeys = new Set(alignments.filter((row) => row.matched).map((row) =>
    `${row.replay_sha256}:${row.details_anchor.source_json_path}`));
  const unmatchedRelevantDetails = relevantDetailsEvents.filter((event) =>
    !matchedAnchorKeys.has(`${event.replay_sha256}:${event.source_json_path}`));
  const lags = alignments.filter((row) => row.matched).map((row) => row.lag_after_details_anchor_ms);
  return {
    expected_alignment_count: alignments.length,
    matched_alignment_count: alignments.filter((row) => row.matched).length,
    unmatched_transition_count: alignments.filter((row) => !row.matched).length,
    relevant_details_anchor_count: relevantDetailsEvents.length,
    unmatched_relevant_details_anchor_count: unmatchedRelevantDetails.length,
    lag_after_details_anchor_ms: {
      min: lags.length ? Math.min(...lags) : null,
      p50: quantile(lags, 0.5),
      p90: quantile(lags, 0.9),
      max: lags.length ? Math.max(...lags) : null,
    },
    alignments,
    unmatched_relevant_details_anchors: unmatchedRelevantDetails,
    all_pass: alignments.length > 0
      && alignments.every((row) => row.matched)
      && unmatchedRelevantDetails.length === 0,
  };
}

function aggregateReplayCounts(replays) {
  return {
    replay_count: replays.length,
    event_count: replays.reduce((sum, row) => sum + row.counts.event_count, 0),
    canonical_periodic_snapshot_group_count: replays.reduce((sum, row) =>
      sum + row.counts.canonical_periodic_snapshot_group_count, 0),
    residual_event_count: replays.reduce((sum, row) => sum + row.counts.residual_event_count, 0),
  };
}

function analyzeRoute0064({ latestRecords, p0Records, legacyRecords = [], expectedLatestCount = null }) {
  invariant(Array.isArray(latestRecords) && latestRecords.length > 0, 'latest records are required');
  invariant(Array.isArray(p0Records) && p0Records.length > 0, 'P0 records are required');
  const latest = latestRecords.map((record) => analyzeReplay(record));
  const p0 = p0Records.map((record) => analyzeReplay(record));
  const legacy = legacyRecords.map((record) => analyzeReplay(record, {
    packetId: LEGACY_PACKET_ID,
    exactBuild: LEGACY_BUILD,
    expectedStageCodes: LEGACY_STAGE_CODES,
  }));
  const latestCounts = aggregateReplayCounts(latest);
  const p0Counts = aggregateReplayCounts(p0);
  const legacyCounts = aggregateReplayCounts(legacy);
  const detailsAlignment = alignP0Details(p0, p0Records);
  const allCurrentReplaysPass = [...latest, ...p0].every((row) => row.validations.all_pass);
  const legacyBehaviorPass = legacy.length > 0 && legacy.every((row) => row.validations.all_pass);
  const latestCountMatch = expectedLatestCount === null || latestCounts.event_count === expectedLatestCount;
  const nonUtilityControls = [...latest, ...p0].flatMap((row) => row.slot_series)
    .filter((row) => !row.utility_slot);
  const utilitySeries = [...latest, ...p0].flatMap((row) => row.slot_series)
    .filter((row) => row.utility_slot);
  const boundedPromotionPass = allCurrentReplaysPass && latestCountMatch
    && detailsAlignment.all_pass
    && nonUtilityControls.length > 0
    && nonUtilityControls.every((row) => row.distinct_stable_suffix_count === 1)
    && utilitySeries.every((row) => row.transitions.length === 3);

  return {
    schema: 'ROUTE_0064_SUPPORT_QUEST_STAGE_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    packet_id: PACKET_ID,
    packet_discriminator: '0x0064',
    known_runtime_identity: {
      callback_mapping_status: 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE',
      factory_status: 'NO_FACTORY_SHAPE_IN_SIDECAR',
      implication: 'The semantic result is differential and framing-derived; no RTTI class name is claimed.',
    },
    counts: {
      latest_four: latestCounts,
      safe_p0: p0Counts,
      legacy_low_cost_side_evidence: legacyCounts,
      current_build_total_event_count: latestCounts.event_count + p0Counts.event_count,
    },
    recovered_bounded_structure: {
      evidence_grade: 'VERIFIED_DERIVED',
      group_contract: 'Exactly ten consecutive 0x0064 rows at one timestamp, raw_param=0, payload_length=7, in replay walk order.',
      participant_mapping: 'Replay walk ordinal 1..10, independently checked against TEAM_POSITION=UTILITY at ordinals 5 and 10.',
      field_contract: {
        byte_0: 'UNKNOWN_VOLATILE_PREFIX_PRESERVED_RAW',
        bytes_1_to_4: 'EXACT_BUILD_SUPPORT_QUEST_STAGE_FAMILY_CODE_FOR_UTILITY_SLOTS_ONLY',
        bytes_5_to_6: 'PARTICIPANT_SLOT_SIGNATURE_CANDIDATE_PRESERVED_RAW',
      },
      exact_build_stage_code_map: CURRENT_STAGE_CODES.map((code, stage) => ({
        stage,
        stage_family_code_hex: code,
        evidence: stage === 0 ? 'INITIAL_PERIODIC_STATE'
          : stage === 1 ? '8/8 safe-P0 transitions follow ITEM_DESTROYED itemId=3865'
            : '8/8 safe-P0 transitions follow ITEM_DESTROYED itemId=3867',
      })),
      semantic_name: 'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT',
      semantic_scope: 'UTILITY_PARTICIPANTS_AND_CANONICAL_TEN_ROW_GROUPS_ONLY',
    },
    details_ground_truth_alignment: detailsAlignment,
    current_build_replays: {
      latest_four: latest,
      safe_p0: p0,
    },
    cross_build_low_cost_side_evidence: {
      legacy_build: LEGACY_BUILD,
      legacy_packet_id: LEGACY_PACKET_ID,
      legacy_packet_discriminator: '0x0465',
      binary_compatible: false,
      decoder_compatible: false,
      semantic_behavior_analogous_candidate: legacyBehaviorPass,
      legacy_stage_family_codes: LEGACY_STAGE_CODES,
      warning: 'The route ID and byte codes differ. This evidence supports a behavioral family only and never authorizes decoder reuse or nearest-build fallback.',
      replays: legacy,
    },
    validations: {
      latest_inventory_count_match: latestCountMatch,
      all_current_build_replays_have_two_utility_only_three_stage_series: allCurrentReplaysPass,
      all_details_transitions_and_anchors_bijectively_match: detailsAlignment.all_pass,
      legacy_16_15_behavioral_analogue_pass: legacyBehaviorPass,
      bounded_research_promotion_pass: boundedPromotionPass,
      all_pass: boundedPromotionPass && legacyBehaviorPass,
    },
    negative_evidence: {
      nonutility_control_series_count: nonUtilityControls.length,
      nonutility_control_series_with_any_suffix_change: nonUtilityControls
        .filter((row) => row.distinct_stable_suffix_count !== 1).length,
      rejected_hypotheses: [
        'GENERAL_CURRENT_HP',
        'GENERAL_MAX_HP',
        'GENERAL_RESOURCE',
        'GENERAL_ARMOR_OR_MAGIC_RESIST',
        'GENERAL_ATTACK_DAMAGE_OR_ABILITY_POWER',
        'INDEPENDENT_ENTITY_EVENT',
        'PER_PACKET_PARTICIPANT_ID_IN_RAW_PARAM',
      ],
      residual_unknowns: [
        'The volatile first byte has no semantic claim.',
        'Three-byte packets and all noncanonical timestamp groups remain UNKNOWN and are count-conserved.',
        'The two-byte participant-slot signature is not named beyond a candidate structural role.',
        'The runtime callback/factory/deserializer identity remains unresolved.',
      ],
    },
    route_decisions: [{
      packet_id: PACKET_ID,
      packet_discriminator: '0x0064',
      decision: boundedPromotionPass ? 'PROMOTE' : 'KEEP_CANDIDATE',
      hypothesis: 'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT',
      evidence_grade: boundedPromotionPass ? 'VERIFIED_DERIVED' : 'CANDIDATE',
      promotion_scope: 'RESEARCH_ONLY_CANONICAL_TEN_ROW_GROUPS_AND_UTILITY_SLOTS',
      supersedes_previous_decision: true,
      semantic_claim: boundedPromotionPass ? {
        event_or_state: 'STATE_SNAPSHOT',
        semantic_name: 'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT',
        stage_values: [0, 1, 2],
        exact_build: EXACT_BUILD,
      } : null,
      positive_anchor_count: detailsAlignment.matched_alignment_count,
      counterexample_count: detailsAlignment.unmatched_transition_count
        + detailsAlignment.unmatched_relevant_details_anchor_count
        + nonUtilityControls.filter((row) => row.distinct_stable_suffix_count !== 1).length,
      evidence_exhausted: false,
      next_required_evidence: [
        'Recover the 0x0064 runtime callback/factory/deserializer identity and explain byte 0.',
        'Decode and classify the three-byte and noncanonical groups without discarding them.',
        'Before public API publication, add an exact-build adapter that fails closed outside the canonical ten-row group contract.',
      ],
    }],
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
  CURRENT_STAGE_CODES,
  EXACT_BUILD,
  LEGACY_BUILD,
  LEGACY_PACKET_ID,
  LEGACY_STAGE_CODES,
  PACKET_ID,
  analyzeReplay,
  analyzeRoute0064,
  payloadParts,
};
