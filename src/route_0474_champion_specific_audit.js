'use strict';

const EXACT_BUILD = '16.16.805.0442';
const PACKET_ID = 0x0474;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 8) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function participantFromRawParam(value) {
  const participantId = ((value >>> 0) & 0xff) - 0xad;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function canonicalHeroEntity(participantId) {
  return participantId === null ? null : (0x400000ad + participantId) >>> 0;
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

function seriesRows(events) {
  const series = new Map();
  for (const event of events) {
    const participantId = participantFromRawParam(event.raw_param);
    const champion = event.champion ?? null;
    const key = `${event.replay_sha256}:${participantId ?? 'unknown'}:${champion ?? 'UNKNOWN'}`;
    if (!series.has(key)) {
      series.set(key, {
        replay_sha256: event.replay_sha256,
        replay_label: event.replay_label ?? null,
        participant_id: participantId,
        champion,
        events: [],
      });
    }
    series.get(key).events.push(event);
  }
  return [...series.values()].map((entry) => {
    entry.events.sort((left, right) => left.replay_time_ms - right.replay_time_ms
      || left.occurrence_index - right.occurrence_index);
    const times = entry.events.map((event) => event.replay_time_ms);
    const uniqueTimes = new Set(times);
    const canonicalCount = entry.events.filter((event) => event.raw_param
      === canonicalHeroEntity(entry.participant_id)).length;
    const spanMs = times.length ? times[times.length - 1] - times[0] : 0;
    return {
      replay_sha256: entry.replay_sha256,
      replay_label: entry.replay_label,
      participant_id: entry.participant_id,
      champion: entry.champion,
      event_count: entry.events.length,
      unique_timestamp_count: uniqueTimes.size,
      first_time_ms: times[0] ?? null,
      last_time_ms: times[times.length - 1] ?? null,
      span_ms: spanMs,
      approximate_event_rate_per_second: spanMs > 0
        ? round(entry.events.length / (spanMs / 1000)) : null,
      canonical_entity_count: canonicalCount,
      upper_byte_variant_count: entry.events.length - canonicalCount,
      canonical_entity_rate: round(canonicalCount / entry.events.length),
      distinct_raw_param_count: new Set(entry.events.map((event) => event.raw_param)).size,
      distinct_payload_count: new Set(entry.events.map((event) => event.raw_payload_hex)).size,
      payload_distribution: countRows(entry.events.map((event) => event.raw_payload_hex), 'payload_hex', 16),
      length_distribution: countRows(entry.events.map((event) => event.payload_length), 'payload_length'),
    };
  }).sort((left, right) => right.event_count - left.event_count
    || String(left.replay_sha256).localeCompare(String(right.replay_sha256))
    || (left.participant_id ?? 999) - (right.participant_id ?? 999));
}

function analyzeRoute0474(events, expectedCount = null, replayRecords = []) {
  for (const event of events) {
    invariant(event.packet_id === PACKET_ID, `unexpected packet ${event.packet_id}`);
    invariant(event.replay_version === EXACT_BUILD, `wrong build ${event.replay_version}`);
  }
  const mappedEvents = events.filter((event) => participantFromRawParam(event.raw_param) !== null);
  const series = seriesRows(events);
  const championCounts = countRows(mappedEvents.map((event) => event.champion ?? 'UNKNOWN'), 'champion');
  const dominantChampion = championCounts[0] ?? { champion: null, count: 0 };
  const dominantEvents = mappedEvents.filter((event) => (event.champion ?? 'UNKNOWN') === dominantChampion.champion);
  const dominantPayloads = countRows(dominantEvents.map((event) => event.raw_payload_hex), 'payload_hex');
  const dominantPayload = dominantPayloads[0] ?? { payload_hex: null, count: 0 };
  const totalParticipantSlots = replayRecords.reduce((sum, replay) => sum + (replay.roster?.length ?? 0), 0);
  const coveredParticipantSlots = new Set(mappedEvents.map((event) =>
    `${event.replay_sha256}:${participantFromRawParam(event.raw_param)}`)).size;
  const inventoryPass = expectedCount === null || events.length === expectedCount;
  const allParticipantLike = mappedEvents.length === events.length;
  const dominantRate = events.length ? dominantChampion.count / events.length : 0;
  const dominantPayloadRate = dominantEvents.length ? dominantPayload.count / dominantEvents.length : 0;
  const dominantTwoByteRate = dominantEvents.length
    ? dominantEvents.filter((event) => event.payload_length === 2).length / dominantEvents.length : 0;
  const generalHeroStateRejected = events.length > 0
    && totalParticipantSlots > 0
    && coveredParticipantSlots / totalParticipantSlots < 0.5
    && dominantRate > 0.95
    && dominantPayloadRate > 0.95;

  return {
    schema: 'ROUTE_0474_CHAMPION_SPECIFIC_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    packet_id: PACKET_ID,
    packet_discriminator: '0x0474',
    counts: {
      event_count: events.length,
      replay_count: replayRecords.length,
      mapped_participant_event_count: mappedEvents.length,
      unmapped_raw_param_event_count: events.length - mappedEvents.length,
      total_roster_participant_slots: totalParticipantSlots,
      covered_replay_participant_slots: coveredParticipantSlots,
      covered_replay_participant_rate: totalParticipantSlots
        ? round(coveredParticipantSlots / totalParticipantSlots) : null,
    },
    distributions: {
      stream: countRows(events.map((event) => event.chunk_stream), 'chunk_stream'),
      payload_length: countRows(events.map((event) => event.payload_length), 'payload_length'),
      payload: countRows(events.map((event) => event.raw_payload_hex), 'payload_hex', 32),
      champion: championCounts,
      replay: countRows(events.map((event) => event.replay_sha256), 'replay_sha256'),
    },
    dominant_behavior: {
      champion: dominantChampion.champion,
      event_count: dominantChampion.count,
      event_rate: round(dominantRate),
      top_payload_hex: dominantPayload.payload_hex,
      top_payload_count: dominantPayload.count,
      top_payload_rate_within_dominant_champion: round(dominantPayloadRate),
      two_byte_payload_rate_within_dominant_champion: round(dominantTwoByteRate),
    },
    entity_series: series,
    replay_rosters: replayRecords.map((replay) => ({
      replay_label: replay.replay_label,
      replay_sha256: replay.replay_sha256,
      roster: replay.roster,
    })),
    validations: {
      inventory_count_match: inventoryPass,
      all_raw_params_have_participant_like_low_byte: allParticipantLike,
      dominant_champion_rate_at_least_95_percent: dominantRate >= 0.95,
      dominant_champion_top_payload_rate_at_least_95_percent: dominantPayloadRate >= 0.95,
      general_hero_persistent_state_hypothesis_rejected: generalHeroStateRejected,
      all_pass: inventoryPass && allParticipantLike && generalHeroStateRejected,
    },
    negative_evidence: {
      rejected_hypotheses: generalHeroStateRejected ? [
        'GENERAL_CURRENT_HP',
        'GENERAL_MAX_HP',
        'GENERAL_CURRENT_MANA_OR_RESOURCE',
        'GENERAL_MAX_MANA_OR_RESOURCE',
        'GENERAL_ARMOR',
        'GENERAL_MAGIC_RESIST',
        'GENERAL_ATTACK_DAMAGE',
        'GENERAL_ABILITY_POWER',
        'GENERAL_ATTACK_SPEED',
        'GENERAL_MOVE_SPEED',
      ] : [],
      reason: generalHeroStateRejected
        ? 'The exact four-replay route is overwhelmingly concentrated on one champion and one constant payload while most replay-participant slots never emit it; a general volatile Hero-state scalar cannot have this behavior.'
        : 'The configured rejection thresholds were not met.',
      semantic_claim: null,
    },
    route_decisions: [{
      packet_id: PACKET_ID,
      packet_discriminator: '0x0474',
      decision: generalHeroStateRejected ? 'REPURPOSE' : 'KEEP_CANDIDATE',
      hypothesis: generalHeroStateRejected
        ? 'CHAMPION_SPECIFIC_PERIODIC_COMPONENT_FAMILY_DOMINATED_BY_ZILEAN'
        : 'ENTITY_SCOPED_UPDATE_FAMILY',
      evidence_grade: 'CANDIDATE',
      evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS',
      supersedes_previous_decision: true,
      semantic_claim: null,
      positive_anchor_count: dominantChampion.count,
      counterexample_count: events.length - dominantChampion.count,
      evidence_exhausted: false,
      next_required_evidence: [
        'Recover the exact runtime callback/factory/deserializer identity for 0x0474.',
        'Acquire or identify a controlled exact-build Zilean calibration replay and compare with a no-Zilean control.',
        'Explain the upper-byte raw_param variants and sparse non-Zilean rows before naming the component operation.',
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
  EXACT_BUILD,
  PACKET_ID,
  analyzeRoute0474,
  canonicalHeroEntity,
  participantFromRawParam,
};
