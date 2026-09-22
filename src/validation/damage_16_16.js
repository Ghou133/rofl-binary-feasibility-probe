'use strict';

const DAMAGE_COMPONENTS = Object.freeze([
  Object.freeze({ field: 'physicalDamage', damage_type: 'physical', expected_code: 0 }),
  Object.freeze({ field: 'magicDamage', damage_type: 'magic', expected_code: 1 }),
  Object.freeze({ field: 'trueDamage', damage_type: 'true', expected_code: 2 }),
]);

function collectDetailsDamageAnchors(details, options = {}) {
  const frames = details?.json?.frames;
  if (!Array.isArray(frames)) throw new TypeError('DETAILS wrapper requires json.frames');
  const maxTimeMs = options.maxTimeMs ?? Infinity;
  const anchors = [];
  for (const [frameIndex, frame] of frames.entries()) {
    for (const [eventIndex, event] of (frame.events || []).entries()) {
      if (event.type !== 'CHAMPION_KILL' || !Number.isFinite(event.timestamp)
          || event.timestamp > maxTimeMs || !Number.isInteger(event.victimId)) continue;
      for (const [damageIndex, damage] of (event.victimDamageReceived || []).entries()) {
        if (!Number.isInteger(damage.participantId)
            || damage.participantId < 1 || damage.participantId > 10) continue;
        for (const component of DAMAGE_COMPONENTS) {
          const amount = damage[component.field];
          if (!Number.isFinite(amount) || amount <= 0) continue;
          anchors.push({
            timestamp_ms: event.timestamp,
            source_participant_id: damage.participantId,
            target_participant_id: event.victimId,
            source_network_id: 0x400000ad + damage.participantId,
            target_network_id: 0x400000ad + event.victimId,
            damage_type: component.damage_type,
            expected_damage_type_code: component.expected_code,
            details_amount: amount,
            details_path: `$.json.frames[${frameIndex}].events[${eventIndex}]`
              + `.victimDamageReceived[${damageIndex}].${component.field}`,
          });
        }
      }
    }
  }
  return anchors.sort((left, right) => left.timestamp_ms - right.timestamp_ms
    || left.source_participant_id - right.source_participant_id
    || left.target_participant_id - right.target_participant_id
    || left.expected_damage_type_code - right.expected_damage_type_code
    || left.details_amount - right.details_amount
    || left.details_path.localeCompare(right.details_path));
}

function canonicalDecodedRow(row, index) {
  const fields = row?.decoded_fields || {};
  if (row?.fully_consumed !== true || row?.deserialize_return_al === 0
      || !Number.isInteger(fields.field_10_u32)
      || !Number.isInteger(fields.field_14_u32)
      || !Number.isFinite(fields.field_24_f32)
      || !Number.isInteger(fields.field_28_u8)) return null;
  return {
    row_index: index,
    replay_time_ms: row.replay_time_ms,
    source_network_id: fields.field_10_u32 >>> 0,
    target_network_id: fields.field_14_u32 >>> 0,
    recorded_amount: fields.field_24_f32,
    damage_type_code: fields.field_28_u8,
    secondary_amount: Number.isFinite(fields.field_2c_f32) ? fields.field_2c_f32 : null,
    protocol_field_30: Number.isInteger(fields.field_30_u32) ? fields.field_30_u32 >>> 0 : null,
    raw_packet_ref: {
      replay_sha256: row.replay_sha256 ?? null,
      chunk_index: row.chunk_index ?? null,
      decompressed_block_offset: row.decompressed_block_offset ?? null,
      packet_id: row.packet_id ?? null,
      payload_length: row.payload_length ?? null,
      raw_param: row.raw_param ?? null,
      raw_payload_sha256: row.raw_payload_sha256 ?? null,
    },
  };
}

function matchDetailsDamageAnchors(anchors, decodedRows, options = {}) {
  const windowMs = options.windowMs ?? 100;
  const rows = decodedRows.map(canonicalDecodedRow).filter(Boolean);
  const used = new Set();
  const matches = [];
  const unmatched = [];
  for (const anchor of anchors) {
    const candidates = rows.filter((row) => !used.has(row.row_index)
      && row.source_network_id === anchor.source_network_id
      && row.target_network_id === anchor.target_network_id
      && Number.isFinite(row.replay_time_ms)
      && Math.abs(row.replay_time_ms - anchor.timestamp_ms) <= windowMs
      && Math.round(row.recorded_amount) === anchor.details_amount)
      .sort((left, right) => (
        Math.abs(left.replay_time_ms - anchor.timestamp_ms)
          - Math.abs(right.replay_time_ms - anchor.timestamp_ms)
        || Math.abs(left.recorded_amount - anchor.details_amount)
          - Math.abs(right.recorded_amount - anchor.details_amount)
        || left.row_index - right.row_index
      ));
    const selected = candidates[0];
    if (!selected) {
      unmatched.push(anchor);
      continue;
    }
    used.add(selected.row_index);
    matches.push({
      ...anchor,
      replay_packet_time_ms: selected.replay_time_ms,
      timestamp_delta_ms: selected.replay_time_ms - anchor.timestamp_ms,
      recorded_amount: selected.recorded_amount,
      rounded_recorded_amount: Math.round(selected.recorded_amount),
      amount_delta_from_details: selected.recorded_amount - anchor.details_amount,
      observed_damage_type_code: selected.damage_type_code,
      damage_type_code_matches: selected.damage_type_code === anchor.expected_damage_type_code,
      secondary_amount: selected.secondary_amount,
      protocol_field_30: selected.protocol_field_30,
      raw_packet_ref: selected.raw_packet_ref,
    });
  }
  return { matches, unmatched };
}

function createDamageAnchorValidation(input, options = {}) {
  const anchors = collectDetailsDamageAnchors(input.details, {
    maxTimeMs: options.maxTimeMs,
  });
  const matched = matchDetailsDamageAnchors(anchors, input.decodedRows, {
    windowMs: options.windowMs,
  });
  const typeCounts = Object.fromEntries(DAMAGE_COMPONENTS.map((component) => [
    component.damage_type,
    matched.matches.filter((row) => row.damage_type === component.damage_type
      && row.damage_type_code_matches).length,
  ]));
  const typeMismatchCount = matched.matches.filter((row) => !row.damage_type_code_matches).length;
  const requiredTypesObserved = DAMAGE_COMPONENTS.every(
    (component) => typeCounts[component.damage_type] > 0,
  );
  return {
    schema: 'ROFL_16_16_DAMAGE_ANCHOR_VALIDATION_V1',
    schema_version: 1,
    status: requiredTypesObserved && typeMismatchCount === 0 ? 'PASS' : 'FAIL',
    exact_build: '16.16.805.0442',
    evidence_grade: 'VERIFIED_DIRECT',
    details_role: 'VALIDATION_ORACLE_ONLY_NOT_A_REPLAY_SEMANTIC_SOURCE',
    matching_policy: {
      source_target: 'exact champion network ids derived from DETAILS participant ids',
      timestamp_window_ms: options.windowMs ?? 100,
      amount: 'Math.round(decoded primary amount) === integer DETAILS component',
      damage_type_code: 'not used for selection; evaluated only after a one-to-one match',
    },
    amount_semantic_stage: 'UNKNOWN',
    amount_semantic_stage_note: (
      'Correlation proves the direct recorded amount field tracks the integer DETAILS '
      + 'damage component; it does not prove pre/post-mitigation or effective HP-loss stage.'
    ),
    decoded_row_count: input.decodedRows.length,
    details_anchor_count: anchors.length,
    matched_anchor_count: matched.matches.length,
    unmatched_anchor_count: matched.unmatched.length,
    damage_type_match_counts: typeCounts,
    damage_type_mismatch_count: typeMismatchCount,
    all_three_damage_types_observed: requiredTypesObserved,
    matches: matched.matches,
    unmatched_details_anchors: matched.unmatched,
    provenance: input.provenance ?? {},
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      consumed: false,
    },
  };
}

module.exports = {
  DAMAGE_COMPONENTS,
  collectDetailsDamageAnchors,
  createDamageAnchorValidation,
  matchDetailsDamageAnchors,
};

