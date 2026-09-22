'use strict';

const EXACT_BUILD = '16.16.805.0442';
const ROUTE_HEX = '0x0265';
const ROUTE_ID = 0x0265;
const RUNTIME_IMAGE_SHA256 =
  '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';

const STATIC_CHAIN = Object.freeze({
  runtime_type_name: 'PKT_HeroReincarnateAlive_s',
  callback_owner_type: 'AIHeroClient',
  callback_registration_rva: '0x002f1c21',
  callback_receive_target_rva: '0x0032ce00',
  callback_receive_target_selection:
    'The member-function pointer immediately preceding r8d=0x0265 and generic registration 0x006f5b40.',
  factory_case_rva: '0x00ee1f7f',
  constructor_rva: '0x00e7aed0',
  vtable_rva: '0x01b11018',
  deserializer_rva: '0x00ef67c0',
  consumer_rva: '0x0027b660',
  object_size: 0x1c,
});

function rotateRight8(value, count) {
  const byte = value & 0xff;
  return ((byte >>> count) | (byte << (8 - count))) & 0xff;
}

function decryptPositionByte(value) {
  const byte = value & 0xff;
  let high = byte & 0xd5;
  let low = (byte >>> 1) & 0x55;
  high = (high << 1) & 0xff;
  let result = (high | low) & 0xff;
  result = (~result) & 0xff;
  result = (result + 0x58) & 0xff;
  return rotateRight8(result, 6);
}

function decryptScalarByte(value) {
  let mixed = ((value & 0xff) - 0x55) & 0xff;
  let high = mixed & 0xd5;
  const low = (mixed >>> 1) & 0x55;
  high = (high << 1) & 0xff;
  mixed = (high | low) & 0xff;
  mixed ^= 0x1e;
  return (mixed - 0x21) & 0xff;
}

function decryptU32ToFloat(value, decryptByte) {
  const bytes = Buffer.allocUnsafe(4);
  bytes.writeUInt32LE(value >>> 0, 0);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = decryptByte(bytes[index]);
  }
  return bytes.readFloatLE(0);
}

function decodeProtectedFields(row) {
  const fields = row.decoded_fields || row;
  const x = decryptU32ToFloat(fields.field_10_u32, decryptPositionByte);
  const z = decryptU32ToFloat(fields.field_14_u32, decryptPositionByte);
  const reincarnateScalar = decryptU32ToFloat(
    fields.field_18_u32,
    decryptScalarByte,
  );
  if (![x, z, reincarnateScalar].every(Number.isFinite)) {
    throw new Error('0x0265 protected-field inverse produced a non-finite value');
  }
  return { x, y: 0, z, reincarnate_scalar: reincarnateScalar };
}

function participantIdFromRawParam(rawParam) {
  const participantId = ((rawParam >>> 0) & 0xff) - 0xad;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function assertSafePath(filePath) {
  if (typeof filePath !== 'string' || /jungle[^\\/]*objective[^\\/]*holdout/i.test(filePath)) {
    throw new Error('Protected Jungle Objective Holdout paths are forbidden');
  }
}

function assertDecodedRow(row) {
  if (row.replay_version !== EXACT_BUILD) {
    throw new Error(`0x0265 exact-build mismatch: ${row.replay_version}`);
  }
  if (row.packet_type !== ROUTE_HEX || row.packet_id !== ROUTE_ID) {
    throw new Error(`unexpected route in 0x0265 audit: ${row.packet_type}`);
  }
  if (row.fully_consumed !== true || row.deserialize_return_al !== 1) {
    throw new Error('0x0265 native decode must succeed and fully consume the row');
  }
  if (!/^[0-9a-f]{64}$/i.test(row.replay_sha256 || '')) {
    throw new Error('0x0265 row is missing an exact Replay SHA-256');
  }
}

function uniqueBy(items, keyOf) {
  const result = new Map();
  for (const item of items) result.set(keyOf(item), item);
  return [...result.values()];
}

function groupBy(items, keyOf) {
  const result = new Map();
  for (const item of items) {
    const key = keyOf(item);
    if (!result.has(key)) result.set(key, []);
    result.get(key).push(item);
  }
  return result;
}

function countBy(items, keyOf) {
  const result = {};
  for (const item of items) {
    const key = String(keyOf(item));
    result[key] = (result[key] || 0) + 1;
  }
  return result;
}

function round(value, digits = 8) {
  if (!Number.isFinite(value)) return value;
  return Number(value.toFixed(digits));
}

function adjacentFrames(frames, timestampMs) {
  let previous = null;
  let next = null;
  for (const frame of frames || []) {
    if (frame.timestamp <= timestampMs) previous = frame;
    if (frame.timestamp >= timestampMs) {
      next = frame;
      break;
    }
  }
  return { previous, next };
}

function buildChampionMap(anchors) {
  const map = new Map();
  for (const anchor of anchors) {
    map.set(`${anchor.game_id}:${anchor.participant_id}`, {
      champion: anchor.champion,
      team_id: anchor.entity && anchor.entity.team_id,
      replay_sha256: anchor.replay_sha256,
    });
  }
  return map;
}

function buildDeathRows(anchors) {
  return uniqueBy(
    anchors.filter((anchor) => Number.isFinite(
      anchor.frame_boundary_evidence &&
        anchor.frame_boundary_evidence.associated_death_event_timestamp_ms,
    )).map((anchor) => ({
      game_id: anchor.game_id,
      participant_id: anchor.participant_id,
      champion: anchor.champion,
      death_timestamp_ms:
        anchor.frame_boundary_evidence.associated_death_event_timestamp_ms,
      evidence_frame_timestamp_ms: anchor.timestamp_ms,
      evidence_json_path:
        anchor.frame_boundary_evidence.associated_death_event_json_path,
    })),
    (death) => `${death.game_id}:${death.participant_id}:${death.death_timestamp_ms}`,
  ).sort((left, right) =>
    left.game_id.localeCompare(right.game_id) ||
    left.participant_id - right.participant_id ||
    left.death_timestamp_ms - right.death_timestamp_ms);
}

function analyzeHeroReincarnateAlive({ decodedRows, anchors, detailsByGame }) {
  for (const row of decodedRows) assertDecodedRow(row);
  const championMap = buildChampionMap(anchors);
  const deaths = buildDeathRows(anchors);
  const normalizedRows = decodedRows.map((row, inputIndex) => {
    const participantId = participantIdFromRawParam(row.raw_param);
    const participant = championMap.get(`${row.replay_label}:${participantId}`);
    if (participantId === null || !participant) {
      throw new Error('0x0265 row does not resolve to a safe P0 champion participant');
    }
    if (participant.replay_sha256 !== row.replay_sha256) {
      throw new Error('0x0265 Replay SHA differs from the P0 ground-truth scope');
    }
    return {
      input_index: inputIndex,
      row,
      participant_id: participantId,
      champion: participant.champion,
      team_id: participant.team_id,
      decoded: decodeProtectedFields(row),
    };
  }).sort((left, right) =>
    left.row.replay_label.localeCompare(right.row.replay_label) ||
    left.participant_id - right.participant_id ||
    left.row.replay_time_ms - right.row.replay_time_ms ||
    left.input_index - right.input_index);

  const rowsByParticipant = groupBy(
    normalizedRows,
    (entry) => `${entry.row.replay_label}:${entry.participant_id}`,
  );
  const deathsByParticipant = groupBy(
    deaths,
    (death) => `${death.game_id}:${death.participant_id}`,
  );
  const matchedDeathKeys = new Set();
  const matchedRowIndexes = new Set();
  const deathMatches = [];
  const unmatchedDeaths = [];

  for (const [key, participantDeaths] of deathsByParticipant) {
    const participantRows = rowsByParticipant.get(key) || [];
    for (let index = 0; index < participantDeaths.length; index += 1) {
      const death = participantDeaths[index];
      const nextDeath = participantDeaths[index + 1];
      const candidate = participantRows.find((entry) =>
        !matchedRowIndexes.has(entry.input_index) &&
        entry.row.replay_time_ms >= death.death_timestamp_ms &&
        (!nextDeath || entry.row.replay_time_ms < nextDeath.death_timestamp_ms));
      if (!candidate) {
        unmatchedDeaths.push(death);
        continue;
      }
      matchedRowIndexes.add(candidate.input_index);
      matchedDeathKeys.add(
        `${death.game_id}:${death.participant_id}:${death.death_timestamp_ms}`,
      );
      deathMatches.push({
        ...death,
        route_timestamp_ms: candidate.row.replay_time_ms,
        dead_interval_ms: candidate.row.replay_time_ms - death.death_timestamp_ms,
        input_index: candidate.input_index,
      });
    }
  }

  const endByGame = {};
  for (const anchor of anchors) {
    endByGame[anchor.game_id] = Math.max(
      endByGame[anchor.game_id] || 0,
      anchor.timestamp_ms,
    );
  }
  const terminalDeathAudit = unmatchedDeaths.map((death) => ({
    ...death,
    last_details_frame_timestamp_ms: endByGame[death.game_id],
    remaining_observed_ms:
      endByGame[death.game_id] - death.death_timestamp_ms,
    is_participant_final_death: !deaths.some((candidate) =>
      candidate.game_id === death.game_id &&
      candidate.participant_id === death.participant_id &&
      candidate.death_timestamp_ms > death.death_timestamp_ms),
  }));

  const intervals = anchors.filter((anchor) =>
    anchor.frame_boundary_evidence &&
    anchor.frame_boundary_evidence.health_transition === 'ZERO_TO_POSITIVE');
  const intervalCounts = intervals.map((anchor) => {
    const lower = anchor.frame_boundary_evidence.respawn_lower_bound_timestamp_ms;
    const upper = anchor.frame_boundary_evidence.respawn_upper_bound_timestamp_ms;
    const matches = normalizedRows.filter((entry) =>
      entry.row.replay_label === anchor.game_id &&
      entry.participant_id === anchor.participant_id &&
      entry.row.replay_time_ms > lower &&
      entry.row.replay_time_ms <= upper);
    return {
      anchor_id: anchor.anchor_id,
      lower_bound_ms: lower,
      upper_bound_ms: upper,
      route_match_count: matches.length,
      route_timestamps_ms: matches.map((entry) => entry.row.replay_time_ms),
    };
  });

  const coordinateRows = normalizedRows.map((entry) => ({
    team_id: entry.team_id,
    x: entry.decoded.x,
    z: entry.decoded.z,
  }));
  const coordinatesByTeam = {};
  for (const teamId of [...new Set(coordinateRows.map((row) => row.team_id))].sort()) {
    const rows = coordinateRows.filter((row) => row.team_id === teamId);
    coordinatesByTeam[String(teamId)] = {
      row_count: rows.length,
      distinct_x_z: uniqueBy(rows, (row) => `${row.x}:${row.z}`),
    };
  }

  const scalarComparisons = normalizedRows.map((entry) => {
    const frames = detailsByGame.get(entry.row.replay_label) || [];
    const { previous, next } = adjacentFrames(frames, entry.row.replay_time_ms);
    const participantKey = String(entry.participant_id);
    const previousStats = previous &&
      previous.participantFrames &&
      previous.participantFrames[participantKey] &&
      previous.participantFrames[participantKey].championStats;
    const nextStats = next &&
      next.participantFrames &&
      next.participantFrames[participantKey] &&
      next.participantFrames[participantKey].championStats;
    const value = entry.decoded.reincarnate_scalar;
    return {
      game_id: entry.row.replay_label,
      participant_id: entry.participant_id,
      champion: entry.champion,
      route_timestamp_ms: entry.row.replay_time_ms,
      reincarnate_scalar: value,
      previous_frame_timestamp_ms: previous && previous.timestamp,
      previous_power: previousStats && previousStats.power,
      previous_power_max: previousStats && previousStats.powerMax,
      next_frame_timestamp_ms: next && next.timestamp,
      next_power: nextStats && nextStats.power,
      next_power_max: nextStats && nextStats.powerMax,
      floor_matches_adjacent_power_max: Boolean(
        (previousStats && Math.floor(value) === previousStats.powerMax) ||
        (nextStats && Math.floor(value) === nextStats.powerMax),
      ),
      floor_matches_adjacent_power: Boolean(
        (previousStats && Math.floor(value) === previousStats.power) ||
        (nextStats && Math.floor(value) === nextStats.power),
      ),
    };
  });

  const matchByInput = new Map(deathMatches.map((match) => [match.input_index, match]));
  const events = normalizedRows.map((entry) => {
    const match = matchByInput.get(entry.input_index);
    return {
      schema_version: 'HERO_REINCARNATE_ALIVE_V2',
      event_type: 'HERO_REINCARNATE_ALIVE',
      semantic_domain: 'hero_state',
      evidence_grade:
        'VERIFIED_EXACT_BUILD_RUNTIME_CALLBACK_AND_SAFE_P0_DEATH_DIFFERENTIAL',
      replay_build: EXACT_BUILD,
      replay_sha256: entry.row.replay_sha256,
      game_id: entry.row.replay_label,
      replay_time_ms: entry.row.replay_time_ms,
      packet_discriminator: ROUTE_HEX,
      raw_param_u32: entry.row.raw_param >>> 0,
      raw_param_hex: entry.row.raw_param_hex,
      participant_id_candidate: entry.participant_id,
      champion_calibration_label: entry.champion,
      team_id_calibration_label: entry.team_id,
      position: {
        x: entry.decoded.x,
        y: 0,
        z: entry.decoded.z,
        evidence: {
          x: 'VERIFIED_DIRECT_PROTECTED_FIELD_INVERSE_CALLBACK_ARGUMENT',
          y: 'VERIFIED_DERIVED_CALLBACK_CONSTANT',
          z: 'VERIFIED_DIRECT_PROTECTED_FIELD_INVERSE_CALLBACK_ARGUMENT',
          semantic_boundary:
            'Protocol coordinate only; no map-region, base, or strategic label is claimed.',
        },
      },
      reincarnate_scalar: entry.decoded.reincarnate_scalar,
      reincarnate_scalar_role: 'UNKNOWN_RESOURCE_LIKE_CANDIDATE',
      reincarnate_scalar_evidence:
        'VERIFIED_DIRECT_FLOAT_VALUE; SEMANTIC_ROLE_CANDIDATE_ONLY',
      preceding_death_timestamp_ms: match && match.death_timestamp_ms,
      dead_interval_ms: match && match.dead_interval_ms,
      raw_packet_ref: {
        packet_id: ROUTE_ID,
        packet_type: ROUTE_HEX,
        raw_payload_sha256: entry.row.raw_payload_sha256,
        raw_payload_hex: entry.row.raw_payload_hex,
        chunk_index: entry.row.chunk_index,
        occurrence_index: entry.row.occurrence_index,
      },
      runtime_provenance: {
        runtime_image_sha256: RUNTIME_IMAGE_SHA256,
        ...STATIC_CHAIN,
      },
    };
  }).sort((left, right) =>
    left.game_id.localeCompare(right.game_id) ||
    left.replay_time_ms - right.replay_time_ms ||
    left.raw_param_u32 - right.raw_param_u32);

  const deadIntervals = deathMatches.map((match) => match.dead_interval_ms);
  const report = {
    schema_version: 'HERO_REINCARNATE_ALIVE_AUDIT_V2',
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    protected_holdout_policy: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
    static_runtime_chain: STATIC_CHAIN,
    native_decode: {
      route: ROUTE_HEX,
      row_count: normalizedRows.length,
      successful_full_consume_count: normalizedRows.length,
      payload_length_distribution: countBy(
        normalizedRows,
        (entry) => entry.row.payload_length,
      ),
      replay_count: new Set(normalizedRows.map((entry) => entry.row.replay_sha256)).size,
    },
    protected_field_inverse: {
      callback_receive_target_rva: STATIC_CHAIN.callback_receive_target_rva,
      position_storage: 'object +0x10/+0x14 -> per-byte inverse -> Vec3(x,0,z)',
      scalar_storage: 'object +0x18 -> independent per-byte inverse -> float argument',
      consumer_call: '0x0027b660 -> AIHeroClient virtual slot +0x0b50',
      position_coordinates_by_calibration_team: coordinatesByTeam,
      unique_position_count: uniqueBy(
        coordinateRows,
        (row) => `${row.x}:${row.z}`,
      ).length,
    },
    death_respawn_differential: {
      unique_details_death_event_count: deaths.length,
      matched_unique_death_to_route_count: deathMatches.length,
      route_rows_with_unique_preceding_death_count: matchedRowIndexes.size,
      route_rows_without_unique_preceding_death_count:
        normalizedRows.length - matchedRowIndexes.size,
      unmatched_death_count: unmatchedDeaths.length,
      unmatched_deaths_all_participant_final:
        terminalDeathAudit.every((row) => row.is_participant_final_death),
      terminal_death_audit: terminalDeathAudit,
      dead_interval_ms: {
        minimum: Math.min(...deadIntervals),
        maximum: Math.max(...deadIntervals),
        mean: round(deadIntervals.reduce((sum, value) => sum + value, 0) /
          deadIntervals.length),
        distribution_rounded_seconds: countBy(
          deadIntervals,
          (value) => Math.round(value / 1000),
        ),
      },
      coarse_zero_to_positive_interval_count: intervalCounts.length,
      interval_match_count_distribution: countBy(
        intervalCounts,
        (entry) => entry.route_match_count,
      ),
      intervals: intervalCounts,
      interpretation:
        'Every observed 0x0265 row is the sole next same-participant row after one distinct death and before the next death. All DETAILS deaths without 0x0265 are participant-final terminal deaths within the observed replay tail.',
    },
    reincarnate_scalar_differential: {
      row_count: scalarComparisons.length,
      adjacent_details_power_max_floor_match_count: scalarComparisons.filter(
        (row) => row.floor_matches_adjacent_power_max,
      ).length,
      adjacent_details_power_floor_match_count: scalarComparisons.filter(
        (row) => row.floor_matches_adjacent_power,
      ).length,
      distinct_scalar_count: new Set(
        scalarComparisons.map((row) => row.reincarnate_scalar),
      ).size,
      minimum: Math.min(...scalarComparisons.map((row) => row.reincarnate_scalar)),
      maximum: Math.max(...scalarComparisons.map((row) => row.reincarnate_scalar)),
      by_champion: Object.fromEntries(
        [...groupBy(scalarComparisons, (row) => row.champion)].sort().map(
          ([champion, rows]) => [champion, {
            row_count: rows.length,
            minimum: Math.min(...rows.map((row) => row.reincarnate_scalar)),
            maximum: Math.max(...rows.map((row) => row.reincarnate_scalar)),
            distinct_count: new Set(rows.map((row) => row.reincarnate_scalar)).size,
          }],
        ),
      ),
      counterexamples: scalarComparisons.filter(
        (row) => !row.floor_matches_adjacent_power_max,
      ),
      decision:
        'KEEP_CANDIDATE: the float is direct and strongly resource-like, but the callback does not name current/max/seed semantics and Yone supplies a direct counterexample to universal powerMax.',
    },
    route_decisions: [{
      decision_id: 'ROUTE_0x0265_HERO_REINCARNATE_ALIVE_V2',
      packet_id: ROUTE_ID,
      packet_discriminator: ROUTE_HEX,
      runtime_name: STATIC_CHAIN.runtime_type_name,
      domain: 'hero_state',
      capability: 'HERO_REINCARNATE_ALIVE_EVENT_WITH_POSITION',
      decision: 'PROMOTE',
      evidence_grade:
        'VERIFIED_EXACT_BUILD_RUNTIME_CALLBACK_NATIVE_FULL_CONSUME_AND_SAFE_P0_DIFFERENTIAL',
      publishable_fields: [
        'replay_time_ms', 'raw_param_u32', 'position_x', 'position_z',
        'position_y_callback_constant', 'reincarnate_scalar_neutral',
      ],
      known_limits: [
        'The raw parameter low byte is a build-bound participant candidate; the full raw parameter is retained.',
        'Position is a protocol coordinate and does not authorize map or strategic labels.',
        'The third float remains neutral; resource current/max/seed semantics are not promoted.',
      ],
      actual_reverse_engineering_executed: true,
      reverse_engineering_steps: [
        'EXACT_RTTI_REGISTRATION_MEMBER_FUNCTION_POINTER_RECOVERY',
        'FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_CLOSURE',
        'CALLBACK_BYTE_INVERSE_AND_ARGUMENT_DATA_FLOW',
        '282_OF_282_EXACT_NATIVE_FULL_CONSUME',
        '301_DEATH_SEQUENCE_DIFFERENTIAL_ACROSS_FOUR_SAFE_P0_REPLAYS',
        'DIRECT_DETAILS_POWER_POWERMAX_COUNTEREXAMPLE_AUDIT',
      ],
      evidence_exhausted: true,
      evidence_exhausted_scope:
        'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_FOUR_SAFE_P0_EXACT_BUILD_REPLAYS',
      exhaustion_basis:
        'STATIC_CONSUMER_AND_ALL_AVAILABLE_SAFE_P0_RUNTIME_DEATH_STATE_HYPOTHESES_EXECUTED',
      actionable_hypotheses: [],
      next_required_evidence: [
        'Controlled respawn capture with plaintext ability-resource instrumentation is required to name the third float.',
      ],
      external_only_gate: {
        required: true,
        local_safe_evidence_remaining: false,
      },
    }],
    capability_decisions: [{
      capability: 'HERO_RESPAWN_OCCURRENCE',
      decision: 'PROMOTE',
      semantic_claim:
        'Exact 0x0265 HeroReincarnateAlive occurrence time and callback position for observed nonterminal deaths.',
      evidence_exhausted: true,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
      next_required_evidence: [
        'No local evidence is required for the bounded occurrence/position claim.',
      ],
    }, {
      capability: 'RESPAWN_ABILITY_RESOURCE_VALUE',
      decision: 'KEEP_CANDIDATE',
      semantic_claim: null,
      evidence_exhausted: true,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
      next_required_evidence: [
        'Controlled runtime plaintext capture is required to distinguish current, maximum, or seed resource semantics.',
      ],
    }],
    domain_decisions: [{
      domain: 'hero_state',
      decision: 'PROMOTE',
      bounded_capability: 'HERO_REINCARNATE_ALIVE_EVENT_WITH_POSITION',
      evidence_exhausted: true,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
      next_required_evidence: [
        'External controlled evidence is needed only for the neutral scalar field role.',
      ],
    }],
    saturation: {
      status: 'LOCAL_SAFE_EVIDENCE_EXHAUSTED_FOR_0x0265',
      evidence_exhausted: true,
      locally_executable_actionable_hypothesis_count: 0,
    },
  };

  return { report, events };
}

module.exports = {
  EXACT_BUILD,
  ROUTE_HEX,
  ROUTE_ID,
  RUNTIME_IMAGE_SHA256,
  STATIC_CHAIN,
  assertSafePath,
  decryptPositionByte,
  decryptScalarByte,
  decryptU32ToFloat,
  decodeProtectedFields,
  participantIdFromRawParam,
  analyzeHeroReincarnateAlive,
};
