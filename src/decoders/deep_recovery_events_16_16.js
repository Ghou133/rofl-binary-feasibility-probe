'use strict';

const crypto = require('node:crypto');

const {
  DEEP_RECOVERY_SEMANTIC_PROFILES,
  EXACT_BUILD,
  RUNTIME_IMAGE_SHA256,
} = require('../deep_recovery_semantic_profiles_16_16');
const { CURRENT_STAGE_CODES } = require('../route_0064_support_quest_audit');

const BUFF_OPERATIONS = Object.freeze({
  0x0326: 'ADD',
  0x0123: 'UPDATE_COUNT',
  0x041f: 'UPDATE_COUNTER',
  0x043c: 'REPLACE',
  0x045b: 'REMOVE',
});
const STAGE_BY_ENCODED_CODE = Object.freeze(Object.fromEntries(
  CURRENT_STAGE_CODES.map((code, stage) => [code, stage]),
));
const STAGE_CODE_F32 = Object.freeze([1.17, 1.27, 1.47]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function exactBuild(value) {
  return value?.header?.version ?? value?.exact_build ?? value?.replay_version
    ?? value?.build ?? value?.game_version ?? null;
}

function replaySha(value) {
  return value?.source_sha256 ?? value?.replay_sha256 ?? null;
}

function assertSafeExactReplay(replay) {
  invariant(replay && exactBuild(replay) === EXACT_BUILD,
    `deep-recovery adapter only supports exact build ${EXACT_BUILD}`);
  const sha = replaySha(replay);
  invariant(typeof sha === 'string' && /^[a-f0-9]{64}$/i.test(sha),
    'deep-recovery adapter requires an exact Replay SHA-256');
  invariant(!/holdout/i.test(String(replay.source_path ?? '')),
    'protected Holdout paths are forbidden');
  return sha.toLowerCase();
}

function assertRowScope(replay, row, packetId) {
  const sha = assertSafeExactReplay(replay);
  invariant(row && exactBuild(row) === EXACT_BUILD, 'decoded row build mismatch');
  invariant(String(replaySha(row)).toLowerCase() === sha, 'decoded row Replay SHA mismatch');
  invariant(row.packet_id === packetId, `decoded row is not route 0x${packetId.toString(16)}`);
  invariant(row.fully_consumed === true && row.deserialize_return_al !== 0,
    'decoded row is not an exact successful full-consume row');
  return sha;
}

function participantIdFromNetworkId(value) {
  return Number.isInteger(value) && value >= 0x400000ae && value <= 0x400000b7
    ? value - 0x400000ad : null;
}

function participantMetadata(replay) {
  const rows = replay?.tail?.stats ?? replay?.participants ?? [];
  return rows.map((row, index) => ({
    participant_id: Number(row.participant_id ?? index + 1),
    entity_network_id: Number(row.entity_network_id ?? 0x400000ae + index),
    champion: row.SKIN ?? row.champion ?? null,
    team_position: row.TEAM_POSITION ?? row.team_position ?? null,
  }));
}

function rawPacketRef(row) {
  return {
    replay_sha256: replaySha(row),
    source_path: row.replay_path ?? null,
    chunk_index: row.chunk_index ?? null,
    chunk_id: row.chunk_id ?? null,
    chunk_stream: row.chunk_stream ?? null,
    decompressed_block_offset: row.decompressed_block_offset ?? null,
    decompressed_payload_offset: row.decompressed_payload_offset ?? null,
    packet_id: row.packet_id ?? null,
    payload_length: row.payload_length ?? null,
    raw_param: row.raw_param ?? null,
    payload_sha256: row.raw_payload_sha256 ?? row.parameter_blob_sha256
      ?? row.packet_object_sha256 ?? null,
  };
}

function semanticScope(profile, replaySha256) {
  return {
    exact_build: EXACT_BUILD,
    game_version: EXACT_BUILD,
    patch: '16.16',
    build_profile: profile.id,
    replay_sha256: replaySha256,
  };
}

function rotateRight8(value, count) {
  const shift = count & 7;
  return ((value >>> shift) | (value << (8 - shift))) & 0xff;
}

function decodeDeathTimerByte(encoded) {
  let value = rotateRight8(encoded, 6);
  value = (value - 0x67) & 0xff;
  let even = value;
  value = (value >>> 1) & 0x55;
  even = (even & 0xd5) * 2;
  value = (even | value) & 0xff;
  value = rotateRight8(value, 5);
  return (~value) & 0xff;
}

function decodeDeathTimerObjectHex(objectHex) {
  invariant(typeof objectHex === 'string' && /^[a-f0-9]+$/i.test(objectHex),
    'death timer object_hex is required');
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x14, 'death timer object is shorter than 0x14 bytes');
  const plaintext = Buffer.from(object.subarray(0x10, 0x14).map(decodeDeathTimerByte));
  const value = plaintext.readFloatLE(0);
  invariant(Number.isFinite(value) && value >= 0, 'death timer value is not a finite nonnegative f32');
  return value;
}

function deathTimerEventFromDecodedRow(replay, row) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.hero_death_timer;
  const sha = assertRowScope(replay, row, profile.replay_block_packet_id);
  invariant(row.decoder_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'death timer runtime image mismatch');
  invariant(row.decoder_profile_sha256 === profile.runtime_decoder_profile_sha256,
    'death timer decoder profile mismatch');
  invariant(row.decoded_opcode === profile.client_opcode && row.opcode_matches_profile === true,
    'death timer opcode attestation failed');
  const entityId = row.raw_param >>> 0;
  const participantId = participantIdFromNetworkId(entityId);
  return {
    event_type: 'HERO_DEATH_TIMER_UPDATE',
    semantic_type: 'EntityLifecycle',
    semantic_domain: 'hero_state',
    ...semanticScope(profile, sha),
    replay_time_ms: row.replay_time_ms,
    entity_id: entityId,
    participant_id: participantId,
    entity_type: participantId === null ? 'UNKNOWN_ENTITY' : 'CHAMPION',
    lifecycle_operation: 'DEATH_TIMER_UPDATE',
    death_timer_seconds: decodeDeathTimerObjectHex(row.object_hex),
    respawn_timestamp_ms: null,
    semantic_status: 'VERIFIED_DIRECT',
    confidence: 'VERIFIED_DIRECT',
    field_confidence: {
      entity_id: 'VERIFIED_DIRECT',
      participant_id: participantId === null ? 'UNAVAILABLE' : 'VERIFIED_DERIVED',
      entity_type: participantId === null ? 'UNKNOWN' : 'VERIFIED_DERIVED',
      lifecycle_operation: 'VERIFIED_DIRECT',
      death_timer_seconds: 'VERIFIED_DIRECT',
      respawn_timestamp_ms: 'UNAVAILABLE',
    },
    decoder_profile: profile.id,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawPacketRef(row),
    known_limits: [...profile.known_limits],
  };
}

function numericIdentifier(value) {
  return Number.isInteger(value) ? `0x${(value >>> 0).toString(16).padStart(8, '0')}` : null;
}

function buffEventFromDecodedRow(replay, row) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.buff;
  const operation = BUFF_OPERATIONS[row?.packet_id];
  invariant(operation, 'row is not an exact recovered Buff route');
  const sha = assertRowScope(replay, row, row.packet_id);
  invariant(Number.isInteger(row.target_network_id_candidate),
    'Buff callback routing entity is missing');
  let slotIndex = row.slot_candidate ?? null;
  let identifier = null;
  if (row.packet_id === 0x0326) identifier = numericIdentifier(row.u32_candidates?.['0x04']);
  else if (row.packet_id === 0x045b) identifier = numericIdentifier(row.network_or_hash_candidate);
  else if (row.packet_id === 0x041f) {
    identifier = numericIdentifier(row.u32_candidate_a);
    slotIndex = row.counter_candidate_a ?? null;
  }
  return {
    event_type: 'BUFF_OPERATION',
    semantic_type: 'BuffEvent',
    semantic_domain: 'buff',
    ...semanticScope(profile, sha),
    replay_time_ms: row.replay_time_ms,
    subject_entity_id: null,
    routing_entity_id: row.target_network_id_candidate >>> 0,
    source_entity_id: null,
    operation,
    buff_identifier: identifier,
    slot_index: Number.isInteger(slotIndex) ? slotIndex : null,
    stack_count: null,
    duration_seconds: null,
    remaining_seconds: null,
    semantic_status: 'VERIFIED_DIRECT',
    confidence: 'VERIFIED_DIRECT',
    field_confidence: {
      subject_entity_id: 'UNAVAILABLE',
      routing_entity_id: 'VERIFIED_DIRECT',
      source_entity_id: 'CANDIDATE',
      operation: 'VERIFIED_DIRECT',
      buff_identifier: identifier === null ? 'UNKNOWN' : 'VERIFIED_DIRECT',
      slot_index: Number.isInteger(slotIndex) ? 'VERIFIED_DIRECT' : 'UNKNOWN',
      stack_count: 'CANDIDATE',
      duration_seconds: 'UNAVAILABLE',
      remaining_seconds: 'UNAVAILABLE',
    },
    decoder_profile: profile.id,
    raw_payload_sha256: row.packet_object_sha256,
    raw_packet_ref: rawPacketRef(row),
    protocol_fields: { ...row },
    known_limits: [...profile.known_limits],
  };
}

function spellCastEventFromDecodedRow(replay, row) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.cast_spell;
  const sha = assertRowScope(replay, row, profile.replay_block_packet_id);
  invariant(Number.isInteger(row.spell_key_candidate)
    && typeof row.caster_name_exact_translator === 'string',
  'cast translator fields are missing');
  const participants = participantMetadata(replay);
  const candidateId = participantIdFromNetworkId(row.caster_network_id_candidate);
  const participant = participants.find((entry) => entry.participant_id === candidateId) ?? null;
  const casterMatch = Boolean(participant?.champion
    && participant.champion === row.caster_name_exact_translator);
  return {
    event_type: 'SPELL_CAST_OCCURRENCE',
    semantic_type: 'SpellCast',
    semantic_domain: 'spell',
    ...semanticScope(profile, sha),
    replay_time_ms: row.replay_time_ms,
    caster_entity_id: casterMatch ? row.caster_network_id_candidate >>> 0 : null,
    caster_name: row.caster_name_exact_translator,
    chain_owner_entity_id: null,
    target_entity_id: null,
    spell_identifier: numericIdentifier(row.spell_key_candidate),
    numeric_spell_key: row.spell_key_candidate >>> 0,
    spell_slot: null,
    target_position: null,
    cast_result: null,
    cast_time_seconds: null,
    semantic_status: 'VERIFIED_DIRECT',
    confidence: 'VERIFIED_DIRECT',
    field_confidence: {
      caster_entity_id: casterMatch ? 'VERIFIED_DERIVED' : 'CANDIDATE',
      caster_name: 'VERIFIED_DIRECT',
      chain_owner_entity_id: 'CANDIDATE',
      target_entity_id: 'UNAVAILABLE',
      spell_identifier: 'VERIFIED_DIRECT',
      numeric_spell_key: 'VERIFIED_DIRECT',
      spell_slot: 'CANDIDATE',
      target_position: 'UNAVAILABLE',
      cast_result: 'UNAVAILABLE',
      cast_time_seconds: 'CANDIDATE',
    },
    decoder_profile: profile.id,
    raw_payload_sha256: row.packet_object_sha256,
    raw_packet_ref: rawPacketRef(row),
    protocol_fields: { ...row },
    known_limits: [...profile.known_limits],
  };
}

function protectionPairKey(row) {
  return [replaySha(row), row.replay_time_ms, row.parameter_blob_sha256,
    row.source_network_id_candidate, row.target_network_id_candidate,
    row.amount_candidate].join(':');
}

function canonicalProtectionEventsFromDecodedRows(replay, rows) {
  assertSafeExactReplay(replay);
  invariant(Array.isArray(rows), 'protection decoded rows must be an array');
  const receive = new Map();
  const grant = new Map();
  for (const row of rows) {
    assertRowScope(replay, { ...row, fully_consumed: true, deserialize_return_al: 1 }, 0x0371);
    invariant([0x004b, 0x00ed, 0x00ee].includes(row.event_id),
      'unexpected protection event id');
    invariant(row.schema_id_matches_cross_build_hypothesis === true
      && row.parameter_size_matches_cross_build_hypothesis === true,
    'protection parameter schema gate failed');
    if (row.event_id === 0x00ed) receive.set(protectionPairKey(row), (receive.get(protectionPairKey(row)) ?? 0) + 1);
    if (row.event_id === 0x00ee) grant.set(protectionPairKey(row), (grant.get(protectionPairKey(row)) ?? 0) + 1);
  }
  invariant(receive.size === grant.size
    && [...receive].every(([key, count]) => grant.get(key) === count),
  'shield receive/grant duplicate-pair gate failed');
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.protection;
  return rows.filter((row) => row.event_id !== 0x00ee).map((row) => {
    const heal = row.event_id === 0x004b;
    return {
      event_type: heal ? 'HEAL_REPORTED' : 'SHIELD_APPLICATION',
      semantic_type: 'ProtectionEvent',
      semantic_domain: 'protection',
      ...semanticScope(profile, replaySha(row)),
      replay_time_ms: row.replay_time_ms,
      subject_entity_id: row.target_network_id_candidate >>> 0,
      source_entity_id: row.source_network_id_candidate >>> 0,
      protection_type: heal ? 'HEAL_REPORTED' : 'SHIELD_APPLICATION',
      reported_amount: row.amount_candidate,
      effective_amount: null,
      amount_stage: heal ? 'REPORTED_OR_GROSS' : 'APPLICATION_OR_GENERATED',
      duplicate_suppressed: !heal,
      semantic_status: 'VERIFIED_DIRECT',
      confidence: 'VERIFIED_DIRECT',
      field_confidence: {
        subject_entity_id: 'VERIFIED_DIRECT',
        source_entity_id: 'VERIFIED_DIRECT',
        protection_type: 'VERIFIED_DIRECT',
        reported_amount: 'VERIFIED_DIRECT',
        effective_amount: 'UNAVAILABLE',
        amount_stage: 'VERIFIED_DIRECT',
        duplicate_suppressed: heal ? 'VERIFIED_DIRECT' : 'VERIFIED_DERIVED',
      },
      decoder_profile: profile.id,
      raw_payload_sha256: row.parameter_blob_sha256,
      raw_packet_ref: rawPacketRef(row),
      known_limits: [...profile.known_limits],
    };
  });
}

function normalizeInventoryEntries(value) {
  invariant(Array.isArray(value), 'inventory snapshot entries must be an array');
  return value.map((entry) => {
    invariant(Number.isInteger(entry.slot ?? entry.slot_index)
      && Number.isInteger(entry.item_id ?? entry.item_identifier)
      && Number.isInteger(entry.stack_count),
    'inventory snapshot entry is incomplete');
    return {
      slot_index: entry.slot ?? entry.slot_index,
      item_identifier: String(entry.item_id ?? entry.item_identifier),
      stack_count: entry.stack_count,
    };
  }).sort((left, right) => left.slot_index - right.slot_index);
}

function inventorySnapshotEvent(replay, row) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.item_state;
  const sha = assertSafeExactReplay(replay);
  invariant(exactBuild(row) === EXACT_BUILD && String(replaySha(row)).toLowerCase() === sha,
    'inventory snapshot scope mismatch');
  invariant([0x0311, 0x02ea, 0x006c].includes(row.packet_id),
    'inventory snapshot row has an unsupported route');
  invariant(row.fully_consumed === true, 'failed inventory rows cannot be published');
  const entries = normalizeInventoryEntries(row.inventory_entries ?? row.snapshot_items);
  return {
    event_type: 'ITEM_STATE_SNAPSHOT',
    semantic_type: 'ItemEvent',
    semantic_domain: 'item',
    ...semanticScope(profile, sha),
    replay_time_ms: row.replay_time_ms,
    subject_entity_id: row.raw_param >>> 0,
    operation: 'INVENTORY_SNAPSHOT',
    item_identifier: null,
    source_item_identifier: null,
    target_item_identifier: null,
    slot_index: null,
    source_slot_index: null,
    target_slot_index: null,
    inventory_entries: entries,
    stage: null,
    stage_code: null,
    snapshot_scope: row.chunk_stream === 'keyframe' ? 'KEYFRAME_OBSERVATION' : 'LIVE_STREAM_RESET',
    quantity: null,
    gold_delta: null,
    semantic_status: 'VERIFIED_DIRECT',
    confidence: 'VERIFIED_DIRECT',
    field_confidence: {
      subject_entity_id: 'VERIFIED_DIRECT', operation: 'VERIFIED_DIRECT',
      inventory_entries: 'VERIFIED_DIRECT', snapshot_scope: 'VERIFIED_DIRECT',
    },
    decoder_profile: profile.id,
    raw_payload_sha256: row.raw_payload_sha256 ?? null,
    raw_packet_ref: rawPacketRef(row),
    known_limits: [...profile.known_limits],
  };
}

function inventorySwapEvent(replay, row) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.item_swap;
  const sha = assertSafeExactReplay(replay);
  invariant(exactBuild(row) === EXACT_BUILD && String(replaySha(row)).toLowerCase() === sha,
    'inventory swap scope mismatch');
  invariant(row.packet_id === 0x01e8 && row.fully_consumed === true,
    'inventory swap exact-route gate failed');
  const first = row.first_slot_index;
  const second = row.second_slot_index;
  invariant(Number.isInteger(first) && first >= 0 && first <= 5
    && Number.isInteger(second) && second >= 0 && second <= 5,
  'inventory swap selector domain failed');
  return {
    event_type: 'ITEM_SWAP', semantic_type: 'ItemEvent', semantic_domain: 'item',
    ...semanticScope(profile, sha),
    replay_time_ms: row.replay_time_ms, subject_entity_id: row.raw_param >>> 0,
    operation: 'SWAP', item_identifier: null, source_item_identifier: null,
    target_item_identifier: null, slot_index: null, source_slot_index: first,
    target_slot_index: second, inventory_entries: null, stage: null, stage_code: null,
    snapshot_scope: null, quantity: null, gold_delta: null,
    semantic_status: 'VERIFIED_DIRECT', confidence: 'VERIFIED_DIRECT',
    field_confidence: {
      subject_entity_id: 'VERIFIED_DIRECT', operation: 'VERIFIED_DIRECT',
      source_slot_index: 'VERIFIED_DIRECT', target_slot_index: 'VERIFIED_DIRECT',
    },
    decoder_profile: profile.id, raw_payload_sha256: row.raw_payload_sha256 ?? null,
    raw_packet_ref: rawPacketRef(row), known_limits: [...profile.known_limits],
  };
}

function itemSubstitutionMapEvent(replay, row) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.item_substitution_map;
  const sha = assertSafeExactReplay(replay);
  invariant(exactBuild(row) === EXACT_BUILD && String(replaySha(row)).toLowerCase() === sha,
    'item substitution scope mismatch');
  invariant(row.packet_id === 0x005a && row.fully_consumed === true,
    'item substitution exact-route gate failed');
  const source = Number(row.source_item_id);
  const target = Number(row.target_item_id);
  invariant(profile.observed_mapping[source] === target, 'unverified item substitution pair');
  return {
    event_type: 'ITEM_SUBSTITUTION_MAP_UPDATE', semantic_type: 'ItemEvent',
    semantic_domain: 'item', ...semanticScope(profile, sha), replay_time_ms: row.replay_time_ms,
    subject_entity_id: row.raw_param >>> 0, operation: 'SUBSTITUTION_MAP_UPDATE',
    item_identifier: null, source_item_identifier: String(source),
    target_item_identifier: String(target), slot_index: null, source_slot_index: null,
    target_slot_index: null, inventory_entries: null, stage: null, stage_code: null,
    snapshot_scope: null, quantity: null, gold_delta: null,
    semantic_status: 'VERIFIED_DIRECT', confidence: 'VERIFIED_DIRECT',
    field_confidence: {
      subject_entity_id: 'VERIFIED_DIRECT', operation: 'VERIFIED_DIRECT',
      source_item_identifier: 'VERIFIED_DIRECT', target_item_identifier: 'VERIFIED_DIRECT',
    },
    decoder_profile: profile.id, raw_payload_sha256: row.raw_payload_sha256 ?? null,
    raw_packet_ref: rawPacketRef(row), known_limits: [...profile.known_limits],
  };
}

function route0064GroupKey(row) {
  return [row.chunk_index ?? '', row.replay_time_ms].join(':');
}

function supportQuestStageEventsFromRows(replay, rows) {
  const profile = DEEP_RECOVERY_SEMANTIC_PROFILES.support_quest_item_stage;
  const sha = assertSafeExactReplay(replay);
  invariant(Array.isArray(rows), '0x0064 rows must be an array');
  const roster = participantMetadata(replay);
  const utilityIds = roster.filter((row) => row.team_position === 'UTILITY')
    .map((row) => row.participant_id).sort((a, b) => a - b);
  invariant(JSON.stringify(utilityIds) === JSON.stringify([5, 10]),
    'support-stage adapter requires exact utility participants 5 and 10');
  const groups = new Map();
  rows.forEach((row, index) => {
    invariant(exactBuild(row) === EXACT_BUILD && String(replaySha(row)).toLowerCase() === sha,
      '0x0064 row scope mismatch');
    invariant(row.packet_id === 0x0064, 'support-stage input contains another route');
    const key = route0064GroupKey(row);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ row, index });
  });
  const events = [];
  const residuals = [];
  for (const group of groups.values()) {
    group.sort((left, right) => (left.row.occurrence_index ?? left.index)
      - (right.row.occurrence_index ?? right.index));
    const canonical = group.length === 10 && group.every(({ row }) => row.raw_param === 0
      && row.payload_length === 7 && /^[a-f0-9]{14}$/i.test(row.raw_payload_hex ?? ''));
    if (!canonical) {
      residuals.push(...group.map(({ row }) => ({ ...row, residual_reason: 'NONCANONICAL_GROUP' })));
      continue;
    }
    const utilityStages = utilityIds.map((participantId) => {
      const row = group[participantId - 1].row;
      const encodedCode = row.raw_payload_hex.slice(2, 10).toLowerCase();
      return { participantId, row, stage: STAGE_BY_ENCODED_CODE[encodedCode] };
    });
    if (utilityStages.some(({ stage }) => !Number.isInteger(stage))) {
      residuals.push(...group.map(({ row }) => ({
        ...row,
        residual_reason: 'CANONICAL_GROUP_UTILITY_STAGE_CODE_UNMAPPED',
      })));
      continue;
    }
    for (const { participantId, row, stage } of utilityStages) {
      events.push({
        event_type: 'SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT', semantic_type: 'ItemEvent',
        semantic_domain: 'item', ...semanticScope(profile, sha), replay_time_ms: row.replay_time_ms,
        subject_entity_id: 0x400000ad + participantId,
        operation: 'SUPPORT_QUEST_STAGE_SNAPSHOT', item_identifier: null,
        source_item_identifier: null, target_item_identifier: null, slot_index: null,
        source_slot_index: null, target_slot_index: null, inventory_entries: null,
        stage, stage_code: STAGE_CODE_F32[stage], snapshot_scope: 'CANONICAL_UTILITY_TEN_ROW_GROUP',
        quantity: null, gold_delta: null, semantic_status: 'VERIFIED_DERIVED',
        confidence: 'VERIFIED_DERIVED',
        field_confidence: {
          subject_entity_id: 'VERIFIED_DERIVED', operation: 'VERIFIED_DERIVED',
          stage: 'VERIFIED_DERIVED', stage_code: 'VERIFIED_DIRECT',
          snapshot_scope: 'VERIFIED_DIRECT',
        },
        decoder_profile: profile.id, raw_payload_sha256: row.raw_payload_sha256
          ?? crypto.createHash('sha256').update(Buffer.from(row.raw_payload_hex, 'hex')).digest('hex'),
        raw_packet_ref: rawPacketRef(row), known_limits: [...profile.known_limits],
      });
    }
  }
  invariant(events.length + residuals.length <= rows.length,
    'support-stage output exceeded input conservation');
  return {
    profile,
    events,
    residuals,
    input_row_count: rows.length,
    canonical_event_count: events.length,
    residual_row_count: residuals.length,
    input_conserved: events.length / 2 * 10 + residuals.length === rows.length,
  };
}

module.exports = {
  BUFF_OPERATIONS,
  STAGE_BY_ENCODED_CODE,
  buffEventFromDecodedRow,
  canonicalProtectionEventsFromDecodedRows,
  deathTimerEventFromDecodedRow,
  decodeDeathTimerObjectHex,
  inventorySnapshotEvent,
  inventorySwapEvent,
  itemSubstitutionMapEvent,
  participantIdFromNetworkId,
  participantMetadata,
  spellCastEventFromDecodedRow,
  supportQuestStageEventsFromRows,
};
