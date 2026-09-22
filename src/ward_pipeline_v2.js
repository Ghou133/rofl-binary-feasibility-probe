'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { sha256, walkBlocks } = require('./rofl');
const {
  artifactShaMatches,
  buildReplayPacketIndex,
  verifiedPacketRecord,
} = require('./provenance_v2');

const WARD_PIPELINE_SCHEMA_VERSION = 2;
const WARD_P0_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-ward-cast-candidate-v2-p0',
  replay_version: '16.15.801.3452',
  stream_tag: 1,
  stream: 'game_chunk',
  replay_block_packet_id: 0x0459,
  participant_param_low_byte_base: 0xad,
  champion_network_id_prefix: 0x40000000,
});

// This metadata identifies the current-build semantic WardSpawn handler. It is
// intentionally descriptive only: this pipeline consumes independently decoded
// rows and never attempts to decrypt packet 0x0353 in JavaScript.
const WARD_SPAWN_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-ward-spawn-unicorn-v1',
  replay_version: '16.15.801.3452',
  replay_packet_id: 0x0353,
  vtable_rva: 0x01b141b0,
  constructor_rva: 0x00eb0640,
  deserialize_rva: 0x0103b1c0,
  deserialize_end_rva: 0x0103d737,
  factory_rva: 0x00eddb80,
  generic_callback_rva: 0x00735f80,
  object_size: 0x90,
  field_offsets: Object.freeze({
    position_x: 0x18,
    position_height: 0x1c,
    position_y: 0x20,
    owner_network_id: 0x30,
    entity_network_id: 0x44,
    generic_name_pointer: 0x50,
    generic_name_length: 0x58,
    entity_name_pointer: 0x78,
    entity_name_length: 0x80,
  }),
  field_write_policy: Object.freeze({
    position: 'fifth/last size-4 plaintext write',
    owner_network_id: 'first size-4 plaintext write',
    entity_network_id: 'first size-4 plaintext write',
    names: 'first pointer/length writes',
  }),
  name_storage: 'object inline or current emulated heap allocation',
  artifact_sha256: Object.freeze({
    ward_spawns: 'c61e623e5b73829a28d16b952ae76fe5d7e7e8869374945e435b2ca09528eaf3',
    ward_lifecycles: 'a7101f7440cb515370a44797ad906703b5c154cbbd6f28e2f4d42cab1f52f817',
  }),
});
const WARD_SPAWN_MAX_TIME_DELTA_MS = 5000;

// Coordinates are kept in the WardSpawn object's native vector convention.
// The direct planar axes come only from packet 0x0353 object writes; CastSpell
// vectors are retained as validation anchors and are never decoder inputs. A
// canonical Summoner's Rift bound is deliberately not asserted until an
// independent map calibration is available.
const WARD_COORDINATE_SYSTEM = Object.freeze({
  map_name: 'SUMMONERS_RIFT',
  map_id: null,
  patch: WARD_P0_PROFILE.replay_version,
  raw_axis_mapping: Object.freeze({
    x: 'WardSpawn.object.position_x (+0x18)',
    y: 'WardSpawn.object.position_y (+0x20)',
    vertical: 'WardSpawn.object.position_height (+0x1c)',
  }),
  castspell_validation_axis_mapping: Object.freeze({
    target_position_planar: 'CastSpell.target_position.x/z',
    target_position_end_planar: 'CastSpell.target_position_end.x/z',
    vertical: 'CastSpell target vector .y',
  }),
  castspell_coordinates_are_decoder_inputs: false,
  transform: 'NONE_RAW_REPLAY_ORIENTATION',
  bounds_status: 'CANONICAL_BOUNDS_UNVERIFIED',
  bounds: Object.freeze({ x_min: null, x_max: null, y_min: null, y_max: null }),
  normalized_coordinates: 'NOT_EMITTED',
});

// A dictionary hit is not enough to label a replay event. Only identifiers
// observed in the pinned, fully decoded CastSpell corpus are allowed to create
// verified Ward candidates.
const VERIFIED_WARD_SPELLS = Object.freeze(new Set([
  'TrinketTotemLvl1',
]));
const WARD_SPELL_METADATA = Object.freeze({
  TrinketTotemLvl1: Object.freeze({
    spell_key: 0x0fb93891,
    ward_type: 'YELLOW_TRINKET',
    ward_candidate_type: 'YELLOW_TRINKET',
    evidence_status: 'VERIFIED_REPLAY_OBSERVED',
  }),
  TrinketTotemLvl2: Object.freeze({
    spell_key: 0x0fb93892,
    ward_type: 'YELLOW_TRINKET_LVL2',
    ward_candidate_type: 'YELLOW_TRINKET_LVL2',
    evidence_status: 'KNOWN_DICTIONARY_NOT_OBSERVED',
  }),
});
const EXCLUDED_WARD_ACTIONS = Object.freeze(new Set([
  'TrinketSweeperLvl1',
  'TrinketSweeperLvl2',
  'TrinketSweeperLvl3',
]));

function isWardSpellIdentifier(identifier) {
  return typeof identifier === 'string' && VERIFIED_WARD_SPELLS.has(identifier);
}

function positionCoordinates(position) {
  const values = Array.isArray(position)
    ? [position[0], position[1], position[2]]
    : position && typeof position === 'object'
      ? [position.x, position.y, position.z]
      : [null, null, null];
  return values.map((value) => Number.isFinite(value) ? value : null);
}

function gameIdFromReplay(replay) {
  return /(?:^|[-_])(\d+)\.rofl$/i.exec(path.basename(replay.source_path ?? ''))?.[1]
    ?? replay.tail?.metadata?.gameId
    ?? replay.tail?.metadata?.game_id
    ?? null;
}

function verifiedWardCandidateFromSpell(replay, spell, occurrenceIndex, descriptor) {
  const [x, y, z] = positionCoordinates(spell.target_position ?? spell.position);
  const [endX, endY, endZ] = positionCoordinates(spell.target_position_end);
  const replaySha256 = replay.source_sha256 ?? spell.replay_sha256 ?? null;
  const rawReplaySha256 = spell.raw_packet_ref?.replay_sha256;
  const rawPacketMatches = spell.raw_packet_ref?.packet_id === WARD_P0_PROFILE.replay_block_packet_id
    && (rawReplaySha256 === null || rawReplaySha256 === undefined
      || rawReplaySha256 === replaySha256);
  const directSemantic = spell.semantic_status === 'VERIFIED_DIRECT'
    && (spell.confidence === 'VERIFIED_DIRECT' || spell.confidence === 'VERIFIED');
  const provenanceStatus = rawPacketMatches && directSemantic ? 'VERIFIED_DIRECT' : 'PARTIAL';
  const positionSource = x === null || z === null ? 'UNAVAILABLE' : 'CAST_TARGET_DIRECT';
  const identifier = spell.spell_identifier;
  return {
    schema_version: WARD_PIPELINE_SCHEMA_VERSION,
    candidate_kind: 'ward_cast',
    candidate_status: provenanceStatus === 'VERIFIED_DIRECT' ? 'VERIFIED' : 'PARTIAL',
    confidence: provenanceStatus,
    semantic_status: provenanceStatus,
    limitation: 'Cast target is direct replay input; final Ward spawn, adjustment, and lifecycle are not decoded.',
    game_id: spell.game_id ?? gameIdFromReplay(replay),
    replay_path: replay.source_path ?? null,
    replay_sha256: replaySha256,
    replay_version: replay.header?.version ?? null,
    timestamp: Number.isFinite(spell.replay_time_ms) ? spell.replay_time_ms : null,
    timestamp_ms: Number.isFinite(spell.replay_time_ms) ? spell.replay_time_ms : null,
    occurrence_index: occurrenceIndex,
    caster_entity: spell.caster_network_id ?? spell.source_network_id ?? null,
    caster_network_id: spell.caster_network_id ?? spell.source_network_id ?? null,
    caster_participant_id: spell.caster_participant_id ?? spell.source_participant_id ?? null,
    caster_champion: spell.caster_champion ?? spell.source_champion ?? null,
    caster_team: spell.caster_team_id ?? spell.source_team_id ?? null,
    team: spell.caster_team_id ?? spell.source_team_id ?? null,
    spell_key: spell.spell_key ?? descriptor.spell_key,
    spell_key_hex: spell.spell_key_hex
      ?? `0x${descriptor.spell_key.toString(16).padStart(8, '0')}`,
    spell_name: spell.spell_name ?? null,
    spell_identifier: identifier,
    ward_candidate_type: descriptor.ward_candidate_type,
    ward_type: descriptor.ward_type,
    ward_spell_evidence_status: descriptor.evidence_status,
    cast_target_x: x,
    cast_target_y: y,
    cast_target_z: z,
    cast_target_end_x: endX,
    cast_target_end_y: endY,
    cast_target_end_z: endZ,
    position_source: positionSource,
    coordinate_system: WARD_COORDINATE_SYSTEM.map_name,
    map_id: WARD_COORDINATE_SYSTEM.map_id,
    map_name: WARD_COORDINATE_SYSTEM.map_name,
    patch: replay.header?.patch ?? WARD_COORDINATE_SYSTEM.patch,
    normalized_x: null,
    normalized_y: null,
    perspective_team: spell.perspective_team ?? null,
    perspective_participant: spell.perspective_participant ?? null,
    role: spell.caster_role ?? spell.source_role ?? null,
    side: spell.caster_side ?? spell.source_side ?? null,
    actual_x: null,
    actual_y: null,
    actual_z: null,
    spawn_time_ms: null,
    despawn_time_ms: null,
    lifecycle_status: null,
    position: positionSource === 'CAST_TARGET_DIRECT' ? { x, y, z } : null,
    raw_payload_hex: spell.raw_payload_hex ?? null,
    raw_payload_sha256: spell.raw_payload_sha256
      ?? spell.raw_packet_ref?.payload_sha256
      ?? null,
    raw_packet_ref: spell.raw_packet_ref ?? null,
    field_confidence: {
      timestamp_ms: Number.isFinite(spell.replay_time_ms) ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
      caster_entity: Number.isInteger(spell.caster_network_id) ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
      caster_participant_id: Number.isInteger(spell.caster_participant_id)
        ? 'VERIFIED_DERIVED'
        : 'UNAVAILABLE',
      spell_key: Number.isInteger(spell.spell_key) ? 'VERIFIED_DIRECT' : 'VERIFIED_DERIVED',
      spell_identifier: 'VERIFIED_DERIVED',
      spell_name: spell.spell_name ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      cast_target_position: positionSource === 'CAST_TARGET_DIRECT'
        ? 'VERIFIED_DIRECT'
        : 'UNAVAILABLE',
      cast_target_end_position: endX === null || endZ === null
        ? 'UNAVAILABLE'
        : 'VERIFIED_DIRECT',
      spawn_position: 'UNAVAILABLE',
      raw_packet: spell.raw_packet_ref ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
    },
  };
}

const WARD_SPAWN_TRACE_CONFIDENCE = 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE';

function valueAtPath(row, pathName) {
  return pathName.split('.').reduce((value, key) => value?.[key], row);
}

function directSpawnField(row, valueNames, confidenceNames) {
  const confidence = row?.field_confidence;
  if (!confidence || typeof confidence !== 'object') return null;
  const isDirect = confidenceNames.some(
    (name) => confidence[name] === WARD_SPAWN_TRACE_CONFIDENCE,
  );
  if (!isDirect) return null;
  for (const name of valueNames) {
    const value = valueAtPath(row, name);
    if (value !== undefined && value !== null) return value;
  }
  return null;
}

function normalizeVerifiedWardSpawn(
  replay, row, profile = WARD_SPAWN_PROFILE, provenance = {},
) {
  if (!row || typeof row !== 'object') return null;
  const replaySha256 = replay.source_sha256;
  const rawPacketRef = row.raw_packet_ref;
  if (!artifactShaMatches(provenance.inputSha256, profile.artifact_sha256.ward_spawns)
      || !replaySha256
      || (row.replay_sha256 !== undefined && row.replay_sha256 !== replaySha256)
      || row.decoder_profile !== profile.id || row.decoder_return_al !== 1 || row.fully_consumed !== true
      || !rawPacketRef || rawPacketRef.replay_sha256 !== replaySha256
      || rawPacketRef.packet_id !== profile.replay_packet_id) return null;

  // Replay time is recovered by the packet framer; all object fields below
  // must additionally originate in the current decoder's write trace.
  const timestampMs = valueAtPath(row, 'timestamp_ms')
    ?? valueAtPath(row, 'replay_time_ms')
    ?? valueAtPath(row, 'timestamp');
  const entityNetworkId = directSpawnField(
    row, ['entity_network_id', 'ward_network_id'], ['entity_network_id', 'ward_network_id'],
  );
  const ownerNetworkId = directSpawnField(
    row, ['owner_network_id'], ['owner_network_id'],
  );
  const entityName = directSpawnField(row, ['entity_name', 'name'], ['entity_name', 'name']);
  const x = directSpawnField(row, ['x', 'position_x', 'position.x'], ['x', 'position_x', 'position']);
  const y = directSpawnField(row, ['y', 'position_y', 'position.y'], ['y', 'position_y', 'position']);
  if (!Number.isFinite(timestampMs) || !Number.isInteger(entityNetworkId)
      || !Number.isInteger(ownerNetworkId) || typeof entityName !== 'string' || !entityName
      || !Number.isFinite(x) || !Number.isFinite(y)) return null;
  if (!verifiedPacketRecord(replay, provenance.packetIndex, rawPacketRef, {
    packetId: profile.replay_packet_id,
    timestampMs,
  })) return null;
  return {
    timestamp_ms: timestampMs,
    replay_sha256: replaySha256,
    ward_network_id: entityNetworkId,
    owner_network_id: ownerNetworkId,
    entity_name: entityName,
    x,
    y,
    raw_packet_ref: rawPacketRef,
    source: row,
  };
}

function euclideanDistance(x1, y1, x2, y2) {
  return Number.isFinite(x1) && Number.isFinite(y1) && Number.isFinite(x2) && Number.isFinite(y2)
    ? Math.hypot(x1 - x2, y1 - y2) : null;
}

function normalizeExplicitWardLifecycle(
  replay, row, profile = WARD_SPAWN_PROFILE, provenance = {},
) {
  if (!row || typeof row !== 'object' || !Number.isInteger(row.ward_network_id)
      || !Number.isFinite(row.spawn_time_ms) || !Number.isFinite(row.remove_time_ms)
      || row.remove_time_ms < row.spawn_time_ms) return null;
  const spawnRef = row.spawn_raw_packet_ref;
  const removeRef = row.remove_raw_packet_ref;
  if (!artifactShaMatches(provenance.inputSha256, profile.artifact_sha256.ward_lifecycles)
      || !replay.source_sha256 || !spawnRef || !removeRef
      || spawnRef.replay_sha256 !== replay.source_sha256
      || removeRef.replay_sha256 !== replay.source_sha256
      || spawnRef.packet_id !== profile.replay_packet_id
      || removeRef.packet_id !== profile.replay_packet_id) return null;
  const durationMs = row.remove_time_ms - row.spawn_time_ms;
  if (row.duration_ms !== undefined && row.duration_ms !== durationMs) return null;
  if (!verifiedPacketRecord(replay, provenance.packetIndex, spawnRef, {
    packetId: profile.replay_packet_id,
    timestampMs: row.spawn_time_ms,
  }) || !verifiedPacketRecord(replay, provenance.packetIndex, removeRef, {
    packetId: profile.replay_packet_id,
    timestampMs: row.remove_time_ms,
  })) return null;
  return {
    ...row,
    replay_sha256: replay.source_sha256,
    duration_ms: durationMs,
    lifecycle_status: 'DERIVED_CORPSE_REMOVAL',
  };
}

function lifecycleForSpawn(lifecycles, spawn) {
  const spawnPayloadSha256 = spawn.raw_packet_ref?.raw_payload_sha256
    ?? spawn.raw_packet_ref?.payload_sha256
    ?? null;
  const matches = lifecycles.filter((lifecycle) => {
    const lifecyclePayloadSha256 = lifecycle.spawn_raw_packet_ref?.raw_payload_sha256
      ?? lifecycle.spawn_raw_packet_ref?.payload_sha256
      ?? null;
    return lifecycle.ward_network_id === spawn.ward_network_id
      && lifecycle.spawn_time_ms === spawn.timestamp_ms
      && typeof spawnPayloadSha256 === 'string'
      && lifecyclePayloadSha256 === spawnPayloadSha256;
  });
  return matches.length === 1 ? matches[0] : null;
}

function matchVerifiedWardSpawns(candidates, spawns, options = {}) {
  const maximumDeltaMs = Number.isFinite(options.ward_spawn_max_time_delta_ms)
    && options.ward_spawn_max_time_delta_ms >= 0
    ? options.ward_spawn_max_time_delta_ms
    : WARD_SPAWN_MAX_TIME_DELTA_MS;
  const proposed = [];
  spawns.forEach((spawn, spawnIndex) => {
    const eligible = candidates.map((candidate, candidateIndex) => ({ candidate, candidateIndex }))
      .filter(({ candidate }) => candidate?.confidence === 'VERIFIED_DIRECT'
        && candidate.replay_sha256 === spawn.replay_sha256
        && candidate.caster_network_id === spawn.owner_network_id
        && Number.isFinite(candidate.timestamp_ms)
        && spawn.timestamp_ms >= candidate.timestamp_ms)
      .map((entry) => ({ ...entry, deltaMs: spawn.timestamp_ms - entry.candidate.timestamp_ms }))
      .filter((entry) => entry.deltaMs <= maximumDeltaMs);
    if (eligible.length === 0) return;
    const minimumDeltaMs = Math.min(...eligible.map((entry) => entry.deltaMs));
    const best = eligible.filter((entry) => entry.deltaMs === minimumDeltaMs);
    if (best.length !== 1) return;
    proposed.push({ ...best[0], spawn, spawnIndex });
  });

  // A Ward cast can create only one Ward. Retain a candidate only when exactly
  // one spawn claims it at the nearest timestamp; otherwise leave it unmatched.
  const claimsByCandidate = new Map();
  for (const match of proposed) {
    const claims = claimsByCandidate.get(match.candidateIndex) ?? [];
    claims.push(match);
    claimsByCandidate.set(match.candidateIndex, claims);
  }
  const matches = [];
  for (const claims of claimsByCandidate.values()) {
    const minimumDeltaMs = Math.min(...claims.map((claim) => claim.deltaMs));
    const best = claims.filter((claim) => claim.deltaMs === minimumDeltaMs);
    if (best.length !== 1) continue;
    const { candidate, candidateIndex, spawn, spawnIndex, deltaMs } = best[0];
    matches.push({
      schema_version: WARD_PIPELINE_SCHEMA_VERSION,
      match_status: 'ENTITY_SPAWN_DIRECT',
      replay_sha256: spawn.replay_sha256,
      cast_candidate_index: candidateIndex,
      spawn_event_index: spawnIndex,
      owner_network_id: spawn.owner_network_id,
      ward_network_id: spawn.ward_network_id,
      entity_name: spawn.entity_name,
      cast_timestamp_ms: candidate.timestamp_ms,
      spawn_timestamp_ms: spawn.timestamp_ms,
      time_delta_ms: deltaMs,
      cast_target_x: candidate.cast_target_x,
      cast_target_y: candidate.cast_target_y,
      cast_target_z: candidate.cast_target_z,
      cast_target_end_x: candidate.cast_target_end_x,
      cast_target_end_y: candidate.cast_target_end_y,
      cast_target_end_z: candidate.cast_target_end_z,
      actual_x: spawn.x,
      actual_y: spawn.y,
      coordinate_error_start_like: euclideanDistance(
        candidate.cast_target_x, candidate.cast_target_z, spawn.x, spawn.y,
      ),
      coordinate_error_end: euclideanDistance(
        candidate.cast_target_end_x, candidate.cast_target_end_z, spawn.x, spawn.y,
      ),
      cast_raw_packet_ref: candidate.raw_packet_ref,
      spawn_raw_packet_ref: spawn.raw_packet_ref,
      field_confidence: {
        timestamp: 'VERIFIED_DIRECT',
        ward_network_id: WARD_SPAWN_TRACE_CONFIDENCE,
        owner_network_id: WARD_SPAWN_TRACE_CONFIDENCE,
        entity_name: WARD_SPAWN_TRACE_CONFIDENCE,
        spawn_position: WARD_SPAWN_TRACE_CONFIDENCE,
      },
    });
  }
  return matches.sort((a, b) => a.cast_candidate_index - b.cast_candidate_index);
}

function candidateWithVerifiedSpawn(candidate, match, lifecycle = null) {
  if (!match) return candidate;
  return {
    ...candidate,
    ward_network_id: match.ward_network_id,
    ward_entity_name: match.entity_name,
    actual_x: match.actual_x,
    actual_y: match.actual_y,
    actual_z: null,
    spawn_time_ms: match.spawn_timestamp_ms,
    spawn_raw_packet_ref: match.spawn_raw_packet_ref,
    despawn_time_ms: lifecycle?.remove_time_ms ?? candidate.despawn_time_ms,
    lifecycle_status: lifecycle?.lifecycle_status ?? candidate.lifecycle_status,
    lifecycle_duration_ms: lifecycle?.duration_ms ?? null,
    removal_reason: lifecycle?.removal_reason ?? null,
    removal_raw_packet_ref: lifecycle?.remove_raw_packet_ref ?? null,
    position_source: 'ENTITY_SPAWN_DIRECT',
    field_confidence: {
      ...candidate.field_confidence,
      ward_network_id: WARD_SPAWN_TRACE_CONFIDENCE,
      spawn_position: WARD_SPAWN_TRACE_CONFIDENCE,
    },
  };
}

function buildVerifiedWardCandidates(replay, spellEvents = []) {
  return spellEvents
    .filter((spell) => isWardSpellIdentifier(spell?.spell_identifier))
    .filter((spell) => !EXCLUDED_WARD_ACTIONS.has(spell?.spell_identifier))
    .filter((spell) => {
      const sourceSha256 = spell.raw_packet_ref?.replay_sha256 ?? spell.replay_sha256;
      return sourceSha256 === null || sourceSha256 === undefined
        || sourceSha256 === replay.source_sha256;
    })
    .map((spell, index) => verifiedWardCandidateFromSpell(
      replay,
      spell,
      index,
      WARD_SPELL_METADATA[spell.spell_identifier],
    ));
}

function wardEventFromCandidate(candidate) {
  const hasDirectSpawn = candidate.position_source === 'ENTITY_SPAWN_DIRECT'
    && Number.isFinite(candidate.actual_x) && Number.isFinite(candidate.actual_y)
    && Number.isInteger(candidate.ward_network_id);
  return {
    schema_version: WARD_PIPELINE_SCHEMA_VERSION,
    event_type: 'ward_cast',
    event_status: hasDirectSpawn ? 'ENTITY_SPAWN_DIRECT' : 'CAST_OBSERVED_SPAWN_UNAVAILABLE',
    game_id: candidate.game_id,
    replay_sha256: candidate.replay_sha256,
    timestamp: candidate.timestamp,
    timestamp_ms: candidate.timestamp_ms,
    owner_entity: candidate.caster_entity,
    owner_participant: candidate.caster_participant_id,
    owner_champion: candidate.caster_champion,
    owner_team: candidate.team,
    ward_type: candidate.ward_type,
    ward_network_id: hasDirectSpawn ? candidate.ward_network_id : null,
    ward_entity_name: hasDirectSpawn ? candidate.ward_entity_name : null,
    spawn_timestamp_ms: hasDirectSpawn ? candidate.spawn_time_ms : null,
    actual_x: hasDirectSpawn ? candidate.actual_x : null,
    actual_y: hasDirectSpawn ? candidate.actual_y : null,
    actual_z: null,
    cast_target_x: candidate.cast_target_x,
    cast_target_y: candidate.cast_target_y,
    cast_target_z: candidate.cast_target_z,
    cast_target_end_x: candidate.cast_target_end_x,
    cast_target_end_y: candidate.cast_target_end_y,
    cast_target_end_z: candidate.cast_target_end_z,
    position_source: candidate.position_source,
    coordinate_system: candidate.coordinate_system ?? WARD_COORDINATE_SYSTEM.map_name,
    map_id: candidate.map_id ?? WARD_COORDINATE_SYSTEM.map_id,
    map_name: candidate.map_name ?? WARD_COORDINATE_SYSTEM.map_name,
    patch: candidate.patch ?? WARD_COORDINATE_SYSTEM.patch,
    normalized_x: candidate.normalized_x ?? null,
    normalized_y: candidate.normalized_y ?? null,
    perspective_team: candidate.perspective_team ?? null,
    perspective_participant: candidate.perspective_participant ?? null,
    role: candidate.role ?? null,
    side: candidate.side ?? null,
    despawn_time_ms: candidate.despawn_time_ms ?? null,
    lifecycle_duration_ms: candidate.lifecycle_duration_ms ?? null,
    removal_reason: candidate.removal_reason ?? null,
    lifecycle_status: candidate.lifecycle_status ?? 'UNAVAILABLE',
    confidence: hasDirectSpawn ? 'VERIFIED_DIRECT' : candidate.confidence,
    field_confidence: {
      cast_timestamp: candidate.field_confidence.timestamp_ms,
      owner: candidate.field_confidence.caster_entity,
      ward_type: 'VERIFIED_DERIVED',
      cast_target_position: candidate.field_confidence.cast_target_position,
      spawn_position: hasDirectSpawn
        ? candidate.field_confidence.spawn_position
        : 'UNAVAILABLE',
      lifecycle: candidate.lifecycle_status === 'DERIVED_CORPSE_REMOVAL'
        ? 'VERIFIED_DERIVED'
        : 'UNAVAILABLE',
    },
    cast_raw_packet_ref: candidate.raw_packet_ref,
    removal_raw_packet_ref: candidate.removal_raw_packet_ref ?? null,
    raw_packet_ref: hasDirectSpawn ? candidate.spawn_raw_packet_ref : candidate.raw_packet_ref,
  };
}

function heatmapRowFromCandidate(candidate) {
  const hasDirectSpawn = candidate.position_source === 'ENTITY_SPAWN_DIRECT'
    && Number.isFinite(candidate.actual_x) && Number.isFinite(candidate.actual_y);
  if (!hasDirectSpawn && (candidate.cast_target_x === null || candidate.cast_target_z === null)) return null;
  return {
    schema_version: WARD_PIPELINE_SCHEMA_VERSION,
    game_id: candidate.game_id,
    replay_sha256: candidate.replay_sha256,
    timestamp: candidate.timestamp,
    minute: Number.isFinite(candidate.timestamp) ? Math.floor(candidate.timestamp / 60000) : null,
    team: candidate.team,
    participant: candidate.caster_participant_id,
    champion: candidate.caster_champion,
    ward_type: candidate.ward_type,
    ward_network_id: hasDirectSpawn ? candidate.ward_network_id : null,
    ward_entity_name: hasDirectSpawn ? candidate.ward_entity_name : null,
    spawn_timestamp_ms: hasDirectSpawn ? candidate.spawn_time_ms : null,
    x: hasDirectSpawn ? candidate.actual_x : candidate.cast_target_x,
    y: hasDirectSpawn ? candidate.actual_y : candidate.cast_target_z,
    cast_target_y: candidate.cast_target_y,
    position_source: hasDirectSpawn ? 'ENTITY_SPAWN_DIRECT' : 'CAST_TARGET_DIRECT',
    coordinate_system: WARD_COORDINATE_SYSTEM.map_name,
    map_id: WARD_COORDINATE_SYSTEM.map_id,
    map_name: WARD_COORDINATE_SYSTEM.map_name,
    patch: candidate.patch ?? WARD_COORDINATE_SYSTEM.patch,
    normalized_x: null,
    normalized_y: null,
    perspective_team: candidate.perspective_team ?? null,
    perspective_participant: candidate.perspective_participant ?? null,
    role: candidate.role ?? null,
    side: candidate.side ?? null,
    confidence: hasDirectSpawn ? 'VERIFIED_DIRECT' : candidate.confidence,
    is_spawn_position: hasDirectSpawn,
    cast_raw_packet_ref: candidate.raw_packet_ref,
    raw_packet_ref: hasDirectSpawn ? candidate.spawn_raw_packet_ref : candidate.raw_packet_ref,
  };
}

function participantIdFromRawParam(rawParam, profile = WARD_P0_PROFILE) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const participantId = (rawParam & 0xff) - profile.participant_param_low_byte_base;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function championNetworkIdFromRawParam(rawParam, profile = WARD_P0_PROFILE) {
  return participantIdFromRawParam(rawParam, profile) === null
    ? null
    : (profile.champion_network_id_prefix | (rawParam & 0xff)) >>> 0;
}

function rawPacketRef(replay, chunk, block) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    compressed_body_offset: chunk.body_offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    payload_length: block.payload_length,
    payload_sha256: sha256(block.payload),
  };
}

function candidateFromBlock(replay, chunk, block, occurrenceIndex, profile = WARD_P0_PROFILE) {
  const participantId = participantIdFromRawParam(block.param, profile);
  return {
    schema_version: WARD_PIPELINE_SCHEMA_VERSION,
    candidate_kind: 'ward_cast',
    candidate_status: 'INFERRED',
    confidence: 'INFERRED',
    semantic_status: 'INFERRED',
    limitation: 'CastSpell payload fields are not decoded; ward identity and placement are unavailable.',
    replay_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    replay_version: replay.header?.version ?? null,
    replay_time_ms: Number.isFinite(block.timestamp_ms) ? block.timestamp_ms : null,
    occurrence_index: occurrenceIndex,
    caster_network_id: championNetworkIdFromRawParam(block.param, profile),
    caster_participant_id: participantId,
    caster_champion: Array.isArray(replay.tail?.stats) && participantId
      ? replay.tail.stats[participantId - 1]?.SKIN ?? null
      : null,
    ward_type: null,
    position: null,
    spell_identifier: null,
    raw_param: block.param >>> 0,
    raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: sha256(block.payload),
    decoder_profile: profile.id,
    coordinate_system: WARD_COORDINATE_SYSTEM.map_name,
    map_id: WARD_COORDINATE_SYSTEM.map_id,
    map_name: WARD_COORDINATE_SYSTEM.map_name,
    patch: replay.header?.patch ?? WARD_COORDINATE_SYSTEM.patch,
    normalized_x: null,
    normalized_y: null,
    perspective_team: null,
    perspective_participant: null,
    role: null,
    side: null,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      caster_network_id: participantId === null ? 'UNAVAILABLE' : 'VERIFIED_DERIVED',
      caster_participant_id: participantId === null ? 'UNAVAILABLE' : 'VERIFIED_DERIVED',
      caster_champion: participantId === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
      ward_type: 'UNAVAILABLE',
      position: 'UNAVAILABLE',
      spell_identifier: 'UNAVAILABLE',
    },
    raw_packet_ref: rawPacketRef(replay, chunk, block),
  };
}

function buildWardCastCandidates(replay, options = {}) {
  const profile = options.profile ?? WARD_P0_PROFILE;
  if (!replay || !replay.header) throw new TypeError('replay with header is required');
  if (replay.header.version !== profile.replay_version) {
    const error = new Error(
      `ward candidate profile ${profile.id} only supports ${profile.replay_version}; got ${replay.header.version}`,
    );
    error.code = 'WARD_REPLAY_VERSION_UNSUPPORTED';
    throw error;
  }
  const candidates = [];
  let occurrenceIndex = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (chunk.stream_tag !== profile.stream_tag
        || block.packet_id !== profile.replay_block_packet_id) return;
    candidates.push(candidateFromBlock(replay, chunk, block, occurrenceIndex, profile));
    occurrenceIndex += 1;
  }, { includeStreams: [profile.stream_tag], strict: options.strict !== false });
  if (walk.errors.length > 0) throw new Error('ward candidate extraction encountered framing errors');
  return candidates;
}

function buildWardOutputs(replay, options = {}) {
  if (!replay || !replay.header) throw new TypeError('replay with header is required');
  if (replay.header.version !== WARD_P0_PROFILE.replay_version) {
    const error = new Error(
      `ward candidate profile ${WARD_P0_PROFILE.id} only supports ${WARD_P0_PROFILE.replay_version}; got ${replay.header.version}`,
    );
    error.code = 'WARD_REPLAY_VERSION_UNSUPPORTED';
    throw error;
  }
  const spellEvents = options.spell_events ?? options.spellEvents;
  const semanticCandidates = Array.isArray(spellEvents)
    ? buildVerifiedWardCandidates(replay, spellEvents) : null;
  const baseCandidates = options.candidates ?? semanticCandidates ?? buildWardCastCandidates(replay, options);
  const wardSpawnEvents = options.ward_spawn_events ?? options.wardSpawnEvents;
  const explicitWardLifecycles = options.ward_lifecycles ?? options.wardLifecycles;
  const wardSpawnInputSha256 = options.ward_spawn_input_sha256
    ?? options.wardSpawnInputSha256
    ?? null;
  const wardLifecycleInputSha256 = options.ward_lifecycle_input_sha256
    ?? options.wardLifecycleInputSha256
    ?? null;
  const hasTrustedSpawnArtifact = Array.isArray(wardSpawnEvents)
    && artifactShaMatches(
      wardSpawnInputSha256, WARD_SPAWN_PROFILE.artifact_sha256.ward_spawns,
    );
  const hasTrustedLifecycleArtifact = Array.isArray(explicitWardLifecycles)
    && artifactShaMatches(
      wardLifecycleInputSha256, WARD_SPAWN_PROFILE.artifact_sha256.ward_lifecycles,
    );
  let packetProvenanceIndex = options.packet_provenance_index
    ?? options.packetProvenanceIndex
    ?? null;
  if ((hasTrustedSpawnArtifact || hasTrustedLifecycleArtifact)
      && !(packetProvenanceIndex instanceof Map) && Array.isArray(replay.chunks)) {
    packetProvenanceIndex = buildReplayPacketIndex(replay, [WARD_SPAWN_PROFILE.replay_packet_id]);
  }
  const verifiedSpawns = hasTrustedSpawnArtifact
    ? wardSpawnEvents.map((row) => normalizeVerifiedWardSpawn(
      replay, row, WARD_SPAWN_PROFILE, {
        inputSha256: wardSpawnInputSha256,
        packetIndex: packetProvenanceIndex,
      },
    )).filter(Boolean)
    : [];
  const verifiedWardLifecycles = hasTrustedLifecycleArtifact
    ? explicitWardLifecycles.map((row) => normalizeExplicitWardLifecycle(
      replay, row, WARD_SPAWN_PROFILE, {
        inputSha256: wardLifecycleInputSha256,
        packetIndex: packetProvenanceIndex,
      },
    )).filter(Boolean)
    : [];
  const matchedWardLifecycles = [...new Set(verifiedSpawns
    .map((spawn) => lifecycleForSpawn(verifiedWardLifecycles, spawn))
    .filter(Boolean))];
  const directSpawnMatches = Array.isArray(wardSpawnEvents)
    ? matchVerifiedWardSpawns(baseCandidates, verifiedSpawns, options)
    : null;
  const spawnMatchByCandidateIndex = new Map(
    (directSpawnMatches ?? []).map((match) => [match.cast_candidate_index, match]),
  );
  const candidates = directSpawnMatches === null
    ? baseCandidates
    : baseCandidates.map((candidate, index) => candidateWithVerifiedSpawn(
      candidate, spawnMatchByCandidateIndex.get(index),
      spawnMatchByCandidateIndex.has(index)
          ? lifecycleForSpawn(matchedWardLifecycles, verifiedSpawns[
          spawnMatchByCandidateIndex.get(index).spawn_event_index
        ])
        : null,
    ));
  const hasDirectSpawnMatch = (directSpawnMatches?.length ?? 0) > 0;
  const hasDerivedLifecycle = candidates.some(
    (candidate) => candidate.lifecycle_status === 'DERIVED_CORPSE_REMOVAL',
  );
  const explicitWardEvents = options.ward_events ?? options.wardEvents;
  const wardEvents = Array.isArray(explicitWardEvents)
    ? explicitWardEvents
    : semanticCandidates ? candidates.map(wardEventFromCandidate) : [];
  const wardLifecycles = matchedWardLifecycles;
  const spawnMatches = directSpawnMatches ?? (Array.isArray(
    options.ward_cast_spawn_matches ?? options.wardCastSpawnMatches,
  ) ? (options.ward_cast_spawn_matches ?? options.wardCastSpawnMatches) : []);
  const explicitHeatmapInput = options.ward_heatmap_input ?? options.wardHeatmapInput;
  const heatmapInput = Array.isArray(explicitHeatmapInput)
    ? explicitHeatmapInput
    : semanticCandidates ? candidates.map(heatmapRowFromCandidate).filter(Boolean) : [];
  const verifiedCandidateCount = candidates.filter(
    (candidate) => candidate.confidence === 'VERIFIED_DIRECT',
  ).length;
  const sweeperExcludedCount = Array.isArray(spellEvents)
    ? spellEvents.filter((spell) => EXCLUDED_WARD_ACTIONS.has(spell?.spell_identifier)).length
    : 0;
  return {
    schema_version: WARD_PIPELINE_SCHEMA_VERSION,
    pipeline: 'ward-p0-v2',
    status: hasDirectSpawnMatch
      ? 'WARD_SPAWN_POSITION_VERIFIED_DIRECT'
      : (semanticCandidates ? 'WARD_CAST_POSITION_VERIFIED_DIRECT' : 'INFERRED'),
    replay_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    replay_version: replay.header?.version ?? null,
    ward_cast_position_status: semanticCandidates
      ? 'WARD_CAST_POSITION_VERIFIED_DIRECT'
      : 'UNAVAILABLE',
    ward_spawn_position_status: hasDirectSpawnMatch ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
    ward_event_status: hasDirectSpawnMatch
      ? 'ENTITY_SPAWN_DIRECT'
      : (semanticCandidates ? 'CAST_ONLY' : 'UNAVAILABLE'),
    ward_lifecycle_status: hasDerivedLifecycle ? 'DERIVED_CORPSE_REMOVAL' : 'UNAVAILABLE',
    ward_cast_spawn_match_status: hasDirectSpawnMatch ? 'ENTITY_SPAWN_DIRECT' : 'UNAVAILABLE',
    ward_heatmap_status: hasDirectSpawnMatch && !Array.isArray(explicitHeatmapInput)
      ? 'ENTITY_SPAWN_DIRECT'
      : (heatmapInput.length > 0 ? 'CAST_TARGET_ONLY' : 'UNAVAILABLE'),
    ward_cast_candidates: candidates,
    ward_events: wardEvents,
    ward_lifecycles: wardLifecycles,
    ward_cast_spawn_matches: spawnMatches,
    ward_heatmap_input: heatmapInput,
    provenance: {
      fact_source: 'ROFL_REPLAY_PACKET_BYTES',
      candidate_profile: WARD_P0_PROFILE.id,
      position_policy: 'CAST_TARGET_DIRECT is never renamed or promoted to an actual Ward spawn coordinate.',
      coordinate_system: WARD_COORDINATE_SYSTEM,
      confidence_policy: semanticCandidates
        ? 'Ward candidates are filtered from verified CastSpell rows by pinned ward identifiers; sweeper casts are excluded.'
        : 'Candidates are INFERRED until a verified CastSpell payload decoder identifies ward casts.',
      oracle_policy: 'Match Details may validate candidate counts/timing but cannot become event fact source.',
      semantic_spell_event_count: Array.isArray(spellEvents) ? spellEvents.length : null,
      verified_candidate_count: verifiedCandidateCount,
      sweeper_excluded_count: sweeperExcludedCount,
      ...(hasDirectSpawnMatch ? {
        ward_spawn_profile: WARD_SPAWN_PROFILE,
        ward_spawn_input_count: Array.isArray(wardSpawnEvents) ? wardSpawnEvents.length : 0,
        ward_spawn_verified_direct_count: verifiedSpawns.length,
        ward_spawn_input_sha256: wardSpawnInputSha256,
        ward_spawn_artifact_hash_verified: hasTrustedSpawnArtifact,
        ward_lifecycle_input_sha256: wardLifecycleInputSha256,
        ward_lifecycle_artifact_hash_verified: hasTrustedLifecycleArtifact,
        ward_lifecycle_packet_verified_count: verifiedWardLifecycles.length,
        ward_lifecycle_verified_derived_count: matchedWardLifecycles.length,
      } : {}),
      unsupported_fields: {
        ward_network_id: hasDirectSpawnMatch ? undefined : null,
        actual_x: hasDirectSpawnMatch ? undefined : null,
        actual_y: hasDirectSpawnMatch ? undefined : null,
        actual_z: null,
        spawn_timestamp_ms: hasDirectSpawnMatch ? undefined : null,
        despawn_time_ms: hasDerivedLifecycle ? undefined : null,
        lifecycle_status: hasDerivedLifecycle ? undefined : null,
      },
    },
  };
}

function writeWardOutputs(outputDir, outputs) {
  if (!outputDir) throw new TypeError('outputDir is required');
  fs.mkdirSync(outputDir, { recursive: true });
  const candidatesPath = path.join(outputDir, 'ward_cast_candidates.jsonl');
  const eventsPath = path.join(outputDir, 'ward_events.jsonl');
  const eventsCsvPath = path.join(outputDir, 'ward_events.csv');
  const lifecyclesPath = path.join(outputDir, 'ward_lifecycles.jsonl');
  const spawnMatchesPath = path.join(outputDir, 'ward_cast_spawn_matches.jsonl');
  const heatmapPath = path.join(outputDir, 'ward_heatmap_input.jsonl');
  const heatmapCsvPath = path.join(outputDir, 'ward_heatmap_input.csv');
  const provenancePath = path.join(outputDir, 'ward_provenance.json');
  const outputPath = path.join(outputDir, 'ward_outputs.json');
  fs.writeFileSync(candidatesPath,
    outputs.ward_cast_candidates.map((row) => JSON.stringify(row)).join('\n')
      + (outputs.ward_cast_candidates.length ? '\n' : ''), 'utf8');
  fs.writeFileSync(eventsPath,
    outputs.ward_events.map((row) => JSON.stringify(row)).join('\n')
      + (outputs.ward_events.length ? '\n' : ''), 'utf8');
  const lifecycles = outputs.ward_lifecycles ?? [];
  const spawnMatches = outputs.ward_cast_spawn_matches ?? [];
  const heatmapInput = outputs.ward_heatmap_input ?? [];
  fs.writeFileSync(lifecyclesPath,
    lifecycles.map((row) => JSON.stringify(row)).join('\n')
      + (lifecycles.length ? '\n' : ''), 'utf8');
  fs.writeFileSync(spawnMatchesPath,
    spawnMatches.map((row) => JSON.stringify(row)).join('\n')
      + (spawnMatches.length ? '\n' : ''), 'utf8');
  fs.writeFileSync(heatmapPath,
    heatmapInput.map((row) => JSON.stringify(row)).join('\n')
      + (heatmapInput.length ? '\n' : ''), 'utf8');
  const heatmapColumns = [
    'game_id',
    'timestamp',
    'minute',
    'team',
    'participant',
    'champion',
    'ward_type',
    'ward_network_id',
    'ward_entity_name',
    'spawn_timestamp_ms',
    'x',
    'y',
    'cast_target_y',
    'position_source',
    'coordinate_system',
    'map_id',
    'map_name',
    'patch',
    'normalized_x',
    'normalized_y',
    'perspective_team',
    'perspective_participant',
    'role',
    'side',
    'confidence',
    'is_spawn_position',
  ];
  const csvCell = (value) => {
    if (value === null || value === undefined) return '';
    const text = String(value);
    return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  };
  fs.writeFileSync(heatmapCsvPath, [
    heatmapColumns.join(','),
    ...heatmapInput.map((row) => heatmapColumns.map((column) => csvCell(row[column])).join(',')),
  ].join('\n') + '\n', 'utf8');
  const eventColumns = [
    'game_id', 'timestamp_ms', 'owner_participant', 'owner_champion',
    'owner_team', 'ward_type', 'ward_network_id', 'ward_entity_name',
    'spawn_timestamp_ms', 'cast_target_x', 'cast_target_y', 'cast_target_z',
    'cast_target_end_x', 'cast_target_end_y', 'cast_target_end_z',
    'actual_x', 'actual_y', 'actual_z',
    'position_source', 'confidence', 'event_status', 'lifecycle_status',
    'coordinate_system', 'map_id', 'patch',
  ];
  fs.writeFileSync(eventsCsvPath, [
    eventColumns.join(','),
    ...outputs.ward_events.map((row) => eventColumns.map((column) => csvCell(row[column])).join(',')),
  ].join('\n') + '\n', 'utf8');
  fs.writeFileSync(provenancePath, `${JSON.stringify(outputs.provenance, null, 2)}\n`, 'utf8');
  fs.writeFileSync(outputPath, `${JSON.stringify(outputs, null, 2)}\n`, 'utf8');
  return {
    candidates_path: candidatesPath,
    events_path: eventsPath,
    events_csv_path: eventsCsvPath,
    lifecycles_path: lifecyclesPath,
    spawn_matches_path: spawnMatchesPath,
    heatmap_input_path: heatmapPath,
    heatmap_input_csv_path: heatmapCsvPath,
    provenance_path: provenancePath,
    outputs_path: outputPath,
  };
}

module.exports = {
  WARD_PIPELINE_SCHEMA_VERSION,
  WARD_P0_PROFILE,
  WARD_SPAWN_PROFILE,
  WARD_SPAWN_MAX_TIME_DELTA_MS,
  WARD_COORDINATE_SYSTEM,
  VERIFIED_WARD_SPELLS,
  WARD_SPELL_METADATA,
  EXCLUDED_WARD_ACTIONS,
  isWardSpellIdentifier,
  verifiedWardCandidateFromSpell,
  buildVerifiedWardCandidates,
  normalizeVerifiedWardSpawn,
  matchVerifiedWardSpawns,
  candidateWithVerifiedSpawn,
  wardEventFromCandidate,
  heatmapRowFromCandidate,
  participantIdFromRawParam,
  championNetworkIdFromRawParam,
  candidateFromBlock,
  buildWardCastCandidates,
  buildWardOutputs,
  writeWardOutputs,
};
