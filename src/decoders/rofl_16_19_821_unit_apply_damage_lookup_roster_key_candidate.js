'use strict';

// The native callback's +0x24 value is a lookup-key candidate. Matching that
// full value to the canonical HeroStats roster does not identify a damage
// actor, source, target, victim, or health effect.
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { replaySourceError } = require('./replay_source_integrity');
const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE,
  decodeUnitApplyDamageLookupKeyFromRaw821,
} = require('./rofl_16_19_821_unit_apply_damage_packet_candidate');
const {
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: RAW_PAIR_PROFILE,
  associateUnitApplyDamageRosterKeys821,
} = require('./rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { PROFILES } = require('./rofl_16_19_821_float_stats_candidate');
const { RUNTIME_IMAGE_SHA256 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const LAST_KEY = 0x400000b7;
const MAX_DAMAGE_ROWS = 100_000;
const MAX_SNAPSHOT_ROWS = 10_000;
const EVIDENCE_STATUS =
  'CANDIDATE_821_UNIT_APPLY_DAMAGE_NATIVE_LOOKUP_KEY_HEROSTATS_FULL_KEY_COOCCURRENCE';
const RELATIONS = ['EQUAL', 'RAW_PARAM_IS_LOOKUP_PLUS_0X100', 'OTHER'];
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;

const UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-unit-apply-damage-lookup-roster-key-candidate-v1',
  replay_version: BUILD,
  capability: 'unit_apply_damage_lookup_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze([
    'unit_apply_damage_packet', 'hero_minions_killed_snapshot',
    'unit_apply_damage_roster_key_pair',
  ]),
  packet_ids: Object.freeze([0x005f, 0x0089]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_lookup_key_0x24_table_sha256:
    DAMAGE_PROFILE.evidence_lookup_key_0x24_table_sha256,
  known_limits: Object.freeze([
    'The +0x24 native callback value is a candidate lookup key; a matching HeroStats full key does not prove a successful object lookup or runtime type conversion.',
    'The HeroStats participant candidate comes only from the ten-key 0x0089 roster. Damage actor, source, target, victim, actual amount, and health effect remain UNKNOWN.',
    'A raw_param +0x100 alias is included only when the independently decoded +0x24 full key matches a canonical roster key; no global alias normalization is applied.',
    'The referenced HeroStats packet is roster evidence from the first keyframe, not a contemporaneous damage observation.',
    'The complete native-witnessed v3 damage outcome, complete same-roster keyframes, and source-bound raw-key pair validation are required.',
  ]),
});

function count(value, max) {
  return Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function u32(value) {
  return count(value, 0xffffffff);
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function expectedRelation(rawParam, key24) {
  if (rawParam === key24) return 'EQUAL';
  if (rawParam - key24 === 0x100) return 'RAW_PARAM_IS_LOOKUP_PLUS_0X100';
  return 'OTHER';
}

function isAliasRawParam(rawParam) {
  return rawParam >= FIRST_KEY + 0x100 && rawParam <= LAST_KEY + 0x100;
}

function sourceRefMatches(replay, ref, packetId, rawParam) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && ref.packet_id === packetId && ref.raw_param === rawParam
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index
    && chunk.chunk_id === ref.chunk_id && chunk.offset === ref.chunk_file_offset
    && chunk.stream === ref.chunk_stream
    && ref.chunk_stream === (packetId === 0x0089 ? 'keyframe' : 'game_chunk')
    && count(ref.decompressed_block_offset, Number.MAX_SAFE_INTEGER)
    && count(ref.decompressed_payload_offset, Number.MAX_SAFE_INTEGER)
    && count(ref.replay_time_ms, Number.MAX_SAFE_INTEGER);
}

function checkedRoster(replay, snapshot, pair) {
  if (snapshot?.status !== 'CANDIDATE'
      || snapshot.profile_id !== SNAPSHOT_PROFILE.id
      || !Array.isArray(snapshot.events)
      || !count(snapshot.event_count, MAX_SNAPSHOT_ROWS)
      || snapshot.events.length !== snapshot.event_count
      || snapshot.input_count !== snapshot.event_count
      || snapshot.keyframe_count === 0
      || snapshot.event_count !== snapshot.keyframe_count * 10
      || pair.snapshot_count !== snapshot.event_count
      || pair.keyframe_count !== snapshot.keyframe_count) return null;
  const frames = new Map();
  for (const row of snapshot.events) {
    const key = row?.hero_raw_param;
    const ref = row?.raw_packet_ref;
    if (!u32(key) || key < FIRST_KEY || key > LAST_KEY
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== SNAPSHOT_PROFILE.id
        || row.event_type !== 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE'
        || row.replay_sha256 !== replay.source_sha256
        || row.replay_time_ms !== ref?.replay_time_ms
        || row.participant_id_candidate !== key - FIRST_KEY + 1
        || !sourceRefMatches(replay, ref, 0x0089, key)) return null;
    const frame = frames.get(ref.chunk_index) ?? new Map();
    if (frame.has(key)) return null;
    frame.set(key, row);
    frames.set(ref.chunk_index, frame);
  }
  const keyframes = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (frames.size !== snapshot.keyframe_count
      || keyframes.length !== frames.size
      || keyframes.some((chunk) => !frames.has(chunk.index))
      || [...frames.values()].some((frame) => frame.size !== 10)) return null;
  const roster = frames.get(keyframes[0].index);
  if (!roster || roster.size !== 10 || pair.canonical_roster_key_count !== 10) return null;
  for (let key = FIRST_KEY; key <= LAST_KEY; key += 1) {
    if ([...frames.values()].some((frame) => !frame.has(key))) return null;
  }
  return roster;
}

function checkedPairMetadata(replay, damage, snapshot, pair) {
  return pair?.status === 'CANDIDATE'
    && pair.profile_id === RAW_PAIR_PROFILE.id
    && pair.evidence_status === RAW_PAIR_PROFILE.evidence_status
    && pair.replay_sha256 === replay.source_sha256
    && pair.runtime_image_status === 'MATCHED_USED'
    && pair.runtime_image_used === true
    && pair.runtime_image_sha256 === RUNTIME_IMAGE_SHA256
    && pair.damage_packet_count === damage.event_count
    && pair.snapshot_count === snapshot.event_count
    && pair.verified_raw_packet_count === damage.event_count + snapshot.event_count
    && pair.input_count === pair.verified_raw_packet_count
    && count(pair.matched_full_key_packet_count, damage.event_count)
    && pair.event_count === pair.matched_full_key_packet_count
    && Array.isArray(pair.events) && pair.events.length === pair.event_count
    && count(pair.unmatched_packet_count, damage.event_count)
    && pair.unmatched_packet_count + pair.event_count === damage.event_count
    && count(pair.excluded_alias_0x100_packet_count, pair.unmatched_packet_count)
    && pair.dependency_statuses?.unit_apply_damage_packet === 'CANDIDATE'
    && pair.dependency_statuses?.hero_minions_killed_snapshot === 'CANDIDATE';
}

function associateUnitApplyDamageLookupRosterKeys821(replay, {
  unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome,
  validatedRawRosterPairOutcome,
} = {}) {
  const profile = UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE;
  const base = {
    profile_id: profile.id,
    depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    evidence_lookup_key_0x24_table_sha256:
      profile.evidence_lookup_key_0x24_table_sha256,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    runtime_image_status:
      unitApplyDamagePacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: unitApplyDamagePacketOutcome?.runtime_image_used ?? false,
    runtime_image_sha256: unitApplyDamagePacketOutcome?.runtime_image_sha256 ?? null,
    damage_packet_count: null, snapshot_count: null, keyframe_count: null,
    canonical_roster_key_count: null, matched_lookup_key_packet_count: null,
    matched_alias_0x100_packet_count: null, matched_equal_packet_count: null,
    matched_other_relation_packet_count: null, unmatched_packet_count: null,
    unmatched_alias_0x100_packet_count: null, first_unmatched_packet_refs: null,
    verified_raw_packet_count: null, input_count: null, event_count: null,
    events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `UnitApplyDamage lookup roster key candidate supports only ${BUILD}`);
  }
  let sourceError;
  try { sourceError = replaySourceError(replay); } catch (error) { sourceError = error.message; }
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!unitApplyDamagePacketOutcome || !minionsKilledSnapshotOutcome) {
    return fail('MISSING_INPUT', 'both exact-build source outcomes are required', {
      missing_inputs: [
        ...(!unitApplyDamagePacketOutcome ? ['unit_apply_damage_packet'] : []),
        ...(!minionsKilledSnapshotOutcome ? ['hero_minions_killed_snapshot'] : []),
      ],
    });
  }
  const damage = unitApplyDamagePacketOutcome;
  const snapshot = minionsKilledSnapshotOutcome;
  if (damage.status !== 'CANDIDATE' || snapshot.status !== 'CANDIDATE') {
    const priority = ['DECODE_FAILED', 'INCONSISTENT', 'UNSUPPORTED',
      'MISSING_INPUT', 'PROFILE_UNAVAILABLE'];
    const decisive = priority.find((status) =>
      damage.status === status || snapshot.status === status) ?? 'INCONSISTENT';
    return fail(decisive, 'one or both exact-build source outcomes are unavailable', {
      dependency_statuses: {
        unit_apply_damage_packet: damage.status ?? null,
        hero_minions_killed_snapshot: snapshot.status ?? null,
      },
    });
  }
  if (damage.profile_id !== DAMAGE_PROFILE.id) {
    return fail('PROFILE_UNAVAILABLE', 'native +0x24 lookup-key association requires the exact 821 v3 damage profile');
  }
  if (!count(damage.event_count, MAX_DAMAGE_ROWS) || damage.event_count === 0
      || !Array.isArray(damage.events)
      || damage.events.length !== damage.event_count
      || damage.native_witness_status !== 'FULLY_CONSUMED_ALL'
      || damage.native_full_success_count !== damage.event_count
      || damage.native_callback_lookup_full_write_count !== damage.event_count
      || damage.runtime_image_status !== 'MATCHED_USED'
      || damage.runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || damage.runtime_image_used !== true
      || damage.evidence_lookup_key_0x24_table_sha256
        !== profile.evidence_lookup_key_0x24_table_sha256
      || damage.evidence_lookup_key_0x2c_table_sha256
        !== DAMAGE_PROFILE.evidence_lookup_key_0x2c_table_sha256) {
    return fail('INCONSISTENT', 'native v3 damage lookup witness is incomplete or differs');
  }
  const pair = validatedRawRosterPairOutcome
    ?? associateUnitApplyDamageRosterKeys821(replay, {
      unitApplyDamagePacketOutcome: damage,
      minionsKilledSnapshotOutcome: snapshot,
    });
  if (pair?.status !== 'CANDIDATE') {
    const status = pair?.status ?? 'INCONSISTENT';
    return fail(status, 'source-bound raw-key roster pair is unavailable', {
      dependency_statuses: { unit_apply_damage_roster_key_pair: pair?.status ?? null },
      dependency_error: pair?.error ?? null,
    });
  }
  if (!checkedPairMetadata(replay, damage, snapshot, pair)) {
    return fail('INCONSISTENT', 'source-bound raw-key pair result identity or counts differ');
  }
  const roster = checkedRoster(replay, snapshot, pair);
  if (!roster) return fail('INCONSISTENT', 'canonical ten-key HeroStats roster differs');

  const events = [];
  const firstUnmatched = { alias_0x100: null, other: null };
  const relationCounts = Object.fromEntries(RELATIONS.map((relation) => [relation, 0]));
  let rawPairIndex = 0;
  let rawUnmatched = 0;
  let rawExcludedAlias = 0;
  let matchedAlias = 0;
  let unmatchedAlias = 0;
  let unmatched = 0;
  const nativeInput = crypto.createHash('sha256');
  const nativeHeader = Buffer.alloc(8);
  for (const [index, row] of damage.events.entries()) {
    const ref = row?.raw_packet_ref;
    const key24 = row?.native_callback_lookup_key_u32_0x24_candidate;
    const key2c = row?.native_callback_lookup_key_u32_0x2c_candidate;
    const relation = expectedRelation(row?.raw_param, key24);
    if (row?.event_type !== 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE'
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== DAMAGE_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256
        || row.replay_time_ms !== ref?.replay_time_ms
        || !u32(row.raw_param) || row.raw_param === 0
        || !sourceRefMatches(replay, ref, 0x005f, row.raw_param)
        || !count(ref.payload_length, 25) || ref.payload_length < 8
        || typeof ref.raw_payload_hex !== 'string'
        || !/^[0-9a-f]+$/.test(ref.raw_payload_hex)
        || ref.raw_payload_hex.length !== ref.payload_length * 2
        || !u32(key24) || key24 === 0 || !u32(key2c) || key2c === 0
        || decodeUnitApplyDamageLookupKeyFromRaw821(
          row.native_callback_lookup_key_0x24_encoded_bytes_hex, 0x24) !== key24
        || decodeUnitApplyDamageLookupKeyFromRaw821(
          row.native_callback_lookup_key_0x2c_encoded_bytes_hex, 0x2c) !== key2c
        || row.native_callback_lookup_key_0x24_raw_param_relation !== relation
        || row.semantic_effect_status !== 'UNKNOWN') {
      return fail('INCONSISTENT', 'native lookup row identity, key, relation, or source reference differs', {
        source: 'unit_apply_damage_packet', event_index: index,
      });
    }
    const payload = Buffer.from(ref.raw_payload_hex, 'hex');
    if (crypto.createHash('sha256').update(payload).digest('hex')
        !== ref.raw_payload_sha256) {
      return fail('INCONSISTENT', 'damage raw payload digest differs', {
        source: 'unit_apply_damage_packet', event_index: index,
      });
    }
    nativeHeader.writeUInt32LE(row.raw_param, 0);
    nativeHeader.writeUInt32LE(payload.length, 4);
    nativeInput.update(nativeHeader);
    nativeInput.update(payload);
    relationCounts[relation] += 1;
    const directRosterRow = roster.get(row.raw_param);
    if (directRosterRow) {
      const directPairEvent = pair.events[rawPairIndex++];
      if (directPairEvent?.raw_param !== row.raw_param
          || directPairEvent.hero_stats_participant_id_candidate
            !== directRosterRow.participant_id_candidate
          || !isDeepStrictEqual(directPairEvent.unit_apply_damage_raw_packet_ref, ref)
          || !isDeepStrictEqual(directPairEvent.hero_stats_roster_raw_packet_ref,
            directRosterRow.raw_packet_ref)) {
        return fail('INCONSISTENT', 'cached raw-key pair differs from source rows', {
          source: 'unit_apply_damage_roster_key_pair', event_index: rawPairIndex - 1,
        });
      }
    } else {
      rawUnmatched += 1;
      if (isAliasRawParam(row.raw_param)) rawExcludedAlias += 1;
    }
    const rosterRow = roster.get(key24);
    if (!rosterRow) {
      unmatched += 1;
      if (isAliasRawParam(row.raw_param)) {
        unmatchedAlias += 1;
        firstUnmatched.alias_0x100 ??= structuredClone(ref);
      } else {
        firstUnmatched.other ??= structuredClone(ref);
      }
      continue;
    }
    if (relation === 'RAW_PARAM_IS_LOOKUP_PLUS_0X100') matchedAlias += 1;
    const damageRef = structuredClone(ref);
    const rosterRef = structuredClone(rosterRow.raw_packet_ref);
    events.push({
      event_type: 'UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: row.replay_time_ms,
      raw_param: row.raw_param,
      native_callback_lookup_key_u32_0x24_candidate: key24,
      native_callback_lookup_key_0x24_encoded_bytes_hex:
        row.native_callback_lookup_key_0x24_encoded_bytes_hex,
      native_callback_lookup_key_0x24_raw_param_relation: relation,
      hero_raw_param: rosterRow.hero_raw_param,
      hero_stats_participant_id_candidate: rosterRow.participant_id_candidate,
      pair_basis: 'NATIVE_CALLBACK_LOOKUP_KEY_0X24_EXACT_FULL_KEY_IN_CANONICAL_HEROSTATS_ROSTER',
      lookup_resolution_status: 'UNKNOWN',
      actor_assignment_status: 'UNKNOWN',
      source_target_role_status: 'UNKNOWN',
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      unit_apply_damage_raw_packet_ref: damageRef,
      hero_stats_roster_raw_packet_ref: rosterRef,
      raw_packet_refs: [damageRef, rosterRef],
    });
  }
  if (rawPairIndex !== pair.event_count
      || rawUnmatched !== pair.unmatched_packet_count
      || rawExcludedAlias !== pair.excluded_alias_0x100_packet_count
      || nativeInput.digest('hex') !== damage.native_input_sha256
      || !damage.native_callback_lookup_key_0x24_raw_param_relation_counts
      || RELATIONS.some((relation) => relationCounts[relation]
        !== damage.native_callback_lookup_key_0x24_raw_param_relation_counts[relation])) {
    return fail('INCONSISTENT', 'raw-key pair or native lookup relation counts differ');
  }
  const matchedEqual = events.filter((row) =>
    row.native_callback_lookup_key_0x24_raw_param_relation === 'EQUAL').length;
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    dependency_statuses: {
      unit_apply_damage_packet: damage.status,
      hero_minions_killed_snapshot: snapshot.status,
      unit_apply_damage_roster_key_pair: pair.status,
    },
    damage_packet_count: damage.event_count,
    snapshot_count: snapshot.event_count,
    keyframe_count: snapshot.keyframe_count,
    canonical_roster_key_count: roster.size,
    matched_lookup_key_packet_count: events.length,
    matched_alias_0x100_packet_count: matchedAlias,
    matched_equal_packet_count: matchedEqual,
    matched_other_relation_packet_count: events.length - matchedEqual - matchedAlias,
    unmatched_packet_count: unmatched,
    unmatched_alias_0x100_packet_count: unmatchedAlias,
    first_unmatched_packet_refs: firstUnmatched,
    verified_raw_packet_count: pair.verified_raw_packet_count,
    input_count: pair.input_count,
    event_count: events.length, events,
  };
}

module.exports = {
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE,
  associateUnitApplyDamageLookupRosterKeys821,
};
