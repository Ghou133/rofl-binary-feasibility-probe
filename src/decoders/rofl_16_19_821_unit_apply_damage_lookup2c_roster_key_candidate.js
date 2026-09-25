'use strict';

// The native callback's +0x2c full key can be compared with the canonical
// HeroStats roster. A match is a co-key candidate, not a damage role or effect.
const { isDeepStrictEqual } = require('node:util');
const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE,
} = require('./rofl_16_19_821_unit_apply_damage_packet_candidate');
const {
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: RAW_PAIR_PROFILE,
  associateUnitApplyDamageRosterKeys821,
} = require('./rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const {
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE: KEY24_PAIR_PROFILE,
  associateUnitApplyDamageLookupRosterKeys821,
} = require('./rofl_16_19_821_unit_apply_damage_lookup_roster_key_candidate');
const { RUNTIME_IMAGE_SHA256 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const LAST_KEY = 0x400000b7;
const EVIDENCE_STATUS =
  'CANDIDATE_821_UNIT_APPLY_DAMAGE_NATIVE_LOOKUP2C_KEY_HEROSTATS_FULL_KEY_COOCCURRENCE';
const KEY24_ROSTER_RELATIONS = Object.freeze([
  'SAME_ROSTER_KEY', 'DIFFERENT_ROSTER_KEY', 'KEY24_NOT_IN_ROSTER',
]);

const UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-unit-apply-damage-lookup2c-roster-key-candidate-v1',
  replay_version: BUILD,
  capability: 'unit_apply_damage_lookup2c_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze([
    'unit_apply_damage_packet', 'hero_minions_killed_snapshot',
    'unit_apply_damage_roster_key_pair', 'unit_apply_damage_lookup_roster_key_pair',
  ]),
  packet_ids: Object.freeze([0x005f, 0x0089]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_lookup_key_0x24_table_sha256:
    DAMAGE_PROFILE.evidence_lookup_key_0x24_table_sha256,
  evidence_lookup_key_0x2c_table_sha256:
    DAMAGE_PROFILE.evidence_lookup_key_0x2c_table_sha256,
  known_limits: Object.freeze([
    'The +0x2c native callback value is a candidate lookup key; a full-key HeroStats roster match does not prove a successful object lookup or runtime type conversion.',
    'The HeroStats participant candidate comes only from the ten-key 0x0089 roster. Damage actor, source, target, victim, actual amount, and health effect remain UNKNOWN.',
    'The +0x24 key and its raw-parameter relation are retained as separate candidates; equal or different roster keys do not establish damage roles.',
    'The referenced HeroStats packet is roster evidence from the first keyframe, not a contemporaneous damage observation.',
    'The complete native-witnessed v3 damage outcome, complete same-Replay roster, and physically source-bound raw-key pair are required.',
  ]),
});

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function associateUnitApplyDamageLookup2cRosterKeys821(replay, {
  unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome,
  validatedRawRosterPairOutcome, validatedLookup24RosterPairOutcome,
} = {}) {
  const profile = UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_821_PROFILE;
  const damage = unitApplyDamagePacketOutcome;
  const snapshot = minionsKilledSnapshotOutcome;
  const base = {
    profile_id: profile.id,
    depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    evidence_lookup_key_0x24_table_sha256:
      profile.evidence_lookup_key_0x24_table_sha256,
    evidence_lookup_key_0x2c_table_sha256:
      profile.evidence_lookup_key_0x2c_table_sha256,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    runtime_image_status: damage?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: damage?.runtime_image_used ?? false,
    runtime_image_sha256: damage?.runtime_image_sha256 ?? null,
    damage_packet_count: null, snapshot_count: null, keyframe_count: null,
    canonical_roster_key_count: null, matched_lookup_key_packet_count: null,
    unmatched_packet_count: null, matched_key24_roster_counts: null,
    first_unmatched_packet_refs: null,
    verified_raw_packet_count: null, input_count: null, event_count: null,
    events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `UnitApplyDamage +0x2c roster candidate supports only ${BUILD}`);
  }
  if (!sha(replay?.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!damage || !snapshot) {
    return fail('MISSING_INPUT', 'both exact-build source outcomes are required', {
      missing_inputs: [
        ...(!damage ? ['unit_apply_damage_packet'] : []),
        ...(!snapshot ? ['hero_minions_killed_snapshot'] : []),
      ],
    });
  }
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
    return fail('PROFILE_UNAVAILABLE', 'native +0x2c roster association requires the exact 821 v3 damage profile');
  }

  // Recheck all 0x005f/0x0089 references against the physical Replay even
  // when the caller supplies a cached pair. A cached result alone cannot
  // attest the physical source bytes.
  const rawPair = associateUnitApplyDamageRosterKeys821(replay, {
    unitApplyDamagePacketOutcome: damage,
    minionsKilledSnapshotOutcome: snapshot,
  });
  if (rawPair.status !== 'CANDIDATE') {
    return fail(rawPair.status, 'source-bound raw-key roster pair is unavailable', {
      dependency_statuses: { unit_apply_damage_roster_key_pair: rawPair.status },
      dependency_error: rawPair.error ?? null,
    });
  }
  if (rawPair.profile_id !== RAW_PAIR_PROFILE.id) {
    return fail('INCONSISTENT', 'source-bound raw-key roster profile differs');
  }
  if (validatedRawRosterPairOutcome
      && !isDeepStrictEqual(rawPair, validatedRawRosterPairOutcome)) {
    return fail('INCONSISTENT', 'cached raw-key roster pair differs from the physical Replay');
  }
  const key24Pair = associateUnitApplyDamageLookupRosterKeys821(replay, {
    unitApplyDamagePacketOutcome: damage,
    minionsKilledSnapshotOutcome: snapshot,
    validatedRawRosterPairOutcome: rawPair,
  });
  if (key24Pair.status !== 'CANDIDATE') {
    return fail(key24Pair.status, 'native lookup keys or canonical roster are unavailable', {
      dependency_statuses: { unit_apply_damage_lookup_roster_key_pair: key24Pair.status },
      dependency_error: key24Pair.error ?? null,
    });
  }
  if (key24Pair.profile_id !== KEY24_PAIR_PROFILE.id) {
    return fail('INCONSISTENT', 'native +0x24 roster profile differs');
  }
  if (validatedLookup24RosterPairOutcome
      && !isDeepStrictEqual(key24Pair, validatedLookup24RosterPairOutcome)) {
    return fail('INCONSISTENT', 'cached +0x24 roster pair differs from revalidated exact-build inputs');
  }
  if (key24Pair.replay_sha256 !== replay.source_sha256
      || key24Pair.damage_packet_count !== damage.event_count
      || key24Pair.snapshot_count !== snapshot.event_count
      || key24Pair.verified_raw_packet_count
        !== damage.event_count + snapshot.event_count) {
    return fail('INCONSISTENT', 'native +0x24 roster proof identity or counts differ');
  }

  const firstFrame = replay.chunks.find((chunk) => chunk.stream === 'keyframe');
  const roster = new Map(snapshot.events
    .filter((row) => row.raw_packet_ref.chunk_index === firstFrame?.index)
    .map((row) => [row.hero_raw_param, row]));
  if (roster.size !== 10 || key24Pair.canonical_roster_key_count !== 10
      || Array.from({ length: 10 }, (_, index) => FIRST_KEY + index)
        .some((key) => !roster.has(key))
      || [...roster.keys()].some((key) => key < FIRST_KEY || key > LAST_KEY)) {
    return fail('INCONSISTENT', 'canonical first-keyframe roster differs');
  }

  const events = [];
  const matchedKey24Counts = Object.fromEntries(
    KEY24_ROSTER_RELATIONS.map((relation) => [relation, 0]));
  const firstUnmatched = { key24_in_roster: null, key24_not_in_roster: null };
  for (const row of damage.events) {
    const key24 = row.native_callback_lookup_key_u32_0x24_candidate;
    const key2c = row.native_callback_lookup_key_u32_0x2c_candidate;
    const rosterRow = roster.get(key2c);
    if (!rosterRow) {
      const category = roster.has(key24)
        ? 'key24_in_roster' : 'key24_not_in_roster';
      firstUnmatched[category] ??= structuredClone(row.raw_packet_ref);
      continue;
    }
    const relation = key24 === key2c ? 'SAME_ROSTER_KEY'
      : roster.has(key24) ? 'DIFFERENT_ROSTER_KEY' : 'KEY24_NOT_IN_ROSTER';
    matchedKey24Counts[relation] += 1;
    const damageRef = structuredClone(row.raw_packet_ref);
    const rosterRef = structuredClone(rosterRow.raw_packet_ref);
    events.push({
      event_type: 'UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: row.replay_time_ms,
      raw_param: row.raw_param,
      native_callback_lookup_key_u32_0x24_candidate: key24,
      native_callback_lookup_key_0x24_encoded_bytes_hex:
        row.native_callback_lookup_key_0x24_encoded_bytes_hex,
      native_callback_lookup_key_u32_0x2c_candidate: key2c,
      native_callback_lookup_key_0x2c_encoded_bytes_hex:
        row.native_callback_lookup_key_0x2c_encoded_bytes_hex,
      native_callback_lookup_key_0x24_raw_param_relation:
        row.native_callback_lookup_key_0x24_raw_param_relation,
      key24_roster_relation: relation,
      hero_raw_param: rosterRow.hero_raw_param,
      hero_stats_participant_id_candidate: rosterRow.participant_id_candidate,
      pair_basis: 'NATIVE_CALLBACK_LOOKUP_KEY_0X2C_EXACT_FULL_KEY_IN_CANONICAL_HEROSTATS_ROSTER',
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
  if (KEY24_ROSTER_RELATIONS.reduce((sum, relation) =>
    sum + matchedKey24Counts[relation], 0) !== events.length) {
    return fail('INCONSISTENT', 'matched +0x24 roster relation counts differ');
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    dependency_statuses: {
      unit_apply_damage_packet: damage.status,
      hero_minions_killed_snapshot: snapshot.status,
      unit_apply_damage_roster_key_pair: rawPair.status,
      unit_apply_damage_lookup_roster_key_pair: key24Pair.status,
    },
    damage_packet_count: damage.event_count,
    snapshot_count: snapshot.event_count,
    keyframe_count: snapshot.keyframe_count,
    canonical_roster_key_count: roster.size,
    matched_lookup_key_packet_count: events.length,
    unmatched_packet_count: damage.event_count - events.length,
    matched_key24_roster_counts: matchedKey24Counts,
    first_unmatched_packet_refs: firstUnmatched,
    verified_raw_packet_count: rawPair.verified_raw_packet_count,
    input_count: rawPair.input_count,
    event_count: events.length, events,
  };
}

module.exports = {
  UNIT_APPLY_DAMAGE_LOOKUP2C_ROSTER_KEY_821_PROFILE,
  associateUnitApplyDamageLookup2cRosterKeys821,
};
