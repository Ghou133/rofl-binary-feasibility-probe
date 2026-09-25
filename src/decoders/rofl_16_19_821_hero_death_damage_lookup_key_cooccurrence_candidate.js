'use strict';

// A same-chunk, same-millisecond native lookup-key occurrence beside a death
// route is an observation only. Neither key is a confirmed damage role.
const { isDeepStrictEqual } = require('node:util');
const { parseReplayBuffer } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const {
  HERO_DEATH_CANDIDATE_PROFILE_821: DEATH_PROFILE,
  decodeHeroDeathCandidates821,
} = require('./rofl_16_19_821_7343');
const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821: DAMAGE_V3_ID,
} = require('./rofl_16_19_821_unit_apply_damage_packet_candidate');
const {
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: RAW_PAIR_PROFILE,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821: RAW_PAIR_PROFILE_V1,
  associateUnitApplyDamageRosterKeys821,
} = require('./rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { PROFILES } = require('./rofl_16_19_821_float_stats_candidate');
const { RUNTIME_IMAGE_SHA256 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const FIRST_ROSTER_KEY = 0x400000ae;
const EVIDENCE_STATUS = 'CANDIDATE_821_HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;

const HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-death-damage-lookup-key-cooccurrence-candidate-v1',
  replay_version: BUILD,
  capability: 'hero_death_damage_lookup_key_cooccurrence',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze([
    'hero_death', 'unit_apply_damage_packet', 'hero_minions_killed_snapshot',
    'unit_apply_damage_roster_key_pair',
  ]),
  packet_ids: Object.freeze([0x0259, 0x0438, 0x031b, 0x03d4, 0x005f, 0x0089]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_lookup_key_0x24_table_sha256:
    DAMAGE_PROFILE.evidence_lookup_key_0x24_table_sha256,
  evidence_lookup_key_0x2c_table_sha256:
    DAMAGE_PROFILE.evidence_lookup_key_0x2c_table_sha256,
  known_limits: Object.freeze([
    'The output preserves every exact same-chunk, same-millisecond 0x005f packet with a +0x24 key equal to the death candidate victim roster key, including zero or multiple packets per death anchor.',
    'A +0x2c key equal to the decoded death die-source u32 is only an additional numeric co-occurrence; it does not select a fatal packet or establish a damage actor, source, target, or effect.',
    'The victim participant is a Replay-tail candidate and the roster key is from the first exact-build HeroStats keyframe; lookup resolution remains UNKNOWN.',
    'The death route is freshly decoded and the complete native-witnessed v3 damage and HeroStats sources are physically checked against the same Replay.',
    'A death die-source that cannot be decoded remains unavailable, never a numeric zero or a failed equality claim.',
  ]),
});

const HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE = Object.freeze({
  ...HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821,
  id: 'rofl-16.19.821.7343-kr-hero-death-damage-lookup-key-cooccurrence-candidate-v2',
  known_limits: Object.freeze([
    ...HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821.known_limits.slice(0, 3),
    'The death route is freshly decoded and the complete native-witnessed v4 damage and HeroStats sources are physically checked against the same Replay.',
    ...HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821.known_limits.slice(4),
  ]),
});

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function anchorKey(chunkIndex, timeMs, lookupKey) {
  return `${chunkIndex}/${timeMs}/${lookupKey}`;
}

function associateHeroDeathDamageLookupKeyCooccurrence821(replay, {
  heroDeathOutcome, unitApplyDamagePacketOutcome,
  minionsKilledSnapshotOutcome, validatedRawRosterPairOutcome,
  precollected = null,
} = {}) {
  const profile = unitApplyDamagePacketOutcome?.profile_id === DAMAGE_V3_ID
    ? HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821
    : HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE;
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
    runtime_image_status: unitApplyDamagePacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: unitApplyDamagePacketOutcome?.runtime_image_used ?? false,
    runtime_image_sha256: unitApplyDamagePacketOutcome?.runtime_image_sha256 ?? null,
    death_anchor_count: null, damage_packet_count: null,
    snapshot_count: null, canonical_roster_key_count: null,
    verified_raw_damage_roster_packet_count: null,
    verified_hero_death_route_packet_count: null,
    matched_victim_key24_packet_count: null,
    death_anchor_with_victim_key24_packet_count: null,
    death_anchor_without_victim_key24_packet_count: null,
    multiple_victim_key24_packet_anchor_count: null,
    max_victim_key24_packet_count_per_anchor: null,
    matched_die_source_key2c_packet_count: null,
    death_anchor_with_die_source_key2c_match_count: null,
    death_anchor_without_die_source_key2c_match_count: null,
    death_anchor_die_source_unavailable_count: null,
    input_count: null, event_count: null, events: null,
    error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `death/damage lookup-key co-occurrence supports only ${BUILD}`);
  }
  let sourceError;
  try { sourceError = replaySourceError(replay); } catch (error) { sourceError = error.message; }
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  // The death decoder uses Replay-tail counts. Keep that caller-writable
  // metadata bound to the bytes, in addition to its normal packet checks.
  try {
    const parsed = parseReplayBuffer(replay.buffer, replay.source_path);
    if (parsed.source_sha256 !== replay.source_sha256
        || !isDeepStrictEqual(parsed.tail, replay.tail)) {
      return fail('INCONSISTENT', 'Replay tail differs from physical source bytes');
    }
  } catch (error) {
    return fail('DECODE_FAILED', `Replay tail source check failed: ${error.message}`);
  }
  const supplied = {
    hero_death: heroDeathOutcome,
    unit_apply_damage_packet: unitApplyDamagePacketOutcome,
    hero_minions_killed_snapshot: minionsKilledSnapshotOutcome,
  };
  const missing = Object.entries(supplied).filter(([, outcome]) => !outcome)
    .map(([capability]) => capability);
  if (missing.length) {
    return fail('MISSING_INPUT', 'all three exact-build source outcomes are required',
      { missing_inputs: missing });
  }
  const unavailable = Object.entries(supplied).filter(([, outcome]) =>
    outcome.status !== 'CANDIDATE');
  if (unavailable.length) {
    const priority = ['DECODE_FAILED', 'INCONSISTENT', 'UNSUPPORTED',
      'MISSING_INPUT', 'PROFILE_UNAVAILABLE'];
    const status = priority.find((candidate) =>
      unavailable.some(([, outcome]) => outcome.status === candidate)) ?? 'INCONSISTENT';
    return fail(status, 'one or more source candidates are unavailable', {
      dependency_statuses: Object.fromEntries(Object.entries(supplied)
        .map(([capability, outcome]) => [capability, outcome.status ?? null])),
    });
  }
  const death = heroDeathOutcome;
  const damage = unitApplyDamagePacketOutcome;
  const snapshot = minionsKilledSnapshotOutcome;
  if (death.profile_id !== DEATH_PROFILE.id
      || (damage.profile_id !== DAMAGE_PROFILE.id
        && damage.profile_id !== DAMAGE_V3_ID)
      || snapshot.profile_id !== SNAPSHOT_PROFILE.id) {
    return fail('PROFILE_UNAVAILABLE', 'one or more exact 821 source profiles differ');
  }
  const physicalDeath = decodeHeroDeathCandidates821(replay, precollected);
  if (physicalDeath.status !== 'CANDIDATE') {
    return fail(physicalDeath.status, 'fresh death route decode is unavailable', {
      dependency_statuses: { hero_death: physicalDeath.status },
      dependency_error: physicalDeath.error ?? null,
    });
  }
  if (!isDeepStrictEqual(physicalDeath, death)) {
    return fail('INCONSISTENT', 'supplied death candidate differs from physical Replay re-decode');
  }
  const rawPair = associateUnitApplyDamageRosterKeys821(replay, {
    unitApplyDamagePacketOutcome: damage,
    minionsKilledSnapshotOutcome: snapshot,
    precollected,
  });
  if (rawPair.status !== 'CANDIDATE') {
    return fail(rawPair.status, 'physically source-bound damage/roster pair is unavailable', {
      dependency_statuses: { unit_apply_damage_roster_key_pair: rawPair.status },
      dependency_error: rawPair.error ?? null,
    });
  }
  const expectedRawPair = damage.profile_id === DAMAGE_PROFILE.id
    ? RAW_PAIR_PROFILE : RAW_PAIR_PROFILE_V1;
  if (rawPair.profile_id !== expectedRawPair.id
      || rawPair.damage_packet_count !== damage.event_count
      || rawPair.snapshot_count !== snapshot.event_count
      || rawPair.verified_raw_packet_count !== damage.event_count + snapshot.event_count) {
    return fail('INCONSISTENT', 'physically source-bound damage/roster identity or counts differ');
  }
  if (validatedRawRosterPairOutcome
      && !isDeepStrictEqual(rawPair, validatedRawRosterPairOutcome)) {
    return fail('INCONSISTENT', 'cached damage/roster pair differs from physical Replay proof');
  }
  const firstFrame = replay.chunks.find((chunk) => chunk.stream === 'keyframe');
  const roster = new Map(snapshot.events
    .filter((row) => row.raw_packet_ref.chunk_index === firstFrame?.index)
    .map((row) => [row.hero_raw_param, row]));
  if (!firstFrame || roster.size !== 10 || rawPair.canonical_roster_key_count !== 10
      || Array.from({ length: 10 }, (_, index) => FIRST_ROSTER_KEY + index)
        .some((key) => roster.get(key)?.participant_id_candidate
          !== key - FIRST_ROSTER_KEY + 1)) {
    return fail('INCONSISTENT', 'first HeroStats keyframe canonical victim roster differs');
  }
  if (!Number.isSafeInteger(death.event_count) || death.event_count <= 0
      || !Array.isArray(death.events) || death.events.length !== death.event_count
      || !Number.isSafeInteger(damage.event_count) || damage.event_count <= 0
      || !Array.isArray(damage.events) || damage.events.length !== damage.event_count) {
    return fail('INCONSISTENT', 'source candidate event arrays or counts differ');
  }

  const damageAtKey = new Map();
  for (const row of damage.events) {
    const ref = row.raw_packet_ref;
    const key = anchorKey(ref.chunk_index, row.replay_time_ms,
      row.native_callback_lookup_key_u32_0x24_candidate);
    const rows = damageAtKey.get(key) ?? [];
    rows.push(row);
    damageAtKey.set(key, rows);
  }
  const events = [];
  let matchedVictimPackets = 0;
  let withVictimPackets = 0;
  let multipleVictimPackets = 0;
  let maxVictimPackets = 0;
  let matchedDieSourcePackets = 0;
  let withDieSourcePackets = 0;
  let withoutDieSourcePackets = 0;
  let dieSourceUnavailable = 0;
  for (const [index, deathRow] of death.events.entries()) {
    const primary = deathRow.raw_packet_ref;
    const participantId = deathRow.victim_participant_id;
    const victimKey = FIRST_ROSTER_KEY + participantId - 1;
    const rosterRow = roster.get(victimKey);
    const dieSource = deathRow.die_source_network_id_candidate;
    if (!Number.isSafeInteger(participantId) || participantId < 1 || participantId > 10
        || !rosterRow || !primary || primary.packet_id !== 0x0259
        || primary.chunk_stream !== 'game_chunk'
        || primary.replay_time_ms !== deathRow.replay_time_ms
        || (dieSource !== null && !u32(dieSource))) {
      return fail('INCONSISTENT', 'death candidate victim, source, or primary reference differs',
        { source: 'hero_death', event_index: index });
    }
    const rows = damageAtKey.get(anchorKey(primary.chunk_index,
      deathRow.replay_time_ms, victimKey)) ?? [];
    const packetCandidates = [];
    let before = 0;
    let after = 0;
    let joint = 0;
    for (const row of rows) {
      const ref = row.raw_packet_ref;
      const relative = ref.decompressed_block_offset < primary.decompressed_block_offset
        ? 'BEFORE_PRIMARY' : 'AFTER_PRIMARY';
      if (ref.decompressed_block_offset === primary.decompressed_block_offset) {
        return fail('INCONSISTENT', 'death primary and damage packet share a source offset',
          { source: 'unit_apply_damage_packet', event_index: index });
      }
      if (relative === 'BEFORE_PRIMARY') before += 1;
      else after += 1;
      const dieSourceEqual = dieSource === null ? null
        : row.native_callback_lookup_key_u32_0x2c_candidate === dieSource;
      if (dieSourceEqual) joint += 1;
      packetCandidates.push({
        raw_param: row.raw_param,
        native_callback_lookup_key_u32_0x24_candidate:
          row.native_callback_lookup_key_u32_0x24_candidate,
        native_callback_lookup_key_0x24_encoded_bytes_hex:
          row.native_callback_lookup_key_0x24_encoded_bytes_hex,
        native_callback_lookup_key_u32_0x2c_candidate:
          row.native_callback_lookup_key_u32_0x2c_candidate,
        native_callback_lookup_key_0x2c_encoded_bytes_hex:
          row.native_callback_lookup_key_0x2c_encoded_bytes_hex,
        native_callback_lookup_key_0x24_raw_param_relation:
          row.native_callback_lookup_key_0x24_raw_param_relation,
        die_source_key2c_equal: dieSourceEqual,
        relative_to_death_primary: relative,
        unit_apply_damage_raw_packet_ref: structuredClone(ref),
      });
    }
    matchedVictimPackets += rows.length;
    if (rows.length) withVictimPackets += 1;
    if (rows.length > 1) multipleVictimPackets += 1;
    maxVictimPackets = Math.max(maxVictimPackets, rows.length);
    matchedDieSourcePackets += joint;
    if (dieSource === null) dieSourceUnavailable += 1;
    else if (joint) withDieSourcePackets += 1;
    else withoutDieSourcePackets += 1;
    const deathRefs = structuredClone(deathRow.raw_packet_refs);
    const rosterRef = structuredClone(rosterRow.raw_packet_ref);
    events.push({
      event_type: 'HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: deathRow.replay_time_ms,
      victim_participant_id_candidate: participantId,
      victim_raw_param: deathRow.victim_raw_param,
      victim_lookup_roster_key_u32_candidate: victimKey,
      die_source_network_id_candidate: dieSource,
      same_time_victim_key24_packet_candidate_count: rows.length,
      same_time_victim_key24_packet_before_primary_count: before,
      same_time_victim_key24_packet_after_primary_count: after,
      same_time_die_source_key2c_packet_candidate_count:
        dieSource === null ? null : joint,
      die_source_key2c_match_status: dieSource === null ? 'DIE_SOURCE_UNAVAILABLE'
        : joint ? 'HAS_SAME_TIME_MATCH' : 'NO_SAME_TIME_MATCH',
      same_time_victim_key24_packet_candidates: packetCandidates,
      pair_basis: 'SAME_CHUNK_SAME_MILLISECOND_EXACT_CANONICAL_VICTIM_KEY24',
      lookup_resolution_status: 'UNKNOWN',
      actor_assignment_status: 'UNKNOWN',
      source_target_role_status: 'UNKNOWN',
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      hero_death_raw_packet_ref: structuredClone(primary),
      hero_death_die_source_raw_packet_ref:
        structuredClone(deathRow.die_source_raw_packet_ref),
      hero_death_raw_packet_refs: deathRefs,
      hero_stats_roster_raw_packet_ref: rosterRef,
      raw_packet_refs: [
        ...structuredClone(deathRefs), structuredClone(rosterRef),
        ...packetCandidates.map((row) =>
          structuredClone(row.unit_apply_damage_raw_packet_ref)),
      ],
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    dependency_statuses: {
      hero_death: death.status,
      unit_apply_damage_packet: damage.status,
      hero_minions_killed_snapshot: snapshot.status,
      unit_apply_damage_roster_key_pair: rawPair.status,
    },
    death_anchor_count: death.event_count,
    damage_packet_count: damage.event_count,
    snapshot_count: snapshot.event_count,
    canonical_roster_key_count: roster.size,
    verified_raw_damage_roster_packet_count: rawPair.verified_raw_packet_count,
    verified_hero_death_route_packet_count: death.matched_core_supporting_packet_count,
    matched_victim_key24_packet_count: matchedVictimPackets,
    death_anchor_with_victim_key24_packet_count: withVictimPackets,
    death_anchor_without_victim_key24_packet_count: death.event_count - withVictimPackets,
    multiple_victim_key24_packet_anchor_count: multipleVictimPackets,
    max_victim_key24_packet_count_per_anchor: maxVictimPackets,
    matched_die_source_key2c_packet_count: matchedDieSourcePackets,
    death_anchor_with_die_source_key2c_match_count: withDieSourcePackets,
    death_anchor_without_die_source_key2c_match_count: withoutDieSourcePackets,
    death_anchor_die_source_unavailable_count: dieSourceUnavailable,
    input_count: death.event_count + damage.event_count,
    event_count: events.length, events,
  };
}

module.exports = {
  HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE,
  HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821,
  associateHeroDeathDamageLookupKeyCooccurrence821,
};
