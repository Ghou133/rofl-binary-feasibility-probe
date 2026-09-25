'use strict';

// A full-key co-occurrence with the canonical HeroStats roster is an identity
// candidate only. The 0x005f key is not established as a damage source, target,
// victim, actor, or effective health change.
const crypto = require('node:crypto');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { PROFILES } = require('./rofl_16_19_821_float_stats_candidate');
const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821: DAMAGE_V2_ID,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageLookupKeyFromRaw821,
  isObservedShape,
} = require('./rofl_16_19_821_unit_apply_damage_packet_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const MAX_DAMAGE_ROWS = 100_000;
const MAX_SNAPSHOT_ROWS = 10_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_UNIT_APPLY_DAMAGE_HEROSTATS_FULL_KEY_COOCCURRENCE';
const NATIVE_SOURCES = ['RAW_READER', 'CONSTANT_0', 'CONSTANT_1', 'CONSTANT_2'];
const LOOKUP_RELATIONS = ['EQUAL', 'RAW_PARAM_IS_LOOKUP_PLUS_0X100', 'OTHER'];
const CONSTANTS = { CONSTANT_0: 0, CONSTANT_1: 1, CONSTANT_2: 2 };
const LOOKUP_ROW_FIELDS = [
  'native_callback_lookup_key_u32_0x24_candidate',
  'native_callback_lookup_key_0x24_encoded_bytes_hex',
  'native_callback_lookup_key_u32_0x2c_candidate',
  'native_callback_lookup_key_0x2c_encoded_bytes_hex',
  'native_callback_lookup_key_0x24_raw_param_relation',
];
const LOOKUP_OUTCOME_FIELDS = [
  'native_callback_lookup_full_write_count',
  'native_callback_lookup_key_0x24_raw_param_relation_counts',
  'evidence_lookup_key_0x24_table_sha256',
  'evidence_lookup_key_0x2c_table_sha256',
];

const UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-unit-apply-damage-roster-key-candidate-v1',
  replay_version: BUILD,
  capability: 'unit_apply_damage_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['unit_apply_damage_packet', 'hero_minions_killed_snapshot']),
  packet_ids: Object.freeze([0x005f, 0x0089]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  known_limits: Object.freeze([
    'A full raw-parameter match to the ten-key HeroStats roster is only a co-occurrence; no 0x005f source, target, actor, victim, effective damage, or health change is inferred.',
    'The HeroStats participant candidate comes from the 0x0089 keyframe roster, not from a decoded 0x005f actor field.',
    'The +0x100 aliases and all other nonmatching keys remain excluded and unassigned; low-byte matching is not used.',
    'Both source outcomes, every packet reference, all ten roster keys in every keyframe, and the exact native-witnessed 0x005f profile are required.',
    'Native-gated 0x005f v2 and v3 source outcomes are accepted; v3 lookup keys do not change full raw-parameter roster matching or assign excluded aliases.',
  ]),
});

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function count(value, limit) {
  return Number.isSafeInteger(value) && value >= 0 && value <= limit;
}

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function participantFor(rawParam) {
  return u32(rawParam) && rawParam >= FIRST_PARAM && rawParam <= LAST_PARAM
    ? rawParam - FIRST_PARAM + 1 : null;
}

function validRef(replay, ref, packetId, stream, length) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && count(ref.chunk_index, replay.chunks.length - 1)
    && count(ref.chunk_id, 0xffffffff)
    && ref.chunk_stream === stream
    && count(ref.chunk_file_offset, replay.buffer.length)
    && count(ref.decompressed_block_offset, Number.MAX_SAFE_INTEGER)
    && count(ref.decompressed_payload_offset, Number.MAX_SAFE_INTEGER)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && count(ref.replay_time_ms, Number.MAX_SAFE_INTEGER)
    && ref.payload_length === length && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && count(chunk.uncompressed_length, Number.MAX_SAFE_INTEGER)
    && ref.decompressed_payload_offset + length <= chunk.uncompressed_length;
}

function validSnapshotRow(replay, row) {
  const ref = row?.raw_packet_ref;
  const participant = participantFor(row?.hero_raw_param);
  return row?.event_type === 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === SNAPSHOT_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.hero_raw_param === ref?.raw_param
    && participant !== null && row.participant_id_candidate === participant
    && row.observation_kind === 'KEYFRAME_SNAPSHOT'
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
    && typeof row.raw_payload_field_bytes_hex === 'string'
    && /^[0-9a-f]{8}$/.test(row.raw_payload_field_bytes_hex)
    && Number.isSafeInteger(row.minions_killed_raw_f32_candidate)
    && row.minions_killed_raw_f32_candidate >= 0
    && row.minions_killed_floor_candidate === row.minions_killed_raw_f32_candidate
    && validRef(replay, ref, 0x0089, 'keyframe', 1263);
}

function lookupRelation(rawParam, key24) {
  if (rawParam === key24) return 'EQUAL';
  if (rawParam - key24 === 0x100) return 'RAW_PARAM_IS_LOOKUP_PLUS_0X100';
  return 'OTHER';
}

function validDamageRow(replay, row, damageProfileId) {
  const ref = row?.raw_packet_ref;
  const hex = ref?.raw_payload_hex;
  if (!validRef(replay, ref, 0x005f, 'game_chunk', ref?.payload_length)
      || ref.payload_length < 8 || ref.payload_length > 25
      || typeof hex !== 'string' || !/^[0-9a-f]+$/.test(hex)
      || hex.length !== ref.payload_length * 2
      || sha256(Buffer.from(hex, 'hex')) !== ref.raw_payload_sha256
      || row.event_type !== 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE'
      || row.game_version !== BUILD || row.patch !== '16.19'
      || row.build_profile !== damageProfileId
      || row.replay_sha256 !== replay.source_sha256
      || row.replay_time_ms !== ref.replay_time_ms
      || row.raw_param !== ref.raw_param || row.raw_param === 0
      || row.packet_name_candidate !== DAMAGE_PROFILE.packet_name
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== DAMAGE_PROFILE.evidence_status
      || row.semantic_effect_status !== 'UNKNOWN'
      || !Number.isFinite(row.native_callback_f32_0x20_candidate)) return false;
  const payload = Buffer.from(hex, 'hex');
  const selector24 = payload[3] & 7;
  const selector0 = payload[0] & 7;
  const selector3 = (payload[0] >>> 3) & 7;
  if (row.header_selector_bits_24_26 !== selector24
      || row.header_selector_bits_0_2 !== selector0
      || row.header_selector_bits_3_5 !== selector3
      || !isObservedShape(payload.length, selector24, selector0, selector3)) return false;
  const expectedSource = ({ 3: 'CONSTANT_0', 5: 'CONSTANT_1',
    7: 'CONSTANT_2' })[selector3] ?? 'RAW_READER';
  if (row.native_callback_f32_0x20_source !== expectedSource) return false;
  if (damageProfileId === DAMAGE_V2_ID) {
    if (LOOKUP_ROW_FIELDS.some((field) => field in row)) return false;
  } else {
    const key24 = row.native_callback_lookup_key_u32_0x24_candidate;
    const key2c = row.native_callback_lookup_key_u32_0x2c_candidate;
    if (!u32(key24) || key24 === 0 || !u32(key2c) || key2c === 0
        || decodeUnitApplyDamageLookupKeyFromRaw821(
          row.native_callback_lookup_key_0x24_encoded_bytes_hex, 0x24) !== key24
        || decodeUnitApplyDamageLookupKeyFromRaw821(
          row.native_callback_lookup_key_0x2c_encoded_bytes_hex, 0x2c) !== key2c
        || row.native_callback_lookup_key_0x24_raw_param_relation
          !== lookupRelation(row.raw_param, key24)) return false;
  }
  if (expectedSource !== 'RAW_READER') {
    return row.native_callback_f32_0x20_raw_offset === null
      && row.native_callback_f32_0x20_raw_bytes_hex === null
      && Object.is(row.native_callback_f32_0x20_candidate,
        CONSTANTS[expectedSource]);
  }
  const offset = row.native_callback_f32_0x20_raw_offset;
  return count(offset, payload.length - 4)
    && row.native_callback_f32_0x20_raw_bytes_hex
      === payload.subarray(offset, offset + 4).toString('hex')
    && Object.is(row.native_callback_f32_0x20_candidate,
      decodeUnitApplyDamageCallbackF32FromRaw821(
        row.native_callback_f32_0x20_raw_bytes_hex));
}

class SourceMismatch extends Error {}

function verifyPhysicalRefs(replay, damageRows, snapshotRows) {
  const expected = new Map();
  const nativeInput = crypto.createHash('sha256');
  const nativeHeader = Buffer.alloc(8);
  let damageIndex = 0;
  let snapshotIndex = 0;
  for (const [route, rows] of [['damage', damageRows], ['snapshot', snapshotRows]]) {
    for (const row of rows) {
      const ref = row.raw_packet_ref;
      const at = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
      if (expected.has(at)) return { error: `duplicate source packet reference at ${at}` };
      expected.set(at, { route, row, ref });
    }
  }
  try {
    const walked = walkBlocks(replay, (block, chunk) => {
      const required = block.packet_id === 0x005f
        || (chunk.stream === 'keyframe' && block.packet_id === 0x0089);
      if (!required) return;
      const at = `${chunk.index}/${block.offset}`;
      const selected = expected.get(at);
      if (!selected) throw new SourceMismatch(`source outcome omits route packet at ${at}`);
      const { route, row, ref } = selected;
      if (route === 'damage' ? row !== damageRows[damageIndex++]
        : row !== snapshotRows[snapshotIndex++]) {
        throw new SourceMismatch(`source packet order differs at ${at}`);
      }
      if (block.packet_id !== ref.packet_id
          || block.timestamp_ms !== ref.replay_time_ms
          || (block.param >>> 0) !== ref.raw_param
          || block.payload_offset !== ref.decompressed_payload_offset
          || block.payload_length !== ref.payload_length
          || sha256(block.payload) !== ref.raw_payload_sha256
          || (route === 'damage'
            ? block.payload.toString('hex') !== ref.raw_payload_hex
            : block.payload.subarray(0, 3).toString('hex')
              !== SNAPSHOT_PROFILE.payload_prefix_hex
              || Buffer.from(SNAPSHOT_PROFILE.raw_payload_byte_offsets.map((offset) =>
                block.payload[offset])).toString('hex')
                !== row.raw_payload_field_bytes_hex)) {
        throw new SourceMismatch(`source packet reference or raw field differs at ${at}`);
      }
      if (route === 'damage') {
        nativeHeader.writeUInt32LE(block.param >>> 0, 0);
        nativeHeader.writeUInt32LE(block.payload.length, 4);
        nativeInput.update(nativeHeader);
        nativeInput.update(block.payload);
      }
      expected.delete(at);
    }, { strict: true });
    if (walked.errors.length) return { error: 'Replay framing errors', scan_error: true };
  } catch (error) {
    return { error: error.message, scan_error: !(error instanceof SourceMismatch) };
  }
  if (expected.size) {
    return { error: `source packet reference absent at ${expected.keys().next().value}` };
  }
  if (damageIndex !== damageRows.length || snapshotIndex !== snapshotRows.length) {
    return { error: 'source packet route counts differ' };
  }
  return { verified_count: damageRows.length + snapshotRows.length,
    native_input_sha256: nativeInput.digest('hex') };
}

function associateUnitApplyDamageRosterKeys821(replay, {
  unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome,
} = {}) {
  const profile = UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE;
  const base = {
    profile_id: profile.id,
    depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    runtime_image_status: unitApplyDamagePacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: unitApplyDamagePacketOutcome?.runtime_image_used ?? false,
    runtime_image_sha256: unitApplyDamagePacketOutcome?.runtime_image_sha256 ?? null,
    damage_packet_count: null, snapshot_count: null, keyframe_count: null,
    canonical_roster_key_count: null, matched_full_key_packet_count: null,
    unmatched_packet_count: null, excluded_alias_0x100_packet_count: null,
    first_excluded_packet_refs: null, verified_raw_packet_count: null,
    input_count: null, event_count: null, events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `UnitApplyDamage roster key candidate supports only ${BUILD}`);
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
  const damageIsV2 = damage.profile_id === DAMAGE_V2_ID;
  const damageIsV3 = damage.profile_id === DAMAGE_PROFILE.id;
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
  if ((!damageIsV2 && !damageIsV3)
      || damage.evidence_status !== DAMAGE_PROFILE.evidence_status
      || damage.evidence_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || damage.evidence_scalar_table_sha256
        !== DAMAGE_PROFILE.evidence_scalar_table_sha256
      || damage.evidence_shape_catalog_sha256
        !== DAMAGE_PROFILE.evidence_shape_catalog_sha256
      || damage.runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || damage.runtime_image_status !== 'MATCHED_USED'
      || damage.runtime_image_used !== true
      || damage.input_packet_id !== 0x005f
      || !count(damage.input_count, MAX_DAMAGE_ROWS) || damage.input_count === 0
      || damage.event_count !== damage.input_count
      || !Array.isArray(damage.events) || damage.events.length !== damage.event_count
      || damage.native_witness_status !== 'FULLY_CONSUMED_ALL'
      || damage.native_full_success_count !== damage.event_count
      || damage.native_callback_f32_available_count !== damage.event_count
      || !sha(damage.native_input_sha256)
      || !damage.native_callback_f32_source_counts
      || Object.keys(damage.native_callback_f32_source_counts).sort().join(',')
        !== [...NATIVE_SOURCES].sort().join(',')
      || NATIVE_SOURCES.some((source) =>
        !count(damage.native_callback_f32_source_counts[source], MAX_DAMAGE_ROWS))
      || NATIVE_SOURCES.reduce((sum, source) =>
        sum + damage.native_callback_f32_source_counts[source], 0) !== damage.event_count
      || (damageIsV2 && LOOKUP_OUTCOME_FIELDS.some((field) => field in damage))
      || (damageIsV3 && (
        damage.evidence_lookup_key_0x24_table_sha256
          !== DAMAGE_PROFILE.evidence_lookup_key_0x24_table_sha256
        || damage.evidence_lookup_key_0x2c_table_sha256
          !== DAMAGE_PROFILE.evidence_lookup_key_0x2c_table_sha256
        || damage.native_callback_lookup_full_write_count !== damage.event_count
        || !damage.native_callback_lookup_key_0x24_raw_param_relation_counts
        || Object.keys(damage.native_callback_lookup_key_0x24_raw_param_relation_counts)
          .sort().join(',') !== [...LOOKUP_RELATIONS].sort().join(',')
        || LOOKUP_RELATIONS.some((relation) =>
          !count(damage.native_callback_lookup_key_0x24_raw_param_relation_counts[
            relation], MAX_DAMAGE_ROWS))
        || LOOKUP_RELATIONS.reduce((sum, relation) => sum
          + damage.native_callback_lookup_key_0x24_raw_param_relation_counts[
            relation], 0) !== damage.event_count))
      || snapshot.profile_id !== SNAPSHOT_PROFILE.id
      || snapshot.evidence_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || snapshot.lookup_table_sha256 !== LOOKUP_TABLE_SHA256
      || snapshot.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
      || snapshot.runtime_image_used !== false
      || snapshot.input_packet_id !== 0x0089
      || !count(snapshot.input_count, MAX_SNAPSHOT_ROWS)
      || !count(snapshot.event_count, MAX_SNAPSHOT_ROWS)
      || !count(snapshot.keyframe_count, MAX_SNAPSHOT_ROWS)
      || snapshot.keyframe_count === 0
      || snapshot.input_count !== snapshot.event_count
      || snapshot.event_count !== snapshot.keyframe_count * 10
      || snapshot.observed_participant_count !== 10
      || !Array.isArray(snapshot.events)
      || snapshot.events.length !== snapshot.event_count) {
    return fail('INCONSISTENT', 'exact-build source outcome profile, native witness, image, or counts differ');
  }
  const frames = new Map();
  for (const [index, row] of snapshot.events.entries()) {
    if (!validSnapshotRow(replay, row)) {
      return fail('INCONSISTENT', 'HeroStats roster row identity or source reference differs', {
        source: 'hero_minions_killed_snapshot', event_index: index,
      });
    }
    const ref = row.raw_packet_ref;
    const frame = frames.get(ref.chunk_index) ?? {
      time_ms: ref.replay_time_ms, participants: new Map(),
    };
    if (frame.time_ms !== ref.replay_time_ms
        || frame.participants.has(row.hero_raw_param)) {
      return fail('INCONSISTENT', 'HeroStats keyframe roster time or full key is ambiguous', {
        event_index: index, chunk_index: ref.chunk_index,
      });
    }
    frame.participants.set(row.hero_raw_param, row);
    frames.set(ref.chunk_index, frame);
  }
  const replayKeyframes = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (replayKeyframes.length !== snapshot.keyframe_count
      || frames.size !== snapshot.keyframe_count
      || replayKeyframes.some((chunk) => !frames.has(chunk.index))
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'Replay keyframe does not have a complete ten-key HeroStats roster');
  }
  const firstFrame = frames.get(replayKeyframes[0].index);
  const roster = new Map(firstFrame.participants);
  for (const frame of frames.values()) {
    if ([...roster.keys()].some((key) => !frame.participants.has(key))) {
      return fail('INCONSISTENT', 'canonical HeroStats full-key roster changes across keyframes');
    }
  }
  const sourceCounts = Object.fromEntries(NATIVE_SOURCES.map((source) => [source, 0]));
  const lookupRelationCounts = Object.fromEntries(
    LOOKUP_RELATIONS.map((relation) => [relation, 0]));
  const events = [];
  let aliasCount = 0;
  let unmatchedCount = 0;
  const firstExcluded = { alias_0x100: null, unmatched_other: null };
  for (const [index, row] of damage.events.entries()) {
    if (!validDamageRow(replay, row, damage.profile_id)) {
      return fail('INCONSISTENT', 'UnitApplyDamage row identity, native float, or source reference differs', {
        source: 'unit_apply_damage_packet', event_index: index,
      });
    }
    sourceCounts[row.native_callback_f32_0x20_source] += 1;
    if (damageIsV3) {
      lookupRelationCounts[row.native_callback_lookup_key_0x24_raw_param_relation] += 1;
    }
    const rosterRow = roster.get(row.raw_param);
    if (!rosterRow) {
      unmatchedCount += 1;
      if (row.raw_param >= FIRST_PARAM + 0x100
          && row.raw_param <= LAST_PARAM + 0x100) {
        aliasCount += 1;
        firstExcluded.alias_0x100 ??= structuredClone(row.raw_packet_ref);
      } else {
        firstExcluded.unmatched_other ??= structuredClone(row.raw_packet_ref);
      }
      continue;
    }
    const damageRef = structuredClone(row.raw_packet_ref);
    const rosterRef = structuredClone(rosterRow.raw_packet_ref);
    events.push({
      event_type: 'UNIT_APPLY_DAMAGE_ROSTER_KEY_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: row.replay_time_ms,
      raw_param: row.raw_param,
      hero_stats_participant_id_candidate: rosterRow.participant_id_candidate,
      native_callback_f32_0x20_candidate: row.native_callback_f32_0x20_candidate,
      native_callback_f32_0x20_source: row.native_callback_f32_0x20_source,
      pair_basis: 'EXACT_FULL_RAW_PARAM_IN_CANONICAL_HEROSTATS_ROSTER',
      actor_assignment_status: 'UNKNOWN',
      source_target_role_status: 'UNKNOWN',
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      unit_apply_damage_raw_packet_ref: damageRef,
      hero_stats_roster_raw_packet_ref: rosterRef,
      raw_packet_refs: [damageRef, rosterRef],
    });
  }
  if (NATIVE_SOURCES.some((source) =>
    sourceCounts[source] !== damage.native_callback_f32_source_counts[source])) {
    return fail('INCONSISTENT', 'UnitApplyDamage native float source counts differ');
  }
  if (damageIsV3 && LOOKUP_RELATIONS.some((relation) =>
    lookupRelationCounts[relation]
      !== damage.native_callback_lookup_key_0x24_raw_param_relation_counts[relation])) {
    return fail('INCONSISTENT', 'UnitApplyDamage native lookup relation counts differ');
  }
  const physical = verifyPhysicalRefs(replay, damage.events, snapshot.events);
  if (physical.error) {
    return fail(physical.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', physical.error);
  }
  if (physical.native_input_sha256 !== damage.native_input_sha256) {
    return fail('INCONSISTENT', 'native witness input digest differs from Replay packets');
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    dependency_statuses: {
      unit_apply_damage_packet: damage.status,
      hero_minions_killed_snapshot: snapshot.status,
    },
    damage_packet_count: damage.event_count,
    snapshot_count: snapshot.event_count,
    keyframe_count: snapshot.keyframe_count,
    canonical_roster_key_count: roster.size,
    matched_full_key_packet_count: events.length,
    unmatched_packet_count: unmatchedCount,
    excluded_alias_0x100_packet_count: aliasCount,
    first_excluded_packet_refs: firstExcluded,
    verified_raw_packet_count: physical.verified_count,
    input_count: physical.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE,
  associateUnitApplyDamageRosterKeys821,
};
