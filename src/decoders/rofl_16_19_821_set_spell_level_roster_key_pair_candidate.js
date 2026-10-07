'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const {
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821: PACKET_PROFILE,
  decodeSetSpellLevelU32At10FromRaw821,
  decodeSetSpellLevelU32At14FromRaw821,
} = require('./rofl_16_19_821_set_spell_level_packet_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('./rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const FIRST_HERO_PARAM = 0x400000ae;
const EVIDENCE_STATUS = 'CANDIDATE_821_SET_SPELL_LEVEL_HEADER_ROSTER_KEY_COOCCURRENCE';
const ASSOCIATION_STATUS = 'CANDIDATE_FULL_U32_HEADER_ROSTER_KEY_EQUALITY';
const MAX_PACKET_ROWS = 10_000;

const SET_SPELL_LEVEL_ROSTER_KEY_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-set-spell-level-roster-key-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'set_spell_level_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['set_spell_level_packet', 'hero_roster_metadata_bridge']),
  packet_ids: Object.freeze([0x025d, 0x0089]),
  evidence_runtime_image_sha256: PACKET_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: 283 of 342 native V2 SetSpellLevel packet headers equal a canonical ten-key HeroStats roster key; 59 nonroster nonzero headers are excluded',
  known_limits: Object.freeze([
    'Only full-u32 equality between the 0x025d packet header and a canonical HeroStats roster key is paired; nonroster headers remain in the complete source packet stream and exclusion counts.',
    'The roster-to-Replay-metadata join is a candidate; champion, team and role are direct metadata labels, not independently confirmed packet identity.',
    'The native V2 callback uses a synthetic receiver table. Packet actor, owner, live receiver, spell identity, effective level change and gameplay effect remain UNKNOWN.',
    'A 0x025d packet is not joined to a 0x0197 level observation by this capability.',
  ]),
});

const sha = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const nonnegative = (value) => Number.isSafeInteger(value) && value >= 0;
const u32 = (value) => nonnegative(value) && value <= 0xffffffff;

function validRef(replay, ref, packetId, stream, lengths) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && nonnegative(ref.replay_time_ms)
    && lengths.includes(ref.payload_length) && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function validRosterRow(replay, row, index, metadataSha, statsSha) {
  const key = FIRST_HERO_PARAM + index;
  const ref = row?.raw_packet_ref;
  return row?.event_type === 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === ROSTER_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.hero_raw_param === key
    && row.participant_id_candidate === index + 1
    && row.metadata_index_candidate === index
    && typeof row.champion_metadata === 'string' && row.champion_metadata.trim()
    && row.team_id_metadata === (index < 5 ? 100 : 200)
    && row.team_metadata === (index < 5 ? 'blue' : 'red')
    && ['top', 'jungle', 'mid', 'adc', 'support'].includes(row.role_metadata)
    && row.metadata_sha256 === metadataSha && row.stats_json_sha256 === statsSha
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === ROSTER_PROFILE.evidence_status
    && row.roster_to_metadata_status === ROSTER_PROFILE.evidence_status
    && row.per_packet_actor_status === 'UNKNOWN'
    && validRef(replay, ref, 0x0089, 'keyframe', [1263])
    && ref.raw_param === key;
}

function validPacketRow(replay, row) {
  const ref = row?.raw_packet_ref;
  const at10 = row?.raw_object_u32_0x10_hex;
  const at14 = row?.raw_object_u32_0x14_hex;
  return row?.event_type === 'SET_SPELL_LEVEL_PACKET_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === PACKET_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.raw_param === ref?.raw_param && row.raw_param !== 0
    && typeof at10 === 'string' && /^[0-9a-f]{8}$/.test(at10)
    && typeof at14 === 'string' && /^[0-9a-f]{8}$/.test(at14)
    && u32(row.opaque_u32_0x10) && u32(row.opaque_u32_0x14)
    && row.opaque_u32_0x10 === decodeSetSpellLevelU32At10FromRaw821(at10)
    && row.opaque_u32_0x14 === decodeSetSpellLevelU32At14FromRaw821(at14)
    && row.opaque_u32_0x14 <= 0x7fffffff
    && row.native_receiver_slot_candidate === (row.opaque_u32_0x10 <= 63
      ? row.opaque_u32_0x10 : 0)
    && row.native_receiver_selection_source === (row.opaque_u32_0x10 <= 63
      ? 'INDEXED' : 'FALLBACK_0')
    && row.native_clamped_scalar_candidate === Math.min(row.opaque_u32_0x14, 6)
    && row.native_positive_flag_written === (row.native_clamped_scalar_candidate > 0)
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'
    && validRef(replay, ref, 0x025d, 'game_chunk', [1, 2, 3]);
}

function associateSetSpellLevelRosterKeyPair821(replay, {
  setSpellLevelPacketOutcome, heroRosterMetadataBridgeOutcome,
} = {}) {
  const profile = SET_SPELL_LEVEL_ROSTER_KEY_PAIR_821_PROFILE;
  const dependencyStatuses = {
    set_spell_level_packet: setSpellLevelPacketOutcome?.status ?? 'UNEXECUTED',
    hero_roster_metadata_bridge: heroRosterMetadataBridgeOutcome?.status ?? 'UNEXECUTED',
  };
  const base = {
    profile_id: profile.id,
    input_packet_id: 0x025d,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: dependencyStatuses,
    runtime_image_status: setSpellLevelPacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: setSpellLevelPacketOutcome?.runtime_image_used ?? false,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `set_spell_level_roster_key_pair requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  for (const [name, status] of Object.entries(dependencyStatuses)) {
    if (status !== 'CANDIDATE') {
      return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
        `set_spell_level_roster_key_pair requires ${name}: ${status}`);
    }
  }
  const packet = setSpellLevelPacketOutcome;
  const roster = heroRosterMetadataBridgeOutcome;
  if (packet.profile_id !== PACKET_PROFILE.id
      || packet.evidence_status !== 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'
      || packet.input_packet_id !== 0x025d
      || !nonnegative(packet.input_count) || packet.input_count > MAX_PACKET_ROWS
      || packet.event_count !== packet.input_count
      || !Array.isArray(packet.events) || packet.events.length !== packet.input_count
      || packet.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || JSON.stringify(packet.evidence_callback_table_sha256)
        !== JSON.stringify(PACKET_PROFILE.evidence_callback_table_sha256)
      || packet.evidence_callback_rva !== PACKET_PROFILE.evidence_callback_rva
      || packet.evidence_receiver_write_rva !== PACKET_PROFILE.evidence_receiver_write_rva
      || packet.evidence_callback_witness_mode !== PACKET_PROFILE.evidence_callback_witness_mode
      || packet.evidence_callback_region_sha256 !== PACKET_PROFILE.evidence_callback_region_sha256
      || packet.evidence_receiver_write_region_sha256 !== PACKET_PROFILE.evidence_receiver_write_region_sha256
      || !nonnegative(packet.scanned_block_count)
      || packet.scanned_block_count < packet.input_count
      || packet.runtime_image_status !== 'MATCHED_USED'
      || packet.runtime_image_used !== true
      || packet.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || roster.profile_id !== ROSTER_PROFILE.id
      || roster.evidence_status !== ROSTER_PROFILE.evidence_status
      || roster.input_packet_id !== 0x0089
      || roster.event_count !== 10 || roster.unique_kda_match_count !== 10
      || roster.metadata_player_count !== 10
      || !Array.isArray(roster.events) || roster.events.length !== 10
      || !sha(roster.metadata_sha256) || !sha(roster.stats_json_sha256)) {
    return fail('DECODE_FAILED', 'Incomplete exact-build V2 SetSpellLevel or roster dependency outcome');
  }
  const rosterByKey = new Map();
  for (let index = 0; index < 10; index += 1) {
    const row = roster.events[index];
    if (!validRosterRow(replay, row, index,
      roster.metadata_sha256, roster.stats_json_sha256)) {
      return fail('DECODE_FAILED', `Malformed 0x0089 roster row ${index}`);
    }
    rosterByKey.set(row.hero_raw_param, row);
  }
  const events = [];
  let zeroHeaderCount = 0;
  let nonrosterHeaderCount = 0;
  let plus100AliasExcludedCount = 0;
  let lowByteAliasExcludedCount = 0;
  for (const [index, row] of packet.events.entries()) {
    if (!validPacketRow(replay, row)) {
      return fail('DECODE_FAILED', `Malformed native 0x025d packet row ${index}`, {
        input_count: packet.input_count,
        first_failed_packet_ref: row?.raw_packet_ref ?? null,
      });
    }
    if (row.raw_param === 0) {
      zeroHeaderCount += 1;
      continue;
    }
    const matched = rosterByKey.get(row.raw_param);
    if (!matched) {
      nonrosterHeaderCount += 1;
      if (rosterByKey.has(row.raw_param - 0x100)) plus100AliasExcludedCount += 1;
      if ([...rosterByKey.keys()].some((key) => (key & 255) === (row.raw_param & 255))) {
        lowByteAliasExcludedCount += 1;
      }
      continue;
    }
    events.push({
      event_type: 'SET_SPELL_LEVEL_ROSTER_KEY_PAIR_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: row.replay_time_ms,
      raw_param: row.raw_param,
      hero_raw_param: matched.hero_raw_param,
      participant_id_candidate: matched.participant_id_candidate,
      metadata_index_candidate: matched.metadata_index_candidate,
      champion_metadata: matched.champion_metadata,
      team_id_metadata: matched.team_id_metadata,
      team_metadata: matched.team_metadata,
      role_metadata: matched.role_metadata,
      metadata_sha256: matched.metadata_sha256,
      stats_json_sha256: matched.stats_json_sha256,
      opaque_u32_0x10: row.opaque_u32_0x10,
      opaque_u32_0x14: row.opaque_u32_0x14,
      raw_object_u32_0x10_hex: row.raw_object_u32_0x10_hex,
      raw_object_u32_0x14_hex: row.raw_object_u32_0x14_hex,
      native_receiver_slot_candidate: row.native_receiver_slot_candidate,
      native_receiver_selection_source: row.native_receiver_selection_source,
      native_clamped_scalar_candidate: row.native_clamped_scalar_candidate,
      native_positive_flag_written: row.native_positive_flag_written,
      association_status: ASSOCIATION_STATUS,
      roster_to_metadata_status: matched.roster_to_metadata_status,
      packet_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
      live_receiver_status: 'UNKNOWN', spell_identity_status: 'UNKNOWN',
      actual_level_change_status: 'UNKNOWN', semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        raw_param: 'VERIFIED_DIRECT', hero_raw_param: ASSOCIATION_STATUS,
        participant_id_candidate: ASSOCIATION_STATUS,
        champion_metadata: 'VERIFIED_FROM_METADATA',
        team_metadata: 'VERIFIED_FROM_METADATA',
        role_metadata: 'VERIFIED_FROM_METADATA',
        native_receiver_slot_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
        native_clamped_scalar_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
        packet_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
        actual_level_change_status: 'UNKNOWN',
      },
      raw_packet_ref: row.raw_packet_ref,
      roster_keyframe_packet_ref: matched.raw_packet_ref,
      known_limits: [...profile.known_limits],
    });
  }
  return {
    ...base, status: 'CANDIDATE', input_count: packet.input_count,
    event_count: events.length,
    matched_roster_header_count: events.length,
    zero_header_count: zeroHeaderCount,
    nonroster_nonzero_header_count: nonrosterHeaderCount,
    plus_0x100_alias_excluded_count: plus100AliasExcludedCount,
    low_byte_alias_excluded_count: lowByteAliasExcludedCount,
    runtime_image_sha256: packet.runtime_image_sha256,
    packet_profile_id: packet.profile_id,
    metadata_sha256: roster.metadata_sha256,
    stats_json_sha256: roster.stats_json_sha256,
    events,
  };
}

module.exports = {
  SET_SPELL_LEVEL_ROSTER_KEY_PAIR_821_PROFILE,
  associateSetSpellLevelRosterKeyPair821,
};
