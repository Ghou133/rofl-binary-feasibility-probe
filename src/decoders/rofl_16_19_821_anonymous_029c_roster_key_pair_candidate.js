'use strict';

const crypto = require('node:crypto');
const { replaySourceError } = require('./replay_source_integrity');
const {
  ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821: PACKET_PROFILE,
  decodeProtectedAnonymous029cU32,
  isObservedAnonymous029cPayload,
} = require('./rofl_16_19_821_anonymous_029c_packet_candidate');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE,
} = require('./rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const FIRST_HERO_PARAM = 0x400000ae;
const EVIDENCE_STATUS = 'CANDIDATE_821_ANONYMOUS_029C_HEADER_ROSTER_KEY_COOCCURRENCE';
const ASSOCIATION_STATUS = 'CANDIDATE_FULL_U32_HEADER_ROSTER_KEY_EQUALITY';
const MAX_PACKET_ROWS = 50_000;

const ANONYMOUS_029C_ROSTER_KEY_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-anonymous-029c-roster-key-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'anonymous_029c_roster_key_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['anonymous_029c_packet', 'hero_roster_metadata_bridge']),
  packet_ids: Object.freeze([0x029c, 0x0089]),
  evidence_runtime_image_sha256: PACKET_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required: true,
  evidence_scope: '11 exact-build KR Replays: 25391/457095 anonymous 0x029c packet headers have a full u32 equal to one of ten canonical HeroStats roster keys; 414057 zero and 17647 nonroster headers are excluded',
  known_limits: Object.freeze([
    'Only the 0x029c packet header full u32 is compared to the ten canonical HeroStats roster keys; zero and nonroster headers are excluded.',
    'The native decoded object +0x14 u32 is independent of the header and is never used as a roster or participant key here.',
    'The roster to Replay metadata join is a candidate; champion, team and role labels are direct metadata, not independently confirmed packet identity.',
    'Packet class, actor, target, object role, receiver state, behavior and effect remain UNKNOWN.',
  ]),
});

const isSha = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const nonnegative = (value) => Number.isSafeInteger(value) && value >= 0;
const isU32 = (value) => nonnegative(value) && value <= 0xffffffff;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function validRef(replay, ref, packetId, stream, length) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && nonnegative(ref.replay_time_ms)
    && ref.payload_length === length && isU32(ref.raw_param)
    && isSha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + length <= chunk.uncompressed_length;
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
    && typeof row.champion_metadata === 'string'
    && row.champion_metadata.trim().length > 0
    && row.team_id_metadata === (index < 5 ? 100 : 200)
    && row.team_metadata === (index < 5 ? 'blue' : 'red')
    && ['top', 'jungle', 'mid', 'adc', 'support'].includes(row.role_metadata)
    && row.metadata_sha256 === metadataSha && row.stats_json_sha256 === statsSha
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === ROSTER_PROFILE.evidence_status
    && row.roster_to_metadata_status === ROSTER_PROFILE.evidence_status
    && row.per_packet_actor_status === 'UNKNOWN'
    && validRef(replay, ref, 0x0089, 'keyframe', 1263)
    && ref.raw_param === key;
}

function validPacketRow(replay, row) {
  const ref = row?.raw_packet_ref;
  const hex = ref?.raw_payload_hex;
  const protectedHex = row?.native_protected_u32_hex;
  if (typeof hex !== 'string' || !/^[0-9a-f]+$/.test(hex)
      || hex.length !== ref?.payload_length * 2
      || !isObservedAnonymous029cPayload(Buffer.from(hex, 'hex'))
      || sha256(Buffer.from(hex, 'hex')) !== ref.raw_payload_sha256) return false;
  const value = decodeProtectedAnonymous029cU32(protectedHex);
  return row.event_type === 'ANONYMOUS_029C_PACKET_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === PACKET_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref.replay_time_ms
    && row.raw_param === ref.raw_param
    && row.native_protected_selector_byte_hex === '3e'
    && row.native_selector_u8 === 0
    && isU32(value) && value === row.anonymous_u32_candidate
    && row.anonymous_u32_is_sentinel === (value === 0xffffffff)
    && ((ref.payload_length === 1 && value === 0xffffffff)
      || (ref.payload_length !== 1 && value >>> 24 === 0x40))
    && ['actor_status', 'target_status', 'object_role_status',
      'receiver_state_status', 'behavior_status', 'effect_status']
      .every((field) => row[field] === 'UNKNOWN')
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === PACKET_PROFILE.evidence_status
    && validRef(replay, ref, 0x029c, 'game_chunk', ref.payload_length);
}

function associateAnonymous029cRosterKeyPair821(replay, {
  anonymous029cPacketOutcome, heroRosterMetadataBridgeOutcome,
} = {}) {
  const profile = ANONYMOUS_029C_ROSTER_KEY_PAIR_821_PROFILE;
  const dependencyStatuses = {
    anonymous_029c_packet: anonymous029cPacketOutcome?.status ?? 'UNEXECUTED',
    hero_roster_metadata_bridge: heroRosterMetadataBridgeOutcome?.status ?? 'UNEXECUTED',
  };
  const base = {
    profile_id: profile.id, input_packet_id: 0x029c,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: dependencyStatuses,
    runtime_image_status: anonymous029cPacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: anonymous029cPacketOutcome?.runtime_image_used ?? false,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `anonymous_029c_roster_key_pair requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  for (const [name, status] of Object.entries(dependencyStatuses)) {
    if (status !== 'CANDIDATE') {
      return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
        `anonymous_029c_roster_key_pair requires ${name}: ${status}`);
    }
  }
  const packet = anonymous029cPacketOutcome;
  const roster = heroRosterMetadataBridgeOutcome;
  if (packet.profile_id !== PACKET_PROFILE.id
      || packet.evidence_status !== PACKET_PROFILE.evidence_status
      || packet.input_packet_id !== 0x029c
      || !nonnegative(packet.input_count) || packet.input_count > MAX_PACKET_ROWS
      || packet.event_count !== packet.input_count
      || !Array.isArray(packet.events) || packet.events.length !== packet.input_count
      || packet.native_witness_status !== 'FULLY_CONSUMED_ALL'
      || packet.native_full_success_count !== packet.input_count
      || packet.runtime_image_status !== 'MATCHED_USED'
      || packet.runtime_image_used !== true
      || packet.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || !isSha(packet.native_input_sha256) || !isSha(packet.native_output_sha256)
      || roster.profile_id !== ROSTER_PROFILE.id
      || roster.evidence_status !== ROSTER_PROFILE.evidence_status
      || roster.input_packet_id !== 0x0089
      || roster.event_count !== 10 || roster.unique_kda_match_count !== 10
      || roster.metadata_player_count !== 10
      || !Array.isArray(roster.events) || roster.events.length !== 10
      || !isSha(roster.metadata_sha256) || !isSha(roster.stats_json_sha256)) {
    return fail('DECODE_FAILED', 'Incomplete exact-build 0x029c or roster dependency outcome');
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
  const inputHash = crypto.createHash('sha256');
  const outputHash = crypto.createHash('sha256');
  const inputHeader = Buffer.alloc(8);
  const decodedValue = Buffer.alloc(4);
  let zeroHeaderCount = 0;
  let nonrosterHeaderCount = 0;
  let plus100AliasExcludedCount = 0;
  let lowByteAliasExcludedCount = 0;
  let sentinelCount = 0;
  let nonzeroHeaderSentinelCount = 0;
  for (const [index, row] of packet.events.entries()) {
    if (!validPacketRow(replay, row)) {
      return fail('DECODE_FAILED', `Malformed 0x029c packet row ${index}`, {
        input_count: packet.input_count,
        first_failed_packet_ref: row?.raw_packet_ref ?? null,
      });
    }
    const payload = Buffer.from(row.raw_packet_ref.raw_payload_hex, 'hex');
    inputHeader.writeUInt32LE(row.raw_param, 0);
    inputHeader.writeUInt32LE(payload.length, 4);
    inputHash.update(inputHeader).update(payload);
    decodedValue.writeUInt32LE(row.anonymous_u32_candidate, 0);
    outputHash.update(Buffer.from(row.native_protected_selector_byte_hex, 'hex'))
      .update(Buffer.from(row.native_protected_u32_hex, 'hex'))
      .update(decodedValue);
    if (row.anonymous_u32_is_sentinel) {
      sentinelCount += 1;
      if (row.raw_param !== 0) nonzeroHeaderSentinelCount += 1;
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
      event_type: 'ANONYMOUS_029C_ROSTER_KEY_PAIR_CANDIDATE',
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
      anonymous_u32_candidate: row.anonymous_u32_candidate,
      anonymous_u32_is_sentinel: row.anonymous_u32_is_sentinel,
      association_status: ASSOCIATION_STATUS,
      roster_to_metadata_status: matched.roster_to_metadata_status,
      actor_status: 'UNKNOWN', target_status: 'UNKNOWN',
      object_role_status: 'UNKNOWN', receiver_state_status: 'UNKNOWN',
      behavior_status: 'UNKNOWN', effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        raw_param: 'VERIFIED_DIRECT',
        hero_raw_param: ASSOCIATION_STATUS,
        participant_id_candidate: ASSOCIATION_STATUS,
        champion_metadata: 'VERIFIED_FROM_METADATA',
        team_metadata: 'VERIFIED_FROM_METADATA',
        role_metadata: 'VERIFIED_FROM_METADATA',
        anonymous_u32_candidate: 'CANDIDATE_EXACT_RUNTIME_NATIVE_OBJECT_INDEPENDENT',
        actor_status: 'UNKNOWN', target_status: 'UNKNOWN', object_role_status: 'UNKNOWN',
      },
      raw_packet_ref: row.raw_packet_ref,
      roster_keyframe_packet_ref: matched.raw_packet_ref,
      known_limits: [...profile.known_limits],
    });
  }
  if (inputHash.digest('hex') !== packet.native_input_sha256
      || outputHash.digest('hex') !== packet.native_output_sha256) {
    return fail('DECODE_FAILED', '0x029c ordered native source digest differs', {
      input_count: packet.input_count,
    });
  }
  return {
    ...base, status: 'CANDIDATE', input_count: packet.input_count,
    event_count: events.length,
    zero_header_count: zeroHeaderCount,
    nonroster_nonzero_header_count: nonrosterHeaderCount,
    matched_full_u32_header_count: events.length,
    plus_0x100_alias_excluded_count: plus100AliasExcludedCount,
    low_byte_alias_excluded_count: lowByteAliasExcludedCount,
    anonymous_u32_sentinel_count: sentinelCount,
    nonzero_header_sentinel_count: nonzeroHeaderSentinelCount,
    native_witness_status: packet.native_witness_status,
    native_full_success_count: packet.native_full_success_count,
    runtime_image_sha256: packet.runtime_image_sha256,
    anonymous_029c_native_input_sha256: packet.native_input_sha256,
    anonymous_029c_native_output_sha256: packet.native_output_sha256,
    metadata_sha256: roster.metadata_sha256,
    stats_json_sha256: roster.stats_json_sha256,
    events,
  };
}

module.exports = {
  ANONYMOUS_029C_ROSTER_KEY_PAIR_821_PROFILE,
  associateAnonymous029cRosterKeyPair821,
};
