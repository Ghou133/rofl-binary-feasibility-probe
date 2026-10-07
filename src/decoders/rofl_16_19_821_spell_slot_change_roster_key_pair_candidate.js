'use strict';

const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { normalizePlayers, parseMetadataTail } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { collect821Routes, rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { SPELL_SLOT_CHANGE_REQUEST_821_PROFILE: REQUEST_PROFILE, callbackRequestError } =
  require('./rofl_16_19_821_anonymous_049c_packet_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: ROSTER_PROFILE } =
  require('./rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const EVIDENCE = 'CANDIDATE_821_SLOT_CHANGE_HEADER_ROSTER_KEY_EQUALITY';
const SPELL_SLOT_CHANGE_ROSTER_KEY_PAIR_821_PROFILE = Object.freeze({
  id:'rofl-16.19.821.7343-kr-slot-change-roster-key-pair-candidate-v1',
  replay_version:BUILD, capability:'spell_slot_change_roster_key_pair',
  status:'CANDIDATE', enabled:true, evidence_status:EVIDENCE,
  depends_on:Object.freeze(['spell_slot_change_request','hero_roster_metadata_bridge']),
  packet_ids:Object.freeze([0x049c,0x028e,0x0375,0x0089]),
  evidence_runtime_image_sha256:REQUEST_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required:true,
  known_limits:Object.freeze([
    'Only complete same-Replay full-u32 header/roster key equality is associated; low-byte and +0x100 aliases are rejected.',
    'Champion/team/role are Replay metadata facts. The K/D/A roster mapping and this header-key association remain candidates, not independent packet-actor or receiver confirmation.',
    'A named request is not an applied spell, cast or observed state. Keyframe requests remain keyframe observations; internal slot indices have no Q/W/E/R mapping.',
    'Nonroster requests remain in the complete spell_slot_change_request dependency stream. No NPC, owner or recipient identity is assigned to them.',
    'This calculator consumes fresh native request and roster outcomes; it is not a saved-result query or native authenticity verifier.',
  ]),
});

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const isHash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const nonnegative = value => Number.isSafeInteger(value) && value >= 0;
function validCallbackRequest(row) {
  try { return callbackRequestError(row) === null; }
  catch { return false; }
}

function geometricRef(replay, ref) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null) && ref.replay_sha256 === replay.source_sha256
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === ref.chunk_stream && chunk.offset === ref.chunk_file_offset
    && nonnegative(ref.decompressed_block_offset) && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && nonnegative(ref.payload_length) && nonnegative(ref.replay_time_ms)
    && ref.decompressed_payload_offset+ref.payload_length <= chunk.uncompressed_length
    && isHash(ref.raw_payload_sha256);
}

function matchesPhysicalPacket(replay, row, source) {
  const {block,chunk} = source;
  const ref = row?.raw_packet_ref;
  return geometricRef(replay,ref) && row.raw_param === (block.param>>>0)
    && ref.raw_param === row.raw_param && row.native_packet_id === block.packet_id
    && ref.packet_id === block.packet_id && ref.replay_time_ms === block.timestamp_ms
    && row.replay_time_ms === block.timestamp_ms && row.stream_tag === chunk.stream_tag
    && ref.chunk_index === chunk.index && ref.chunk_id === chunk.chunk_id
    && ref.decompressed_block_offset === block.offset && ref.decompressed_payload_offset === block.payload_offset
    && ref.payload_length === block.payload.length && ref.raw_payload_sha256 === hash(block.payload);
}

function associateSpellSlotChangeRosterKeys821(replay, {
  spellSlotChangeRequestOutcome:request, heroRosterMetadataBridgeOutcome:roster, precollected,
} = {}) {
  const profile = SPELL_SLOT_CHANGE_ROSTER_KEY_PAIR_821_PROFILE;
  const base = {profile_id:profile.id, evidence_status:EVIDENCE,
    input_packet_ids:[0x049c,0x028e,0x0375], dependency_statuses:{
      spell_slot_change_request:request?.status??'UNEXECUTED',
      hero_roster_metadata_bridge:roster?.status??'UNEXECUTED'},
    evidence_runtime_image_sha256:profile.evidence_runtime_image_sha256,
    runtime_image_used:request?.runtime_image_used??false,
    runtime_image_status:request?.runtime_image_status??'NOT_CHECKED',
    known_limits:[...profile.known_limits]};
  const fail = (status,error) => ({...base,status,error,input_count:null,event_count:null,events:null});
  if (replay?.header?.version !== BUILD) return fail('UNSUPPORTED',`requires exact ${BUILD}`);
  const error = replaySourceError(replay);
  if (error) return fail('DECODE_FAILED',error);
  for (const [name,status] of Object.entries(base.dependency_statuses)) {
    if (status !== 'CANDIDATE') return fail(status==='UNEXECUTED'?'MISSING_INPUT':status,`requires ${name}: ${status}`);
  }
  if (request.profile_id !== REQUEST_PROFILE.id || request.evidence_status !== REQUEST_PROFILE.evidence_status
      || !nonnegative(request.input_count) || request.input_count > 30_000
      || request.event_count !== request.input_count || request.native_full_success_count !== request.input_count
      || !Array.isArray(request.events) || request.events.length !== request.input_count
      || request.runtime_image_used !== true || request.runtime_image_status !== 'MATCHED_USED'
      || request.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || roster.profile_id !== ROSTER_PROFILE.id || roster.evidence_status !== ROSTER_PROFILE.evidence_status
      || roster.unique_kda_match_count !== 10 || roster.metadata_player_count !== 10
      || roster.event_count !== 10 || !Array.isArray(roster.events) || roster.events.length !== 10) {
    return fail('DECODE_FAILED','complete exact-build native request and ten-key roster outcomes required');
  }
  let physical;
  let sourceRows;
  try {
    physical = parseMetadataTail(replay.buffer,replay.header.size);
    const selected = rowsFor821Capability(replay,precollected??collect821Routes(replay,['spell_slot_change_request']),
      'spell_slot_change_request');
    if (selected.error || selected.observed_packet_count_minimum) throw new Error(selected.error??'source exceeds scope');
    sourceRows = selected.rows;
  } catch (failure) { return fail('DECODE_FAILED',failure.message); }
  if (!isDeepStrictEqual(physical.metadata,replay.tail.metadata) || !isDeepStrictEqual(physical.stats,replay.tail.stats)
      || sourceRows.length !== request.input_count
      || roster.metadata_sha256 !== hash(JSON.stringify(physical.metadata))
      || roster.stats_json_sha256 !== hash(physical.metadata.statsJson)) {
    return fail('DECODE_FAILED','request source count or physical metadata differs');
  }
  const players = normalizePlayers(replay);
  if (players.length !== 10) return fail('MISSING_INPUT','complete ten-player metadata required');
  const byKey = new Map();
  for (const [index,row] of roster.events.entries()) {
    const player = players[index];
    const ref = row?.raw_packet_ref;
    if (row?.event_type !== 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE' || row.game_version !== BUILD
        || row.build_profile !== ROSTER_PROFILE.id || row.replay_sha256 !== replay.source_sha256
        || row.hero_raw_param !== FIRST_KEY+index || row.participant_id_candidate !== index+1
        || row.metadata_index_candidate !== index || row.champion_metadata !== player.champion
        || row.team_id_metadata !== player.team_id || row.team_metadata !== player.team
        || row.role_metadata !== player.role || !['top','jungle','mid','adc','support'].includes(row.role_metadata)
        || row.metadata_sha256 !== roster.metadata_sha256 || row.stats_json_sha256 !== roster.stats_json_sha256
        || row.roster_to_metadata_status !== ROSTER_PROFILE.evidence_status || row.per_packet_actor_status !== 'UNKNOWN'
        || !geometricRef(replay,ref) || ref.packet_id !== 0x0089 || ref.payload_length !== 1263
        || ref.chunk_stream !== 'keyframe' || ref.raw_param !== row.hero_raw_param
        || row.replay_time_ms !== ref.replay_time_ms) return fail('DECODE_FAILED',`invalid source roster row ${index}`);
    byKey.set(row.hero_raw_param,row);
  }
  const events = [];
  let unmatched = 0, plus100 = 0, lowByte = 0;
  for (const [index,row] of request.events.entries()) {
    if (row?.event_type !== 'SPELL_SLOT_CHANGE_REQUEST_CANDIDATE' || row.game_version !== BUILD
        || row.build_profile !== REQUEST_PROFILE.id || row.replay_sha256 !== replay.source_sha256
        || row.confidence !== 'CANDIDATE' || row.semantic_status !== REQUEST_PROFILE.evidence_status
        || row.deserialize_return_al !== 1 || row.bytes_consumed !== sourceRows[index].block.payload.length
        || row.callback_request_candidate?.status !== 'CANDIDATE_STATIC_RECEIVE_DATAFLOW'
        || row.semantic_effect_status !== 'UNKNOWN' || !validCallbackRequest(row)
        || !matchesPhysicalPacket(replay,row,sourceRows[index])) {
      return fail('DECODE_FAILED',`invalid native/source request row ${index}`);
    }
    const matched = byKey.get(row.raw_param);
    if (!matched) {
      unmatched++;
      if (byKey.has(row.raw_param-0x100)) plus100++;
      if ([...byKey.keys()].some(key => (key&255)===(row.raw_param&255))) lowByte++;
      continue;
    }
    events.push(spellSlotChangeRosterKeyPairRow821(row, matched));
  }
  return {...base,status:'CANDIDATE',input_count:request.input_count,event_count:events.length,events,
    matched_header_count:events.length,nonroster_header_count:unmatched,
    plus_0x100_alias_excluded_count:plus100,low_byte_alias_excluded_count:lowByte,
    runtime_image_sha256:request.runtime_image_sha256};
}

// Shared output constructor; callers validate complete request and roster sources.
function spellSlotChangeRosterKeyPairRow821(row, matched) {
  return {event_type:'SPELL_SLOT_CHANGE_ROSTER_KEY_PAIR_CANDIDATE',
      game_version:BUILD,patch:'16.19',build_profile:SPELL_SLOT_CHANGE_ROSTER_KEY_PAIR_821_PROFILE.id,replay_sha256:row.replay_sha256,
      replay_time_ms:row.replay_time_ms,stream_tag:row.stream_tag,native_packet_id:row.native_packet_id,
      raw_param:row.raw_param,hero_raw_param:matched.hero_raw_param,
      participant_id_candidate:matched.participant_id_candidate,metadata_index_candidate:matched.metadata_index_candidate,
      champion_metadata:matched.champion_metadata,team_id_metadata:matched.team_id_metadata,
      team_metadata:matched.team_metadata,role_metadata:matched.role_metadata,
      slot_index_candidate:row.callback_request_candidate.slot_index,
      operation_kind:row.callback_request_candidate.operation_kind,
      request_candidate:structuredClone(row.callback_request_candidate),
      association_status:'CANDIDATE_FULL_U32_HEADER_ROSTER_KEY_EQUALITY',
      roster_to_metadata_status:matched.roster_to_metadata_status,
      packet_actor_status:'UNKNOWN',owner_status:'UNKNOWN',live_receiver_status:'UNKNOWN',
      actual_application_status:'NOT_OBSERVED',semantic_effect_status:'UNKNOWN',
      confidence:'CANDIDATE',semantic_status:EVIDENCE,
      metadata_sha256:matched.metadata_sha256,stats_json_sha256:matched.stats_json_sha256,
      raw_packet_ref:structuredClone(row.raw_packet_ref),roster_keyframe_packet_ref:structuredClone(matched.raw_packet_ref)};
}

module.exports = {SPELL_SLOT_CHANGE_ROSTER_KEY_PAIR_821_PROFILE,associateSpellSlotChangeRosterKeys821,spellSlotChangeRosterKeyPairRow821};
