#!/usr/bin/env node
'use strict';

const path = require('node:path');

const {
  decodeSemanticReplay,
  getAttackEvents,
  getBuffEvents,
  getDeathTimerEvents,
  getHeroDamage,
  getHeroDeaths,
  getHeroPaths,
  getHeroRespawns,
  getHeroStates,
  getItemEvents,
  getEntityComponentStateEvents,
  getFaceDirectionEvents,
  getGameplayRouteTailEvents,
  getLevelTransitions,
  getProtectionEvents,
  getMissileEvents,
  getSpellStateEvents,
  getSpellEvents,
  queryWardSpawns,
  queryWardEvents,
  validateCanonicalRecord,
} = require('../src/semantic_api');
const { writeJson } = require('../src/io');
const { parseReplayFile } = require('../src/rofl');

const EXPECTED_RUNTIME_SHA256 = (
  '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
);

function parseArgs(argv) {
  const options = {
    replay: null, runtimeImagePath: null, output: null, expectNoLevel: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--replay') options.replay = path.resolve(argv[++index]);
    else if (value === '--runtime-image') options.runtimeImagePath = path.resolve(argv[++index]);
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--expect-no-level') options.expectNoLevel = true;
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.replay) throw new Error('--replay is required');
  if (!options.output) throw new Error('--output is required');
  return options;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const started = process.hrtime.bigint();
  const decoded = decodeSemanticReplay(options.replay, {
    runtimeImagePath: options.runtimeImagePath || undefined,
  });
  const heroPaths = getHeroPaths(decoded);
  const levelTransitions = getLevelTransitions(decoded);
  const wardSpawns = queryWardSpawns(decoded);
  const visionEntityEvents = queryWardEvents(decoded);
  const playerWards = queryWardSpawns(decoded, { player_active_only: true });
  const damageEvents = getHeroDamage(decoded);
  const deathEvents = getHeroDeaths(decoded);
  const heroStates = getHeroStates(decoded);
  const deathTimerEvents = getDeathTimerEvents(decoded);
  const respawnEvents = getHeroRespawns(decoded);
  const buffEvents = getBuffEvents(decoded);
  const spellEvents = getSpellEvents(decoded);
  const protectionEvents = getProtectionEvents(decoded);
  const itemEvents = getItemEvents(decoded);
  const gameplayTailEvents = getGameplayRouteTailEvents(decoded);
  const attackEvents = getAttackEvents(decoded);
  const spellStateEvents = getSpellStateEvents(decoded);
  const faceDirectionEvents = getFaceDirectionEvents(decoded);
  const missileEvents = getMissileEvents(decoded);
  const entityComponentStateEvents = getEntityComponentStateEvents(decoded);
  const canonicalGameplayTailEvents = decoded.events?.canonical_gameplay_route_tail_events ?? [];
  const canonicalRespawnEvents = decoded.events?.canonical_respawn_events ?? [];
  const replay = parseReplayFile(options.replay);
  const metadataOk = [
    ...heroPaths, ...levelTransitions, ...wardSpawns, ...damageEvents, ...deathEvents,
    ...heroStates, ...deathTimerEvents, ...respawnEvents, ...buffEvents, ...spellEvents,
    ...protectionEvents, ...itemEvents, ...gameplayTailEvents,
  ]
    .every((event) => (
    event.game_version === '16.16.805.0442'
    && event.patch === '16.16'
    && typeof event.build_profile === 'string'
    && event.build_profile.length > 0
    ));
  const levelCounts = Object.fromEntries([2, 3, 4].map((level) => [
    level,
    levelTransitions.filter((event) => event.level_after === level).length,
  ]));
  const provenanceOk = heroPaths.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x00f6
    && typeof event.raw_packet_ref?.raw_payload_sha256 === 'string'
  )) && levelTransitions.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x0314
    && typeof event.raw_packet_ref?.raw_payload_sha256 === 'string'
  )) && damageEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x017f
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && deathEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x0112
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && heroStates.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x010c
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && deathTimerEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x0074
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && respawnEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x0265
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && buffEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && [0x0123, 0x0326, 0x041f, 0x043c, 0x045b]
      .includes(event.raw_packet_ref?.packet_id)
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && spellEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x01cf
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && protectionEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x0371
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && itemEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.packet_id === 0x0064
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  )) && gameplayTailEvents.every((event) => (
    event.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref?.replay_sha256 === replay.source_sha256
    && [0x00b8, 0x00e4, 0x01ab, 0x01b5, 0x0298, 0x03d4]
      .includes(event.raw_packet_ref?.packet_id)
    && typeof event.raw_packet_ref?.payload_sha256 === 'string'
  ));
  const fieldConfidenceOk = heroPaths.every((event) => (
    event.confidence === 'VERIFIED_DERIVED'
    && event.field_confidence?.entity_network_id === 'VERIFIED_DIRECT'
    && event.field_confidence?.waypoints_xz === 'VERIFIED_DERIVED_CURRENT_CALIBRATION'
  )) && levelTransitions.every((event) => (
    event.transition_evidence === 'VERIFIED_DIRECT'
    && event.field_confidence?.raw_field_10 === 'VERIFIED_DIRECT'
    && (
      (Number.isInteger(event.level_after)
        && event.confidence === 'VERIFIED_DERIVED'
        && event.level_mapping_evidence === 'VERIFIED_DERIVED'
        && event.field_confidence?.level_after === 'VERIFIED_DERIVED_BUILD_BOUND')
      || (event.level_after === null
        && event.confidence === 'PARTIAL'
        && event.level_mapping_evidence === 'UNAVAILABLE'
        && event.field_confidence?.level_after === 'UNAVAILABLE')
    )
  )) && damageEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && event.field_confidence?.source_network_id === 'VERIFIED_DIRECT'
    && event.field_confidence?.target_network_id === 'VERIFIED_DIRECT'
    && event.field_confidence?.amount === 'VERIFIED_DIRECT'
    && event.amount_semantic_stage === 'UNKNOWN'
    && event.field_confidence?.amount_semantic_stage === 'UNKNOWN'
  )) && deathEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && Number.isInteger(event.victim_participant_id)
    && event.field_confidence?.victim_participant_id === 'VERIFIED_DERIVED'
    && Number.isInteger(event.killer_network_id)
    && Number.isInteger(event.killer_participant_id)
    && event.field_confidence?.killer_network_id === 'VERIFIED_DIRECT'
    && event.field_confidence?.killer_participant_id === 'VERIFIED_DERIVED'
    && event.assists === null
    && event.field_confidence?.assists === 'UNAVAILABLE'
    && event.field_confidence?.other_inner_payload_fields === 'UNKNOWN_RETAINED_RAW'
  )) && heroStates.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && Number.isInteger(event.participant_id)
    && Number.isFinite(event.experience_points)
    && Number.isInteger(event.lane_minions_killed)
    && event.total_gold === null
    && event.jungle_minions_killed === null
    && event.field_confidence?.experience_points === 'VERIFIED_DIRECT'
    && event.field_confidence?.lane_minions_killed === 'VERIFIED_DIRECT'
    && event.field_confidence?.total_gold === 'CANDIDATE'
    && event.field_confidence?.jungle_minions_killed === 'CANDIDATE'
  )) && deathTimerEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && Number.isFinite(event.death_timer_seconds)
    && event.death_timer_seconds >= 0
    && event.respawn_timestamp_ms === null
    && event.field_confidence?.death_timer_seconds === 'VERIFIED_DIRECT'
    && event.field_confidence?.respawn_timestamp_ms === 'UNAVAILABLE'
  )) && respawnEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && event.lifecycle_operation === 'REINCARNATE_ALIVE'
    && event.respawn_timestamp_ms === event.replay_time_ms
    && Number.isInteger(event.participant_id)
    && Number.isFinite(event.position?.x)
    && event.position?.y === 0
    && Number.isFinite(event.position?.z)
    && event.reincarnate_scalar_role === 'UNKNOWN_RESOURCE_LIKE_CANDIDATE'
    && event.field_confidence?.respawn_timestamp_ms === 'VERIFIED_DIRECT'
    && event.field_confidence?.position === 'VERIFIED_DIRECT'
  )) && buffEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && ['ADD', 'UPDATE_COUNT', 'UPDATE_COUNTER', 'REPLACE', 'REMOVE']
      .includes(event.operation)
    && Number.isInteger(event.routing_entity_id)
    && event.subject_entity_id === null
    && event.stack_count === null
    && event.duration_seconds === null
    && event.field_confidence?.routing_entity_id === 'VERIFIED_DIRECT'
  )) && spellEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && Number.isInteger(event.numeric_spell_key)
    && /^0x[0-9a-f]{8}$/.test(event.spell_identifier)
    && event.target_entity_id === null
    && event.cast_result === null
    && event.field_confidence?.numeric_spell_key === 'VERIFIED_DIRECT'
  )) && protectionEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && Number.isFinite(event.reported_amount)
    && event.reported_amount >= 0
    && event.effective_amount === null
    && ['REPORTED_OR_GROSS', 'APPLICATION_OR_GENERATED'].includes(event.amount_stage)
    && event.field_confidence?.reported_amount === 'VERIFIED_DIRECT'
    && event.field_confidence?.effective_amount === 'UNAVAILABLE'
  )) && itemEvents.every((event) => (
    event.confidence === 'VERIFIED_DERIVED'
    && event.operation === 'SUPPORT_QUEST_STAGE_SNAPSHOT'
    && [0, 1, 2].includes(event.stage)
    && [5, 10].includes(event.subject_entity_id - 0x400000ad)
    && event.field_confidence?.stage === 'VERIFIED_DERIVED'
  )) && gameplayTailEvents.every((event) => (
    event.confidence === 'VERIFIED_DIRECT'
    && Number.isInteger(event.subject_network_id)
    && event.field_confidence?.subject_network_id === 'VERIFIED_DIRECT'
    && event.field_confidence?.replay_time_ms === 'VERIFIED_DIRECT'
    && event.semantic_status === 'VERIFIED_DIRECT_BOUNDED_RESEARCH_EVENT'
  ));
  const pathRuntimeOk = decoded.path_decode?.status === 'PASS'
    && decoded.path_decode.runtime_image_sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.path_decode.packet_count > 0
    && decoded.path_decode.packet_count === decoded.path_decode.fully_consumed_count
    && decoded.path_decode.packet_count === decoded.path_decode.deserialize_success_count
    && decoded.path_decode.input_provenance_failure_count === 0
    && decoded.path_decode.infrastructure_failure_count === 0
    && decoded.path_decode.packet_manifest?.count_validation === 'FULL_MATCH';
  const levelRuntimeOk = options.expectNoLevel
    ? decoded.level_transition_decode?.status === 'NO_MATCHING_PACKETS_IN_REPLAY'
      && decoded.level_transition_decode.runtime_image_sha256 === EXPECTED_RUNTIME_SHA256
      && decoded.level_transition_decode.empty_verified_by_strict_replay_scan === true
      && decoded.level_transition_decode.exported_packet_count === 0
      && decoded.replay_event_observation?.level_transition === 'NO_MATCHING_PACKETS'
      && levelTransitions.length === 0
    : decoded.level_transition_decode?.status === 'PASS'
      && decoded.level_transition_decode.runtime_image_sha256 === EXPECTED_RUNTIME_SHA256
      && decoded.level_transition_decode.decoded_rows > 0
      && decoded.level_transition_decode.decoded_rows
        === decoded.level_transition_decode.fully_consumed_success_rows
      && decoded.level_transition_decode.input_provenance_failure_count === 0
      && decoded.level_transition_decode.infrastructure_failure_count === 0
      && decoded.level_transition_decode.packet_manifest?.count_validation === 'FULL_MATCH';
  const levelSemanticOk = options.expectNoLevel
    ? levelTransitions.length === 0
    : levelCounts[2] > 0 && levelCounts[3] > 0 && levelCounts[4] > 0;
  const wardRuntimeOk = decoded.ward_spawn_decode?.status === 'PASS'
    && decoded.ward_spawn_decode.runtime_image_sha256_verified === true
    && decoded.ward_spawn_decode.exported_packet_count > 0
    && decoded.ward_spawn_decode.counts.valid_input_rows
      === decoded.ward_spawn_decode.counts.fully_consumed
    && decoded.ward_spawn_decode.counts.input_provenance_failures === 0
    && decoded.ward_spawn_decode.counts.infrastructure_failures === 0;
  const wardReleaseBoundaryOk = decoded.status_basis
      === 'EXACT_BUILD_PROFILE_PLUS_CURRENT_REPLAY_DECODE_ATTESTATION'
    && decoded.release_attestation?.source === 'EXACT_BUILD_PROFILE_CORPUS_RELEASE'
    && decoded.release_attestation.profile_support_level === 'DEEP_SEMANTIC_READY'
    && decoded.release_attestation.profile_capability_status === 'SEMANTIC_VERIFIED_DERIVED'
    && decoded.release_attestation.current_replay_validation_scope === 'SINGLE_REPLAY_DECODE'
    && decoded.release_attestation.current_replay_decode_status === 'PASS'
    && decoded.release_attestation.current_replay_decode_verified === true
    && decoded.release_attestation.corpus_release_revalidated_on_current_replay === false;
  const damageRuntimeOk = decoded.damage_decode?.decoder_profile
      === 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1'
    && decoded.damage_decode.image_sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.damage_decode.exported_packet_count > 0
    && decoded.damage_decode.event_count === decoded.damage_decode.exported_packet_count
    && decoded.damage_decode.successful_full_consume_count
      === decoded.damage_decode.exported_packet_count
    && (decoded.damage_decode.emulation_error_count ?? 0) === 0
    && damageEvents.length === decoded.damage_decode.exported_packet_count;
  const damageReleaseBoundaryOk = decoded.damage_release_attestation?.source
      === 'EXACT_BUILD_STATIC_RUNTIME_PLUS_DETAILS_ANCHOR_RELEASE'
    && decoded.damage_release_attestation.capability_profile
      === 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1'
    && decoded.damage_release_attestation.profile_support_level === 'DEEP_SEMANTIC_READY'
    && decoded.damage_release_attestation.current_replay_decode_status === 'PASS'
    && decoded.damage_release_attestation.current_replay_decode_verified === true
    && decoded.damage_release_attestation.amount_stage_semantics === 'UNKNOWN'
    && decoded.damage_release_attestation.corpus_release_revalidated_on_current_replay === false;
  const deathRouteOk = decoded.death_decode?.profile?.id
      === 'rofl-16.16.805.0442-hero-death-unicorn-v2'
    && decoded.death_decode.decoder_profile === 'runtime_candidate_16_16_0112'
    && decoded.death_decode.image_sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.death_decode.current_replay_decode_verified === true
    && decoded.death_decode.successful_full_consume_count
      === decoded.death_decode.exported_packet_count
    && decoded.death_decode.signature_count === decoded.death_decode.decoded_event_count
    && decoded.death_decode.rejected_signature_count === 0
    && decoded.death_decode.walk_error_count === 0
    && deathEvents.length === decoded.death_decode.signature_count;
  const deathReleaseBoundaryOk = decoded.death_release_attestation?.source
      === 'EXACT_BUILD_STATIC_RUNTIME_PLUS_DETAILS_FIELD_DIFFERENTIAL'
    && decoded.death_release_attestation.current_replay_decode_verified === true
    && decoded.death_release_attestation.killer_network_id
      === 'VERIFIED_DIRECT_EXACT_HELPER_INVERSE'
    && decoded.death_release_attestation.assists
      === 'UNAVAILABLE_WITH_EXPLICIT_NEGATIVE_DIFFERENTIAL'
    && decoded.death_release_attestation.corpus_release_revalidated_on_current_replay === false;
  const heroStatsRuntimeOk = decoded.hero_scoreboard_decode?.profile?.id
      === 'rofl-16.16.805.0442-hero-stats-scoreboard-unicorn-v1'
    && decoded.hero_scoreboard_decode.image_sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.hero_scoreboard_decode.event_count
      === decoded.hero_scoreboard_decode.exported_packet_count
    && decoded.hero_scoreboard_decode.successful_full_consume_count
      === decoded.hero_scoreboard_decode.exported_packet_count
    && decoded.hero_scoreboard_decode.current_replay_decode_verified === true
    && heroStates.length === decoded.hero_scoreboard_decode.exported_packet_count;
  const heroStatsReleaseBoundaryOk = decoded.hero_scoreboard_release_attestation?.source
      === 'EXACT_BUILD_STATIC_RUNTIME_PLUS_DETAILS_FRAME_FIELD_DIFFERENTIAL'
    && decoded.hero_scoreboard_release_attestation.current_replay_decode_verified === true
    && decoded.hero_scoreboard_release_attestation.verified_fields.includes('experience_points')
    && decoded.hero_scoreboard_release_attestation.verified_fields.includes('lane_minions_killed')
    && decoded.hero_scoreboard_release_attestation.candidate_not_published_fields
      .includes('total_gold');
  const deathTimerRuntimeOk = decoded.death_timer_decode?.image_sha256
      === EXPECTED_RUNTIME_SHA256
    && decoded.death_timer_decode.current_replay_decode_verified === true
    && decoded.death_timer_decode.successful_full_consume_count
      === decoded.death_timer_decode.exported_packet_count
    && decoded.death_timer_decode.decoded_event_count
      === decoded.death_timer_decode.exported_packet_count
    && deathTimerEvents.length === decoded.death_timer_decode.exported_packet_count;
  const heroReincarnateAliveRuntimeOk = decoded.hero_reincarnate_alive_decode?.image_sha256
      === EXPECTED_RUNTIME_SHA256
    && decoded.hero_reincarnate_alive_decode.current_replay_decode_verified === true
    && decoded.hero_reincarnate_alive_decode.successful_full_consume_count
      === decoded.hero_reincarnate_alive_decode.exported_packet_count
    && decoded.hero_reincarnate_alive_decode.decoded_event_count
      === decoded.hero_reincarnate_alive_decode.exported_packet_count
    && respawnEvents.length === decoded.hero_reincarnate_alive_decode.exported_packet_count;
  const buffSpellRuntimeOk = decoded.buff_spell_decode?.status === 'PASS'
    && decoded.buff_spell_decode.runtime_image?.sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.buff_spell_decode.current_replay_decode_verified === true
    && decoded.buff_spell_decode.selected_route_rows
      === decoded.buff_spell_decode.exported_packet_count
    && decoded.buff_spell_decode.fully_consumed_rows
      === decoded.buff_spell_decode.exported_packet_count
    && buffEvents.length + spellEvents.length === decoded.buff_spell_decode.exported_packet_count;
  const protectionRuntimeOk = decoded.protection_decode?.status === 'PASS'
    && decoded.protection_decode.runtime_image?.sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.protection_decode.current_replay_decode_verified === true
    && decoded.protection_decode.input_route_rows
      === decoded.protection_decode.exported_packet_count
    && decoded.protection_decode.fully_consumed_rows
      === decoded.protection_decode.exported_packet_count
    && decoded.protection_decode.selected_candidate_row_count
      + decoded.protection_decode.unclassified_route_row_count
      === decoded.protection_decode.exported_packet_count
    && decoded.protection_decode.selected_candidate_row_count
      - decoded.protection_decode.exact_duplicate_rows_suppressed
      === protectionEvents.length;
  const itemRuntimeOk = decoded.item_decode?.input_conserved === true
    && decoded.item_decode.support_quest_item_stage?.input_conserved === true
    && decoded.item_decode.support_quest_item_stage.canonical_event_count === itemEvents.length
    && decoded.item_decode.support_quest_item_stage.input_row_count
      + decoded.item_decode.route_specific_materializer_pending_row_count
      === decoded.item_decode.exported_packet_count
    && decoded.item_decode.route_specific_materializer_pending_status
      === 'RETAINED_RAW_NOT_SILENTLY_DISCARDED';
  const gameplayTailRuntimeOk = decoded.gameplay_route_tail_decode?.status === 'PASS'
    && decoded.gameplay_route_tail_decode.image_sha256 === EXPECTED_RUNTIME_SHA256
    && decoded.gameplay_route_tail_decode.current_replay_decode_verified === true
    && decoded.gameplay_route_tail_decode.input_event_count
      === decoded.gameplay_route_tail_decode.exported_packet_count
    && decoded.gameplay_route_tail_decode.output_row_count
      === decoded.gameplay_route_tail_decode.exported_packet_count
    && decoded.gameplay_route_tail_decode.successful_full_consume_count
      === decoded.gameplay_route_tail_decode.exported_packet_count
    && decoded.gameplay_route_tail_decode.emulation_error_count === 0
    && gameplayTailEvents.length === decoded.gameplay_route_tail_decode.exported_packet_count;
  const gameplayTailCanonicalOk = canonicalGameplayTailEvents.length === gameplayTailEvents.length
    && canonicalGameplayTailEvents.every((event) => Boolean(validateCanonicalRecord(event)))
    && attackEvents.length > 0
    && spellStateEvents.length > 0
    && faceDirectionEvents.length > 0
    && missileEvents.length > 0
    && entityComponentStateEvents.length > 0
    && new Set(canonicalGameplayTailEvents.map((event) => event.semantic_type)).size === 5;
  const heroRespawnCanonicalOk = canonicalRespawnEvents.length === respawnEvents.length
    && canonicalRespawnEvents.length > 0
    && canonicalRespawnEvents.every((event) => (
      Boolean(validateCanonicalRecord(event))
      && event.semantic_type === 'EntityLifecycle'
      && event.fields?.lifecycle_operation === 'REINCARNATE_ALIVE'
      && event.fields?.participant_id !== null
      && event.fields?.position?.x !== null
      && event.fields?.position?.y === 0
      && event.fields?.position?.z !== null
    ));
  const deepReleaseBoundaryOk = decoded.deep_recovery_release_attestation?.source
      === 'EXACT_BUILD_RUNTIME_DECODERS_PLUS_SAFE_CORPUS_DIFFERENTIALS'
    && decoded.deep_recovery_release_attestation.exact_build === '16.16.805.0442'
    && decoded.deep_recovery_release_attestation.nearest_build_fallback === 'FORBIDDEN'
    && decoded.deep_recovery_release_attestation.death_timer.current_replay_decode_verified
      === true
    && decoded.deep_recovery_release_attestation.hero_reincarnate_alive
      .current_replay_decode_verified === true
    && decoded.deep_recovery_release_attestation.hero_reincarnate_alive
      .respawn_timestamp_semantics === 'VERIFIED_DIRECT_EXACT_PACKET_OCCURRENCE'
    && decoded.deep_recovery_release_attestation.hero_reincarnate_alive
      .reincarnate_scalar_semantics === 'UNKNOWN_RESOURCE_LIKE_CANDIDATE'
    && decoded.deep_recovery_release_attestation.buff_spell.current_replay_decode_verified
      === true
    && decoded.deep_recovery_release_attestation.protection.current_replay_decode_verified
      === true
    && decoded.deep_recovery_release_attestation.item.support_quest_input_conserved === true
    && decoded.deep_recovery_release_attestation.item.other_exact_rows_status
      === 'RETAINED_RAW_NOT_SILENTLY_DISCARDED'
    && decoded.deep_recovery_release_attestation.gameplay_route_tail
      .current_replay_decode_verified === true
    && decoded.deep_recovery_release_attestation.gameplay_route_tail
      .damage_map_truth_or_cooldown_duration_inference === 'NOT_PUBLISHED';
  const wardSemanticOk = playerWards.length > 0 && playerWards.every((event) => (
    event.player_active_ward_confirmed === true
    && event.field_confidence?.position === 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE'
    && event.field_confidence?.owner_entity === 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE'
    && event.raw_packet_ref?.packet_id === 0x049a
  ));
  const status = decoded.status === 'DEEP_SEMANTIC_READY'
    && decoded.downstream_gate === 'RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS'
    && heroPaths.length > 0
    && levelSemanticOk
    && metadataOk
    && provenanceOk
    && fieldConfidenceOk
    && pathRuntimeOk
    && levelRuntimeOk
    && wardRuntimeOk
    && wardReleaseBoundaryOk
    && wardSemanticOk
    && damageRuntimeOk
    && damageReleaseBoundaryOk
    && deathRouteOk
    && deathReleaseBoundaryOk
    && heroStatsRuntimeOk
    && heroStatsReleaseBoundaryOk
    && deathTimerRuntimeOk
    && heroReincarnateAliveRuntimeOk
    && heroRespawnCanonicalOk
    && buffSpellRuntimeOk
    && protectionRuntimeOk
    && itemRuntimeOk
    && gameplayTailRuntimeOk
    && gameplayTailCanonicalOk
    && deepReleaseBoundaryOk
    ? 'PASS'
    : 'FAIL';
  const summary = {
    schema_version: 1,
    status,
    expected_no_level_packets: options.expectNoLevel,
    replay: options.replay,
    game_version: decoded.profile?.game_version ?? null,
    resolved_support_level: decoded.release_level,
    downstream_gate: decoded.downstream_gate,
    path_packet_count: decoded.path_decode?.exported_packet_count ?? 0,
    hero_path_event_count: heroPaths.length,
    level_packet_count: decoded.level_transition_decode?.exported_packet_count ?? 0,
    level_transition_event_count: levelTransitions.length,
    level_after_counts: levelCounts,
    ward_packet_count: decoded.ward_spawn_decode?.exported_packet_count ?? 0,
    ward_vision_event_count: wardSpawns.length,
    vision_entity_event_count: visionEntityEvents.length,
    confirmed_player_ward_count: playerWards.length,
    damage_packet_count: decoded.damage_decode?.exported_packet_count ?? 0,
    damage_event_count: damageEvents.length,
    hero_death_packet_count: decoded.death_decode?.signature_count ?? 0,
    hero_death_event_count: deathEvents.length,
    hero_scoreboard_packet_count: decoded.hero_scoreboard_decode?.exported_packet_count ?? 0,
    hero_state_event_count: heroStates.length,
    hero_death_timer_packet_count: decoded.death_timer_decode?.exported_packet_count ?? 0,
    hero_death_timer_event_count: deathTimerEvents.length,
    hero_reincarnate_alive_packet_count:
      decoded.hero_reincarnate_alive_decode?.exported_packet_count ?? 0,
    hero_respawn_event_count: respawnEvents.length,
    canonical_hero_respawn_event_count: canonicalRespawnEvents.length,
    buff_packet_count: buffEvents.length,
    buff_event_count: buffEvents.length,
    cast_spell_packet_count: spellEvents.length,
    cast_spell_event_count: spellEvents.length,
    protection_route_packet_count: decoded.protection_decode?.exported_packet_count ?? 0,
    protection_canonical_event_count: protectionEvents.length,
    protection_unclassified_route_row_count:
      decoded.protection_decode?.unclassified_route_row_count ?? 0,
    item_route_packet_count: decoded.item_decode?.exported_packet_count ?? 0,
    support_quest_item_stage_event_count: itemEvents.length,
    item_route_specific_materializer_pending_row_count:
      decoded.item_decode?.route_specific_materializer_pending_row_count ?? 0,
    gameplay_route_tail_packet_count:
      decoded.gameplay_route_tail_decode?.exported_packet_count ?? 0,
    gameplay_route_tail_event_count: gameplayTailEvents.length,
    gameplay_route_tail_event_type_counts: Object.fromEntries(
      [...new Set(gameplayTailEvents.map((event) => event.event_type))].sort()
        .map((type) => [type, gameplayTailEvents.filter((event) => event.event_type === type).length]),
    ),
    canonical_gameplay_event_count: canonicalGameplayTailEvents.length,
    public_event_metadata_pass: metadataOk,
    raw_provenance_pass: provenanceOk,
    field_confidence_pass: fieldConfidenceOk,
    path_runtime_gate_pass: pathRuntimeOk,
    level_runtime_gate_pass: levelRuntimeOk,
    ward_runtime_gate_pass: wardRuntimeOk,
    ward_release_boundary_pass: wardReleaseBoundaryOk,
    ward_semantic_gate_pass: wardSemanticOk,
    damage_runtime_gate_pass: damageRuntimeOk,
    damage_release_boundary_pass: damageReleaseBoundaryOk,
    hero_death_route_gate_pass: deathRouteOk,
    hero_death_release_boundary_pass: deathReleaseBoundaryOk,
    hero_scoreboard_runtime_gate_pass: heroStatsRuntimeOk,
    hero_scoreboard_release_boundary_pass: heroStatsReleaseBoundaryOk,
    hero_death_timer_runtime_gate_pass: deathTimerRuntimeOk,
    hero_reincarnate_alive_runtime_gate_pass: heroReincarnateAliveRuntimeOk,
    hero_respawn_canonical_gate_pass: heroRespawnCanonicalOk,
    buff_spell_runtime_gate_pass: buffSpellRuntimeOk,
    protection_runtime_gate_pass: protectionRuntimeOk,
    item_runtime_and_conservation_gate_pass: itemRuntimeOk,
    gameplay_route_tail_runtime_gate_pass: gameplayTailRuntimeOk,
    gameplay_route_tail_canonical_gate_pass: gameplayTailCanonicalOk,
    deep_release_boundary_pass: deepReleaseBoundaryOk,
    runtime_image_sha256: decoded.path_decode?.runtime_image_sha256 ?? null,
    wall_seconds: Number(process.hrtime.bigint() - started) / 1e9,
  };
  writeJson(options.output, summary);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs };
