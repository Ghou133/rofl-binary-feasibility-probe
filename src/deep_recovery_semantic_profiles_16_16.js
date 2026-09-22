'use strict';

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';

function freezeProfile(profile) {
  return Object.freeze(profile);
}

const DEEP_RECOVERY_SEMANTIC_PROFILES = Object.freeze({
  hero_death_timer: freezeProfile({
    id: 'rofl-16.16.805.0442-hero-death-timer-v1',
    capability: 'Hero death timer',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    replay_block_packet_id: 0x0074,
    client_opcode: 0x0074,
    runtime_type_name: 'PKT_S2C_UpdateDeathTimer_s',
    callback_receive_rva: 0x002a6460,
    object_size: 0x14,
    protected_f32_offset: 0x10,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/hero_state/profiles/packet_0074.json',
    runtime_decoder_profile_sha256:
      '3c813628deb00f2c6f44bdb3920dccb621b19b0a26ccdd723cc6f781ac7a349b',
    decoded_event_artifact:
      'artifacts/full_semantic_deep_recovery_v2/hero_state/packet_0074_death_timer_events.jsonl',
    decoded_event_artifact_sha256:
      '0489b439067dacd49afb43bd0cca628928bcd249653150d0b32c3e417cf8bd55',
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json',
    validation_artifact_sha256:
      'fc13dce5e0c89b9d556074af3c2b7b13138eb855b9c101327dbddd9c4e900eab',
    sample_count: Object.freeze({ replay_count: 8, event_count: 608, exact_full_consume_count: 608 }),
    field_evidence: Object.freeze({
      subject_entity_id: 'VERIFIED_DIRECT_RAW_PARAM_WITH_HERO_RANGE_SUBSET',
      death_timer_seconds: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      respawn_timestamp_ms: 'UNAVAILABLE_TIMER_IS_NOT_EXACT_RESPAWN',
    }),
    known_limits: Object.freeze([
      'The timer value is not an exact respawn timestamp and is not converted into one.',
      'One P0 hero-death anchor validates the semantic name; non-hero rows remain raw entities.',
    ]),
  }),
  buff: freezeProfile({
    id: 'rofl-16.16.805.0442-buff-manager-deep-v1',
    capability: 'Buff operations and stable structural fields',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    enabled: true,
    routes: Object.freeze({
      add: 0x0326,
      update_count: 0x0123,
      update_counter: 0x041f,
      replace: 0x043c,
      remove: 0x045b,
    }),
    runtime_names: Object.freeze({
      add: 'PKT_NPC_BuffAdd2_s',
      update_count: 'PKT_NPC_BuffUpdateCount_s',
      update_counter: 'PKT_NPC_BuffUpdateNumCounter_s',
      replace: 'PKT_NPC_BuffReplace_s',
      remove: 'PKT_NPC_BuffRemove2_s',
    }),
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    extractor: 'scripts/decode_buff_spell_callbacks_16_16_deep.py',
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
    validation_artifact_sha256:
      '22a40272b47870bf43b3f15d8c43615f0cd1482d128025313fb50b4e99f20195',
    sample_count: Object.freeze({ replay_count: 4, event_count: 354854, exact_full_consume_count: 354854 }),
    field_evidence: Object.freeze({
      operation: 'VERIFIED_DIRECT_EXACT_ROUTE',
      routing_entity_id: 'VERIFIED_DIRECT_CALLBACK_RECEIVER',
      slot_or_index: 'VERIFIED_DIRECT_CALLBACK_ARGUMENT',
      buff_numeric_identifier: 'VERIFIED_DIRECT_CROSS_OPERATION_SEQUENCE',
      source_entity_id: 'CANDIDATE_STRUCTURAL_FIELD',
      stack_count: 'CANDIDATE_WITH_COUNTEREXAMPLES',
      duration_seconds: 'UNAVAILABLE_UNIVERSAL_ROLE_REJECTED',
    }),
    known_limits: Object.freeze([
      'Routing entity is not renamed as a gameplay target without an independent ownership proof.',
      'Numeric buff identifiers are retained without a human-readable dictionary.',
      'Stack, duration, expiry, and causal source roles remain candidate or unavailable.',
    ]),
  }),
  cast_spell: freezeProfile({
    id: 'rofl-16.16.805.0442-cast-occurrence-translator-v1',
    capability: 'Spell cast occurrence with numeric key and caster candidates',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    enabled: true,
    replay_block_packet_id: 0x01cf,
    client_opcode: 0x01cf,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    extractor: 'scripts/decode_buff_spell_callbacks_16_16_deep.py',
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
    validation_artifact_sha256:
      '22a40272b47870bf43b3f15d8c43615f0cd1482d128025313fb50b4e99f20195',
    sample_count: Object.freeze({ replay_count: 4, event_count: 21013, exact_full_consume_count: 21013 }),
    field_evidence: Object.freeze({
      occurrence: 'VERIFIED_DIRECT_EXACT_ROUTE',
      numeric_spell_key: 'VERIFIED_DIRECT_TRANSLATOR_FIELD',
      caster_name: 'VERIFIED_DIRECT_TRANSLATOR_STRING',
      caster_entity_id: 'VERIFIED_DERIVED_TRANSLATOR_FIELD_PLUS_PARTICIPANT_NAME_CROSS_CHECK',
      chain_owner_entity_id: 'CANDIDATE_STRUCTURAL_FIELD',
      spell_slot: 'CANDIDATE_NUMERIC_ENUM',
      cast_time_seconds: 'CANDIDATE_TIME_FIELD',
      human_readable_ability_id: 'UNAVAILABLE',
      damage_causality: 'UNAVAILABLE',
    }),
    known_limits: Object.freeze([
      'Numeric spell key is not a human-readable ability identity.',
      'Near-time Damage and Missile associations are explicitly insufficient for causality.',
      'Target and result semantics are not published.',
    ]),
  }),
  protection: freezeProfile({
    id: 'rofl-16.16.805.0442-on-event-protection-v1',
    capability: 'Reported heal and shield application events',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    enabled: true,
    replay_block_packet_id: 0x0371,
    client_opcode: 0x0371,
    runtime_name: 'PKT_OnEvent_s',
    event_ids: Object.freeze({ heal_reported: 0x004b, shield_receive: 0x00ed, shield_duplicate_grant: 0x00ee }),
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    extractor: 'scripts/decode_on_event_16_16_deep.py',
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
    validation_artifact_sha256:
      '22a40272b47870bf43b3f15d8c43615f0cd1482d128025313fb50b4e99f20195',
    sample_count: Object.freeze({
      replay_count: 4,
      heal_reported_event_count: 28404,
      shield_application_event_count: 1107,
      exact_duplicate_shield_event_count: 1107,
    }),
    canonicalization: Object.freeze({
      heal: 'retain 0x004b',
      shield: 'retain 0x00ed and suppress exact duplicate 0x00ee',
    }),
    field_evidence: Object.freeze({
      source_entity_id: 'VERIFIED_DIRECT_EXACT_PARAMETER_LAYOUT',
      target_entity_id: 'VERIFIED_DIRECT_EXACT_PARAMETER_LAYOUT',
      reported_amount: 'VERIFIED_DIRECT_REPORTED_OR_GROSS_STAGE',
      effective_amount: 'UNAVAILABLE',
      overheal_amount: 'UNAVAILABLE',
      shield_remaining: 'UNAVAILABLE',
      shield_absorbed: 'UNAVAILABLE',
    }),
    known_limits: Object.freeze([
      'Heal amount is reported or gross and is not effective post-overheal healing.',
      'Shield amount is application/generated, not remaining or absorbed shield.',
      '0x00ee is an exact duplicate of 0x00ed in the bounded corpus and must not double count.',
    ]),
  }),
  item_state: freezeProfile({
    id: 'rofl-16.16.805.0442-inventory-snapshot-layout-v1',
    capability: 'Exact inventory snapshot state',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT_PARTIAL',
    enabled: true,
    routes: Object.freeze({ broadcast: 0x0311, map_view: 0x02ea, special_slot_set: 0x006c }),
    runtime_names: Object.freeze({
      broadcast: 'PKT_S2C_SetInventory_Broadcast_s',
      map_view: 'PKT_S2C_SetInventory_MapView_s',
      special_slot_set: 'PKT_SetItem_s',
    }),
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    extractor: 'scripts/analyze_entity_item_deep_recovery_v2.py',
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
    validation_artifact_sha256:
      'c5614f613bb3116833cc15c1e42486272a7f4431184629ffaca1b89f943485e7',
    sample_count: Object.freeze({
      replay_count: 4,
      broadcast_event_count: 1425,
      broadcast_exact_full_consume_count: 1271,
      broadcast_conserved_failure_count: 154,
      map_view_event_count: 299,
      map_view_exact_full_consume_count: 299,
      special_slot_event_count: 53,
    }),
    record_layout: Object.freeze({
      stride: 0xa0,
      item_id_offset: 0x1c,
      slot_index_offset: 0x22,
      stack_count_offset: 0x78,
      apply_behavior: 'reset ten inventory slots, then iterate decoded records',
    }),
    field_evidence: Object.freeze({
      subject_entity_id: 'VERIFIED_DIRECT_RAW_PARAM',
      snapshot_operation: 'VERIFIED_DIRECT_EXACT_ROUTE',
      slot_index: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
      item_identifier: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
      stack_count: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
      buy_sell_undo_cause: 'UNAVAILABLE_ROUTE_IS_GENERIC_STATE',
    }),
    known_limits: Object.freeze([
      'Only successfully full-consumed rows are published; 154 broadcast failures remain count-conserved.',
      'Keyframe snapshots can lag the live stream and are observations, not mutation commands.',
      'Snapshot routes are not renamed buy, sell, undo, or transform events.',
    ]),
  }),
  item_swap: freezeProfile({
    id: 'rofl-16.16.805.0442-inventory-swap-v1',
    capability: 'Exact inventory slot swap',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    replay_block_packet_id: 0x01e8,
    client_opcode: 0x01e8,
    runtime_type_name: 'PKT_SwapItemAns_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
    validation_artifact_sha256:
      'c5614f613bb3116833cc15c1e42486272a7f4431184629ffaca1b89f943485e7',
    sample_count: Object.freeze({ replay_count: 4, event_count: 258, exact_full_consume_count: 258 }),
    field_evidence: Object.freeze({
      subject_entity_id: 'VERIFIED_DIRECT_RAW_PARAM',
      first_slot_index: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
      second_slot_index: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
    }),
    known_limits: Object.freeze([
      'Both selectors are exact inventory slots 0..5; item identity is intentionally not inferred.',
    ]),
  }),
  item_substitution_map: freezeProfile({
    id: 'rofl-16.16.805.0442-shop-item-substitution-map-v1',
    capability: 'Exact shop item substitution map',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DIRECT',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DIRECT',
    enabled: true,
    replay_block_packet_id: 0x005a,
    client_opcode: 0x005a,
    runtime_type_name: 'PKT_S2C_ShopItemSubstitutionSet_Broadcast_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
    validation_artifact_sha256:
      'c5614f613bb3116833cc15c1e42486272a7f4431184629ffaca1b89f943485e7',
    sample_count: Object.freeze({ replay_count: 4, event_count: 8, exact_full_consume_count: 8 }),
    observed_mapping: Object.freeze({ 1001: 2422, 2420: 2421 }),
    field_evidence: Object.freeze({
      source_item_identifier: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
      target_item_identifier: 'VERIFIED_DIRECT_AFTER_EXACT_RUNTIME_INVERSE',
    }),
    known_limits: Object.freeze([
      'This is a substitution-map update, not proof that an inventory transform occurred.',
      'The two observed mappings do not normalize the retained 3363/3340 undo residual.',
    ]),
  }),
  support_quest_item_stage: freezeProfile({
    id: 'rofl-16.16.805.0442-support-quest-stage-snapshot-v1',
    capability: 'Bounded support quest item stage snapshot',
    replay_version: EXACT_BUILD,
    status: 'SEMANTIC_VERIFIED_DERIVED',
    structure_status: 'STRUCTURE_VERIFIED',
    semantic_status: 'SEMANTIC_VERIFIED_DERIVED',
    enabled: true,
    replay_block_packet_id: 0x0064,
    client_opcode: 0x0064,
    runtime_type_name: null,
    constructor_rva: 0x00e7eb40,
    vtable_rva: 0x01b16940,
    deserialize_rva: 0x010ac010,
    object_size: 0x18,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_support_quest_audit.json',
    validation_artifact_sha256:
      'b5e3a5568b8760d4dee861d4b52c758d125b020132a5f08bad5634e0f9e99d75',
    runtime_validation_artifact:
      'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_runtime_residual_audit.json',
    runtime_validation_artifact_sha256:
      'f7a735addb2e0991bef7455608d4ab286b5ad81bb62d4e8e6f8c726bc82f67f2',
    sample_count: Object.freeze({
      replay_count: 8,
      event_count: 169654,
      exact_full_consume_count: 169654,
      canonical_group_count: 15071,
      canonical_event_count: 150710,
      residual_event_count: 18944,
      independent_details_transition_match_count: 16,
    }),
    exact_build_stage_code_map: Object.freeze({
      '1.17': 0,
      '1.27': 1,
      '1.47': 2,
    }),
    field_evidence: Object.freeze({
      stage_code_f32: 'VERIFIED_DIRECT_EXACT_CODEC',
      participant_entity_routing_key: 'VERIFIED_DIRECT_EXACT_CODEC',
      participant_id: 'VERIFIED_DERIVED_CANONICAL_GROUP_ORDINAL',
      stage: 'VERIFIED_DERIVED_SAFE_DETAILS_AND_INVENTORY_CROSSCHECK',
      byte_0_tags: 'VERIFIED_DIRECT_STRUCTURAL_NOT_GAMEPLAY',
    }),
    known_limits: Object.freeze([
      'Published only for canonical ten-row groups and utility participants 5 and 10.',
      'Noncanonical and three-byte rows remain structured residuals without gameplay names.',
      'The numeric route identity is exact; no symbolic runtime type name is claimed.',
    ]),
  }),
});

function deepRecoveryProfileFor(capability, replayVersion) {
  if (replayVersion !== EXACT_BUILD) {
    return { status: 'UNSUPPORTED_VERSION', profile: null, candidate: null };
  }
  const candidate = DEEP_RECOVERY_SEMANTIC_PROFILES[capability] ?? null;
  if (!candidate) return { status: 'UNAVAILABLE', profile: null, candidate: null };
  return {
    status: candidate.status,
    profile: candidate.enabled ? candidate : null,
    candidate,
  };
}

module.exports = {
  DEEP_RECOVERY_SEMANTIC_PROFILES,
  EXACT_BUILD,
  RUNTIME_IMAGE_SHA256,
  deepRecoveryProfileFor,
};
