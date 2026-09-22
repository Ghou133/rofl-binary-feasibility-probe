const crypto = require('node:crypto');

const {
  buffEvent,
  damageEvent,
  deathEvent,
  healEvent,
  levelTransitionEvent,
  protectionEvent,
  shieldEvent,
  spellCastEvent,
} = require('../events');
const { levelMapping } = require('../level_transition');
const { walkBlocks } = require('../rofl');

const PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-hero-death-v1',
  replay_version: '16.15.801.3452',
  replay_block_packet_id: 0x0160,
  payload_length: 5,
  stream_tag: 1,
  stream: 'game_chunk',
  participant_param_low_byte_base: 0xad,
  champion_network_id_prefix: 0x40000000,
});

const DAMAGE_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-unit-apply-damage-unicorn-v1',
  replay_version: '16.15.801.3452',
  replay_block_packet_id: 0x028a,
  client_opcode: 0x028a,
  stream_tag: 1,
  stream: 'game_chunk',
  runtime_image_sha256: '7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb',
  constructor_rva: 0x00eb1300,
  deserialize_rva: 0x00f1c4b0,
  object_size: 0x34,
});

const DAMAGE_TYPE_BY_CODE = Object.freeze({
  0: 'physical',
  1: 'magic',
  2: 'true',
});

const CRITICAL_DAMAGE_RESULT_CODE = 3;

const LEVEL_UP_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-npc-level-up-unicorn-v1',
  emulator_profile: 'npc_level_up',
  replay_version: '16.15.801.3452',
  replay_block_packet_id: 0x025a,
  client_opcode: 0x025a,
  stream_tag: 1,
  stream: 'game_chunk',
  runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
  constructor_rva: 0x00e82060,
  deserialize_rva: 0x00efaa50,
  object_size: 0x18,
  packet_class_association: Object.freeze([
    'PKT_NPC_LevelUp_Global_s',
    'PKT_NPC_LevelUp_s',
  ]),
  transition_evidence: 'VERIFIED_DIRECT',
  level_mapping_evidence: 'VERIFIED_DERIVED',
  level_mapping_version: '16.15.801.3452',
});

const CAST_SPELL_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-cast-spell-unicorn-v1',
  replay_version: '16.15.801.3452',
  replay_block_packet_id: 0x0459,
  client_opcode: 0x0459,
  stream_tag: 1,
  stream: 'game_chunk',
  runtime_image_sha256: '7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb',
  spell_dictionary_sha256: 'f9dcc019bbde13996242a5ba73e197ca2a27931f820b3a18e23f863b57576f63',
  constructor_rva: 0x00e817a0,
  deserialize_rva: 0x010bbb00,
  business_constructor_rva: 0x008f5970,
  business_translate_rva: 0x0090c4c0,
  object_size: 0x158,
  business_object_size: 0x194,
  spell_key_method: 'ELFHash(lowercase(mScriptName))',
});

const BUFF_PROFILES = Object.freeze({
  add: Object.freeze({
    id: 'rofl-16.15.801.3452-npc-buff-add2-unicorn-v1',
    operation: 'ADD',
    emulator_profile: 'npc_buff_add2',
    replay_version: PROFILE.replay_version,
    replay_block_packet_id: 0x0406,
    client_opcode: 0x0406,
    stream_tag: 1,
    stream: 'game_chunk',
    runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    constructor_rva: 0x00e80970,
    deserialize_rva: 0x010b53f0,
    object_size: 0x70,
  }),
  remove: Object.freeze({
    id: 'rofl-16.15.801.3452-npc-buff-remove2-unicorn-v1',
    operation: 'REMOVE',
    emulator_profile: 'npc_buff_remove2',
    replay_version: PROFILE.replay_version,
    replay_block_packet_id: 0x0031,
    client_opcode: 0x0031,
    stream_tag: 1,
    stream: 'game_chunk',
    runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    constructor_rva: 0x00e80f90,
    deserialize_rva: 0x010b8500,
    object_size: 0x1c,
  }),
  update_count: Object.freeze({
    id: 'rofl-16.15.801.3452-npc-buff-update-count-unicorn-v1',
    operation: 'UPDATE_COUNT',
    emulator_profile: 'npc_buff_update_count',
    replay_version: PROFILE.replay_version,
    replay_block_packet_id: 0x0256,
    client_opcode: 0x0256,
    stream_tag: 1,
    stream: 'game_chunk',
    runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    constructor_rva: 0x00e81440,
    deserialize_rva: 0x010ba590,
    object_size: 0x24,
  }),
});

const ON_EVENT_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-on-event-protection-v4',
  replay_version: PROFILE.replay_version,
  replay_block_packet_id: 0x009e,
  client_opcode: 0x009e,
  stream_tag: 1,
  stream: 'game_chunk',
  runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
  constructor_rva: 0x00e827e0,
  deserialize_rva: 0x00fe12f0,
  object_size: 0x28,
  vtable_rva: 0x01b14f80,
  callback_rva: 0x004d1120,
  events: Object.freeze({
    heal: Object.freeze({
      event_id: 0x004b,
      event_name: 'ParamsHeal',
      params_size: 0x34,
      amount_offset: 0x18,
      consumer_rva: 0x00315530,
    }),
    shield_target_route: Object.freeze({
      event_id: 0x00ed,
      event_name: 'ShieldingParams',
      params_size: 0x14,
      amount_offset: 0x10,
      consumer_rva: 0x00329100,
    }),
    shield_source_route: Object.freeze({
      event_id: 0x00ee,
      event_name: 'ShieldingParams',
      params_size: 0x14,
      amount_offset: 0x10,
      consumer_rva: 0x0031bb90,
    }),
    damage_shielded: Object.freeze({
      event_id: 0x00ef,
      event_name: 'DamageShieldedParams',
      consumer_rva: 0x001f23b0,
    }),
  }),
});

const SHIELD_DAMAGE_PROFILE = Object.freeze({
  id: 'rofl-16.15.801.3452-unit-apply-shield-damage-v4',
  replay_version: PROFILE.replay_version,
  replay_block_packet_id: 0x0017,
  client_opcode: 0x0017,
  stream_tag: 1,
  stream: 'game_chunk',
  runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
  constructor_noop_rva: 0x002cd334,
  factory_inline_construction_rva: 0x00ede2f8,
  deserialize_rva: 0x00f1db80,
  callback_rva: 0x0029edd0,
  object_size: 0x20,
});

const PROTECTION_CAST_KINDS = Object.freeze({
  EyeOfTheStorm: 'SHIELD_CAST',
  KarmaSolKimShield: 'SHIELD_CAST',
  LuluE: 'SHIELD_CAST',
  LuluR: 'TEMPORARY_HP_CAST',
  MilioE: 'SHIELD_CAST',
  MilioR: 'HEAL_CAST',
  MilioW: 'HEAL_CAST',
  NamiE: 'BUFF_CAST',
  NamiW: 'HEAL_CAST',
  ReapTheWhirlwind: 'HEAL_CAST',
  SeraphineW: 'SHIELD_OR_HEAL_CAST',
  SonaW: 'HEAL_AND_SHIELD_CAST',
  SorakaR: 'HEAL_CAST',
  SorakaW: 'HEAL_CAST',
  YuumiE: 'SHIELD_CAST',
  YuumiR: 'HEAL_CAST',
});

const PROTECTION_CASTS_REQUIRING_ALLIED_CHAMPION_TARGET = new Set([
  'LuluE',
  'NamiW',
]);

function payloadSha256(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function rawPacketRef(replay, chunk, block) {
  return {
    source_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    compressed_body_offset: chunk.body_offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    payload_length: block.payload_length,
    payload_sha256: payloadSha256(block.payload),
  };
}

function participantIdFromParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const participantId = (rawParam & 0xff) - PROFILE.participant_param_low_byte_base;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function championNetworkIdFromParam(rawParam) {
  const participantId = participantIdFromParam(rawParam);
  if (participantId === null) return null;
  return (PROFILE.champion_network_id_prefix | (rawParam & 0xff)) >>> 0;
}

function championByParticipant(replay) {
  const result = new Map();
  const stats = Array.isArray(replay.tail?.stats) ? replay.tail.stats : [];
  for (let index = 0; index < stats.length; index += 1) {
    result.set(index + 1, stats[index]?.SKIN ?? null);
  }
  return result;
}

function participantMetadata(replay) {
  const result = new Map();
  const stats = Array.isArray(replay.tail?.stats) ? replay.tail.stats : [];
  for (let index = 0; index < stats.length; index += 1) {
    const participantId = index + 1;
    const teamId = Number(stats[index]?.TEAM);
    result.set(participantId, {
      participant_id: participantId,
      network_id: (PROFILE.champion_network_id_prefix
        | (PROFILE.participant_param_low_byte_base + participantId)) >>> 0,
      champion: stats[index]?.SKIN ?? null,
      team_id: Number.isFinite(teamId) ? teamId : null,
      entity_type: 'champion',
      confidence: 'VERIFIED_DIRECT',
      provenance: 'ROFL_METADATA_STATS_JSON_AND_VERIFIED_NETWORK_ID_RULE',
    });
  }
  return result;
}

function participantIdFromChampionNetworkId(networkId) {
  if (!Number.isInteger(networkId)) return null;
  const normalized = networkId >>> 0;
  const first = (PROFILE.champion_network_id_prefix
    | (PROFILE.participant_param_low_byte_base + 1)) >>> 0;
  const last = (PROFILE.champion_network_id_prefix
    | (PROFILE.participant_param_low_byte_base + 10)) >>> 0;
  if (normalized < first || normalized > last) return null;
  return (normalized & 0xff) - PROFILE.participant_param_low_byte_base;
}

function entityFromNetworkId(networkId, participants) {
  const participantId = participantIdFromChampionNetworkId(networkId);
  return participantId === null ? null : participants.get(participantId) ?? null;
}

function damageRawPacketRef(row) {
  return {
    source_path: row.replay_path,
    replay_sha256: row.replay_sha256,
    chunk_index: row.chunk_index,
    chunk_id: row.chunk_id,
    chunk_stream: row.chunk_stream,
    chunk_file_offset: row.chunk_file_offset,
    compressed_body_offset: row.compressed_body_offset,
    decompressed_block_offset: row.decompressed_block_offset,
    decompressed_payload_offset: row.decompressed_payload_offset,
    packet_id: row.packet_id,
    payload_length: row.payload_length,
    payload_sha256: row.raw_payload_sha256,
  };
}

function onEventRawId(row) {
  return [
    row.replay_sha256,
    row.chunk_index,
    row.decompressed_block_offset,
    row.occurrence_index,
  ].join(':');
}

function onEventRawPacketRef(row) {
  const raw = row.raw_packet_ref || {};
  return {
    source_path: raw.replay_path ?? row.replay_path,
    replay_sha256: raw.replay_sha256 ?? row.replay_sha256,
    chunk_index: raw.chunk_index ?? row.chunk_index,
    chunk_id: raw.chunk_id ?? row.chunk_id,
    chunk_stream: raw.chunk_stream ?? row.chunk_stream,
    chunk_file_offset: raw.chunk_file_offset ?? row.chunk_file_offset,
    compressed_body_offset: raw.compressed_body_offset ?? row.compressed_body_offset,
    decompressed_block_offset: raw.decompressed_block_offset
      ?? row.decompressed_block_offset,
    decompressed_payload_offset: raw.decompressed_payload_offset
      ?? row.decompressed_payload_offset,
    replay_time_ms: raw.replay_time_ms ?? row.replay_time_ms,
    occurrence_index: raw.occurrence_index ?? row.occurrence_index,
    packet_id: raw.packet_id,
    payload_length: raw.payload_length,
    raw_param: raw.raw_param ?? row.raw_param,
    raw_param_hex: raw.raw_param_hex ?? row.raw_param_hex,
    payload_sha256: raw.raw_payload_sha256 ?? row.raw_payload_sha256,
  };
}

function isOnEventDecodedRow(replay, row) {
  if (replay.header.version !== ON_EVENT_PROFILE.replay_version) return false;
  if (row.replay_sha256 !== replay.source_sha256
      || row.replay_version !== replay.header.version
      || row.decoder_profile !== ON_EVENT_PROFILE.id
      || row.raw_packet_ref?.packet_id !== ON_EVENT_PROFILE.replay_block_packet_id
      || row.deserialize_return_al === 0
      || row.fully_consumed !== true) return false;
  return Number.isInteger(row.raw_param)
    && Number.isInteger(row.event_id)
    && Number.isInteger(row.schema_id)
    && row.schema_matches_expected === true
    && Number.isInteger(row.parameter_size)
    && row.parameter_size >= 0
    && Number.isInteger(row.parameter_capacity)
    && row.parameter_capacity >= row.parameter_size
    && row.parameter_size_matches_expected === true
    && typeof row.parameter_blob_sha256 === 'string';
}

function isShieldDamageDecodedRow(replay, row) {
  const raw = row?.raw_packet_ref;
  if (replay.header.version !== SHIELD_DAMAGE_PROFILE.replay_version
      || row?.replay_sha256 !== replay.source_sha256
      || row?.replay_version !== replay.header.version
      || row?.decoder_profile !== SHIELD_DAMAGE_PROFILE.id
      || row?.decoder_runtime_image_sha256 !== SHIELD_DAMAGE_PROFILE.runtime_image_sha256
      || row?.packet_id !== SHIELD_DAMAGE_PROFILE.replay_block_packet_id
      || raw?.packet_id !== SHIELD_DAMAGE_PROFILE.replay_block_packet_id
      || row?.event_kind !== 'SHIELD_ABSORBED_DIRECT'
      || row?.semantic_status !== 'VERIFIED_DIRECT'
      || !Number.isInteger(row?.deserialize_return_al)
      || row.deserialize_return_al === 0
      || row?.fully_consumed !== true
      || row?.network_fields_agree !== true
      || row?.target_matches_raw_param !== true) return false;

  const targetNetworkId = row.target_network_id;
  return Number.isInteger(targetNetworkId)
    && targetNetworkId >= 0
    && targetNetworkId <= 0xffffffff
    && Number.isInteger(row.network_id_field_14)
    && row.network_id_field_14 === targetNetworkId
    && Number.isInteger(row.raw_param)
    && row.raw_param === targetNetworkId
    && Number.isFinite(row.shield_absorbed_amount)
    && row.shield_absorbed_amount >= 0
    && typeof row.shield_absorbed_amount_bits_hex === 'string'
    && typeof row.raw_payload_hex === 'string'
    && Number.isInteger(row.bytes_consumed)
    && row.bytes_consumed > 0
    && Number.isInteger(row.replay_time_ms)
    && row.replay_time_ms >= 0
    && Number.isInteger(row.chunk_index)
    && row.chunk_index >= 0
    && Number.isInteger(row.chunk_id)
    && Number.isInteger(row.chunk_file_offset)
    && Number.isInteger(row.compressed_body_offset)
    && Number.isInteger(row.decompressed_block_offset)
    && Number.isInteger(row.decompressed_payload_offset)
    && Number.isInteger(row.occurrence_index)
    && row.occurrence_index >= 0
    && row.chunk_stream === SHIELD_DAMAGE_PROFILE.stream
    && typeof row.replay_path === 'string'
    && raw.replay_path === row.replay_path
    && raw.replay_sha256 === replay.source_sha256
    && raw.replay_time_ms === row.replay_time_ms
    && raw.chunk_index === row.chunk_index
    && raw.chunk_id === row.chunk_id
    && raw.chunk_stream === row.chunk_stream
    && raw.chunk_file_offset === row.chunk_file_offset
    && raw.compressed_body_offset === row.compressed_body_offset
    && raw.decompressed_block_offset === row.decompressed_block_offset
    && raw.decompressed_payload_offset === row.decompressed_payload_offset
    && raw.occurrence_index === row.occurrence_index
    && Number.isInteger(raw.payload_length)
    && raw.payload_length >= 0
    && raw.raw_param === targetNetworkId
    && raw.raw_param_hex === row.raw_param_hex
    && typeof row.raw_payload_sha256 === 'string'
    && raw.raw_payload_sha256 === row.raw_payload_sha256;
}

function shieldAbsorptionProtectionEventFromDecodedRow(
  replay,
  row,
  participants = participantMetadata(replay),
) {
  if (!isShieldDamageDecodedRow(replay, row)) return null;
  const targetNetworkId = row.target_network_id >>> 0;
  const target = entityFromNetworkId(targetNetworkId, participants);
  const rawRef = onEventRawPacketRef(row);
  return protectionEvent({
    protection_event_id: [
      'shield-absorbed',
      row.replay_sha256,
      row.chunk_index,
      row.decompressed_block_offset,
      row.occurrence_index,
    ].join(':'),
    protection_type: 'SHIELD_ABSORBED',
    source_event_type: 'shield_absorption',
    replay_time_ms: row.replay_time_ms,
    source_network_id: null,
    source_participant_id: null,
    source_champion: null,
    source_team_id: null,
    source_entity_type: 'unknown',
    caster_network_id: null,
    caster_participant_id: null,
    caster_champion: null,
    target_network_id: targetNetworkId,
    target_participant_id: target?.participant_id ?? null,
    target_champion: target?.champion ?? null,
    target_team_id: target?.team_id ?? null,
    target_entity_type: target ? 'champion' : 'unknown',
    shield_instance_id: null,
    generated_amount: null,
    remaining_amount: null,
    absorbed_amount: row.shield_absorbed_amount,
    unused_amount: null,
    direct_heal_amount: null,
    raw_heal_amount: null,
    effective_heal_amount: null,
    overheal_amount: null,
    temporary_hp_amount: null,
    current_hp: null,
    max_hp: null,
    protection_start_ms: null,
    protection_end_ms: null,
    spell_identifier: null,
    spell_slot: null,
    amount_bits_hex: row.shield_absorbed_amount_bits_hex,
    amount_semantics: 'VERIFIED_DIRECT_TARGET_TOTAL_SHIELD_ABSORBED',
    measurement_status: 'VERIFIED_DIRECT_TARGET_TOTAL',
    absorption_attribution_status: 'UNATTRIBUTED_TARGET_TOTAL',
    source_attribution_status: 'UNAVAILABLE_TARGET_TOTAL_ONLY',
    shield_instance_attribution_status: 'UNAVAILABLE',
    protocol_opcode: SHIELD_DAMAGE_PROFILE.client_opcode,
    protocol_opcode_hex: '0x0017',
    protocol_packet_type: row.packet_type_name,
    protocol_event_kind: row.event_kind,
    protocol_fields: {
      protocol_field_10: row.protocol_field_10,
      duplicate_target_network_id: row.network_id_field_14,
      network_fields_agree: row.network_fields_agree,
      target_matches_raw_param: row.target_matches_raw_param,
    },
    ordered_damage_neighbor: row.related_unit_apply_damage ?? null,
    decoder_profile: SHIELD_DAMAGE_PROFILE.id,
    decoder_runtime_image_sha256: SHIELD_DAMAGE_PROFILE.runtime_image_sha256,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawRef,
    raw_packet_refs: [rawRef],
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      target_network_id: 'VERIFIED_DIRECT',
      absorbed_amount: 'VERIFIED_DIRECT',
      source_network_id: 'UNAVAILABLE',
      caster_network_id: 'UNAVAILABLE',
      shield_instance_id: 'UNAVAILABLE',
      spell_identifier: 'UNAVAILABLE',
      generated_amount: 'UNAVAILABLE',
      remaining_amount: 'UNAVAILABLE',
      unused_amount: 'UNAVAILABLE',
      raw_heal_amount: 'UNAVAILABLE',
      effective_heal_amount: 'UNAVAILABLE',
      overheal_amount: 'UNAVAILABLE',
      temporary_hp_amount: 'UNAVAILABLE',
      current_hp: 'UNAVAILABLE',
      max_hp: 'UNAVAILABLE',
    },
  });
}

function protectionEventFromDecodedRow(
  replay,
  row,
  participants = participantMetadata(replay),
) {
  if (!isOnEventDecodedRow(replay, row)) return null;
  const fields = row;
  const heal = fields.event_id === ON_EVENT_PROFILE.events.heal.event_id;
  const shield = fields.event_id === ON_EVENT_PROFILE.events.shield_target_route.event_id
    || fields.event_id === ON_EVENT_PROFILE.events.shield_source_route.event_id;
  if (!heal && !shield) return null;
  const expectedSize = heal
    ? ON_EVENT_PROFILE.events.heal.params_size
    : ON_EVENT_PROFILE.events.shield_target_route.params_size;
  if (fields.parameter_size !== expectedSize
      || !Number.isInteger(fields.source_network_id)
      || !Number.isInteger(fields.target_network_id)
      || !Number.isFinite(fields.amount)
      || fields.amount < 0) return null;

  const sourceNetworkId = fields.source_network_id >>> 0;
  const targetNetworkId = fields.target_network_id >>> 0;
  const source = entityFromNetworkId(sourceNetworkId, participants);
  const target = entityFromNetworkId(targetNetworkId, participants);
  const rawRef = onEventRawPacketRef(row);
  const common = {
    protection_event_id: onEventRawId(row),
    replay_time_ms: row.replay_time_ms,
    source_network_id: sourceNetworkId,
    target_network_id: targetNetworkId,
    source_participant_id: source?.participant_id ?? null,
    target_participant_id: target?.participant_id ?? null,
    source_champion: source?.champion ?? null,
    target_champion: target?.champion ?? null,
    source_team_id: source?.team_id ?? null,
    target_team_id: target?.team_id ?? null,
    source_entity_type: source ? 'champion' : 'unknown',
    target_entity_type: target ? 'champion' : 'unknown',
    amount_bits_hex: fields.amount_bits_hex ?? null,
    protocol_event_id: fields.event_id,
    protocol_event_id_hex: fields.event_id_hex,
    protocol_event_name: fields.parameter_type,
    dispatch_event_name: fields.event_name,
    protocol_event_kind: fields.event_kind,
    schema_id: fields.schema_id,
    schema_id_hex: fields.schema_id_hex,
    event_params_size: fields.parameter_size,
    event_params_sha256: fields.parameter_blob_sha256,
    event_params_hex: fields.parameter_blob_hex,
    decoder_profile: ON_EVENT_PROFILE.id,
    decoder_runtime_image_sha256: ON_EVENT_PROFILE.runtime_image_sha256,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawRef,
    raw_packet_refs: [rawRef],
  };
  if (heal) {
    return healEvent({
      ...common,
      direct_heal_amount: fields.amount,
      raw_heal_amount: null,
      effective_heal_amount: null,
      overheal_amount: null,
      amount_semantics: 'DIRECT_REPORTED_HEAL_AMOUNT_RAW_VS_EFFECTIVE_UNRESOLVED',
      deduplication_status: 'RAW_OCCURRENCE_PRESERVED_SEMANTIC_DEDUPLICATION_UNPROVEN',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        source_network_id: 'VERIFIED_DIRECT',
        target_network_id: 'VERIFIED_DIRECT',
        direct_heal_amount: 'VERIFIED_DIRECT',
        raw_heal_amount: 'UNAVAILABLE',
        effective_heal_amount: 'UNAVAILABLE',
        overheal_amount: 'UNAVAILABLE',
        spell_identifier: 'UNAVAILABLE',
      },
      protocol_fields: {
        protocol_field_08: fields.protocol_field_08,
        protocol_field_0c: fields.protocol_field_0c,
        protocol_field_10: fields.protocol_field_10,
        protocol_field_1c: fields.protocol_field_1c,
        protocol_field_20: fields.protocol_field_20,
        protocol_field_24: fields.protocol_field_24,
        protocol_field_28: fields.protocol_field_28,
        protocol_field_2c: fields.protocol_field_2c,
        protocol_field_30: fields.protocol_field_30,
      },
    });
  }
  return shieldEvent({
    ...common,
    shield_instance_id: null,
    shield_type: null,
    generated_amount: fields.amount,
    remaining_amount: null,
    absorbed_amount: null,
    unused_amount: null,
    apply_time_ms: row.replay_time_ms,
    remove_time_ms: null,
    route_kind: fields.route_kind,
    route_event_ids: [fields.event_id],
    deduplication_status: 'RAW_ROUTE_OCCURRENCE',
    amount_semantics: 'DIRECT_GENERATED_SHIELD_APPLICATION_AMOUNT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      source_network_id: 'VERIFIED_DIRECT',
      target_network_id: 'VERIFIED_DIRECT',
      generated_amount: 'VERIFIED_DIRECT',
      shield_type: 'UNAVAILABLE',
      remaining_amount: 'UNAVAILABLE',
      absorbed_amount: 'UNAVAILABLE',
      unused_amount: 'UNAVAILABLE',
      spell_identifier: 'UNAVAILABLE',
    },
    protocol_fields: {
      protocol_field_04: fields.protocol_field_04,
    },
  });
}

function damageEventFromDecodedRow(replay, row, participants = participantMetadata(replay)) {
  if (replay.header.version !== DAMAGE_PROFILE.replay_version) return null;
  if (row.replay_sha256 !== replay.source_sha256
      || row.replay_version !== replay.header.version
      || row.packet_id !== DAMAGE_PROFILE.replay_block_packet_id
      || row.decoder_profile !== DAMAGE_PROFILE.id
      || row.decoder_runtime_image_sha256 !== DAMAGE_PROFILE.runtime_image_sha256
      || row.decoded_opcode !== DAMAGE_PROFILE.client_opcode
      || row.opcode_matches_profile !== true
      || row.deserialize_return_al === 0
      || row.fully_consumed !== true) return null;

  const fields = row.decoded_fields || {};
  const sourceNetworkId = fields.source_network_id;
  const targetNetworkId = fields.target_network_id;
  const amount = fields.amount;
  if (!Number.isInteger(sourceNetworkId)
      || !Number.isInteger(targetNetworkId)
      || !Number.isFinite(amount)
      || amount < 0) return null;

  const source = entityFromNetworkId(sourceNetworkId, participants);
  const target = entityFromNetworkId(targetNetworkId, participants);
  const damageTypeCode = Number.isInteger(fields.field_21) ? fields.field_21 : null;
  const damageType = damageTypeCode === null ? null : DAMAGE_TYPE_BY_CODE[damageTypeCode] ?? null;
  const spellKey = Number.isInteger(fields.field_1c) ? fields.field_1c >>> 0 : null;
  const damageResultCode = Number.isInteger(fields.field_20) ? fields.field_20 : null;
  const isCritical = damageResultCode === CRITICAL_DAMAGE_RESULT_CODE ? true : null;
  return damageEvent({
    replay_time_ms: row.replay_time_ms,
    source_network_id: sourceNetworkId >>> 0,
    target_network_id: targetNetworkId >>> 0,
    source_participant_id: source?.participant_id ?? null,
    target_participant_id: target?.participant_id ?? null,
    source_champion: source?.champion ?? null,
    target_champion: target?.champion ?? null,
    source_team_id: source?.team_id ?? null,
    target_team_id: target?.team_id ?? null,
    source_entity_type: source ? 'champion' : 'unknown',
    target_entity_type: target ? 'champion' : 'unknown',
    amount,
    damage_type: damageType,
    damage_type_code: damageTypeCode,
    damage_type_status: damageType === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
    spell_key: spellKey,
    spell_key_hex: spellKey === null ? null : `0x${spellKey.toString(16).padStart(8, '0')}`,
    spell_key_status: spellKey === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
    damage_result_code: damageResultCode,
    is_critical: isCritical,
    critical_status: isCritical === true ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      source_network_id: 'VERIFIED_DIRECT',
      target_network_id: 'VERIFIED_DIRECT',
      amount: 'VERIFIED_DIRECT',
      source_participant_id: source ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      target_participant_id: target ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      damage_type: damageType === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
      damage_type_code: damageTypeCode === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
      spell_key: spellKey === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
      damage_result_code: damageResultCode === null ? 'UNAVAILABLE' : 'VERIFIED_DIRECT',
      is_critical: isCritical === true ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      is_basic_attack: 'UNAVAILABLE',
      source_type: 'UNAVAILABLE',
      spell: 'UNAVAILABLE',
      item: 'UNAVAILABLE',
      rune: 'UNAVAILABLE',
      passive: 'UNAVAILABLE',
      pre_mitigation_amount: 'UNAVAILABLE',
      post_mitigation_amount: 'UNAVAILABLE',
      effective_damage: 'UNAVAILABLE',
    },
    decoder_profile: DAMAGE_PROFILE.id,
    decoder_runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: damageRawPacketRef(row),
    protocol_fields: {
      extra_amount: fields.extra_amount,
      field_18: fields.field_18,
      field_1c: fields.field_1c,
      field_20: fields.field_20,
      field_21: fields.field_21,
      field_30: fields.field_30,
    },
  });
}

const LEVEL_SOURCE_PACKET_FIELDS = Object.freeze([
  'schema_version',
  'replay_path',
  'replay_sha256',
  'replay_version',
  'replay_label',
  'chunk_index',
  'chunk_id',
  'chunk_stream',
  'chunk_file_offset',
  'compressed_body_offset',
  'decompressed_block_offset',
  'decompressed_payload_offset',
  'replay_time_ms',
  'occurrence_index',
  'packet_id',
  'packet_type',
  'payload_length',
  'raw_param',
  'raw_param_hex',
  'raw_payload_hex',
  'raw_payload_sha256',
]);

const LEVEL_RAW_PACKET_REF_FIELDS = Object.freeze({
  source_path: 'replay_path',
  replay_sha256: 'replay_sha256',
  chunk_index: 'chunk_index',
  chunk_id: 'chunk_id',
  chunk_stream: 'chunk_stream',
  chunk_file_offset: 'chunk_file_offset',
  compressed_body_offset: 'compressed_body_offset',
  decompressed_block_offset: 'decompressed_block_offset',
  decompressed_payload_offset: 'decompressed_payload_offset',
  replay_time_ms: 'replay_time_ms',
  occurrence_index: 'occurrence_index',
  packet_id: 'packet_id',
  payload_length: 'payload_length',
  raw_param: 'raw_param',
  raw_param_hex: 'raw_param_hex',
  payload_sha256: 'raw_payload_sha256',
});

function isVerifiedLevelSourcePacket(replay, row, sourceRow) {
  if (!sourceRow || typeof sourceRow !== 'object') return false;
  if (LEVEL_SOURCE_PACKET_FIELDS.some((field) => row?.[field] !== sourceRow[field])) {
    return false;
  }
  const expectedRawParamHex = Number.isInteger(sourceRow.raw_param)
    ? `0x${(sourceRow.raw_param >>> 0).toString(16).padStart(8, '0')}`
    : null;
  if (sourceRow.schema_version !== 1
      || sourceRow.replay_path !== replay.source_path
      || sourceRow.replay_sha256 !== replay.source_sha256
      || !/^[0-9a-f]{64}$/.test(sourceRow.replay_sha256)
      || sourceRow.replay_version !== replay.header.version
      || sourceRow.chunk_stream !== LEVEL_UP_PROFILE.stream
      || sourceRow.packet_type !== '0x025a'
      || !Number.isInteger(sourceRow.chunk_index)
      || sourceRow.chunk_index < 0
      || !Number.isInteger(sourceRow.chunk_id)
      || sourceRow.chunk_id < 0
      || !Number.isInteger(sourceRow.chunk_file_offset)
      || sourceRow.chunk_file_offset < 0
      || !Number.isInteger(sourceRow.compressed_body_offset)
      || sourceRow.compressed_body_offset < 0
      || !Number.isInteger(sourceRow.decompressed_block_offset)
      || sourceRow.decompressed_block_offset < 0
      || !Number.isInteger(sourceRow.decompressed_payload_offset)
      || sourceRow.decompressed_payload_offset < 0
      || !Number.isInteger(sourceRow.raw_param)
      || sourceRow.raw_param < 0
      || sourceRow.raw_param > 0xffffffff
      || sourceRow.raw_param_hex !== expectedRawParamHex
      || typeof sourceRow.raw_payload_hex !== 'string'
      || !/^(?:[0-9a-f]{2})*$/.test(sourceRow.raw_payload_hex)
      || typeof sourceRow.raw_payload_sha256 !== 'string'
      || !/^[0-9a-f]{64}$/.test(sourceRow.raw_payload_sha256)) return false;
  const payload = Buffer.from(sourceRow.raw_payload_hex, 'hex');
  return payload.length === sourceRow.payload_length
    && payloadSha256(payload) === sourceRow.raw_payload_sha256;
}

function isVerifiedLevelRawPacketRef(row) {
  const raw = row?.raw_packet_ref;
  if (!raw || typeof raw !== 'object') return false;
  return Object.entries(LEVEL_RAW_PACKET_REF_FIELDS)
    .every(([rawField, rowField]) => raw[rawField] === row[rowField]);
}

function isLevelTransitionDecodedRow(replay, row, sourceRow = null) {
  const fields = row?.decoded_fields || {};
  return replay.header.version === LEVEL_UP_PROFILE.replay_version
    && isVerifiedLevelSourcePacket(replay, row, sourceRow)
    && isVerifiedLevelRawPacketRef(row)
    && row?.replay_sha256 === replay.source_sha256
    && row?.replay_version === replay.header.version
    && row?.decoder_profile === LEVEL_UP_PROFILE.id
    && row?.decoder_runtime_image_sha256 === LEVEL_UP_PROFILE.runtime_image_sha256
    && row?.decoder_constructor_rva === LEVEL_UP_PROFILE.constructor_rva
    && row?.decoder_deserialize_rva === LEVEL_UP_PROFILE.deserialize_rva
    && row?.decoder_object_size === LEVEL_UP_PROFILE.object_size
    && row?.packet_id === LEVEL_UP_PROFILE.replay_block_packet_id
    && row?.decoded_opcode === LEVEL_UP_PROFILE.client_opcode
    && row?.opcode_matches_profile === true
    && Number.isInteger(row?.deserialize_return_al)
    && row.deserialize_return_al !== 0
    && row?.fully_consumed === true
    && Number.isInteger(row?.raw_param)
    && row.raw_param >= 0
    && row.raw_param <= 0xffffffff
    && Number.isInteger(row?.replay_time_ms)
    && row.replay_time_ms >= 0
    && Number.isInteger(row?.occurrence_index)
    && row.occurrence_index >= 0
    && Number.isInteger(row?.bytes_consumed)
    && typeof row?.base_header_hex === 'string'
    && /^(?:[0-9a-f]{2})+$/.test(row.base_header_hex)
    && row.bytes_consumed === row.payload_length + (row.base_header_hex.length / 2)
    && Number.isInteger(row?.wrapper_return_al)
    && row.wrapper_return_al !== 0
    && row?.wrapper_bytes_consumed === 2
    && Number.isInteger(fields.field_10)
    && fields.field_10 >= 0
    && fields.field_10 <= 0xff
    && Number.isInteger(fields.field_11)
    && fields.field_11 >= 0
    && fields.field_11 <= 0xff
    && typeof row?.raw_payload_sha256 === 'string';
}

function levelTransitionEventFromDecodedRow(
  replay,
  row,
  participants = participantMetadata(replay),
  sourceRow = null,
) {
  if (!isLevelTransitionDecodedRow(replay, row, sourceRow)) return null;
  const entityNetworkId = row.raw_param >>> 0;
  const entity = entityFromNetworkId(entityNetworkId, participants);
  if (!entity) return null;

  const fields = row.decoded_fields;
  const isInitialization = row.replay_time_ms === 0;
  const mapping = levelMapping(fields.field_10, replay.header.version);
  const rawRef = {
    ...damageRawPacketRef(row),
    replay_time_ms: row.replay_time_ms,
    occurrence_index: row.occurrence_index,
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
  };
  const mappingEvidence = isInitialization ? 'UNAVAILABLE' : mapping.evidence;
  return levelTransitionEvent({
    replay_time_ms: row.replay_time_ms,
    timestamp_ms: row.replay_time_ms,
    source_network_id: entityNetworkId,
    target_network_id: entityNetworkId,
    entity_network_id: entityNetworkId,
    source_participant_id: entity.participant_id,
    target_participant_id: entity.participant_id,
    participant_id: entity.participant_id,
    source_champion: entity.champion,
    target_champion: entity.champion,
    champion: entity.champion,
    champion_id: null,
    source_team_id: entity.team_id,
    target_team_id: entity.team_id,
    raw_field_10: fields.field_10,
    raw_field_11: fields.field_11,
    level_before: isInitialization ? null : mapping.level_before,
    level_after: isInitialization ? null : mapping.level_after,
    transition_evidence: LEVEL_UP_PROFILE.transition_evidence,
    level_mapping_evidence: mappingEvidence,
    level_mapping_qualification: isInitialization
      ? 'TIMESTAMP_ZERO_PRE_GAME_INITIALIZATION'
      : mapping.qualification,
    game_version: replay.header.version,
    is_initialization: isInitialization,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      timestamp_ms: 'VERIFIED_DIRECT',
      entity_network_id: 'VERIFIED_DIRECT',
      raw_field_10: 'VERIFIED_DIRECT',
      raw_field_11: 'VERIFIED_DIRECT',
      participant_id: 'VERIFIED_DERIVED',
      champion: 'VERIFIED_DERIVED',
      champion_id: 'UNAVAILABLE',
      level_before: mappingEvidence,
      level_after: mappingEvidence,
    },
    decoder_profile: LEVEL_UP_PROFILE.id,
    decoder_runtime_image_sha256: LEVEL_UP_PROFILE.runtime_image_sha256,
    packet_class_association: LEVEL_UP_PROFILE.packet_class_association,
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawRef,
  });
}

function spellDictionaryEntry(dictionary, fields) {
  if (!Number.isInteger(fields.spell_key)) return null;
  const key = `0x${(fields.spell_key >>> 0).toString(16).padStart(8, '0')}`;
  const entries = dictionary?.by_hash?.[key] || [];
  return entries.find((entry) => entry.champion_alias === fields.caster_name)
    ?? entries.find((entry) => entry.champion_alias === null)
    ?? null;
}

function finiteVector(value) {
  return value === null || value === undefined
    || (Array.isArray(value) && value.length === 3 && value.every(Number.isFinite));
}

function isCastSpellDecodedRow(replay, row) {
  if (replay.header.version !== CAST_SPELL_PROFILE.replay_version) return false;
  if (row.replay_sha256 !== replay.source_sha256
      || row.replay_version !== replay.header.version
      || row.packet_id !== CAST_SPELL_PROFILE.replay_block_packet_id
      || row.decoded_opcode !== CAST_SPELL_PROFILE.client_opcode
      || row.opcode_matches_profile !== true
      || row.deserialize_return_al === 0
      || row.fully_consumed !== true) return false;
  const fields = row.decoded_fields || {};
  const targets = Array.isArray(fields.targets) ? fields.targets : [];
  return Number.isInteger(fields.caster_network_id)
    && Number.isInteger(fields.spell_key)
    && Number.isFinite(fields.cast_time_seconds)
    && (fields.caster_name === null || typeof fields.caster_name === 'string')
    && (fields.spell_chain_owner_network_id === null
      || Number.isInteger(fields.spell_chain_owner_network_id))
    && targets.every((target) => Number.isInteger(target.network_id)
      && Number.isInteger(target.hit_result))
    && finiteVector(fields.target_position)
    && finiteVector(fields.target_position_end)
    && finiteVector(fields.cast_direction);
}

function spellEventFromDecodedRow(
  replay,
  row,
  dictionary,
  participants = participantMetadata(replay),
) {
  if (!isCastSpellDecodedRow(replay, row)) return null;

  const fields = row.decoded_fields || {};
  const casterNetworkId = fields.caster_network_id;
  const caster = entityFromNetworkId(casterNetworkId, participants);
  if (!caster || !Number.isInteger(fields.spell_key)) return null;
  const rawTargets = Array.isArray(fields.targets) ? fields.targets : [];
  const targets = rawTargets.map((target) => {
    const entity = entityFromNetworkId(target.network_id, participants);
    return {
      network_id: target.network_id >>> 0,
      participant_id: entity?.participant_id ?? null,
      champion: entity?.champion ?? null,
      team_id: entity?.team_id ?? null,
      entity_type: entity ? 'champion' : 'unknown',
      hit_result: target.hit_result,
      confidence: entity ? 'VERIFIED_DERIVED' : 'VERIFIED_DIRECT',
    };
  });
  const singleTarget = targets.length === 1 ? targets[0] : null;
  const dictionaryEntry = spellDictionaryEntry(dictionary, fields);
  const spellKey = fields.spell_key >>> 0;
  const castTimeMs = Number.isFinite(fields.cast_time_seconds)
    ? fields.cast_time_seconds * 1000
    : null;
  const playerSlots = new Set(['Q', 'W', 'E', 'R']);
  const protectionCandidate = PROTECTION_CAST_KINDS[dictionaryEntry?.script_name] ?? null;
  const alliedChampionTarget = targets.some((target) => target.team_id === caster.team_id);
  const protectionCastKind = protectionCandidate
    && (!PROTECTION_CASTS_REQUIRING_ALLIED_CHAMPION_TARGET.has(dictionaryEntry.script_name)
      || alliedChampionTarget)
    ? protectionCandidate
    : null;
  return spellCastEvent({
    replay_time_ms: row.replay_time_ms,
    source_network_id: casterNetworkId >>> 0,
    caster_network_id: casterNetworkId >>> 0,
    source_participant_id: caster.participant_id,
    caster_participant_id: caster.participant_id,
    source_champion: caster.champion,
    caster_champion: caster.champion,
    source_team_id: caster.team_id,
    caster_team_id: caster.team_id,
    caster_runtime_name: fields.caster_name || null,
    spell_key: spellKey,
    spell_key_hex: `0x${spellKey.toString(16).padStart(8, '0')}`,
    spell_identifier: dictionaryEntry?.script_name ?? null,
    spell_name: dictionaryEntry?.display_name ?? null,
    spell_slot: dictionaryEntry?.spell_slot ?? null,
    spell_phase: dictionaryEntry?.phase ?? null,
    spell_dictionary_source: dictionaryEntry?.source ?? null,
    is_primary_player_ability: dictionaryEntry?.phase === 'PRIMARY'
      && playerSlots.has(dictionaryEntry.spell_slot),
    protection_cast_kind: protectionCastKind,
    protection_cast_confidence: protectionCastKind ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
    shield_amount: null,
    healing_amount: null,
    temporary_hp_amount: null,
    spell_chain_owner_network_id: Number.isInteger(fields.spell_chain_owner_network_id)
      ? fields.spell_chain_owner_network_id >>> 0
      : null,
    target_network_id: singleTarget?.network_id ?? null,
    target_participant_id: singleTarget?.participant_id ?? null,
    target_champion: singleTarget?.champion ?? null,
    target_team_id: singleTarget?.team_id ?? null,
    targets,
    target_count: targets.length,
    target_position: fields.target_position ?? null,
    target_position_end: fields.target_position_end ?? null,
    cast_direction: fields.cast_direction ?? null,
    position: fields.target_position ?? null,
    internal_cast_time_ms: castTimeMs,
    internal_vs_replay_time_delta_ms: castTimeMs === null
      ? null
      : castTimeMs - row.replay_time_ms,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      caster_network_id: 'VERIFIED_DIRECT',
      caster_participant_id: 'VERIFIED_DERIVED',
      spell_key: 'VERIFIED_DIRECT',
      spell_identifier: dictionaryEntry ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      spell_slot: dictionaryEntry?.spell_slot ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      targets: 'VERIFIED_DIRECT',
      target_participant_id: singleTarget?.participant_id
        ? 'VERIFIED_DERIVED'
        : 'UNAVAILABLE',
      target_position: fields.target_position ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
    },
    decoder_profile: CAST_SPELL_PROFILE.id,
    decoder_runtime_image_sha256: CAST_SPELL_PROFILE.runtime_image_sha256,
    spell_dictionary_sha256: CAST_SPELL_PROFILE.spell_dictionary_sha256,
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: damageRawPacketRef(row),
  });
}

function isBuffDecodedRow(replay, row, profile) {
  if (!profile || replay.header.version !== profile.replay_version) return false;
  if (row.replay_sha256 !== replay.source_sha256
      || row.replay_version !== replay.header.version
      || row.packet_id !== profile.replay_block_packet_id
      || row.decoded_opcode !== profile.client_opcode
      || row.opcode_matches_profile !== true
      || row.deserialize_return_al === 0
      || row.fully_consumed !== true) return false;
  const fields = row.decoded_fields || {};
  if (!Number.isInteger(fields.raw_param)
      || fields.raw_param !== row.raw_param
      || !Number.isInteger(fields.buff_slot)
      || fields.buff_slot < 0
      || fields.buff_slot > 0xff) return false;
  if (profile.operation === 'ADD') {
    return Number.isInteger(fields.caster_network_id)
      && Number.isInteger(fields.buff_name_hash)
      && Number.isInteger(fields.buff_type)
      && Number.isInteger(fields.count)
      && Number.isFinite(fields.duration_seconds)
      && fields.duration_seconds >= 0
      && Number.isFinite(fields.running_time_seconds)
      && fields.running_time_seconds >= 0;
  }
  if (profile.operation === 'REMOVE') {
    return Number.isInteger(fields.buff_name_hash)
      && Number.isFinite(fields.removal_time_seconds)
      && fields.removal_time_seconds >= 0;
  }
  return profile.operation === 'UPDATE_COUNT'
    && Number.isInteger(fields.caster_network_id)
    && Number.isInteger(fields.count)
    && Number.isFinite(fields.time_10_seconds)
    && fields.time_10_seconds >= 0
    && Number.isFinite(fields.time_18_seconds)
    && fields.time_18_seconds >= 0;
}

function buffEventFromDecodedRow(
  replay,
  row,
  profile,
  participants = participantMetadata(replay),
) {
  if (!isBuffDecodedRow(replay, row, profile)) return null;
  const fields = row.decoded_fields;
  const targetNetworkId = fields.raw_param >>> 0;
  const target = entityFromNetworkId(targetNetworkId, participants);
  const hasCaster = profile.operation !== 'REMOVE';
  const sourceNetworkId = hasCaster ? fields.caster_network_id >>> 0 : null;
  const source = hasCaster ? entityFromNetworkId(sourceNetworkId, participants) : null;
  const add = profile.operation === 'ADD';
  const remove = profile.operation === 'REMOVE';
  const event = buffEvent({
    replay_time_ms: row.replay_time_ms,
    source_network_id: sourceNetworkId,
    target_network_id: targetNetworkId,
    source_participant_id: source?.participant_id ?? null,
    target_participant_id: target?.participant_id ?? null,
    source_champion: source?.champion ?? null,
    target_champion: target?.champion ?? null,
    source_team_id: source?.team_id ?? null,
    target_team_id: target?.team_id ?? null,
    source_entity_type: source ? 'champion' : hasCaster ? 'unknown' : null,
    target_entity_type: target ? 'champion' : 'unknown',
    buff_operation: profile.operation,
    buff_slot: fields.buff_slot,
    buff_name_hash: add || remove ? fields.buff_name_hash >>> 0 : null,
    buff_name_hash_hex: add || remove
      ? `0x${(fields.buff_name_hash >>> 0).toString(16).padStart(8, '0')}`
      : null,
    buff_type: add ? fields.buff_type : null,
    stack_count: add || profile.operation === 'UPDATE_COUNT' ? fields.count : null,
    duration_seconds: add ? fields.duration_seconds
      : profile.operation === 'UPDATE_COUNT' ? fields.time_10_seconds : null,
    running_time_seconds: add ? fields.running_time_seconds
      : profile.operation === 'UPDATE_COUNT' ? fields.time_18_seconds : null,
    removal_time_seconds: remove ? fields.removal_time_seconds : null,
    is_hidden: null,
    package_hash: null,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      buff_operation: 'VERIFIED_DIRECT',
      target_network_id: 'VERIFIED_DIRECT',
      source_network_id: hasCaster ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
      buff_slot: 'VERIFIED_DIRECT',
      buff_name_hash: add || remove ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
      buff_type: add ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
      stack_count: add || profile.operation === 'UPDATE_COUNT'
        ? 'VERIFIED_DIRECT'
        : 'UNAVAILABLE',
      duration_seconds: add || profile.operation === 'UPDATE_COUNT'
        ? 'VERIFIED_DIRECT'
        : 'UNAVAILABLE',
      running_time_seconds: add || profile.operation === 'UPDATE_COUNT'
        ? 'VERIFIED_DIRECT'
        : 'UNAVAILABLE',
      removal_time_seconds: remove ? 'VERIFIED_DIRECT' : 'UNAVAILABLE',
      is_hidden: 'UNVERIFIED',
      package_hash: 'UNVERIFIED',
    },
    decoder_profile: profile.id,
    decoder_runtime_image_sha256: profile.runtime_image_sha256,
    raw_param: row.raw_param,
    raw_param_hex: row.raw_param_hex,
    raw_payload_hex: row.raw_payload_hex,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: damageRawPacketRef(row),
  });
  if (add) {
    event.protocol_fields = {
      field_14: fields.field_14,
      field_18: fields.field_18,
      field_28: fields.field_28,
      field_30: fields.field_30,
      field_34: fields.field_34,
      field_38: fields.field_38,
      field_50: fields.field_50,
      field_68: fields.field_68,
    };
  }
  return event;
}

function hasHeroDeathSignature(block, chunk) {
  return chunk.stream_tag === PROFILE.stream_tag
    && block.packet_id === PROFILE.replay_block_packet_id
    && block.payload_length === PROFILE.payload_length;
}

function decodeHeroDeathBlock(replay, chunk, block, champions = championByParticipant(replay)) {
  if (replay.header.version !== PROFILE.replay_version) return null;
  if (!hasHeroDeathSignature(block, chunk)) return null;

  const rawParam = block.param >>> 0;
  const participantId = participantIdFromParam(rawParam);
  const victimNetworkId = championNetworkIdFromParam(rawParam);
  if (participantId === null || victimNetworkId === null) return null;

  const victimChampion = champions.get(participantId) ?? null;
  const rawPayloadSha256 = payloadSha256(block.payload);
  return deathEvent({
    replay_time_ms: block.timestamp_ms,
    victim_network_id: victimNetworkId,
    victim_participant_id: participantId,
    victim_champion: victimChampion,
    target_network_id: victimNetworkId,
    target_participant_id: participantId,
    target_champion: victimChampion,
    confidence: 'VERIFIED',
    semantic_status: 'VERIFIED',
    decoder_profile: PROFILE.id,
    raw_param: rawParam,
    raw_param_hex: `0x${rawParam.toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: rawPayloadSha256,
    raw_packet_ref: rawPacketRef(replay, chunk, block),
  });
}

function decodeHeroDeaths(replay, options = {}) {
  if (replay.header.version !== PROFILE.replay_version) {
    const error = new Error(
      `decoder ${PROFILE.id} only supports ${PROFILE.replay_version}; got ${replay.header.version}`,
    );
    error.code = 'UNSUPPORTED_REPLAY_VERSION';
    throw error;
  }

  const champions = championByParticipant(replay);
  const events = [];
  let signatureCount = 0;
  let rejectedSignatureCount = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (hasHeroDeathSignature(block, chunk)) signatureCount += 1;
    const event = decodeHeroDeathBlock(replay, chunk, block, champions);
    if (event) events.push(event);
    else if (hasHeroDeathSignature(block, chunk)) rejectedSignatureCount += 1;
  }, {
    includeStreams: [PROFILE.stream_tag],
    strict: options.strict !== false,
  });

  return {
    profile: PROFILE,
    events,
    signature_count: signatureCount,
    rejected_signature_count: rejectedSignatureCount,
    walk,
  };
}

module.exports = {
  BUFF_PROFILES,
  CAST_SPELL_PROFILE,
  DAMAGE_PROFILE,
  LEVEL_UP_PROFILE,
  ON_EVENT_PROFILE,
  SHIELD_DAMAGE_PROFILE,
  PROTECTION_CAST_KINDS,
  PROFILE,
  championByParticipant,
  championNetworkIdFromParam,
  buffEventFromDecodedRow,
  damageEventFromDecodedRow,
  decodeHeroDeathBlock,
  decodeHeroDeaths,
  entityFromNetworkId,
  hasHeroDeathSignature,
  isBuffDecodedRow,
  isCastSpellDecodedRow,
  isLevelTransitionDecodedRow,
  isOnEventDecodedRow,
  isShieldDamageDecodedRow,
  participantIdFromChampionNetworkId,
  participantIdFromParam,
  participantMetadata,
  rawPacketRef,
  protectionEventFromDecodedRow,
  levelTransitionEventFromDecodedRow,
  shieldAbsorptionProtectionEventFromDecodedRow,
  spellDictionaryEntry,
  spellEventFromDecodedRow,
};
