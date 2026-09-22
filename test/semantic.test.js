const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const zlib = require('node:zlib');

const {
  BUFF_PROFILES,
  CAST_SPELL_PROFILE,
  ON_EVENT_PROFILE,
  PROFILE,
  DAMAGE_PROFILE,
  SHIELD_DAMAGE_PROFILE,
  buffEventFromDecodedRow,
  championNetworkIdFromParam,
  damageEventFromDecodedRow,
  decodeHeroDeathBlock,
  decodeHeroDeaths,
  isCastSpellDecodedRow,
  isBuffDecodedRow,
  isOnEventDecodedRow,
  isShieldDamageDecodedRow,
  participantIdFromParam,
  participantIdFromChampionNetworkId,
  participantMetadata,
  protectionEventFromDecodedRow,
  shieldAbsorptionProtectionEventFromDecodedRow,
  spellEventFromDecodedRow,
} = require('../src/decoders/rofl_16_15_801_3452');
const { parseReplayFile } = require('../src/rofl');
const {
  annotateBuffLifecycles,
  annotateBuffSpellCorrelations,
  annotatePlayerCastGroups,
  annotateProtectionCorrelations,
  buildAdcDeathRecords,
  deduplicateShieldRoutes,
  runBuffDecoder,
  runCastSpellDecoder,
  runProtectionV4Decoder,
} = require('../src/semantic_pipeline');

const REPLAY_EXPECTATIONS = Object.freeze({
  '11154791609': {
    sha256: 'b911ddc894b50569eb6664518e4862f90740e0f84eb127ecfe2f3f6712be5233',
    deaths: 71,
  },
  '11158122245': {
    sha256: '4b803c3084266a8774f878aa96932b46fc372a14735d7d290a6f6d0c61719b18',
    deaths: 48,
  },
  '11158276256': {
    sha256: '1a7e1b9b82ad412fc7e0bf47f2e9c10e27d699c07721c21b02e4e97ae94b7bf1',
    deaths: 64,
  },
  '11172852368': {
    sha256: 'f3ad2680d408c6420442818f318d6e2985b72069c44293c731e9df584461bf7d',
    deaths: 62,
  },
});

function syntheticReplay(version = PROFILE.replay_version) {
  return {
    source_path: 'synthetic.rofl',
    source_sha256: 'synthetic',
    header: { version },
    tail: { stats: [{ SKIN: 'Annie' }] },
  };
}

function syntheticChunk() {
  return {
    index: 3,
    chunk_id: 4,
    stream_tag: 1,
    stream: 'game_chunk',
    offset: 100,
    body_offset: 117,
  };
}

function syntheticBlock(fields = {}) {
  return {
    offset: 20,
    payload_offset: 27,
    packet_id: PROFILE.replay_block_packet_id,
    payload_length: PROFILE.payload_length,
    payload: Buffer.from('1cb9ab7777', 'hex'),
    timestamp_ms: 184231,
    param: 0x400000ae,
    ...fields,
  };
}

function encodedAbsoluteBlock(timestampSeconds, packetId, rawParam, payloadHex) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampSeconds, 1);
  header[5] = payload.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function syntheticProtectionRouteReplay() {
  const onEventPayload = [
    '11e64f0dd9d6e982ecb1c1c11bc1c1c5281800d1c1a9b661',
    '1bc1c1c51bc1c1c5c9ddc0b572a9b661b1357d7d1bc1c1c5',
    '72a9b661c1c1c1c1c191c1c1',
  ].join('');
  const shieldDamagePayload = '3abd45b08caebb4f3637';
  const body = Buffer.concat([
    encodedAbsoluteBlock(1, ON_EVENT_PROFILE.replay_block_packet_id, 0x400000af,
      onEventPayload),
    encodedAbsoluteBlock(2, SHIELD_DAMAGE_PROFILE.replay_block_packet_id, 0x400000b6,
      shieldDamagePayload),
  ]);
  const compressed = zlib.zstdCompressSync(body);
  const stats = Array.from({ length: 10 }, (_, index) => ({
    SKIN: index === 1 ? 'Soraka' : index === 8 ? 'Samira' : `Champion${index + 1}`,
    TEAM: index < 5 ? 100 : 200,
  }));
  return {
    buffer: compressed,
    source_path: path.resolve('fixture-protection-routes.rofl'),
    source_sha256: 'fixture-protection-routes-sha256',
    header: { version: PROFILE.replay_version },
    tail: { stats },
    chunks: [{
      index: 0,
      chunk_id: 0,
      stream_tag: 1,
      stream: 'game_chunk',
      offset: 0,
      body_offset: 0,
      body_length: compressed.length,
      body_end: compressed.length,
      uncompressed_length: body.length,
      is_compressed: true,
    }],
  };
}

test('16.15 death param mapping preserves raw routing while normalizing the champion id', () => {
  assert.equal(participantIdFromParam(0x400000ae), 1);
  assert.equal(participantIdFromParam(0x400001b0), 3);
  assert.equal(championNetworkIdFromParam(0x400001b0), 0x400000b0);
  assert.equal(participantIdFromParam(0x400000ad), null);
  assert.equal(participantIdFromParam(0x400000b8), null);
});

test('16.15 champion network mapping rejects non-champion entities', () => {
  assert.equal(participantIdFromChampionNetworkId(0x400000ae), 1);
  assert.equal(participantIdFromChampionNetworkId(0x400000b7), 10);
  assert.equal(participantIdFromChampionNetworkId(0x400000ad), null);
  assert.equal(participantIdFromChampionNetworkId(0x400000b8), null);
  assert.equal(participantIdFromChampionNetworkId(0x40000285), null);
});

test('16.15 damage row preserves direct fields and RAW provenance', () => {
  const replay = syntheticReplay();
  replay.tail.stats = [
    { SKIN: 'Annie', TEAM: 100 },
    { SKIN: 'Olaf', TEAM: 200 },
  ];
  replay.source_sha256 = 'replay-sha';
  const row = {
    replay_path: 'synthetic.rofl',
    replay_sha256: 'replay-sha',
    replay_version: DAMAGE_PROFILE.replay_version,
    replay_time_ms: 12345,
    chunk_index: 3,
    chunk_id: 4,
    chunk_stream: 'game_chunk',
    chunk_file_offset: 100,
    compressed_body_offset: 117,
    decompressed_block_offset: 20,
    decompressed_payload_offset: 27,
    packet_id: DAMAGE_PROFILE.replay_block_packet_id,
    decoder_profile: DAMAGE_PROFILE.id,
    decoder_runtime_image_sha256: DAMAGE_PROFILE.runtime_image_sha256,
    payload_length: 13,
    raw_param: 0x400000ae,
    raw_param_hex: '0x400000ae',
    raw_payload_hex: '00',
    raw_payload_sha256: 'payload-sha',
    deserialize_return_al: 1,
    fully_consumed: true,
    decoded_opcode: DAMAGE_PROFILE.client_opcode,
    opcode_matches_profile: true,
    decoded_fields: {
      source_network_id: 0x400000ae,
      target_network_id: 0x400000af,
      amount: 42.5,
      extra_amount: 0,
      field_18: 0,
      field_1c: 1,
      field_20: 5,
      field_21: 0,
      field_30: 0,
    },
  };
  const event = damageEventFromDecodedRow(replay, row, participantMetadata(replay));
  assert.equal(event.confidence, 'VERIFIED_DIRECT');
  assert.equal(event.source_participant_id, 1);
  assert.equal(event.target_participant_id, 2);
  assert.equal(event.source_champion, 'Annie');
  assert.equal(event.target_champion, 'Olaf');
  assert.equal(event.amount, 42.5);
  assert.equal(event.damage_type, 'physical');
  assert.equal(event.damage_type_code, 0);
  assert.equal(event.damage_type_status, 'VERIFIED_DIRECT');
  assert.equal(event.spell_key, 1);
  assert.equal(event.spell_key_hex, '0x00000001');
  assert.equal(event.spell_key_status, 'VERIFIED_DIRECT');
  assert.equal(event.damage_result_code, 5);
  assert.equal(event.is_critical, null);
  assert.equal(event.critical_status, 'UNAVAILABLE');
  assert.equal(event.pre_mitigation_amount, null);
  assert.equal(event.post_mitigation_amount, null);
  assert.equal(event.source_type, null);
  assert.equal(event.raw_packet_ref.payload_sha256, 'payload-sha');

  const critical = damageEventFromDecodedRow(replay, {
    ...row,
    decoded_fields: { ...row.decoded_fields, field_20: 3, field_21: 2 },
  });
  assert.equal(critical.damage_type, 'true');
  assert.equal(critical.is_critical, true);
  assert.equal(critical.critical_status, 'VERIFIED_DERIVED');

  const unknownType = damageEventFromDecodedRow(replay, {
    ...row,
    decoded_fields: { ...row.decoded_fields, field_21: 9 },
  });
  assert.equal(unknownType.damage_type, null);
  assert.equal(unknownType.damage_type_status, 'UNAVAILABLE');

  assert.equal(damageEventFromDecodedRow(replay, {
    ...row,
    decoded_fields: { ...row.decoded_fields, source_network_id: 0x40000285 },
  }).source_participant_id, null);

  assert.equal(damageEventFromDecodedRow(replay, {
    ...row,
    decoder_profile: 'wrong-profile',
  }), null);
  assert.equal(damageEventFromDecodedRow(replay, {
    ...row,
    decoder_runtime_image_sha256: 'wrong-image',
  }), null);
});

test('16.15 CastSpell row preserves direct fields, targets, and derived dictionary semantics', () => {
  const replay = syntheticReplay();
  replay.tail.stats = [
    { SKIN: 'Lulu', TEAM: 100 },
    { SKIN: 'Jinx', TEAM: 100 },
  ];
  replay.source_sha256 = 'replay-sha';
  const row = {
    replay_path: 'synthetic.rofl',
    replay_sha256: 'replay-sha',
    replay_version: CAST_SPELL_PROFILE.replay_version,
    replay_time_ms: 125990,
    chunk_index: 3,
    chunk_id: 4,
    chunk_stream: 'game_chunk',
    chunk_file_offset: 100,
    compressed_body_offset: 117,
    decompressed_block_offset: 20,
    decompressed_payload_offset: 27,
    packet_id: CAST_SPELL_PROFILE.replay_block_packet_id,
    payload_length: 128,
    raw_param: 0x400000ae,
    raw_param_hex: '0x400000ae',
    raw_payload_hex: '00',
    raw_payload_sha256: 'payload-sha',
    deserialize_return_al: 1,
    fully_consumed: true,
    decoded_opcode: CAST_SPELL_PROFILE.client_opcode,
    opcode_matches_profile: true,
    decoded_fields: {
      spell_key: 0x0073c3b5,
      caster_name: 'Lulu',
      caster_network_id: 0x400000ae,
      spell_chain_owner_network_id: 0x400000ae,
      targets: [{ network_id: 0x400000af, hit_result: 0 }],
      cast_time_seconds: 125.99025,
      target_position: [100, 50, 200],
      target_position_end: [100, 50, 200],
      cast_direction: [1, 0, 0],
    },
  };
  const dictionary = {
    by_hash: {
      '0x0073c3b5': [{
        champion_alias: 'Lulu',
        script_name: 'LuluE',
        display_name: 'Help, Pix!',
        spell_slot: 'E',
        phase: 'PRIMARY',
        source: 'TEST_PINNED_CLIENT_DATA',
      }],
    },
  };
  assert.equal(isCastSpellDecodedRow(replay, row), true);
  const event = spellEventFromDecodedRow(replay, row, dictionary, participantMetadata(replay));
  assert.equal(event.confidence, 'VERIFIED_DIRECT');
  assert.equal(event.caster_participant_id, 1);
  assert.equal(event.caster_champion, 'Lulu');
  assert.equal(event.spell_identifier, 'LuluE');
  assert.equal(event.spell_slot, 'E');
  assert.equal(event.target_participant_id, 2);
  assert.equal(event.target_champion, 'Jinx');
  assert.equal(event.protection_cast_kind, 'SHIELD_CAST');
  assert.equal(event.internal_vs_replay_time_delta_ms, 0.25);
  assert.equal(event.raw_packet_ref.payload_sha256, 'payload-sha');
  assert.equal(event.field_confidence.spell_identifier, 'VERIFIED_DERIVED');
  assert.equal(isCastSpellDecodedRow(replay, {
    ...row,
    decoded_fields: { ...row.decoded_fields, cast_direction: [1, 0] },
  }), false);
});

test('16.15 Buff rows preserve verified fields and null unverified semantics', () => {
  const replay = syntheticReplay();
  replay.tail.stats = [
    { SKIN: 'Lulu', TEAM: 100 },
    { SKIN: 'Jinx', TEAM: 100 },
  ];
  replay.source_sha256 = 'replay-sha';
  const row = {
    replay_path: 'synthetic.rofl',
    replay_sha256: 'replay-sha',
    replay_version: PROFILE.replay_version,
    replay_time_ms: 125990,
    chunk_index: 3,
    chunk_id: 4,
    chunk_stream: 'game_chunk',
    chunk_file_offset: 100,
    compressed_body_offset: 117,
    decompressed_block_offset: 20,
    decompressed_payload_offset: 27,
    packet_id: BUFF_PROFILES.add.replay_block_packet_id,
    payload_length: 20,
    raw_param: 0x400000af,
    raw_param_hex: '0x400000af',
    raw_payload_hex: '00',
    raw_payload_sha256: 'payload-sha',
    deserialize_return_al: 1,
    fully_consumed: true,
    decoded_opcode: BUFF_PROFILES.add.client_opcode,
    opcode_matches_profile: true,
    decoded_fields: {
      raw_param: 0x400000af,
      running_time_seconds: 0,
      field_14: 0,
      field_18: 123,
      duration_seconds: 2.5,
      buff_type: 2,
      count: 1,
      buff_name_hash: 0x01234567,
      field_28: 0,
      caster_network_id: 0x400000ae,
      field_30: 0,
      field_34: 3,
      field_38: 0,
      field_50: 1,
      field_68: 0,
      buff_slot: 7,
    },
  };
  assert.equal(isBuffDecodedRow(replay, row, BUFF_PROFILES.add), true);
  const event = buffEventFromDecodedRow(replay, row, BUFF_PROFILES.add);
  assert.equal(event.buff_operation, 'ADD');
  assert.equal(event.source_champion, 'Lulu');
  assert.equal(event.target_champion, 'Jinx');
  assert.equal(event.buff_name_hash, 0x01234567);
  assert.equal(event.buff_slot, 7);
  assert.equal(event.duration_seconds, 2.5);
  assert.equal(event.is_hidden, null);
  assert.equal(event.package_hash, null);
  assert.equal(event.protocol_fields.field_34, 3);
  assert.equal(event.field_confidence.package_hash, 'UNVERIFIED');
  assert.equal(event.raw_packet_ref.payload_sha256, 'payload-sha');
});

function syntheticOnEventRow(fields = {}) {
  return {
    schema_version: 1,
    replay_path: 'synthetic.rofl',
    replay_sha256: 'replay-sha',
    replay_version: ON_EVENT_PROFILE.replay_version,
    replay_label: 'synthetic',
    chunk_index: 3,
    chunk_id: 4,
    chunk_stream: 'game_chunk',
    chunk_file_offset: 100,
    compressed_body_offset: 117,
    decompressed_block_offset: 20,
    decompressed_payload_offset: 27,
    replay_time_ms: 160140,
    occurrence_index: 7,
    event_id: 0x00ed,
    event_id_hex: '0x00ed',
    event_name: 'OnReceiveShield',
    parameter_type: 'ShieldingParams',
    event_kind: 'SHIELD_APPLICATION_DIRECT',
    route_kind: 'TARGET_ROUTE',
    canonical_route: true,
    schema_id: 0x8f7f3f4e,
    schema_id_hex: '0x8f7f3f4e',
    schema_matches_expected: true,
    parameter_size: 0x14,
    parameter_capacity: 0x14,
    parameter_size_matches_expected: true,
    parameter_blob_hex: '00',
    parameter_blob_sha256: 'params-sha',
    deserialize_return_al: 1,
    fully_consumed: true,
    raw_param: 0x400000af,
    raw_param_hex: '0x400000af',
    raw_payload_hex: '00',
    raw_payload_sha256: 'payload-sha',
    raw_packet_ref: {
      replay_path: 'synthetic.rofl',
      replay_sha256: 'replay-sha',
      chunk_index: 3,
      chunk_id: 4,
      chunk_stream: 'game_chunk',
      chunk_file_offset: 100,
      compressed_body_offset: 117,
      decompressed_block_offset: 20,
      decompressed_payload_offset: 27,
      replay_time_ms: 160140,
      occurrence_index: 7,
      packet_id: 0x009e,
      payload_length: 29,
      raw_param: 0x400000af,
      raw_param_hex: '0x400000af',
      raw_payload_sha256: 'payload-sha',
    },
    semantic_status: 'VERIFIED_DIRECT',
    decoder_profile: ON_EVENT_PROFILE.id,
    decoder_runtime_image_sha256: ON_EVENT_PROFILE.runtime_image_sha256,
    source_network_id: 0x400000ae,
    target_network_id: 0x400000af,
    amount: 78.2249984741211,
    amount_bits_hex: '0x429c7333',
    protocol_field_04: 0,
    ...fields,
  };
}

function syntheticShieldDamageRow(fields = {}) {
  return {
    schema_version: 1,
    replay_path: 'synthetic.rofl',
    replay_sha256: 'replay-sha',
    replay_version: SHIELD_DAMAGE_PROFILE.replay_version,
    replay_label: 'synthetic',
    chunk_index: 3,
    chunk_id: 4,
    chunk_stream: 'game_chunk',
    chunk_file_offset: 100,
    compressed_body_offset: 117,
    decompressed_block_offset: 20,
    decompressed_payload_offset: 27,
    replay_time_ms: 160150,
    occurrence_index: 8,
    packet_id: SHIELD_DAMAGE_PROFILE.replay_block_packet_id,
    packet_id_hex: '0x0017',
    packet_type_name: 'PKT_UnitApplyShieldDamage_s',
    event_kind: 'SHIELD_ABSORBED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT',
    target_network_id: 0x400000af,
    target_network_id_hex: '0x400000af',
    network_id_field_14: 0x400000af,
    network_id_field_14_hex: '0x400000af',
    protocol_field_10: 0,
    shield_absorbed_amount: 30.5,
    shield_absorbed_amount_bits_hex: '0x41f40000',
    network_fields_agree: true,
    target_matches_raw_param: true,
    deserialize_return_al: 1,
    bytes_consumed: 13,
    fully_consumed: true,
    raw_param: 0x400000af,
    raw_param_hex: '0x400000af',
    raw_payload_hex: '00',
    raw_payload_sha256: 'shield-damage-payload-sha',
    raw_packet_ref: {
      replay_path: 'synthetic.rofl',
      replay_sha256: 'replay-sha',
      chunk_index: 3,
      chunk_id: 4,
      chunk_stream: 'game_chunk',
      chunk_file_offset: 100,
      compressed_body_offset: 117,
      decompressed_block_offset: 20,
      decompressed_payload_offset: 27,
      replay_time_ms: 160150,
      occurrence_index: 8,
      packet_id: SHIELD_DAMAGE_PROFILE.replay_block_packet_id,
      payload_length: 10,
      raw_param: 0x400000af,
      raw_param_hex: '0x400000af',
      raw_payload_sha256: 'shield-damage-payload-sha',
    },
    decoder_profile: SHIELD_DAMAGE_PROFILE.id,
    decoder_runtime_image_sha256: SHIELD_DAMAGE_PROFILE.runtime_image_sha256,
    related_unit_apply_damage: {
      relation: 'FIRST_SAME_TARGET_SAME_TIMESTAMP_FOLLOWING_UNIT_APPLY_DAMAGE',
      semantic_status: 'VERIFIED_ORDERED_NEIGHBOR',
      source_network_id: 0x400000b0,
      target_network_id: 0x400000af,
      unit_apply_damage_amount: 80,
      decompressed_block_offset: 40,
    },
    ...fields,
  };
}

test('16.15 OnEvent protection rows preserve direct amounts and unavailable state fields', () => {
  const replay = syntheticReplay();
  replay.source_sha256 = 'replay-sha';
  replay.tail.stats = [
    { SKIN: 'Lulu', TEAM: 100 },
    { SKIN: 'Jinx', TEAM: 100 },
  ];
  const shieldRow = syntheticOnEventRow();
  assert.equal(isOnEventDecodedRow(replay, shieldRow), true);
  const shield = protectionEventFromDecodedRow(replay, shieldRow);
  assert.equal(shield.event_type, 'shield');
  assert.equal(shield.source_champion, 'Lulu');
  assert.equal(shield.target_champion, 'Jinx');
  assert.equal(shield.generated_amount, 78.2249984741211);
  assert.equal(shield.remaining_amount, null);
  assert.equal(shield.absorbed_amount, null);
  assert.equal(shield.unused_amount, null);

  const healRow = syntheticOnEventRow({
    event_id: 0x004b,
    event_id_hex: '0x004b',
    event_name: 'OnCastHeal',
    parameter_type: 'ParamsHeal',
    event_kind: 'HEAL_REPORTED_DIRECT',
    route_kind: 'HEAL_EVENT',
    schema_id: 0x7c044fe1,
    schema_id_hex: '0x7c044fe1',
    parameter_size: 0x34,
    parameter_capacity: 0x34,
    amount: 63.1212158203125,
    amount_bits_hex: '0x427c7c20',
  });
  const heal = protectionEventFromDecodedRow(replay, healRow);
  assert.equal(heal.event_type, 'heal');
  assert.equal(heal.direct_heal_amount, 63.1212158203125);
  assert.equal(heal.raw_heal_amount, null);
  assert.equal(heal.effective_heal_amount, null);
  assert.equal(heal.overheal_amount, null);
});

test('16.15 shield-damage rows emit one direct unattributed target-total event', () => {
  const replay = syntheticReplay();
  replay.source_sha256 = 'replay-sha';
  replay.tail.stats = [
    { SKIN: 'Lulu', TEAM: 100 },
    { SKIN: 'Jinx', TEAM: 100 },
    { SKIN: 'Zed', TEAM: 200 },
  ];
  const row = syntheticShieldDamageRow();
  assert.equal(isShieldDamageDecodedRow(replay, row), true);
  assert.equal(isShieldDamageDecodedRow(replay, {
    ...row,
    network_fields_agree: false,
  }), false);
  assert.equal(isShieldDamageDecodedRow(replay, {
    ...row,
    decoder_runtime_image_sha256: 'wrong-image',
  }), false);
  assert.equal(isShieldDamageDecodedRow(replay, {
    ...row,
    shield_absorbed_amount: -1,
  }), false);

  const event = shieldAbsorptionProtectionEventFromDecodedRow(replay, row);
  assert.equal(event.event_type, 'protection');
  assert.equal(event.protection_type, 'SHIELD_ABSORBED');
  assert.equal(event.target_participant_id, 2);
  assert.equal(event.target_champion, 'Jinx');
  assert.equal(event.absorbed_amount, 30.5);
  assert.equal(event.absorption_attribution_status, 'UNATTRIBUTED_TARGET_TOTAL');
  assert.equal(event.source_network_id, null);
  assert.equal(event.source_participant_id, null);
  assert.equal(event.caster_network_id, null);
  assert.equal(event.spell_identifier, null);
  assert.equal(event.shield_instance_id, null);
  assert.equal(event.generated_amount, null);
  assert.equal(event.remaining_amount, null);
  assert.equal(event.unused_amount, null);
  assert.equal(event.raw_heal_amount, null);
  assert.equal(event.effective_heal_amount, null);
  assert.equal(event.overheal_amount, null);
  assert.equal(event.temporary_hp_amount, null);
  assert.equal(event.current_hp, null);
  assert.equal(event.max_hp, null);
  assert.equal(event.semantic_status, 'VERIFIED_DIRECT');
  assert.equal(event.raw_packet_ref.occurrence_index, 8);
  assert.equal(event.raw_packet_refs.length, 1);
  assert.equal(event.ordered_damage_neighbor.source_network_id, 0x400000b0);
});

test('ADC timelines sum target-total absorption without external ally attribution', () => {
  const replay = syntheticReplay();
  replay.source_path = 'HN1-123456.rofl';
  replay.source_sha256 = 'replay-sha';
  replay.tail.stats = [
    { SKIN: 'Jinx', TEAM: 100, INDIVIDUAL_POSITION: 'BOTTOM' },
    { SKIN: 'Lulu', TEAM: 100, INDIVIDUAL_POSITION: 'UTILITY' },
    { SKIN: 'Zed', TEAM: 200, INDIVIDUAL_POSITION: 'MIDDLE' },
  ];
  const absorption = shieldAbsorptionProtectionEventFromDecodedRow(
    replay,
    syntheticShieldDamageRow({
      replay_time_ms: 1500,
      target_network_id: 0x400000ae,
      network_id_field_14: 0x400000ae,
      raw_param: 0x400000ae,
      raw_packet_ref: {
        ...syntheticShieldDamageRow().raw_packet_ref,
        replay_time_ms: 1500,
        raw_param: 0x400000ae,
      },
    }),
  );
  assert.ok(absorption);
  const records = buildAdcDeathRecords(
    replay,
    [{
      victim_participant_id: 1,
      victim_network_id: 0x400000ae,
      replay_time_ms: 2000,
    }],
    [{
      replay_time_ms: 1000,
      source_network_id: 0x400000b0,
      source_participant_id: 3,
      source_champion: 'Zed',
      target_network_id: 0x400000ae,
      amount: 100,
      is_basic_attack: null,
      spell: null,
    }],
    [],
    [],
    [],
    [absorption],
  );
  assert.equal(records.length, 1);
  const record = records[0];
  assert.equal(record.target_total_shield_absorbed, 30.5);
  assert.equal(record.target_shield_absorption_event_count, 1);
  assert.equal(record.target_shield_absorption_events[0], absorption);
  assert.equal(record.target_shield_absorption_attribution_status,
    'UNATTRIBUTED_TARGET_TOTAL');
  assert.equal(record.external_shield_absorbed, null);
  assert.equal(record.external_shield_absorption_attribution_status,
    'UNAVAILABLE_SOURCE_ATTRIBUTION');
  assert.equal(record.external_protection_event_count, 0);
  assert.equal(record.support_protection_event_count, 0);
  assert.equal(record.protection_context_status, 'PROTECTION_EVENTS_OBSERVED');
});

test('Protection V4 merges a non-empty decoded 0x0017 route exactly once in raw order',
  { timeout: 120000 }, () => {
    const decoded = runProtectionV4Decoder(syntheticProtectionRouteReplay(), [], []);
    assert.equal(decoded.summary.required_decoder_routes_verified, true);
    assert.equal(decoded.summary.decoder_route_status, 'BOTH_REQUIRED_ROUTES_VERIFIED');
    assert.equal(decoded.summary.decoder_routes.on_event.input_event_count, 1);
    assert.equal(decoded.summary.decoder_routes.shield_damage.input_event_count, 1);
    assert.equal(decoded.summary.decoder_routes.shield_damage.decoder_route_status, 'DECODED');
    assert.equal(decoded.shieldAbsorptionEvents.length, 1);

    const absorbed = decoded.protectionEvents.filter(
      (event) => event.protection_type === 'SHIELD_ABSORBED',
    );
    assert.equal(absorbed.length, 1);
    assert.equal(absorbed[0], decoded.shieldAbsorptionEvents[0]);
    assert.equal(absorbed[0].absorbed_amount, 375.13690185546875);
    assert.equal(absorbed[0].source_network_id, null);
    assert.equal(absorbed[0].source_participant_id, null);
    assert.equal(absorbed[0].absorption_attribution_status, 'UNATTRIBUTED_TARGET_TOTAL');
    assert.equal(absorbed[0].raw_packet_ref.packet_id,
      SHIELD_DAMAGE_PROFILE.replay_block_packet_id);
    assert.deepEqual(
      decoded.protectionEvents.map((event) => event.protection_type),
      ['HEAL_DIRECT_REPORTED', 'SHIELD_ABSORBED'],
    );
    assert.ok(decoded.protectionEvents[0].replay_time_ms
      < decoded.protectionEvents[1].replay_time_ms);
    assert.equal(decoded.summary.semantic_output_event_count, 2);
    assert.equal(decoded.summary.shield_absorption.event_count, 1);
  });

test('shield route deduplication preserves both raw packet references', () => {
  const replay = syntheticReplay();
  replay.source_sha256 = 'replay-sha';
  replay.tail.stats = [
    { SKIN: 'Lulu', TEAM: 100 },
    { SKIN: 'Jinx', TEAM: 100 },
  ];
  const target = protectionEventFromDecodedRow(replay, syntheticOnEventRow());
  const source = protectionEventFromDecodedRow(replay, syntheticOnEventRow({
    event_id: 0x00ee,
    event_id_hex: '0x00ee',
    event_name: 'OnGrantShield',
    route_kind: 'SOURCE_ROUTE_DUPLICATE',
    canonical_route: false,
    decompressed_block_offset: 10,
    occurrence_index: 6,
    raw_payload_sha256: 'grant-payload-sha',
    raw_packet_ref: {
      ...syntheticOnEventRow().raw_packet_ref,
      decompressed_block_offset: 10,
      occurrence_index: 6,
      raw_payload_sha256: 'grant-payload-sha',
    },
  }));
  const deduplicated = deduplicateShieldRoutes([target, source]);
  assert.equal(deduplicated.events.length, 1);
  assert.equal(deduplicated.summary.paired_route_count, 1);
  assert.equal(deduplicated.events[0].raw_packet_refs.length, 2);
  assert.equal(deduplicated.events[0].deduplication_status,
    'PAIRED_SOURCE_AND_TARGET_ROUTES');
});

test('protection spell attribution requires exact timestamp, caster, and target', () => {
  const shield = {
    event_type: 'shield',
    replay_time_ms: 1000,
    source_network_id: 0x400000ae,
    target_network_id: 0x400000af,
    field_confidence: { spell_identifier: 'UNAVAILABLE' },
  };
  const spell = {
    replay_time_ms: 1000,
    caster_network_id: 0x400000ae,
    targets: [{ network_id: 0x400000af }],
    protection_cast_kind: 'SHIELD_CAST',
    is_player_cast_group_leader: true,
    player_cast_group_id: 'cast-1',
    spell_identifier: 'LuluE',
    spell_name: 'Help, Pix!',
    spell_slot: 'E',
    raw_packet_ref: { decompressed_block_offset: 1 },
  };
  const summary = annotateProtectionCorrelations([shield], [], [spell], []);
  assert.equal(summary.exact_spell_match_count, 1);
  assert.equal(shield.spell_identifier, 'LuluE');
  const nearMiss = { ...shield, replay_time_ms: 1001, spell_identifier: null };
  annotateProtectionCorrelations([nearMiss], [], [spell], []);
  assert.equal(nearMiss.spell_identifier, null);
  assert.equal(nearMiss.spell_correlation_status,
    'NO_EXACT_TIMESTAMP_CASTER_TARGET_MATCH');
});

test('Buff lifecycle derives update identity only from a matching active Add', () => {
  const raw = (offset) => ({
    replay_sha256: 'replay-sha',
    chunk_index: 3,
    decompressed_block_offset: offset,
  });
  const add = {
    replay_time_ms: 1000,
    target_network_id: 0x400000af,
    source_network_id: 0x400000ae,
    buff_operation: 'ADD',
    buff_slot: 7,
    buff_name_hash: 0x01234567,
    buff_name_hash_hex: '0x01234567',
    buff_type: 2,
    duration_seconds: 5,
    lifecycle_match_status: null,
    raw_packet_ref: raw(10),
  };
  const update = {
    replay_time_ms: 2000,
    target_network_id: 0x400000af,
    source_network_id: 0x400000ae,
    buff_operation: 'UPDATE_COUNT',
    buff_slot: 7,
    buff_name_hash: null,
    buff_type: null,
    duration_seconds: 4,
    running_time_seconds: 1,
    field_confidence: { buff_name_hash: 'UNAVAILABLE', buff_type: 'UNAVAILABLE' },
    raw_packet_ref: raw(20),
  };
  const remove = {
    replay_time_ms: 6000,
    target_network_id: 0x400000af,
    source_network_id: null,
    buff_operation: 'REMOVE',
    buff_slot: 7,
    buff_name_hash: 0x01234567,
    raw_packet_ref: raw(30),
  };
  const summary = annotateBuffLifecycles([remove, update, add]);
  assert.equal(summary.remove_active_hash_consistency, 1);
  assert.equal(summary.update_caster_match_rate, 1);
  assert.equal(summary.update_duration_sum_match_rate, 1);
  assert.equal(update.buff_name_hash, add.buff_name_hash);
  assert.equal(update.field_confidence.buff_name_hash, 'VERIFIED_DERIVED');
  assert.equal(remove.lifecycle_id, add.lifecycle_id);
  assert.equal(add.lifecycle_match_status, 'CLOSED_BY_REMOVE');
});

test('Buff-to-spell correlation requires exact timestamp, caster, and target', () => {
  const buff = {
    replay_time_ms: 1000,
    source_network_id: 0x400000ae,
    target_network_id: 0x400000af,
    buff_operation: 'ADD',
    buff_name_hash_hex: '0x01234567',
    field_confidence: {},
  };
  const spell = {
    replay_time_ms: 1000,
    caster_network_id: 0x400000ae,
    is_player_cast_group_leader: true,
    player_cast_group_id: 'cast-1',
    spell_identifier: 'LuluE',
    spell_key_hex: '0x00000001',
    spell_slot: 'E',
    protection_cast_kind: 'SHIELD_CAST',
    targets: [{ network_id: 0x400000af }],
  };
  const summary = annotateBuffSpellCorrelations([buff], [spell]);
  assert.equal(summary.exact_timestamp_caster_target_match_count, 1);
  assert.equal(summary.protection_buff_match_count, 1);
  assert.equal(buff.origin_spell_identifier, 'LuluE');
  assert.equal(buff.protection_cast_kind, 'SHIELD_CAST');
  assert.equal(buff.field_confidence.protection_cast_kind, 'VERIFIED_DERIVED');
});

test('CastSpell player-cast grouping never merges rows across Replays', () => {
  const event = (replaySha256, primary = true) => ({
    replay_time_ms: 1000,
    caster_network_id: 0x400000ae,
    spell_key_hex: '0x00000001',
    is_primary_player_ability: primary,
    raw_packet_ref: { replay_sha256: replaySha256 },
  });
  const events = [event('replay-a'), event('replay-a'), event('replay-b'), event('replay-a', false)];
  annotatePlayerCastGroups(events);
  assert.equal(events[0].player_cast_group_size, 2);
  assert.equal(events[0].is_player_cast_group_leader, true);
  assert.equal(events[1].is_player_cast_group_leader, false);
  assert.equal(events[2].player_cast_group_size, 1);
  assert.equal(events[2].is_player_cast_group_leader, true);
  assert.notEqual(events[0].player_cast_group_id, events[2].player_cast_group_id);
  assert.equal(events[3].player_cast_group_id, null);
  assert.equal(events[3].is_player_cast_group_leader, false);
});

test('16.15 death decoder emits a fully traceable event and rejects signature drift', () => {
  const event = decodeHeroDeathBlock(syntheticReplay(), syntheticChunk(), syntheticBlock());
  assert.equal(event.confidence, 'VERIFIED');
  assert.equal(event.victim_participant_id, 1);
  assert.equal(event.victim_network_id, 0x400000ae);
  assert.equal(event.victim_champion, 'Annie');
  assert.equal(event.raw_param, 0x400000ae);
  assert.equal(event.raw_payload_hex, '1cb9ab7777');
  assert.equal(event.raw_packet_ref.chunk_index, 3);
  assert.equal(event.raw_packet_ref.decompressed_block_offset, 20);

  assert.equal(decodeHeroDeathBlock(
    syntheticReplay('16.16.0.0'),
    syntheticChunk(),
    syntheticBlock(),
  ), null);
  assert.equal(decodeHeroDeathBlock(
    syntheticReplay(),
    syntheticChunk(),
    syntheticBlock({ payload_length: 6 }),
  ), null);
  assert.equal(decodeHeroDeathBlock(
    syntheticReplay(),
    syntheticChunk(),
    syntheticBlock({ param: 0x400000ad }),
  ), null);
});

test('four real 16.15 Replays produce 245 one-to-one verified Hero Death events', { timeout: 120000 }, () => {
  const root = path.resolve(__dirname, '..');
  const anchorBundle = JSON.parse(fs.readFileSync(
    path.join(root, 'artifacts', 'semantic_probe', 'known_event_anchors.json'),
    'utf8',
  ));
  let totalEvents = 0;
  let totalAnchors = 0;
  for (const [gameId, expected] of Object.entries(REPLAY_EXPECTATIONS)) {
    const replay = parseReplayFile(path.join(root, 'replay', `HN1-${gameId}.rofl`));
    assert.equal(replay.source_sha256, expected.sha256);
    assert.equal(replay.header.version, PROFILE.replay_version);
    const decoded = decodeHeroDeaths(replay);
    assert.equal(decoded.walk.errors.length, 0);
    assert.equal(decoded.rejected_signature_count, 0);
    assert.equal(decoded.signature_count, expected.deaths);
    assert.equal(decoded.events.length, expected.deaths);

    const anchors = anchorBundle.replays.find((item) => String(item.game_id) === gameId).deaths;
    assert.equal(anchors.length, expected.deaths);
    for (let index = 0; index < decoded.events.length; index += 1) {
      const event = decoded.events[index];
      const anchor = anchors[index];
      assert.ok(event.victim_participant_id >= 1 && event.victim_participant_id <= 10);
      assert.equal(event.victim_participant_id, anchor.victim_participant_id);
      assert.ok(event.replay_time_ms - anchor.timestamp_ms >= 0);
      assert.ok(event.replay_time_ms - anchor.timestamp_ms <= 1);
      assert.equal(event.victim_network_id, (0x40000000 | (event.raw_param & 0xff)) >>> 0);
      assert.ok(event.victim_champion);
      assert.equal(event.raw_packet_ref.replay_sha256, expected.sha256);
    }
    totalEvents += decoded.events.length;
    totalAnchors += anchors.length;
  }
  assert.equal(totalEvents, 245);
  assert.equal(totalAnchors, 245);
});

test('real 16.15 Replay CastSpell decoder fully consumes packets and recovers support casts', { timeout: 120000 }, () => {
  const root = path.resolve(__dirname, '..');
  const expected = REPLAY_EXPECTATIONS['11158276256'];
  const replay = parseReplayFile(path.join(root, 'replay', 'HN1-11158276256.rofl'));
  assert.equal(replay.source_sha256, expected.sha256);
  const decoded = runCastSpellDecoder(replay);
  assert.equal(decoded.summary.event_count, 4762);
  assert.equal(decoded.summary.successful_full_consume_count, 4762);
  assert.equal(decoded.summary.semantic_output_event_count, 3833);
  assert.equal(decoded.summary.non_champion_caster_count, 929);
  assert.equal(decoded.events.length, 3833);
  assert.ok(decoded.events.every((event) => event.raw_packet_ref.replay_sha256 === expected.sha256));
  assert.ok(decoded.events.every((event) => event.field_confidence.replay_time_ms === 'VERIFIED_DIRECT'));
  const playerCasts = decoded.events.filter((event) => event.is_player_cast_group_leader);
  assert.equal(playerCasts.filter((event) => event.caster_champion === 'Janna'
    && event.spell_slot === 'E').length, 53);
  assert.equal(playerCasts.filter((event) => event.caster_champion === 'Janna'
    && event.spell_slot === 'R').length, 8);
  assert.equal(playerCasts.filter((event) => event.caster_champion === 'Lulu'
    && event.spell_slot === 'E').length, 89);
  assert.ok(playerCasts.some((event) => event.protection_cast_kind === 'SHIELD_CAST'));
});

test('real 16.15 Replay Buff decoder fully consumes all three packet families', { timeout: 120000 }, () => {
  const root = path.resolve(__dirname, '..');
  const expected = REPLAY_EXPECTATIONS['11154791609'];
  const replay = parseReplayFile(path.join(root, 'replay', 'HN1-11154791609.rofl'));
  assert.equal(replay.source_sha256, expected.sha256);
  const decoded = runBuffDecoder(replay);
  assert.equal(decoded.summary.event_count, 33595);
  assert.equal(decoded.summary.successful_full_consume_count, 33595);
  assert.equal(decoded.summary.profiles.add.event_count, 12661);
  assert.equal(decoded.summary.profiles.remove.event_count, 12404);
  assert.equal(decoded.summary.profiles.update_count.event_count, 8530);
  assert.ok(decoded.summary.lifecycle.remove_active_hash_consistency > 0.95);
  assert.ok(decoded.summary.lifecycle.update_caster_match_rate > 0.95);
  assert.ok(decoded.summary.lifecycle.update_duration_sum_match_rate > 0.85);
  assert.ok(decoded.events.every((event) => event.raw_packet_ref.replay_sha256 === expected.sha256));
  assert.ok(decoded.events.some((event) => event.source_champion && event.target_champion));
});

test('real 16.15 Replay Protection V4 decoder recovers direct shield and heal amounts', { timeout: 120000 }, () => {
  const root = path.resolve(__dirname, '..');
  const expected = REPLAY_EXPECTATIONS['11154791609'];
  const replay = parseReplayFile(path.join(root, 'replay', 'HN1-11154791609.rofl'));
  assert.equal(replay.source_sha256, expected.sha256);
  const casts = runCastSpellDecoder(replay);
  const buffs = runBuffDecoder(replay);
  const decoded = runProtectionV4Decoder(replay, casts.events, buffs.events);
  assert.equal(decoded.summary.input_event_count, 8386);
  assert.equal(decoded.summary.deserialize_success_count, 8386);
  assert.equal(decoded.summary.fully_consumed_count, 8386);
  assert.equal(decoded.summary.selected_event_counts['0x004b'], 5674);
  assert.equal(decoded.summary.selected_event_counts['0x00ed'], 684);
  assert.equal(decoded.summary.selected_event_counts['0x00ee'], 684);
  assert.equal(decoded.summary.required_decoder_routes_verified, true);
  assert.equal(decoded.summary.decoder_route_status, 'BOTH_REQUIRED_ROUTES_VERIFIED');
  assert.equal(decoded.summary.decoder_routes.shield_damage.input_event_count, 0);
  assert.equal(decoded.summary.decoder_routes.shield_damage.output_event_count, 0);
  assert.equal(decoded.summary.decoder_routes.shield_damage.decoder_route_status,
    'NO_PROTECTION_EVENT');
  assert.equal(decoded.shieldAbsorptionEvents.length, 0);
  assert.equal(decoded.shieldEvents.length, 684);
  assert.equal(decoded.healEvents.length, 5674);
  assert.ok(decoded.shieldEvents.every((event) => event.generated_amount >= 0));
  assert.ok(decoded.healEvents.every((event) => event.direct_heal_amount >= 0));
  const lulu = decoded.shieldEvents.find((event) => (
    event.replay_time_ms === 160140
    && event.source_network_id === 0x400000b7
    && event.target_network_id === 0x400000b6
  ));
  assert.ok(lulu);
  assert.equal(lulu.generated_amount, 78.2249984741211);
  assert.equal(lulu.spell_identifier, 'LuluE');
  assert.equal(lulu.raw_packet_refs.length, 2);
});
