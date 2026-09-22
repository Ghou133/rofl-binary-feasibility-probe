'use strict';

const crypto = require('node:crypto');

const EXACT_BUILD = '16.16.805.0442';
const PATCH = '16.16';
const RUNTIME_IMAGE_SHA256 =
  '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const VALIDATION_ARTIFACT =
  'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_machine_decisions_16_16.json';
const VALIDATION_ARTIFACT_SHA256 =
  'c66da8f8721e1dfced6b1eb7dae3f612d6ac53596eef9aaa09208f786f112e51';

function freezeProfile(profile) {
  return Object.freeze({
    ...profile,
    sample_count: Object.freeze({ ...profile.sample_count }),
    publishable_fields: Object.freeze([...profile.publishable_fields]),
    field_evidence: Object.freeze({ ...profile.field_evidence }),
    known_limits: Object.freeze([...profile.known_limits]),
  });
}

const GAMEPLAY_ROUTE_TAIL_PROFILES = Object.freeze({
  '0x00b8': freezeProfile({
    id: 'rofl-16.16.805.0442-ability-cooldown-broadcast-research-v1',
    event_type: 'ABILITY_COOLDOWN_BROADCAST',
    semantic_domain: 'spell',
    replay_version: EXACT_BUILD,
    packet_id: 0x00b8,
    runtime_type_name: 'PKT_CHAR_SetCooldown_Broadcast_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/profiles/route_00b8.json',
    runtime_decoder_profile_id:
      '16.16.805.0442-route-00b8-set-cooldown-broadcast-structural-v1',
    runtime_decoder_profile_sha256:
      'dc12a27487e0aad483fb6b15ab61e2220028c778eca37d1c3bd18809f361a75c',
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    sample_count: {
      replay_count: 4,
      full_corpus_event_count: 62000,
      stratified_native_event_count: 683,
      exact_full_consume_count: 683,
    },
    publishable_fields: [
      'subject_network_id=raw_param', 'replay_time_ms', 'spell_slot_key_1c_u8',
      'numeric_10_f32', 'numeric_18_f32', 'numeric_20_f32', 'numeric_24_f32',
      'flag_14_u8',
    ],
    field_evidence: {
      subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      spell_slot_key_1c_u8: 'VERIFIED_DIRECT_CONSUMER_LOOKUP_KEY',
      numeric_10_f32: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      numeric_18_f32: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      numeric_20_f32: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      numeric_24_f32: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      flag_14_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
    },
    known_limits: [
      'The four numeric values are decoded protocol fields, not named cooldown start, end, duration, or current values.',
      'Differential short branches default omitted fields, so decoded zero does not prove an explicit transmitted zero.',
      'This structural cooldown broadcast is not a spell-cast causality claim.',
    ],
  }),
  '0x00e4': freezeProfile({
    id: 'rofl-16.16.805.0442-instant-stop-attack-research-v1',
    event_type: 'INSTANT_STOP_ATTACK',
    semantic_domain: 'combat',
    replay_version: EXACT_BUILD,
    packet_id: 0x00e4,
    runtime_type_name: 'PKT_NPC_InstantStop_Attack_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/profiles/route_00e4.json',
    runtime_decoder_profile_id:
      '16.16.805.0442-route-00e4-instant-stop-attack-structural-v1',
    runtime_decoder_profile_sha256:
      'd811d3d093fdb957561dfba7e149ab2436e20b089b9a708a200b184c77c40cf2',
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    sample_count: {
      replay_count: 4,
      full_corpus_event_count: 96782,
      stratified_native_event_count: 549,
      exact_full_consume_count: 549,
    },
    publishable_fields: [
      'subject_network_id=raw_param', 'replay_time_ms', 'attack_sequence_14_u32',
      'target_network_id_candidate_1c_u32',
    ],
    field_evidence: {
      subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      attack_sequence_14_u32: 'VERIFIED_DIRECT_CONSUMER_COMPARISON_VALUE',
      target_network_id_candidate_1c_u32: 'CANDIDATE_NULLABLE_CONSUMER_ARGUMENT',
      flag_10_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      flag_11_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      flag_18_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      selector_19_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ATTACK_BRANCH_ROLE',
    },
    known_limits: [
      'The nullable +0x1c value remains a target-network-ID candidate rather than a promoted target role.',
      'Flags and selector values retain neutral protocol names.',
      'Occurrence does not prove damage, hit, animation completion, or damage application.',
    ],
  }),
  '0x01ab': freezeProfile({
    id: 'rofl-16.16.805.0442-face-direction-vector-research-v1',
    event_type: 'FACE_DIRECTION_VECTOR',
    semantic_domain: 'entity',
    replay_version: EXACT_BUILD,
    packet_id: 0x01ab,
    runtime_type_name: 'PKT_S2C_FaceDirection_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/profiles/route_01ab.json',
    runtime_decoder_profile_id:
      '16.16.805.0442-route-01ab-face-direction-structural-v1',
    runtime_decoder_profile_sha256:
      '6e587df7d30dc97efbd06d9f77b1465f7a9ad2ba8b488d68014955377c70a433',
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    sample_count: {
      replay_count: 4,
      full_corpus_event_count: 105124,
      stratified_native_event_count: 192,
      exact_full_consume_count: 192,
    },
    publishable_fields: [
      'subject_network_id=raw_param', 'replay_time_ms', 'direction_x_f32',
      'direction_y_f32', 'direction_z_f32',
    ],
    field_evidence: {
      subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      direction_x_f32: 'VERIFIED_DIRECT_CONSUMER_FACE_DIRECTION_COMPONENT',
      direction_y_f32: 'VERIFIED_DIRECT_CONSUMER_FACE_DIRECTION_COMPONENT',
      direction_z_f32: 'VERIFIED_DIRECT_CONSUMER_FACE_DIRECTION_COMPONENT',
      flag_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_ROLE',
      scalar_20_f32: 'VERIFIED_DIRECT_VALUE_OPTIONAL_UNKNOWN_NEUTRAL_ROLE',
    },
    known_limits: [
      'The vector is a facing direction and is not a world position or path.',
      'The +0x10 flag and optional +0x20 scalar retain unknown neutral roles.',
      'The 13-byte branch omits or defaults the optional scalar.',
    ],
  }),
  '0x01b5': freezeProfile({
    id: 'rofl-16.16.805.0442-basic-attack-position-minion-research-v1',
    event_type: 'BASIC_ATTACK_POSITION_MINION',
    semantic_domain: 'minion',
    replay_version: EXACT_BUILD,
    packet_id: 0x01b5,
    runtime_type_name: 'PKT_Basic_Attack_Pos_Minion_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/profiles/route_01b5.json',
    runtime_decoder_profile_id:
      '16.16.805.0442-route-01b5-basic-attack-position-minion-structural-v1',
    runtime_decoder_profile_sha256:
      '43e4c4377dce36d4d01269b58925d81d30116344d7b4499cb2e0b013ed1767df',
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    sample_count: {
      replay_count: 4,
      full_corpus_event_count: 52986,
      stratified_native_event_count: 571,
      exact_full_consume_count: 571,
    },
    publishable_fields: [
      'subject_network_id=raw_param', 'replay_time_ms', 'target_network_id_u32',
      'position_x_f32', 'position_z_f32',
    ],
    field_evidence: {
      subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      target_network_id_u32: 'VERIFIED_DIRECT_CONSUMER_ENTITY_LOOKUP_KEY',
      position_x_f32: 'VERIFIED_DIRECT_FIRST_POSITION_VECTOR_COMPONENT',
      position_z_f32: 'VERIFIED_DIRECT_SECOND_POSITION_VECTOR_COMPONENT',
      inline_attack_subobject: 'UNKNOWN_STRUCTURAL_RETAINED_RAW',
    },
    known_limits: [
      'The position vector is exactly two X/Z components in the validated exact-build rows.',
      'The inline attack subobject remains structural and is not assigned business field names.',
      'This attack command/state carrier is not evidence of damage application.',
    ],
  }),
  '0x0298': freezeProfile({
    id: 'rofl-16.16.805.0442-wall-tracking-cache-snapshot-research-v1',
    event_type: 'WALL_TRACKING_CACHE_SNAPSHOT',
    semantic_domain: 'entity',
    replay_version: EXACT_BUILD,
    packet_id: 0x0298,
    runtime_type_name: 'PKT_S2C_WallTrackingComponentCacheData_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/profiles/route_0298.json',
    runtime_decoder_profile_id:
      '16.16.805.0442-route-0298-wall-tracking-cache-data-structural-v1',
    runtime_decoder_profile_sha256:
      'dc60a5f5f98a5531410cb5228a50cb42991f8bd96b43dea998d1758f1ec2a9cf',
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    sample_count: {
      replay_count: 4,
      full_corpus_event_count: 77706,
      stratified_native_event_count: 768,
      exact_full_consume_count: 768,
    },
    publishable_fields: [
      'subject_network_id=raw_param', 'cache_selector_10_u16',
      'coordinate_x_18_f32', 'coordinate_z_1c_f32', 'numeric_14_f32',
      'field_20_u8', 'field_21_u8', 'field_22_u8',
    ],
    field_evidence: {
      subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      cache_selector_10_u16: 'VERIFIED_DIRECT_CONSUMER_CACHE_SLOT_SELECTOR',
      coordinate_x_18_f32: 'VERIFIED_DIRECT_CACHE_COORDINATE_COMPONENT',
      coordinate_z_1c_f32: 'VERIFIED_DIRECT_CACHE_COORDINATE_COMPONENT',
      numeric_14_f32: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_CACHE_ROLE',
      field_20_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_CACHE_ROLE',
      field_21_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_CACHE_ROLE',
      field_22_u8: 'VERIFIED_DIRECT_VALUE_UNKNOWN_NEUTRAL_CACHE_ROLE',
    },
    known_limits: [
      'This is keyframe component-cache state, not a live wall-collision event.',
      'Coordinates and selector do not establish map truth.',
      'The numeric and byte cache fields retain neutral protocol roles.',
    ],
  }),
  '0x03d4': freezeProfile({
    id: 'rofl-16.16.805.0442-missile-movement-complete-research-v1',
    event_type: 'MISSILE_MOVEMENT_COMPLETE',
    semantic_domain: 'missile',
    replay_version: EXACT_BUILD,
    packet_id: 0x03d4,
    runtime_type_name: 'PKT_S2C_SyncMovementCompleteCount_s',
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_decoder_profile:
      'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/profiles/route_03d4.json',
    runtime_decoder_profile_id:
      '16.16.805.0442-route-03d4-sync-movement-complete-count-structural-v1',
    runtime_decoder_profile_sha256:
      '4cab7185757f5c98e9ce4b1b1a50ffa308ba01a904683a9472f7bf07b459a27f',
    validation_artifact: VALIDATION_ARTIFACT,
    validation_artifact_sha256: VALIDATION_ARTIFACT_SHA256,
    sample_count: {
      replay_count: 4,
      full_corpus_event_count: 85503,
      stratified_native_event_count: 96,
      exact_full_consume_count: 96,
    },
    publishable_fields: [
      'subject_network_id=raw_param', 'replay_time_ms', 'movement_complete_count_u8',
    ],
    field_evidence: {
      subject_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      replay_time_ms: 'VERIFIED_DIRECT_PACKET_TIMESTAMP',
      movement_complete_count_u8: 'VERIFIED_DIRECT_CONSUMER_MISSILE_COMPLETION_COUNT',
    },
    known_limits: [
      'The current exact-build corpus observes only movement-completion count 1.',
      'The subject is MissileClient-scoped and is not promoted as a hero path subject.',
      'Values above 1 require a new governed exact-build replay for characterization.',
    ],
  }),
});

const ROUTE_IDS = Object.freeze(Object.values(GAMEPLAY_ROUTE_TAIL_PROFILES)
  .map((profile) => profile.packet_id));
const verifiedRuntimeImages = new WeakSet();

function routeHex(packetId) {
  const numeric = typeof packetId === 'string'
    ? Number.parseInt(packetId, packetId.startsWith('0x') ? 16 : 10)
    : Number(packetId);
  if (!Number.isInteger(numeric)) throw new Error(`invalid packet route ${packetId}`);
  return `0x${numeric.toString(16).padStart(4, '0')}`;
}

function profileForRoute(packetId) {
  const profile = GAMEPLAY_ROUTE_TAIL_PROFILES[routeHex(packetId)] ?? null;
  if (!profile) throw new Error(`unsupported gameplay-route-tail object ${routeHex(packetId)}`);
  return profile;
}

function u8(value) {
  return value & 0xff;
}

function rotateRight8(value, count) {
  const shift = count & 7;
  return ((u8(value) >>> shift) | (u8(value) << ((8 - shift) & 7))) & 0xff;
}

function rotateLeft8(value, count) {
  return rotateRight8(value, 8 - (count & 7));
}

function swapAdjacentBits(value) {
  return ((((u8(value) & 0xd5) * 2) | ((u8(value) >>> 1) & 0x55))) & 0xff;
}

function assertRuntimeImage(image) {
  if (!Buffer.isBuffer(image)) throw new Error('exact runtime image Buffer is required');
  if (verifiedRuntimeImages.has(image)) return image;
  const sha = crypto.createHash('sha256').update(image).digest('hex');
  if (sha !== RUNTIME_IMAGE_SHA256) throw new Error(`runtime image SHA mismatch: ${sha}`);
  verifiedRuntimeImages.add(image);
  return image;
}

function imageTable(image, rva) {
  if (image.length < rva + 0x100) {
    throw new Error(`runtime image does not contain 256-byte table at ${routeHex(rva)}`);
  }
  return (index) => image[rva + u8(index)];
}

function decodeBytes(storage, transform) {
  return Buffer.from(storage.map((value) => transform(value)));
}

function decodeRouteObject(packetType, objectHex, runtimeImage) {
  const profile = profileForRoute(packetType);
  const image = assertRuntimeImage(runtimeImage);
  if (typeof objectHex !== 'string' || !/^[a-f0-9]+$/i.test(objectHex)
      || objectHex.length % 2 !== 0) {
    throw new Error(`${routeHex(profile.packet_id)} object_hex is invalid`);
  }
  const object = Buffer.from(objectHex, 'hex');
  const t27950 = imageTable(image, 0x01a27950);
  const t239b0 = imageTable(image, 0x01a239b0);
  const requireLength = (length) => {
    if (object.length < length) {
      throw new Error(`${routeHex(profile.packet_id)} object shorter than ${length} bytes`);
    }
  };
  if (profile.packet_id === 0x01ab) {
    requireLength(0x24);
    const vectorByte = (encoded) => t27950(u8(rotateRight8(
      u8(~rotateRight8(t27950(t27950(encoded)), 1)), 7,
    ) - 0x28));
    const scalarByte = (encoded) => u8(
      swapAdjacentBits(rotateRight8(u8(~encoded), 3)) + 0x5c,
    ) ^ 0x12;
    const vector = decodeBytes(object.subarray(0x14, 0x20), vectorByte);
    const scalar = decodeBytes(object.subarray(0x20, 0x24), scalarByte);
    const flag = rotateRight8(swapAdjacentBits(u8(
      rotateRight8(swapAdjacentBits(object[0x10]), 3) + 0x76,
    )), 3);
    const values = [vector.readFloatLE(0), vector.readFloatLE(4), vector.readFloatLE(8)];
    return {
      flag_u8: flag,
      direction_x_f32: values[0],
      direction_y_f32: values[1],
      direction_z_f32: values[2],
      direction_norm: Math.hypot(...values),
      scalar_20_f32: scalar.readFloatLE(0),
    };
  }
  if (profile.packet_id === 0x00e4) {
    requireLength(0x20);
    const u10 = (x) => rotateRight8(swapAdjacentBits(u8(
      rotateRight8(swapAdjacentBits(x), 3) + 0x76,
    )), 3);
    const u11 = (x) => rotateRight8(swapAdjacentBits(rotateRight8(x ^ 0x09, 1)) ^ 0xbc, 6);
    const u14 = (x) => swapAdjacentBits(rotateRight8(t27950(u8(x - 0x32) ^ 0x59), 2));
    const u18 = (x) => t27950(u8((rotateRight8(t27950(u8(~x)), 1) ^ 0x94) - 0x47));
    const u19 = (x) => u8(rotateRight8(
      swapAdjacentBits(rotateRight8(rotateRight8(x, 5) ^ 1, 1)), 7,
    ) + 4);
    const u1c = (x) => rotateRight8(u8(
      (u8(u8(~rotateRight8(u8(~x), 6)) - 5) ^ 0x48) + 0x62,
    ), 2);
    return {
      flag_10_u8: u10(object[0x10]),
      flag_11_u8: u11(object[0x11]),
      attack_sequence_14_u32: decodeBytes(object.subarray(0x14, 0x18), u14)
        .readUInt32LE(0),
      flag_18_u8: u18(object[0x18]),
      selector_19_u8: u19(object[0x19]),
      target_network_id_candidate_1c_u32:
        decodeBytes(object.subarray(0x1c, 0x20), u1c).readUInt32LE(0),
    };
  }
  if (profile.packet_id === 0x00b8) {
    requireLength(0x28);
    const f10 = (x) => u8(u8(~swapAdjacentBits(rotateRight8(u8(~x), 6))) - 0x7a);
    const flag14 = (x) => u8(0x6f - rotateRight8(
      swapAdjacentBits(rotateRight8(x, 5)), 1,
    ));
    const f18 = (x) => u8(u8(~rotateRight8(swapAdjacentBits(
      rotateRight8(u8(u8(x + 0x2d) ^ 0xd9), 2),
    ), 3)) - 0x78);
    const slot1c = (x) => swapAdjacentBits(u8(
      u8(~rotateRight8(x, 5)) - 0x3a,
    ) ^ 0x32);
    const f20 = (x) => rotateRight8(u8(
      t27950(swapAdjacentBits(u8(x - 0x58))) - 0x53,
    ), 1);
    const f24 = (x) => u8(rotateRight8(
      rotateRight8(swapAdjacentBits(x), 6) ^ 0x8c, 1,
    ) - 0x72);
    return {
      numeric_10_f32: decodeBytes(object.subarray(0x10, 0x14), f10).readFloatLE(0),
      flag_14_u8: flag14(object[0x14]),
      numeric_18_f32: decodeBytes(object.subarray(0x18, 0x1c), f18).readFloatLE(0),
      spell_slot_key_1c_u8: slot1c(object[0x1c]),
      numeric_20_f32: decodeBytes(object.subarray(0x20, 0x24), f20).readFloatLE(0),
      numeric_24_f32: decodeBytes(object.subarray(0x24, 0x28), f24).readFloatLE(0),
    };
  }
  if (profile.packet_id === 0x0298) {
    requireLength(0x23);
    const selector = (x) => u8(
      (rotateRight8(rotateRight8(x, 6) ^ 0x9f, 6) ^ 0xe0) + 0x51,
    );
    const f14 = (x) => t239b0(u8(~rotateRight8(
      u8(rotateRight8(u8((x ^ 0x48) - 0x4f), 1) - 0x3d), 2,
    )));
    const q18 = (x) => u8(t239b0(u8(~t239b0(
      rotateLeft8(t239b0(swapAdjacentBits(x ^ 0xfa)), 1),
    ))) - 0x70);
    const u20 = (x) => u8(~swapAdjacentBits(u8(
      rotateRight8(u8(rotateRight8(x, 5) + 0x73), 7) + 0x30,
    )));
    const u21 = (x) => u8(rotateRight8(u8((t239b0(x) ^ 0xf5) + 0x13), 5) + 0x3b);
    const u22 = (x) => t239b0(t239b0(rotateRight8(
      u8(t239b0(t239b0(u8(~x))) - 0x7b), 1,
    )));
    const coordinates = decodeBytes(object.subarray(0x18, 0x20), q18);
    return {
      cache_selector_10_u16: decodeBytes(object.subarray(0x10, 0x12), selector)
        .readUInt16LE(0),
      numeric_14_f32: decodeBytes(object.subarray(0x14, 0x18), f14).readFloatLE(0),
      coordinate_x_18_f32: coordinates.readFloatLE(0),
      coordinate_z_1c_f32: coordinates.readFloatLE(4),
      field_20_u8: u20(object[0x20]),
      field_21_u8: u21(object[0x21]),
      field_22_u8: u22(object[0x22]),
    };
  }
  if (profile.packet_id === 0x03d4) {
    requireLength(0x11);
    const count = (x) => u8(u8(~rotateRight8(swapAdjacentBits(
      rotateRight8(u8((swapAdjacentBits(x) ^ 0x8f) - 2), 2),
    ), 3)) + 5);
    return { movement_complete_count_u8: count(object[0x10]) };
  }
  if (profile.packet_id === 0x01b5) {
    requireLength(0x48);
    const target = (x) => u8(~rotateRight8(u8(t27950(x) - 0x2c), 6));
    return {
      target_network_id_u32: decodeBytes(object.subarray(0x44, 0x48), target)
        .readUInt32LE(0),
    };
  }
  throw new Error(`unsupported gameplay-route-tail object ${routeHex(profile.packet_id)}`);
}

function exactBuild(value) {
  return value?.header?.version ?? value?.replay_version ?? value?.exact_build
    ?? value?.game_version ?? value?.build ?? null;
}

function replaySha(value) {
  return value?.source_sha256 ?? value?.replay_sha256 ?? null;
}

function assertSafePath(value) {
  if (value !== null && value !== undefined && /holdout/i.test(String(value))) {
    throw new Error(`protected Holdout path is forbidden: ${value}`);
  }
}

function assertSha256(value, label) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) {
    throw new Error(`${label} must be an exact SHA-256`);
  }
  return value.toLowerCase();
}

function assertFiniteFields(decoded, names) {
  for (const name of names) {
    if (!Number.isFinite(decoded[name])) throw new Error(`${name} is not finite`);
  }
}

function assertGameplayRouteTailDecodedRow(replay, row, runtimeImage) {
  if (!replay || !row) throw new Error('replay and decoded row are required');
  assertSafePath(replay.source_path);
  assertSafePath(row.replay_path);
  if (exactBuild(replay) !== EXACT_BUILD || exactBuild(row) !== EXACT_BUILD) {
    throw new Error(`gameplay-route-tail adapter only supports exact build ${EXACT_BUILD}`);
  }
  const sourceSha = assertSha256(replaySha(replay), 'Replay SHA-256');
  const rowSha = assertSha256(replaySha(row), 'decoded row Replay SHA-256');
  if (sourceSha !== rowSha) throw new Error('decoded row Replay SHA mismatch');
  const profile = profileForRoute(row.packet_id);
  if (row.packet_type !== undefined && row.packet_type !== routeHex(profile.packet_id)) {
    throw new Error('decoded row packet discriminator mismatch');
  }
  if (row.fully_consumed !== true || row.deserialize_return_al !== 1) {
    throw new Error('decoded row is not an exact successful full-consume row');
  }
  if (row.decoder_runtime_image_sha256 !== profile.runtime_image_sha256) {
    throw new Error('decoded row runtime image SHA mismatch');
  }
  if (row.decoder_profile_sha256 !== profile.runtime_decoder_profile_sha256
      || row.decoder_profile !== profile.runtime_decoder_profile_id) {
    throw new Error('decoded row runtime profile mismatch');
  }
  if (row.decoded_opcode !== profile.packet_id || row.opcode_matches_profile !== true) {
    throw new Error('decoded row opcode attestation failed');
  }
  if (!Number.isInteger(row.raw_param) || !Number.isFinite(Number(row.replay_time_ms))) {
    throw new Error('decoded row subject/time fields are invalid');
  }
  const payloadSha = assertSha256(row.raw_payload_sha256, 'decoded row payload SHA-256');
  if (typeof row.raw_payload_hex !== 'string' || !/^[a-f0-9]*$/i.test(row.raw_payload_hex)
      || row.raw_payload_hex.length % 2 !== 0
      || crypto.createHash('sha256').update(Buffer.from(row.raw_payload_hex, 'hex'))
        .digest('hex') !== payloadSha) {
    throw new Error('decoded row payload SHA does not match raw_payload_hex');
  }
  if (typeof row.object_hex !== 'string' || !/^[a-f0-9]+$/i.test(row.object_hex)
      || row.object_hex.length % 2 !== 0) {
    throw new Error('decoded row object_hex is invalid');
  }
  const object = Buffer.from(row.object_hex, 'hex');
  if (object.length < 0x10 || object.readUInt16LE(0x08) !== profile.packet_id
      || object.readUInt32LE(0x0c) !== (row.raw_param >>> 0)) {
    throw new Error('decoded row object header route/subject mismatch');
  }
  assertRuntimeImage(runtimeImage);
  const decoded = decodeRouteObject(profile.packet_id, row.object_hex, runtimeImage);
  if (profile.packet_id === 0x01b5) {
    const components = row.decoded_fields?.position_components;
    if (!Array.isArray(components) || components.length !== 2
        || components.some((entry) => !Number.isFinite(entry?.value_f32))) {
      throw new Error('0x01b5 requires exactly two finite position components');
    }
    decoded.position_x_f32 = components[0].value_f32;
    decoded.position_z_f32 = components[1].value_f32;
  }
  const floatFields = {
    '0x00b8': ['numeric_10_f32', 'numeric_18_f32', 'numeric_20_f32', 'numeric_24_f32'],
    '0x01ab': [
      'direction_x_f32', 'direction_y_f32', 'direction_z_f32', 'direction_norm',
      'scalar_20_f32',
    ],
    '0x01b5': ['position_x_f32', 'position_z_f32'],
    '0x0298': ['numeric_14_f32', 'coordinate_x_18_f32', 'coordinate_z_1c_f32'],
  }[routeHex(profile.packet_id)] ?? [];
  assertFiniteFields(decoded, floatFields);
  if (profile.packet_id === 0x01ab
      && Math.abs(decoded.direction_norm - 1) > 0.001) {
    throw new Error('0x01ab face-direction vector is outside the validated unit-vector bound');
  }
  return { profile, replay_sha256: sourceSha, decoded };
}

function isGameplayRouteTailDecodedRow(replay, row, runtimeImage) {
  try {
    assertGameplayRouteTailDecodedRow(replay, row, runtimeImage);
    return true;
  } catch {
    return false;
  }
}

function rawPacketRef(row) {
  return {
    source_path: row.replay_path ?? null,
    replay_sha256: row.replay_sha256,
    chunk_index: row.chunk_index ?? null,
    chunk_id: row.chunk_id ?? null,
    chunk_stream: row.chunk_stream ?? null,
    chunk_file_offset: row.chunk_file_offset ?? null,
    compressed_body_offset: row.compressed_body_offset ?? null,
    decompressed_block_offset: row.decompressed_block_offset ?? null,
    decompressed_payload_offset: row.decompressed_payload_offset ?? null,
    occurrence_index: row.occurrence_index ?? null,
    packet_id: row.packet_id,
    packet_type: routeHex(row.packet_id),
    payload_length: row.payload_length ?? null,
    raw_param: row.raw_param,
    payload_sha256: row.raw_payload_sha256,
  };
}

function fieldConfidence(profile) {
  return Object.fromEntries(Object.entries(profile.field_evidence).map(([name, evidence]) => {
    if (evidence.startsWith('CANDIDATE')) return [name, 'CANDIDATE'];
    if (evidence.includes('UNKNOWN')) return [name, 'UNKNOWN_ROLE_VALUE_VERIFIED_DIRECT'];
    return [name, 'VERIFIED_DIRECT'];
  }));
}

function protocolFields(profile, decoded) {
  if (profile.packet_id === 0x00e4) {
    return {
      flag_10_u8: decoded.flag_10_u8,
      flag_11_u8: decoded.flag_11_u8,
      flag_18_u8: decoded.flag_18_u8,
      selector_19_u8: decoded.selector_19_u8,
      neutral_role_status: 'UNKNOWN_RETAINED_DECODED',
    };
  }
  if (profile.packet_id === 0x01ab) {
    return {
      flag_u8: decoded.flag_u8,
      scalar_20_f32: decoded.scalar_20_f32,
      direction_norm_validation: decoded.direction_norm,
      flag_role_status: 'UNKNOWN_RETAINED_DECODED',
      scalar_role_status: 'UNKNOWN_RETAINED_DECODED',
    };
  }
  if (profile.packet_id === 0x01b5) {
    return { inline_attack_subobject_status: 'UNKNOWN_STRUCTURAL_RETAINED_IN_RAW_PACKET_REF' };
  }
  return {};
}

function publishableValues(profile, decoded) {
  if (profile.packet_id === 0x00b8) return { ...decoded };
  if (profile.packet_id === 0x00e4) {
    return {
      attack_sequence_14_u32: decoded.attack_sequence_14_u32,
      target_network_id_candidate_1c_u32: decoded.target_network_id_candidate_1c_u32,
    };
  }
  if (profile.packet_id === 0x01ab) {
    return {
      direction_x_f32: decoded.direction_x_f32,
      direction_y_f32: decoded.direction_y_f32,
      direction_z_f32: decoded.direction_z_f32,
    };
  }
  if (profile.packet_id === 0x01b5) {
    return {
      target_network_id_u32: decoded.target_network_id_u32,
      position_x_f32: decoded.position_x_f32,
      position_z_f32: decoded.position_z_f32,
    };
  }
  if (profile.packet_id === 0x0298) return { ...decoded };
  if (profile.packet_id === 0x03d4) return { ...decoded };
  throw new Error(`unsupported public route ${routeHex(profile.packet_id)}`);
}

function gameplayRouteTailEventFromDecodedRow(replay, row, runtimeImage) {
  const { profile, replay_sha256: replaySha256, decoded } =
    assertGameplayRouteTailDecodedRow(replay, row, runtimeImage);
  return {
    event_type: profile.event_type,
    semantic_type: 'ResearchEvent',
    semantic_domain: profile.semantic_domain,
    patch: PATCH,
    build_profile: profile.id,
    exact_build: EXACT_BUILD,
    game_version: EXACT_BUILD,
    replay_sha256: replaySha256,
    replay_time_ms: Number(row.replay_time_ms),
    subject_network_id: row.raw_param >>> 0,
    ...publishableValues(profile, decoded),
    semantic_status: 'VERIFIED_DIRECT_BOUNDED_RESEARCH_EVENT',
    confidence: 'VERIFIED_DIRECT',
    evidence_grade:
      'VERIFIED_EXACT_BUILD_RUNTIME_CONSUMER_PLUS_STRATIFIED_NATIVE_DECODE',
    field_confidence: fieldConfidence(profile),
    field_evidence: { ...profile.field_evidence },
    decoder_profile: profile.id,
    runtime_decoder_profile: profile.runtime_decoder_profile_id,
    decoder_profile_sha256: profile.runtime_decoder_profile_sha256,
    decoder_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    validation_artifact: profile.validation_artifact,
    validation_artifact_sha256: profile.validation_artifact_sha256,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: rawPacketRef(row),
    protocol_fields: protocolFields(profile, decoded),
    known_limits: [...profile.known_limits],
  };
}

module.exports = {
  EXACT_BUILD,
  GAMEPLAY_ROUTE_TAIL_PROFILES,
  PATCH,
  ROUTE_IDS,
  RUNTIME_IMAGE_SHA256,
  VALIDATION_ARTIFACT,
  VALIDATION_ARTIFACT_SHA256,
  assertGameplayRouteTailDecodedRow,
  assertRuntimeImage,
  decodeRouteObject,
  gameplayRouteTailEventFromDecodedRow,
  isGameplayRouteTailDecodedRow,
  profileForRoute,
  rawPacketRef,
  rotateLeft8,
  rotateRight8,
  routeHex,
  swapAdjacentBits,
};
