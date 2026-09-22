'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  ANCHOR_TYPES,
  AnchorIndex,
  PRIMITIVE_TYPES,
  RAW_FIELD_SCHEMA_VERSION,
  TYPED_FIELD_SCHEMA_VERSION,
  bitAndPackedFieldDefinitions,
  candidateRoutesFromReport,
  configuredRawFieldDefinitions,
  createFieldBehaviorProfile,
  createTypedFieldBehaviorProfile,
  normalizeAnchor,
  packetRecordsFromHexField,
  primitiveFieldDefinitions,
  profileRouteRecords,
  readPackedBitsLE,
  readField,
  typedPacketRecordsFromDecodedFields,
  validateTypedFieldSchema,
} = require('../src/field_behavior_profiler');
const {
  loadAnchorFile,
  main: profileMain,
  parseArgs,
  rowsFromJson,
} = require('../scripts/profile_combat_state_fields');

function payload({ hp, maxHp, intValue, uintValue, uint16Value, packed }) {
  const buffer = Buffer.alloc(24);
  buffer.writeFloatLE(hp, 0);
  buffer.writeDoubleLE(maxHp, 4);
  buffer.writeInt32LE(intValue, 12);
  buffer.writeUInt32LE(uintValue, 16);
  buffer.writeUInt16LE(uint16Value, 20);
  buffer.writeUInt8(packed, 22);
  buffer.writeUInt8(0, 23);
  return buffer;
}

function record(replayTimeMs, values, overrides = {}) {
  return {
    build: '16.16.805.0442',
    packet_id: 0x4321,
    payload: payload(values),
    replay_key: 'replay-a',
    replay_time_ms: replayTimeMs,
    entity_id: 0x400000ae,
    champion: 'Ahri',
    sequence: replayTimeMs,
    ...overrides,
  };
}

function findField(profile, collection, type, offset, bitOffset = null) {
  return profile[collection].find((field) => field.type === type
    && field.offset === offset
    && (bitOffset === null || field.bit_offset === bitOffset));
}

test('primitive and packed readers support every required representation at unaligned offsets', () => {
  const buffer = payload({
    hp: 123.5,
    maxHp: 987.25,
    intValue: -12345,
    uintValue: 0xfedcba98,
    uint16Value: 65000,
    packed: 0b10110110,
  });
  const definitions = primitiveFieldDefinitions(buffer.length);
  for (const type of Object.keys(PRIMITIVE_TYPES)) {
    assert.ok(definitions.some((definition) => definition.type === type));
  }
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'float32' && row.offset === 0)), 123.5);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'float64' && row.offset === 4)), 987.25);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'int32' && row.offset === 12)), -12345);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'uint32' && row.offset === 16)), 0xfedcba98);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'uint16' && row.offset === 20)), 65000);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'uint8' && row.offset === 22)), 0b10110110);

  const packed = bitAndPackedFieldDefinitions([22]);
  assert.equal(readField(buffer, packed.find((row) => row.type === 'bitfield_candidate' && row.bit_offset === 1)), 1);
  assert.equal(readField(buffer, packed.find((row) => row.type === 'packed_uint2_candidate' && row.bit_offset === 2)), 1);
  assert.equal(readField(buffer, packed.find((row) => row.type === 'packed_uint4_candidate' && row.bit_offset === 4)), 11);
});

test('v1.2 reads signed widths, exact 64-bit integers, and configured cross-byte packed ranges', () => {
  const buffer = Buffer.alloc(32);
  buffer.writeInt8(-7, 1);
  buffer.writeInt16LE(-1234, 3);
  buffer.writeBigInt64LE(-9007199254740993n, 7);
  buffer.writeBigUInt64LE(18446744073709551615n, 16);
  buffer[24] = 0b10101100;
  buffer[25] = 0b00011110;

  const definitions = primitiveFieldDefinitions(buffer.length);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'int8' && row.offset === 1)), -7);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'int16' && row.offset === 3)), -1234);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'int64' && row.offset === 7)), -9007199254740993n);
  assert.equal(readField(buffer, definitions.find((row) => row.type === 'uint64' && row.offset === 16)), 18446744073709551615n);
  assert.equal(readPackedBitsLE(buffer, 24, 5, 8), 245);

  const configured = configuredRawFieldDefinitions({
    schema: RAW_FIELD_SCHEMA_VERSION,
    fields: [
      { field_id: 'cross_byte_u8', type: 'packed_bits', offset: 24, bit_offset: 5, bit_width: 8 },
      { field_id: 'cross_byte_signed', type: 'packed_bits', offset: 24, bit_offset: 4, bit_width: 12, signed: true },
    ],
  });
  assert.equal(configured[0].byte_length, 2);
  assert.equal(configured[0].endianness, 'little_lsb0');
  assert.equal(readField(buffer, configured[0]), 245);
  assert.equal(readField(buffer, configured[1]), 490);
  assert.throws(() => configuredRawFieldDefinitions({ schema: 'WRONG', fields: [] }), /must declare/);
});

test('raw profiler retains exact decimal ranges and deltas for unsafe uint64 values', () => {
  const values = [9007199254740993n, 9007199254740995n, 9007199254740995n];
  const records = values.map((value, index) => {
    const raw = Buffer.alloc(10);
    raw.writeBigUInt64LE(value, 0);
    raw[8] = index === 0 ? 0b11110000 : 0b00001111;
    raw[9] = index;
    return {
      build: '16.16.805.0442',
      packet_id: 0x0400,
      payload: raw,
      replay_key: 'exact-u64',
      replay_time_ms: index * 1000,
      entity_id: 1,
      sequence: index,
    };
  });
  const profile = profileRouteRecords(records, {
    types: ['uint64'],
    maxCandidatesPerType: 16,
    maxPackedCarrierOffsets: 1,
    configuredFields: {
      schema: RAW_FIELD_SCHEMA_VERSION,
      fields: [{ field_id: 'configured_cross_byte', type: 'packed_bits', offset: 8, bit_offset: 4, bit_width: 9 }],
    },
  });
  const uint64 = findField(profile, 'primitive_fields', 'uint64', 0);
  assert.ok(uint64);
  assert.equal(uint64.observation_count, 3);
  assert.equal(uint64.numeric_observation_count, 0);
  assert.deepEqual(uint64.exact_integer_statistics.range_decimal, {
    min: '9007199254740993',
    max: '9007199254740995',
    span: '2',
  });
  assert.equal(uint64.exact_integer_statistics.numeric_statistics_status, 'NOT_COMPUTABLE_WITHOUT_IEEE754_PRECISION_LOSS');
  assert.equal(uint64.exact_integer_statistics.delta_distribution.change_rate, 0.5);
  assert.equal(uint64.per_entity_stability.entities[0].range_decimal.max, '9007199254740995');
  assert.equal(profile.configured_fields[0].field_id, 'configured_cross_byte');
  assert.equal(profile.configured_fields[0].semantic_claim, null);
});

test('field profiler reports full statistics, entity/champion stability, and anchor correlations as candidates', () => {
  const records = [
    record(0, { hp: 100, maxHp: 1000, intValue: -2, uintValue: 10, uint16Value: 3, packed: 0b00010001 }),
    record(1000, { hp: 90, maxHp: 1000, intValue: -1, uintValue: 11, uint16Value: 3, packed: 0b00010000 }),
    record(2000, { hp: 110, maxHp: 1050, intValue: 0, uintValue: 12, uint16Value: 4, packed: 0b00100011 }),
  ];
  const anchors = [
    { event_type: 'damage', replay_key: 'replay-a', replay_time_ms: 500, entity_id: 0x400000ae, amount: 10 },
    { event_type: 'heal', replay_key: 'replay-a', replay_time_ms: 1500, entity_id: 0x400000ae, amount: 20 },
    { event_type: 'shield_applied', replay_key: 'replay-a', replay_time_ms: 1500, target_network_id: 0x400000ae, shield_amount: 30 },
    { event_type: 'spell_cast', replay_key: 'replay-a', replay_time_ms: 1500, caster_network_id: 0x400000ae },
  ];
  const profile = profileRouteRecords(records, {
    anchorIndex: new AnchorIndex(anchors),
    anchorWindowMs: 1000,
    maxCandidatesPerType: 64,
    maxPackedCarrierOffsets: 24,
    medianSampleLimit: 32,
    maxTrajectoryFields: 1000,
    maxTrajectoryPointsPerEntity: 10,
  });
  const hp = findField(profile, 'primitive_fields', 'float32', 0);
  assert.ok(hp);
  assert.deepEqual(hp.range, { min: 90, max: 110, span: 20 });
  assert.equal(hp.mean, 100);
  assert.equal(hp.median, 100);
  assert.equal(hp.variance, 66.6666666667);
  assert.equal(hp.zero_rate, 0);
  assert.equal(hp.change_rate, 1);
  assert.equal(hp.delta_distribution.negative_count, 1);
  assert.equal(hp.delta_distribution.positive_count, 1);
  assert.equal(hp.per_entity_stability.entity_series_count, 1);
  assert.equal(hp.per_entity_stability.trajectory_status, 'BOUNDED_SAMPLED_TRAJECTORIES_INCLUDED');
  assert.deepEqual(hp.per_entity_stability.entities[0].trajectory, [
    { replay_time_ms: 0, sequence: 0, value: 100 },
    { replay_time_ms: 1000, sequence: 1000, value: 90 },
    { replay_time_ms: 2000, sequence: 2000, value: 110 },
  ]);
  assert.equal(hp.per_champion_behavior.champions[0].champion, 'Ahri');
  assert.equal(hp.correlation_with_damage.matched_anchor_count, 1);
  assert.equal(hp.correlation_with_damage.expected_direction_rate, 1);
  assert.equal(hp.correlation_with_heal.matched_anchor_count, 1);
  assert.equal(hp.correlation_with_heal.expected_direction_rate, 1);
  assert.equal(hp.correlation_with_shield.matched_anchor_count, 1);
  assert.equal(hp.correlation_with_shield.expected_direction_policy, 'NONZERO_DELTA_DIRECTION_AGNOSTIC');
  assert.equal(hp.correlation_with_cast.matched_anchor_count, 1);
  assert.equal(hp.correlation_with_death.status, 'UNAVAILABLE_NO_ANCHORS');
  assert.equal(hp.evidence_grade, 'CANDIDATE');
  assert.equal(hp.semantic_claim, null);
  assert.equal(hp.heuristic_only, true);

  assert.ok(findField(profile, 'primitive_fields', 'float64', 4));
  assert.ok(findField(profile, 'primitive_fields', 'int32', 12));
  assert.ok(findField(profile, 'primitive_fields', 'uint32', 16));
  assert.ok(findField(profile, 'primitive_fields', 'uint16', 20));
  assert.ok(findField(profile, 'primitive_fields', 'uint8', 22));
  assert.ok(findField(profile, 'bitfield_candidates', 'bitfield_candidate', 22, 0));
  assert.ok(findField(profile, 'packed_field_candidates', 'packed_uint4_candidate', 22, 0));
});

test('anchor normalization targets the affected entity and rejects incomplete evidence', () => {
  const normalized = normalizeAnchor({
    event_type: 'hero_damage',
    replay_time_ms: 1234,
    target_network_id: 0x400000ae,
    amount: 25,
    raw_packet_ref: { replay_sha256: 'abc' },
  });
  assert.deepEqual(normalized, {
    event_type: 'damage',
    replay_key: 'abc',
    replay_time_ms: 1234,
    entity_id: 0x400000ae,
    amount: 25,
    champion: null,
    evidence_grade: 'SOURCE_REPORTED',
  });
  assert.equal(normalizeAnchor({ event_type: 'damage', replay_time_ms: 1 }), null);
  assert.deepEqual(ANCHOR_TYPES, [
    'damage',
    'heal',
    'shield',
    'death',
    'respawn',
    'level',
    'item_change',
    'cast',
    'ward',
    'movement',
  ]);
  assert.equal(normalizeAnchor({
    event_type: 'ward_spawn',
    replay_key: 'abc',
    replay_time_ms: 20,
    owner_network_id: 0x400000ae,
  }).event_type, 'ward');
  assert.equal(normalizeAnchor({
    event_type: 'position_update',
    replay_key: 'abc',
    replay_time_ms: 30,
    entity_network_id: 0x400000ae,
    distance: 12,
  }).amount, 12);
  assert.equal(normalizeAnchor({
    event_type: 'item_purchase',
    replay_key: 'abc',
    replay_time_ms: 40,
    owner_network_id: 0x400000af,
  }).entity_id, 0x400000af);
  assert.equal(normalizeAnchor({
    event_type: 'shield_apply',
    replay_key: 'abc',
    replay_time_ms: 50,
    entity_id: 0x400000b0,
    shield_amount: 75,
  }).amount, 75);
});

test('candidate reports and packet inventories rank champion-bound unknown routes without semantic promotion', () => {
  const routes = candidateRoutesFromReport({
    packets: [
      {
        packet_id: 2,
        count: 100000,
        confidence: 'CANDIDATE',
        currently_decoded_as_status: 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
        entity_candidate: { kind: 'RAW_PARAM_ZERO_ONLY' },
        payload_size_distribution: [{ payload_length: 2, count: 100000 }],
      },
      {
        packet_id: 3,
        count: 100,
        confidence: 'CANDIDATE',
        currently_decoded_as_status: 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
        entity_candidate: { kind: 'CHAMPION_NETWORK_ID_RANGE_CANDIDATE' },
        payload_size_distribution: [{ payload_length: 32, count: 100 }],
      },
      {
        packet_id: 4,
        count: 100,
        confidence: 'VERIFIED_DIRECT',
        currently_decoded_as_status: 'EXACT_BUILD_ROUTE_REGISTERED',
      },
    ],
  }, { maxRoutes: 2 });
  assert.deepEqual(routes.map((row) => row.packet_id), [3, 2]);
  assert.ok(routes.every((row) => row.evidence_grade === 'CANDIDATE'));
});

test('decoded nested hex fields are first-class exact-build inputs and negative controls are excluded from ranking', () => {
  const rows = [100, 90, 110].map((hp, index) => ({
    replay_version: '16.16.805.0442',
    replay_sha256: 'replay-export',
    replay_path: 'fixture.rofl',
    replay_time_ms: index * 1000,
    occurrence_index: index,
    packet_id: 0x0178,
    raw_param: 0x400000ae,
    champion: 'Ahri',
    fully_consumed: true,
    decoded_fields: { blob_hex: payload({
      hp,
      maxHp: 1000,
      intValue: index,
      uintValue: index,
      uint16Value: index,
      packed: index,
    }).toString('hex') },
  }));
  rows.push({ ...rows[0], occurrence_index: 99, fully_consumed: false });
  const extracted = packetRecordsFromHexField(rows, 'decoded_fields.blob_hex', {
    targetBuild: '16.16.805.0442',
  });
  assert.equal(extracted.accepted_row_count, 3);
  assert.equal(extracted.rejected.not_fully_consumed, 1);
  assert.equal(extracted.records[0].payload.length, 24);
  assert.equal(extracted.records[0].payload_source_field, 'decoded_fields.blob_hex');
  assert.equal(extracted.champion_mapping.explicit_packet_record_count, 3);
  assert.equal(extracted.records[0].champion, 'Ahri');

  const report = createFieldBehaviorProfile({
    packetRecords: extracted.records,
    packetRecordExtraction: {
      hex_field: extracted.hex_field,
      accepted_row_count: extracted.accepted_row_count,
    },
    routeIds: [0x0178],
    targetBuild: '16.16.805.0442',
    options: {
      maxCandidatesPerType: 8,
      maxPackedCarrierOffsets: 4,
      routeRole: 'NEGATIVE_CONTROL',
      knownRouteSemantics: 'TEST_KNOWN_NON_COMBAT_ROUTE',
    },
  });
  assert.equal(report.input.input_mode, 'DECODED_HEX_FIELD_EXPORT');
  assert.equal(report.route_profiles[0].profiled_value_source, 'decoded_fields.blob_hex');
  assert.equal(report.route_profiles[0].status, 'NEGATIVE_CONTROL_PROFILE_AVAILABLE');
  assert.equal(report.route_profiles[0].known_route_semantics, 'TEST_KNOWN_NON_COMBAT_ROUTE');
  assert.equal(report.route_profiles[0].excluded_from_combat_state_ranking, true);
  assert.deepEqual(report.ranked_candidates, []);
});

test('explicit typed adapter profiles numeric, identifier, enum, string, opaque hash, and vector values without promotion', () => {
  const schema = {
    schema: TYPED_FIELD_SCHEMA_VERSION,
    fields: [
      { field_id: 'decoded_counter', path: 'decoded.counter', type: 'uint64' },
      { field_id: 'identifier_candidate', path: 'decoded.owner', type: 'identifier' },
      { field_id: 'phase_candidate', path: 'decoded.phase', type: 'enum' },
      { field_id: 'name_candidate', path: 'decoded.name', type: 'string' },
      { field_id: 'opaque_hash_candidate', path: 'decoded.hash', type: 'hash', dictionary: [111, 222] },
      { field_id: 'position_candidate', path: 'decoded.position', type: 'vector2' },
    ],
  };
  const rows = [
    { time: 0, entity: 1, champion: 'Ahri', counter: '9007199254740993', owner: 'owner-a', phase: 'idle', name: 'Alpha', hash: 111, position: [3, 4] },
    { time: 1000, entity: 1, champion: 'Ahri', counter: '9007199254740994', owner: 'owner-a', phase: 'cast', name: 'Alpha', hash: 111, position: [0, 5] },
    { time: 0, entity: 2, champion: 'Talon', counter: '9007199254740995', owner: 'owner-b', phase: 'idle', name: 'Beta', hash: 333, position: [5, 12] },
    { time: 1000, entity: 2, champion: 'Talon', counter: '9007199254740996', owner: 'owner-b', phase: 'idle', name: 'Beta', hash: 333, position: [8, 15] },
  ].map((row, index) => ({
    build: '16.16.805.0442',
    replay_sha256: 'typed-replay',
    packet_id: 0x0302,
    replay_time_ms: row.time,
    occurrence_index: index,
    raw_param: row.entity,
    champion: row.champion,
    fully_consumed: true,
    decoded: {
      counter: row.counter,
      owner: row.owner,
      phase: row.phase,
      name: row.name,
      hash: row.hash,
      position: row.position,
    },
  }));
  rows.push({ ...rows[0], occurrence_index: 99, fully_consumed: false });

  const validated = validateTypedFieldSchema(schema);
  assert.equal(validated.semantic_claim, null);
  const extracted = typedPacketRecordsFromDecodedFields(rows, schema, {
    targetBuild: '16.16.805.0442',
  });
  assert.equal(extracted.accepted_row_count, 4);
  assert.equal(extracted.rejected.not_fully_consumed, 1);
  assert.equal(extracted.champion_mapping.replay_tail_lookup_attempted, false);

  const report = createTypedFieldBehaviorProfile({
    packetRecords: extracted.records,
    fieldSchema: schema,
    routeIds: [0x0302],
    targetBuild: '16.16.805.0442',
  });
  assert.equal(report.input.input_mode, 'DECODED_TYPED_FIELD_EXPORT');
  assert.equal(report.semantic_claim, null);
  const fields = Object.fromEntries(report.route_profiles[0].configured_typed_fields
    .map((field) => [field.field_id, field]));
  assert.equal(fields.decoded_counter.exact_integer_statistics.range_decimal.min, '9007199254740993');
  assert.equal(fields.decoded_counter.exact_integer_statistics.numeric_statistics_status, 'NOT_COMPUTABLE_WITHOUT_IEEE754_PRECISION_LOSS');
  assert.equal(fields.identifier_candidate.identifier_candidate_metrics.distinct_value_count, 2);
  assert.equal(fields.identifier_candidate.identifier_candidate_metrics.single_value_entity_series_rate, 1);
  assert.equal(fields.identifier_candidate.semantic_claim, null);
  assert.equal(fields.phase_candidate.categorical_statistics.distinct_count, 2);
  assert.equal(fields.phase_candidate.change_rate, 0.5);
  assert.equal(fields.name_candidate.string_statistics.length.range.max, 5);
  assert.equal(fields.opaque_hash_candidate.hash_candidate_statistics.algorithm_claim, null);
  assert.equal(fields.opaque_hash_candidate.hash_candidate_statistics.dictionary_match_rate, 0.5);
  assert.deepEqual(fields.position_candidate.range, { min: 5, max: 17, span: 12 });
  assert.equal(fields.position_candidate.vector_statistics.direction_statistics.status,
    'NOT_COMPUTABLE_COORDINATE_FRAME_AND_DIRECTION_SEMANTICS_UNDECLARED');
  assert.equal(fields.phase_candidate.correlation_with_damage.status,
    'NOT_COMPUTABLE_CATEGORICAL_ANCHOR_TEST_NOT_DECLARED');
  assert.ok(report.ranked_candidates.every((candidate) => candidate.semantic_claim === null));

  assert.throws(() => validateTypedFieldSchema({ fields: schema.fields }), /must declare/);
});

test('CLI parses explicit exact-build inputs and loads typed JSONL anchors with provenance', () => {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'field-profiler-'));
  try {
    const anchorPath = path.join(temporaryDirectory, 'damage.jsonl');
    fs.writeFileSync(anchorPath, '{"replay_time_ms":10,"target_network_id":1073741998,"replay_sha256":"x","amount":4}\n');
    const loaded = loadAnchorFile({ eventType: 'damage', filePath: anchorPath });
    assert.equal(loaded.anchors[0].event_type, 'damage');
    assert.equal(loaded.source.input_row_count, 1);
    assert.match(loaded.source.source_sha256, /^[0-9a-f]{64}$/);

    const parsed = parseArgs([
      '--build', '16.16.805.0442',
      '--route', '0x04ca',
      '--anchor', `damage=${anchorPath}`,
      'fixture.rofl',
    ]);
    assert.equal(parsed.targetBuild, '16.16.805.0442');
    assert.deepEqual(parsed.routeIds, [0x04ca]);
    assert.equal(parsed.anchorSpecs[0].eventType, 'damage');
    assert.match(parsed.replayPaths[0], /fixture\.rofl$/);

    const packetMode = parseArgs([
      '--packet-records', anchorPath,
      '--field-schema', anchorPath,
      '--route-role', 'negative_control',
      '--max-trajectory-fields', '20',
      '--max-trajectory-points-per-entity', '32',
    ]);
    assert.match(packetMode.fieldSchemaPath, /damage\.jsonl$/);
    assert.equal(packetMode.routeRole, 'NEGATIVE_CONTROL');
    assert.equal(packetMode.maxTrajectoryFields, 20);
    assert.equal(packetMode.maxTrajectoryPointsPerEntity, 32);
    assert.deepEqual(rowsFromJson({ shield_events: [{ amount: 10 }] }), [{ amount: 10 }]);

    const schemaPath = path.join(temporaryDirectory, 'typed-schema.json');
    const packetPath = path.join(temporaryDirectory, 'typed-packets.jsonl');
    const outputPath = path.join(temporaryDirectory, 'typed-profile.json');
    fs.writeFileSync(schemaPath, JSON.stringify({
      schema: TYPED_FIELD_SCHEMA_VERSION,
      fields: [{ field_id: 'state_candidate', path: 'decoded.state', type: 'enum' }],
    }));
    fs.writeFileSync(packetPath, `${JSON.stringify({
      build: '16.16.805.0442',
      replay_sha256: 'typed-cli-replay',
      packet_id: 0x0302,
      replay_time_ms: 10,
      raw_param: 1,
      fully_consumed: true,
      decoded: { state: 'candidate-a' },
    })}\n`);
    const originalWrite = process.stdout.write;
    process.stdout.write = () => true;
    let typedReport;
    try {
      typedReport = profileMain([
        '--packet-records', packetPath,
        '--field-schema', schemaPath,
        '--build', '16.16.805.0442',
        '--route', '0x0302',
        '--output', outputPath,
      ]);
    } finally {
      process.stdout.write = originalWrite;
    }
    assert.equal(typedReport.input.input_mode, 'DECODED_TYPED_FIELD_EXPORT');
    assert.equal(JSON.parse(fs.readFileSync(outputPath)).analyzer_version, 'field-behavior-profiler-v1.2');
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test('latest-four high-frequency evidence coverage conserves every route and packet count at the threshold', () => {
  const root = path.resolve(__dirname, '..');
  const coverage = JSON.parse(fs.readFileSync(path.join(
    root,
    'artifacts',
    'hero_combat_state_v2',
    'profiler',
    'high_frequency_route_evidence_coverage_v1_2.json',
  )));
  const matrix = JSON.parse(fs.readFileSync(path.join(
    root,
    'artifacts',
    'hero_combat_state_v2',
    'profiler',
    'field_behavior_profiler_coverage_matrix.json',
  )));
  const inventory = JSON.parse(fs.readFileSync(path.join(
    root,
    'artifacts',
    'hero_combat_state_v2',
    'inventory',
    'latest_four_16_16_packet_inventory.json',
  )));
  const expected = inventory.packets
    .filter((row) => row.count >= coverage.threshold_inclusive_packet_count);
  const actual = new Map(coverage.routes.map((row) => [row.packet_id, row]));
  assert.equal(actual.size, expected.length);
  for (const row of expected) {
    assert.equal(actual.get(row.packet_id)?.count, row.count);
  }
  assert.equal(coverage.routes.reduce((sum, row) => sum + row.count, 0), 5845299);
  assert.equal(coverage.metrics.uncovered_route_count, 0);
  assert.equal(coverage.metrics.status, 'COMPLETE_EVIDENCE_SURFACE_COVERAGE_NOT_SEMANTIC_COMPLETENESS');
  const newRawRoutes = coverage.routes.filter((row) => row.evidence_class === 'V1_2_LATEST_FOUR_RAW_PROFILE');
  assert.deepEqual(newRawRoutes.map((row) => row.packet_discriminator).sort(), [
    '0x0092', '0x00b9', '0x0105', '0x01c2', '0x029d', '0x03aa', '0x0404', '0x0473',
  ]);
  assert.ok(newRawRoutes.every((row) => row.semantic_claim === null));
  assert.ok(coverage.routes.filter((row) => row.runtime_name)
    .every((row) => row.runtime_name_is_candidate_only === true && row.semantic_claim === null));
  assert.equal(matrix.analyzer_version, 'field-behavior-profiler-v1.2');
  assert.equal(matrix.v1_2_gap_closure.original_explicit_gap_count, 11);
  assert.equal(matrix.v1_2_gap_closure.remaining_gap_count, 6);
  assert.equal(matrix.v1_2_gap_closure.baseline_builder_limit_entry_count, 9);
  assert.equal(matrix.v1_2_gap_closure.original_gap_audit.length, 11);
  assert.equal(matrix.high_frequency_route_evidence.uncovered_route_count, 0);
});
