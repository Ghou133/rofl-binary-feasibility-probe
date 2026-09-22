const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { emptyEventSet } = require('../src/analysis');
const {
  LEVEL_UP_PROFILE,
  isLevelTransitionDecodedRow,
  levelTransitionEventFromDecodedRow,
} = require('../src/decoders/rofl_16_15_801_3452');
const {
  LEVEL_AFTER_BY_FIELD_10,
  LEVEL_MAPPING_REPLAY_VERSION,
  levelMapping,
  queryLevelTransitions,
  summarizeLevelSequences,
} = require('../src/level_transition');
const { runLevelTransitionDecoder, semanticCapabilities } = require('../src/semantic_pipeline');

const fixturePath = path.join(__dirname, 'fixtures', 'level-transition-evidence-v1.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

function syntheticReplay(version = fixture.target_replay_version) {
  const stats = Array.from({ length: 10 }, (_, index) => ({
    SKIN: index === 1 ? 'Graves' : `Champion${index + 1}`,
    TEAM: index < 5 ? '100' : '200',
  }));
  return {
    source_path: 'fixture://11185378168.rofl',
    source_sha256: fixture.selected_rows[0].replay_sha256,
    header: { version },
    tail: { stats },
  };
}

function attestedRow(row) {
  const sourceRow = {
    schema_version: 1,
    replay_label: '11185378168',
    ...row,
  };
  const decodedRow = {
    ...sourceRow,
    bytes_consumed: sourceRow.payload_length + 4,
    base_header_hex: 'fc5fd2fa',
    wrapper_return_al: 1,
    wrapper_bytes_consumed: 2,
    decoder_profile: LEVEL_UP_PROFILE.id,
    decoder_runtime_image_sha256: LEVEL_UP_PROFILE.runtime_image_sha256,
    decoder_constructor_rva: LEVEL_UP_PROFILE.constructor_rva,
    decoder_deserialize_rva: LEVEL_UP_PROFILE.deserialize_rva,
    decoder_object_size: LEVEL_UP_PROFILE.object_size,
    raw_packet_ref: {
      source_path: sourceRow.replay_path,
      replay_sha256: sourceRow.replay_sha256,
      chunk_index: sourceRow.chunk_index,
      chunk_id: sourceRow.chunk_id,
      chunk_stream: sourceRow.chunk_stream,
      chunk_file_offset: sourceRow.chunk_file_offset,
      compressed_body_offset: sourceRow.compressed_body_offset,
      decompressed_block_offset: sourceRow.decompressed_block_offset,
      decompressed_payload_offset: sourceRow.decompressed_payload_offset,
      replay_time_ms: sourceRow.replay_time_ms,
      occurrence_index: sourceRow.occurrence_index,
      packet_id: sourceRow.packet_id,
      payload_length: sourceRow.payload_length,
      raw_param: sourceRow.raw_param,
      raw_param_hex: sourceRow.raw_param_hex,
      payload_sha256: sourceRow.raw_payload_sha256,
    },
  };
  return { decodedRow, sourceRow };
}

test('LevelUp profile is exact-build pinned and synchronized with the runtime emulator', () => {
  assert.equal(LEVEL_UP_PROFILE.replay_version, '16.15.801.3452');
  assert.equal(LEVEL_UP_PROFILE.replay_block_packet_id, 0x025a);
  assert.equal(LEVEL_UP_PROFILE.client_opcode, 0x025a);
  assert.equal(LEVEL_UP_PROFILE.constructor_rva, 0x00e82060);
  assert.equal(LEVEL_UP_PROFILE.deserialize_rva, 0x00efaa50);
  assert.equal(LEVEL_UP_PROFILE.object_size, 0x18);
  assert.equal(LEVEL_UP_PROFILE.runtime_image_sha256, fixture.runtime_image_sha256);
  const emulatorSource = fs.readFileSync(
    path.join(__dirname, '..', 'scripts', 'decode_level_transition.py'),
    'utf8',
  );
  assert.match(emulatorSource, /PROFILE\s*=\s*\{/);
  assert.match(emulatorSource, /'profile': 'npc_level_up'/);
  assert.match(emulatorSource, /'client_opcode': 0x025A/);
  assert.match(emulatorSource, /'constructor_rva': 0x00E82060/);
  assert.match(emulatorSource, /'deserialize_rva': 0x00EFAA50/);
  assert.match(emulatorSource, /EXPECTED_IMAGE_SHA256/);
  assert.match(emulatorSource, /checked_metadata/);
});

test('field_10 level-after mapping is derived only on the validated build', () => {
  assert.equal(LEVEL_MAPPING_REPLAY_VERSION, fixture.target_replay_version);
  assert.deepEqual(LEVEL_AFTER_BY_FIELD_10, fixture.expected.field_10_to_level_after);
  assert.deepEqual(levelMapping(224, fixture.target_replay_version), {
    level_before: 1,
    level_after: 2,
    evidence: 'VERIFIED_DERIVED',
    qualification: 'PATCH_BOUND_TO_16.15.801.3452',
  });
  assert.equal(levelMapping(224, '16.15.801.9999').level_after, null);
  assert.equal(levelMapping(224, '16.15.801.9999').evidence, 'UNSUPPORTED_VERSION');
  assert.equal(levelMapping(206, fixture.target_replay_version).level_after, null);
  assert.equal(levelMapping(206, fixture.target_replay_version).evidence, 'UNAVAILABLE');
});

test('unsupported build cannot execute or inherit the LevelUp semantic profile', () => {
  const replay = syntheticReplay('16.14.999.1');
  const { decodedRow, sourceRow } = attestedRow(fixture.selected_rows[0]);
  assert.equal(isLevelTransitionDecodedRow(replay, decodedRow, sourceRow), false);
  assert.equal(
    levelTransitionEventFromDecodedRow(replay, decodedRow, undefined, sourceRow),
    null,
  );
  assert.throws(
    () => runLevelTransitionDecoder(replay),
    (error) => error.code === 'UNSUPPORTED_REPLAY_VERSION',
  );
});

test('frozen Lv2/Lv3/Lv4 rows build public LevelTransition events with mixed evidence grades', () => {
  const replay = syntheticReplay();
  const events = fixture.selected_rows.map((row) => {
    const { decodedRow, sourceRow } = attestedRow(row);
    assert.equal(isLevelTransitionDecodedRow(replay, decodedRow, sourceRow), true);
    return levelTransitionEventFromDecodedRow(replay, decodedRow, undefined, sourceRow);
  });
  assert.deepEqual(events.map((event) => event.level_after), [2, 3, 4]);
  assert.deepEqual(events.map((event) => event.level_before), [1, 2, 3]);
  assert.deepEqual(events.map((event, index) => event.timestamp_ms - fixture.selected_rows[index].details_time_ms), [1, 1, 0]);
  events.forEach((event, index) => {
    assert.equal(event.event_type, 'level_transition');
    assert.equal(event.entity_network_id, 0x400000af);
    assert.equal(event.participant_id, 2);
    assert.equal(event.champion, 'Graves');
    assert.equal(event.transition_evidence, 'VERIFIED_DIRECT');
    assert.equal(event.level_mapping_evidence, 'VERIFIED_DERIVED');
    assert.equal(event.game_version, fixture.target_replay_version);
    assert.equal(event.raw_packet_ref.occurrence_index, fixture.selected_rows[index].occurrence_index);
    assert.equal(event.raw_packet_ref.raw_param, fixture.selected_rows[index].raw_param);
    assert.equal(event.raw_packet_ref.raw_param_hex, fixture.selected_rows[index].raw_param_hex);
  });
});

test('LevelTransition promotion requires source-packet and decoder attestations', () => {
  const replay = syntheticReplay();
  const { decodedRow, sourceRow } = attestedRow(fixture.selected_rows[0]);
  assert.equal(isLevelTransitionDecodedRow(replay, decodedRow), false);
  assert.equal(isLevelTransitionDecodedRow(replay, {
    ...decodedRow,
    decoder_runtime_image_sha256: '0'.repeat(64),
  }, sourceRow), false);
  assert.equal(isLevelTransitionDecodedRow(replay, {
    ...decodedRow,
    raw_packet_ref: {
      ...decodedRow.raw_packet_ref,
      payload_sha256: '0'.repeat(64),
    },
  }, sourceRow), false);
  assert.equal(isLevelTransitionDecodedRow(replay, {
    ...decodedRow,
    raw_param: decodedRow.raw_param + 1,
  }, sourceRow), false);
  assert.equal(isLevelTransitionDecodedRow(replay, decodedRow, {
    ...sourceRow,
    replay_path: 'fixture://forged.rofl',
  }), false);
  assert.equal(isLevelTransitionDecodedRow(replay, decodedRow, {
    ...sourceRow,
    replay_sha256: 'not-a-sha256',
  }), false);
  const inconsistentParamSource = {
    ...sourceRow,
    raw_param_hex: '0x00000000',
  };
  assert.equal(isLevelTransitionDecodedRow(replay, {
    ...decodedRow,
    raw_param_hex: inconsistentParamSource.raw_param_hex,
    raw_packet_ref: {
      ...decodedRow.raw_packet_ref,
      raw_param_hex: inconsistentParamSource.raw_param_hex,
    },
  }, inconsistentParamSource), false);
  assert.equal(levelTransitionEventFromDecodedRow(replay, decodedRow), null);
});

test('timestamp zero is retained as initialization without inventing a level', () => {
  const replay = syntheticReplay();
  const row = {
    ...fixture.selected_rows[0],
    replay_time_ms: 0,
    occurrence_index: 0,
    decoded_fields: { field_10: 206, field_11: 181 },
  };
  const { decodedRow, sourceRow } = attestedRow(row);
  const event = levelTransitionEventFromDecodedRow(replay, decodedRow, undefined, sourceRow);
  assert.equal(event.is_initialization, true);
  assert.equal(event.level_before, null);
  assert.equal(event.level_after, null);
  assert.equal(event.transition_evidence, 'VERIFIED_DIRECT');
  assert.equal(event.level_mapping_evidence, 'UNAVAILABLE');
  assert.equal(queryLevelTransitions([event]).length, 0);
  assert.equal(queryLevelTransitions([event], { includeInitialization: true }).length, 1);
});

test('public level query returns monotonic Lv2/Lv3/Lv4 timestamps for a participant', () => {
  const replay = syntheticReplay();
  const events = fixture.selected_rows.map(
    (row) => {
      const { decodedRow, sourceRow } = attestedRow(row);
      return levelTransitionEventFromDecodedRow(replay, decodedRow, undefined, sourceRow);
    },
  );
  const queried = queryLevelTransitions(events, { participantId: 2, levels: [2, 3, 4] });
  assert.deepEqual(queried.map((event) => event.timestamp_ms), [79963, 117379, 179577]);
  assert.deepEqual(summarizeLevelSequences(queried), {
    participant_sequence_count: 1,
    monotonic_participant_sequence_count: 1,
    all_monotonic: true,
  });
});

test('capability output keeps negative ROFL results explicit', () => {
  const statuses = new Map(semanticCapabilities().map((row) => [row.capability, row.status]));
  assert.equal(statuses.get('level transition occurrence'), 'VERIFIED_DIRECT');
  assert.equal(statuses.get('level after'), 'VERIFIED_DERIVED');
  assert.equal(statuses.get('camp clear'), 'UNAVAILABLE');
  assert.equal(statuses.get('XP'), 'UNAVAILABLE');
  assert.equal(statuses.get('jungle CS'), 'UNAVAILABLE');
  assert.equal(statuses.get('current gold'), 'UNAVAILABLE');
  assert.equal(statuses.get('total gold'), 'UNAVAILABLE');
  assert.deepEqual(emptyEventSet().level_transition_events, []);
});

test('frozen evidence manifest preserves full-corpus regression expectations', () => {
  assert.equal(fixture.corpus.length, fixture.expected.replay_count);
  assert.equal(fixture.expected.decoded_packet_count, 4045);
  assert.equal(fixture.expected.fully_consumed_count, 4045);
  assert.equal(fixture.expected.matched_packet_count, 494);
  assert.equal(fixture.expected.missing_event_count, 0);
  assert.equal(fixture.expected.hero_param_packet_count, 496);
  assert.equal(fixture.expected.timestamp_zero_initialization_count, 2);
  assert.equal(fixture.expected.participant_sequence_count, 120);
  assert.equal(fixture.expected.monotonic_participant_sequence_count, 120);
  assert.equal(fixture.skill_level_up_proxy.status, 'REJECTED_AS_HERO_LEVEL_TIME');
});
