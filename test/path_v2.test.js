'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  PATH_PACKET_PROFILE,
  buildPathOutputs,
  normalizeVerifiedHeroPosition,
} = require('../src/path_pipeline_v2');
const { packetRefKey } = require('../src/provenance_v2');
const { parseArgs, v2InputsForReplay } = require('../src/cli');

function replay(overrides = {}) {
  return {
    source_sha256: 'a'.repeat(64),
    header: { version: PATH_PACKET_PROFILE.replay_version },
    ...overrides,
  };
}

function row(overrides = {}) {
  return {
    schema_version: 1,
    event_type: 'hero_position_1s',
    replay_sha256: 'a'.repeat(64),
    timestamp_ms: 2000,
    entity_id: 0x400000af,
    position_xz: [8110, 5676],
    source_path_timestamp_ms: 1817,
    coordinate_transform_status: 'VERIFIED_CURRENT_CALIBRATION',
    raw_packet_ref: {
      replay_sha256: 'a'.repeat(64),
      chunk_index: 2,
      decompressed_block_offset: 8192,
      packet_id: 0x02d1,
      packet_timestamp_ms: 1817,
      payload_length: 4,
      raw_param: 0,
      raw_payload_sha256: 'b'.repeat(64),
    },
    ...overrides,
  };
}

function pathProvenance(overrides = {}) {
  const rawPacketRef = row().raw_packet_ref;
  return {
    inputSha256: PATH_PACKET_PROFILE.artifact_sha256.hero_positions,
    packetIndex: new Map([[
      packetRefKey(
        rawPacketRef.chunk_index,
        rawPacketRef.decompressed_block_offset,
        rawPacketRef.packet_id,
      ),
      {
        replay_sha256: rawPacketRef.replay_sha256,
        chunk_index: rawPacketRef.chunk_index,
        decompressed_block_offset: rawPacketRef.decompressed_block_offset,
        packet_id: rawPacketRef.packet_id,
        timestamp_ms: rawPacketRef.packet_timestamp_ms,
        payload_length: rawPacketRef.payload_length,
        raw_param: rawPacketRef.raw_param,
        raw_payload_sha256: rawPacketRef.raw_payload_sha256,
      },
    ]]),
    ...overrides,
  };
}

test('verified one-second Path output becomes a derived semantic position event', () => {
  const event = normalizeVerifiedHeroPosition(replay(), row(), PATH_PACKET_PROFILE, pathProvenance());
  assert.ok(event);
  assert.equal(event.event_type, 'position');
  assert.equal(event.confidence, 'VERIFIED_DERIVED');
  assert.equal(event.network_id, 0x400000af);
  assert.deepEqual(event.position_xz, [8110, 5676]);
  assert.equal(event.decoder_profile, PATH_PACKET_PROFILE.id);
  assert.equal(event.field_confidence.position_xz, 'VERIFIED_DERIVED_INTERPOLATED');
  assert.equal(event.source_raw_packet_ref.packet_id, 0x02d1);
  assert.equal(event.raw_packet_ref, event.source_raw_packet_ref);
});

test('Path ingestion rejects a wrong replay, transform status, or future source path', () => {
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ replay_sha256: 'b'.repeat(64) }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ coordinate_transform_status: 'CANDIDATE_PENDING_CALIBRATION' }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ source_path_timestamp_ms: 2001 }), PATH_PACKET_PROFILE, pathProvenance()), null);
});

test('Path output reports accepted and rejected rows without crossing replay provenance', () => {
  const outputs = buildPathOutputs(replay(), [
    row({ timestamp_ms: 3000 }),
    row({ timestamp_ms: 2000 }),
    row({ position_xz: [Number.NaN, 2] }),
    row({ replay_sha256: 'b'.repeat(64) }),
  ], pathProvenance());
  assert.equal(outputs.status, 'HERO_POSITION_VERIFIED_DERIVED');
  assert.equal(outputs.input_count, 3);
  assert.equal(outputs.accepted_count, 2);
  assert.equal(outputs.rejected_count, 1);
  assert.deepEqual(outputs.position_events.map((event) => event.replay_time_ms), [2000, 3000]);
});

test('Path ingestion requires the pinned whole-file SHA and an exact source packet record', () => {
  assert.equal(normalizeVerifiedHeroPosition(replay(), row(), PATH_PACKET_PROFILE, pathProvenance({
    inputSha256: 'c'.repeat(64),
  })), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ raw_packet_ref: {
    ...row().raw_packet_ref,
    packet_timestamp_ms: 1818,
  } }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ raw_packet_ref: {
    ...row().raw_packet_ref,
    payload_length: 5,
  } }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ raw_packet_ref: {
    ...row().raw_packet_ref,
    raw_param: 1,
  } }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ raw_packet_ref: {
    ...row().raw_packet_ref,
    raw_payload_sha256: 'c'.repeat(64),
  } }), PATH_PACKET_PROFILE, pathProvenance()), null);
});

test('Path ingestion does not verify old unlinked or marker-only position rows', () => {
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({ raw_packet_ref: undefined }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row({
    raw_packet_ref: { replay_sha256: 'a'.repeat(64), packet_id: 0x02d1 },
  }), PATH_PACKET_PROFILE, pathProvenance()), null);
  assert.equal(normalizeVerifiedHeroPosition(replay(), row(), PATH_PACKET_PROFILE, {
    inputSha256: PATH_PACKET_PROFILE.artifact_sha256.hero_positions,
    packetIndex: new Map(),
  }), null);
});

test('CLI accepts explicit additive V2 artifact inputs', () => {
  const parsed = parseArgs([
    'analyze', 'replay/example.rofl',
    '--ward-spawns', 'ward-spawns.jsonl',
    '--ward-lifecycles', 'ward-lifecycles.jsonl',
    '--hero-positions', 'hero-positions.jsonl',
  ]);
  assert.equal(parsed.options.wardSpawns, 'ward-spawns.jsonl');
  assert.equal(parsed.options.wardLifecycles, 'ward-lifecycles.jsonl');
  assert.equal(parsed.options.heroPositions, 'hero-positions.jsonl');
  assert.deepEqual(parsed.positionals, ['replay/example.rofl']);
});

test('CLI hashes V2 JSONL inputs before replay filtering', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-path-input-'));
  const inputPath = path.join(directory, 'positions.jsonl');
  try {
    fs.writeFileSync(inputPath, `${JSON.stringify(row())}\n${JSON.stringify(row({
      replay_sha256: 'b'.repeat(64),
    }))}\n`);
    const inputs = v2InputsForReplay(replay(), { heroPositions: inputPath });
    assert.match(inputs.heroPositionInputSha256, /^[a-f0-9]{64}$/);
    assert.equal(inputs.heroPositions.length, 1);
    assert.equal(inputs.heroPositions[0].replay_sha256, 'a'.repeat(64));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
