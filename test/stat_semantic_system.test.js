'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  RUNTIME_IMAGE_SHA256,
  assertSafePath,
  buildStatSelectorRegistry,
  correlateEvents,
  decodeFloat32Lanes,
  participantIdFromNetworkId,
  writeRegistryArtifacts,
} = require('../src/stat_semantic_system');

function hash(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function packet(overrides = {}) {
  return {
    replay_path: null,
    replay_sha256: 'a'.repeat(64),
    replay_version: EXACT_BUILD,
    replay_label: 'fixture',
    chunk_index: 1,
    chunk_stream: 'game_chunk',
    decompressed_payload_offset: 10,
    replay_time_ms: 100,
    packet_id: 0x042f,
    packet_type: '0x042f',
    raw_param: 0x400000ae,
    raw_payload_sha256: 'b'.repeat(64),
    deserialize_return_al: 1,
    fully_consumed: true,
    opcode_matches_profile: true,
    decoder_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    decoded_fields: {
      outputs: [{
        output_kind_storage: 194,
        formula_values_storage_hex: '0000a03f0000803f0000003e00000000',
      }],
    },
    ...overrides,
  };
}

function writeJsonl(file, rows) {
  fs.writeFileSync(file, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`, 'utf8');
}

function runtimeReport() {
  return {
    exact_build: EXACT_BUILD,
    exact_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    stat_formula_outputs: {
      status: 'VERIFIED_DIRECT_STRUCTURE_AND_WRITER_RELATION',
      route: '0x042f',
      callback_rva: '0x002a5c00',
      owner_storage_offset_hex: '0x49b8',
      exact_full_consume_count: 1,
      writer: { function_rva: '0x00999e40', selector_helper_rva: '0x00982690' },
      reader: {
        status: 'VERIFIED_DIRECT_GENERIC_SELECTOR_LANE_READER',
        wrapper_rva: '0x0028b630', storage_accessor_rva: '0x0028b670',
        lookup_rva: '0x00995c40', wrapper_direct_caller_count: 0,
        storage_accessor_direct_caller_count: 4, lookup_direct_caller_count: 9,
      },
    },
    hud_display_function: {
      non_p0_verified_formatter: {
        semantic: 'MANA_REGEN', selector: 11, lane: 0, format: '%0.f',
        localization_token: '@ManaRegen@', status: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
      },
    },
  };
}

test('four float32 lanes preserve their decoded order and finite values', () => {
  assert.deepEqual(decodeFloat32Lanes('0000a03f0000803f0000003e00000000'), [1.25, 1, 0.125, 0]);
  assert.throws(() => decodeFloat32Lanes('00'), /exactly 16 bytes/);
  assert.throws(() => decodeFloat32Lanes('0000c07f000000000000000000000000'), /finite/);
});

test('canonical champion network IDs map only inside the exact ten-participant range', () => {
  assert.equal(participantIdFromNetworkId(0x400000ae), 1);
  assert.equal(participantIdFromNetworkId(0x400000b7), 10);
  assert.equal(participantIdFromNetworkId(0x400000ad), null);
});

test('registry deduplicates packet identity, rejects unbound rows, and keeps static-only selector 11', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'stat-selector-registry-'));
  try {
    const first = path.join(temp, 'first.jsonl');
    const second = path.join(temp, 'second.jsonl');
    const runtime = path.join(temp, 'runtime.json');
    const events = path.join(temp, 'events.jsonl');
    const row = packet();
    writeJsonl(first, [row, packet({
      decompressed_payload_offset: 11,
      raw_payload_sha256: 'c'.repeat(64),
      decoded_fields: { outputs: [] },
    })]);
    writeJsonl(second, [row, packet({
      decompressed_payload_offset: 12,
      raw_payload_sha256: 'd'.repeat(64),
      decoder_runtime_image_sha256: undefined,
    })]);
    writeJsonl(events, [{ replay_time_ms: 100, target_network_id: 0x400000ae }]);
    fs.writeFileSync(runtime, `${JSON.stringify(runtimeReport())}\n`);
    const registry = await buildStatSelectorRegistry({
      rootDir: temp,
      inputs: {
        selectorSources: [{ id: 'first', path: first }, { id: 'second', path: second }],
        runtimeReport: runtime,
        eventSources: [{
          category: 'DAMAGE', path: events,
          default_replay_sha256: 'a'.repeat(64), default_entity_network_id: 0x400000ae,
        }],
      },
    });
    assert.equal(registry.corpus_scope.accepted_unique_packet_count, 2);
    assert.equal(registry.corpus_scope.duplicate_packet_count, 1);
    assert.equal(registry.corpus_scope.rejected_by_reason.RUNTIME_IMAGE_SHA_MISSING, 1);
    assert.deepEqual(registry.corpus_scope.observed_selector_ids, [194]);
    const selector11 = registry.selectors.find((entry) => entry.selector === 11);
    const selector194 = registry.selectors.find((entry) => entry.selector === 194);
    assert.equal(selector11.observed_output_record_count, 0);
    assert.equal(selector11.lanes[0].semantic, 'MANA_REGEN');
    assert.equal(selector194.lanes[0].semantic_status, 'UNKNOWN_NOT_PROMOTED');
    assert.equal(selector194.lane_relationships.lane0_equals_lane1_plus_lane2_all, false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('event correlation is explicitly temporal and reports unchanged brackets', () => {
  const records = [
    { replay_sha256: 'r', entity_network_id: 1, replay_time_ms: 0, stream: 'keyframe', lanes: [1, 1, 0, 0] },
    { replay_sha256: 'r', entity_network_id: 1, replay_time_ms: 200, stream: 'keyframe', lanes: [1, 1, 0, 0] },
  ];
  const result = correlateEvents(records, 0, [{
    category: 'ITEM', replay_sha256: 'r', entity_network_id: 1, replay_time_ms: 100,
  }], 1000);
  assert.equal(result[0].bracketed_within_90000ms_count, 1);
  assert.equal(result[0].unchanged_count, 1);
  assert.match(result[0].interpretation, /NOT_CAUSAL/);
});

test('artifact manifest binds generated registry and markdown', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'stat-selector-artifacts-'));
  try {
    const source = path.join(temp, 'source.jsonl');
    const runtime = path.join(temp, 'runtime.json');
    const output = path.join(temp, 'out');
    writeJsonl(source, [packet()]);
    fs.writeFileSync(runtime, `${JSON.stringify(runtimeReport())}\n`);
    const result = await writeRegistryArtifacts({
      rootDir: temp,
      outputDir: output,
      inputs: { selectorSources: [{ id: 'fixture', path: source }], runtimeReport: runtime, eventSources: [] },
    });
    for (const artifact of result.manifest.artifacts) {
      const file = path.join(output, artifact.path);
      assert.equal(fs.statSync(file).size, artifact.bytes);
      assert.equal(hash(file), artifact.sha256);
    }
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('protected holdout paths fail before any read', () => {
  assert.throws(() => assertSafePath(path.join('x', 'Protected_Holdout', 'data.json')), /forbidden/);
});

test('protected holdout paths fail through a junction or symlink alias', (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'stat-selector-path-guard-'));
  try {
    const protectedDir = path.join(temp, 'Protected_Holdout');
    const alias = path.join(temp, 'innocent-alias');
    fs.mkdirSync(protectedDir);
    try {
      fs.symlinkSync(protectedDir, alias, process.platform === 'win32' ? 'junction' : 'dir');
    } catch (error) {
      t.skip(`symlink/junction unavailable: ${error.code || error.message}`);
      return;
    }
    assert.throws(() => assertSafePath(path.join(alias, 'future-output.json')), /canonical path is forbidden/);
    assert.equal(fs.existsSync(path.join(protectedDir, 'future-output.json')), false);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});
