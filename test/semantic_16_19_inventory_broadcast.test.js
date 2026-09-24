'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeHeroInventoryBroadcastCandidates,
  decodeHeroInventoryMapViewCandidates,
} = require('../src/decoders/rofl_16_19_820_7193');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';

function packet(packetId, rawParam, payload = Buffer.alloc(79)) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithBroadcast(rows = [
  { stream: 2, param: 0x400000ae },
  { stream: 1, param: 0x400001b1 },
]) {
  return replayFromChunks(rows.map((row) => ({
    stream: row.stream, body: packet(0x03ef, row.param, row.payload),
  })), BUILD);
}

function temporaryImage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-broadcast-integration-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function mockResults(request, failedIndex = -1) {
  return request.packets.map((row, index) => ({
    status: index === failedIndex ? 'FAILED' : 'DECODED',
    input_index: index, raw_param: row.raw_param,
    raw_payload_sha256: crypto.createHash('sha256')
      .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
    deserialize_return_al: index === failedIndex ? 0 : 1,
    bytes_consumed: index === failedIndex ? 75 : row.payload_hex.length / 2,
    record_count: index === failedIndex ? null : 2,
    records: index === failedIndex ? [] : [
      { record_index: 0, slot: 0, item_key_u32: 0, flag: 0,
        raw_slot_byte_hex: '2f', raw_flag_byte_hex: '7d',
        raw_item_key_bytes_hex: 'fcfcfcfc' },
      { record_index: 1, slot: 7, item_key_u32: 2001, flag: 1,
        raw_slot_byte_hex: '02', raw_flag_byte_hex: 'bd',
        raw_item_key_bytes_hex: '7fd5fcfc' },
    ],
    ...(index === failedIndex ? { error: 'truncated payload' } : {}),
  }));
}

test('Broadcast retains keyframe and game packet refs without asserting ownership', (t) => {
  const image = temporaryImage(t);
  const calls = [];
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const request = JSON.parse(options.input);
    calls.push({ args, request });
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockResults(request),
    }) };
  });
  const result = decodeHeroInventoryBroadcastCandidates(replayWithBroadcast(), null,
    { runtimeImagePath: image });
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 4);
  assert.equal(result.decoded_record_count, 4);
  assert.equal(result.observed_keyframe_packet_count, 1);
  assert.equal(result.observed_game_packet_count, 1);
  assert.equal(result.scanned_block_count, 1);
  assert.equal(result.events[0].raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events[2].raw_packet_ref.chunk_stream, 'game_chunk');
  assert.equal(result.events[2].raw_param, 0x400001b1);
  assert.equal(result.events[2].raw_packet_ref.raw_param, 0x400001b1);
  assert.equal(result.events[0].item_key_u32_candidate, 0);
  assert.equal(result.events[1].item_key_u32_candidate, 2001);
  assert.equal(Object.hasOwn(result.events[2], 'participant_id_candidate'), false);
  assert.equal(calls.length, 1);
  assert.match(calls[0].args[1], /decode_broadcast_inventory_16_19\.py$/);
});

test('Broadcast missing image and foreign param fail before runtime', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run');
  });
  const missing = decodeHeroInventoryBroadcastCandidates(replayWithBroadcast());
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.input_count, 2);
  const foreign = decodeHeroInventoryBroadcastCandidates(replayWithBroadcast([
    { stream: 2, param: 0x40000020 },
  ]));
  assert.equal(foreign.status, 'PROFILE_UNAVAILABLE');
  assert.equal(foreign.input_count, null);
  assert.equal(foreign.observed_raw_route_count, 1);
  assert.equal(invoke.mock.callCount(), 0);
});

test('Broadcast wrong image hash fails closed', (t) => {
  const result = decodeHeroInventoryBroadcastCandidates(replayWithBroadcast(), null,
    { runtimeImagePath: temporaryImage(t) });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.event_count, null);
  assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
});

test('Broadcast helper verifies image identity before loading Unicorn', (t) => {
  const image = temporaryImage(t);
  const script = path.resolve(__dirname, '../src/decoders/decode_broadcast_inventory_16_19.py');
  const run = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-S', '-B', script, '--image', image], {
      input: JSON.stringify({ replay_version: BUILD, packets: [] }),
      encoding: 'utf8',
    });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /runtime image SHA-256 mismatch/);
  assert.doesNotMatch(run.stderr, /unicorn/i);
});

test('Broadcast failure conserves raw packet ref and suppresses every record', (t) => {
  const image = temporaryImage(t);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockResults(request, 1),
    }) };
  });
  const result = decodeHeroInventoryBroadcastCandidates(replayWithBroadcast(), null,
    { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.events, null);
  assert.equal(result.event_count, null);
  assert.equal(result.failed_packet_count, 1);
  assert.equal(result.first_failed_packet_ref.packet_id, 0x03ef);
  assert.equal(result.first_failed_packet_ref.raw_param, 0x400001b1);
});

test('keyframe MapView route stays outside the game-only MapView candidate', () => {
  const replay = replayFromChunks([{ stream: 2,
    body: packet(0x0420, 0x400000ae) }], BUILD);
  const result = decodeHeroInventoryMapViewCandidates(replay);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.observed_raw_route_count, 0);
});

test('selected API and capability query expose Broadcast as an image-bound candidate', (t) => {
  const { decodeSemanticReplay, getHeroInventoryBroadcastCandidates } = require('../src/semantic_api');
  const { capabilityQuery } = require('../src/cli');
  const image = temporaryImage(t);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockResults(request),
    }) };
  });
  const replay = replayWithBroadcast();
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['hero_inventory_broadcast'], runtimeImagePath: image,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_inventory_broadcast.event_count, 4);
  assert.deepEqual(Object.keys(decoded.events), ['hero_inventory_broadcast_candidates']);
  assert.equal(getHeroInventoryBroadcastCandidates(decoded).length, 4);
  assert.equal(decoded.events.inventory_events, undefined);
  const row = capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === 'hero_inventory_broadcast');
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, 'hero_inventory_broadcast_candidates');
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
});

test('selected CLI writes Broadcast records and exact packet provenance', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-broadcast-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const image = path.join(root, 'runtime.bin');
  const output = path.join(root, 'output');
  const replay = replayWithBroadcast();
  fs.writeFileSync(input, replay.buffer);
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockResults(request),
    }) };
  });
  assert.equal(await main(['decode', input, '--events', 'hero_inventory_broadcast',
    '--runtime-image', image, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results.hero_inventory_broadcast.event_count, 4);
  const rows = fs.readFileSync(path.join(replayDir, 'hero_inventory_broadcast_candidates.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 4);
  assert.equal(rows[0].item_key_u32_candidate, 0);
  assert.equal(rows[2].raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
  assert.equal(rows[2].raw_packet_ref.raw_param, 0x400001b1);
  assert.equal(Object.hasOwn(rows[2], 'participant_id_candidate'), false);
});
