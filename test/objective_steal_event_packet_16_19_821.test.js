'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { resolveCapability } = require('../src/build_registry');
const { capabilityQuery, parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const {
  OBJECTIVE_STEAL_EVENT_PACKET_821_PROFILE: profile,
  decodeObjectiveStealEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_objective_steal_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const DRAGON = Buffer.alloc(133, 0x31);
const WORM = Buffer.alloc(133, 0x32);
const FOREIGN = Buffer.alloc(133, 0x33);

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(payload, rawParam = 0x400000af, packetId = 0x040a) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream = 1, packets }) => ({
    stream, body: Buffer.concat(packets),
  })), build);
}

function image(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-objective-steal-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'image.bin');
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  return { directory, imagePath };
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const selector = Buffer.from(row.payload_hex, 'hex')[0];
      const dragon = selector === DRAGON[0];
      const worm = selector === WORM[0];
      const blob = Buffer.alloc(124, selector);
      return {
        status: 'DECODED', input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: sha256(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: 133,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: dragon ? 0x00be : worm ? 0x00d6 : 0x0046,
        raw_event_id_hex: dragon ? '0x499e' : worm ? '0x490c' : '0x4918',
        event_blob_length: 124, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: sha256(blob),
      };
    }),
  };
}

test('821 objective steal candidate binds both native children and opaque source bytes', (t) => {
  const { imagePath } = image(t);
  const input = replay([{ packets: [
    packet(DRAGON), packet(WORM), packet(Buffer.alloc(17)), packet(DRAGON, 1, 0x0409),
  ] }]);
  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_objective_steal_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.payload_hex),
      [DRAGON.toString('hex'), WORM.toString('hex')]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(input, { runtimeImagePath: imagePath });
  assert.deepEqual(profile.child_event_ids, [0x00be, 0x00d6]);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.deepEqual(result.child_event_id_counts, { '0x00be': 1, '0x00d6': 1 });
  assert.deepEqual(result.events.map((row) => row.registered_event_name),
    ['OnKillDragonSteal', 'OnKillWormSteal']);
  assert.equal(result.events[0].event_blob_hex, Buffer.alloc(124, DRAGON[0]).toString('hex'));
  assert.equal(result.events[1].raw_packet_ref.raw_payload_sha256, sha256(WORM));
  assert.deepEqual(result.events.map((row) => row.semantic_effect_status),
    ['UNKNOWN', 'UNKNOWN']);
  for (const field of ['actor', 'target', 'objective', 'effective_steal', 'winner']) {
    assert.equal(Object.hasOwn(result.events[0], field), false);
  }
  assert.equal(native.mock.callCount(), 1);
});

test('821 objective steal reports absent, missing image, wrong build, and wrong image distinctly', (t) => {
  const { imagePath } = image(t);
  const absent = replay([{ packets: [packet(Buffer.alloc(17))] }]);
  assert.equal(decode(absent, { runtimeImagePath: imagePath }).status,
    'PROFILE_UNAVAILABLE');
  const present = replay([{ packets: [packet(DRAGON)] }]);
  assert.equal(decode(present).status, 'MISSING_INPUT');
  assert.equal(decode(replay([{ packets: [packet(DRAGON)] }],
    '16.19.820.7193'), { runtimeImagePath: imagePath }).status, 'UNSUPPORTED');
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch', stdout: '',
  }));
  const wrongImage = decode(present, { runtimeImagePath: imagePath });
  assert.equal(wrongImage.status, 'DECODE_FAILED');
  assert.equal(wrongImage.runtime_image_status, 'HASH_MISMATCH');
});

test('821 objective steal rejects a foreign child, partial native read, and forged blob', (t) => {
  const { imagePath } = image(t);
  const input = replay([{ packets: [packet(DRAGON), packet(WORM)] }]);
  let mode = 'foreign';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    if (mode === 'foreign') output.results[0].event_id = 0x0046;
    if (mode === 'partial') output.results[0].bytes_consumed = 132;
    if (mode === 'hash') output.results[1].event_blob_sha256 = '0'.repeat(64);
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  for (mode of ['foreign', 'partial', 'hash']) {
    const result = decode(input, { runtimeImagePath: imagePath });
    assert.equal(result.status, 'DECODE_FAILED', mode);
    assert.equal(result.events, null, mode);
    assert.equal(result.event_count, null, mode);
    assert.equal(result.first_failed_packet_ref.packet_id, 0x040a);
  }
  const wrongStream = replay([{ stream: 2, packets: [packet(DRAGON)] }]);
  assert.equal(decode(wrongStream, { runtimeImagePath: imagePath }).status,
    'PROFILE_UNAVAILABLE');
});

test('821 objective steal is selectable through the shared scan, API, and CLI', (t) => {
  const { directory, imagePath } = image(t);
  const input = replay([{ packets: [packet(DRAGON), packet(WORM)] }]);
  const replayPath = path.join(directory, 'sample.rofl');
  fs.writeFileSync(replayPath, input.buffer);
  assert.equal(resolveCapability(BUILD, 'objective_steal_event_packet').status,
    'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'objective_steal_event_packet');
  assert.equal(queried.output, 'objective_steal_event_packet_candidates');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  const selected = collect821Routes(input, ['objective_steal_event_packet']);
  assert.deepEqual(rowsFor821Capability(input, selected,
    'objective_steal_event_packet').rows.map((row) => row.block.payload_length),
  [133, 133]);
  const native = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input))),
  }));
  const api = decodeSemanticReplay(input, {
    capabilities: ['objective_steal_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(api.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(api.events.objective_steal_event_packet_candidates.length, 2);
  const cli = parseOne(replayPath, {
    semantic: true, events: ['objective_steal_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(cli.ok, true);
  assert.equal(cli.analysis.semantic.capability_results.objective_steal_event_packet.status,
    'CANDIDATE');
  assert.deepEqual(cli.analysis.events.objective_steal_event_packet_candidates
    .map((row) => row.child_event_id), [0x00be, 0x00d6]);
  assert.equal(native.mock.callCount(), 2);
});
