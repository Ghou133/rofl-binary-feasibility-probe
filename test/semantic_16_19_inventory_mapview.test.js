'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { decodeSemanticReplay, getHeroInventoryMapViewCandidates } = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const HERO_PARAM = 0x400000ae;

function packet(packetId, rawParam, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithMapView(rawParam = HERO_PARAM,
  payloads = [Buffer.from('010203', 'hex')]) {
  // Arbitrary bytes exercise orchestration only; exact-runtime decoding is
  // separately checked on the local HN Replay and is not embedded as a fixture.
  const replay = replayFromChunks([{ body: Buffer.concat([
    ...payloads.map((payload) => packet(0x0420, rawParam, payload)),
    packet(0x02b3, HERO_PARAM, Buffer.from('5b', 'hex')),
  ]) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, () => ({ LEVEL: '1' }));
  return replay;
}

function temporaryImage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-mapview-integration-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

test('16.19 MapView uses a bound runtime result and preserves independent level output', (t) => {
  const image = temporaryImage(t);
  const requests = [];
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const request = JSON.parse(options.input);
    requests.push({ args, request });
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: request.packets.map((row, index) => ({
        status: 'DECODED', input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
        record_count: 1, records: [{ record_index: 0, slot: 0, item_id: 1102,
          flag: 1, raw_slot_byte_hex: '2f', raw_item_id_bytes_hex: '6186fcfc' }],
      })),
    }) };
  });
  const replay = replayWithMapView();
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['hero_inventory_mapview', 'hero_level_state'],
    runtimeImagePath: image,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.runtime_image_used, true);
  assert.equal(decoded.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_inventory_mapview.runtime_image_status, 'MATCHED_USED');
  assert.equal(decoded.capability_results.hero_inventory_mapview.input_count, 1);
  assert.equal(decoded.capability_results.hero_inventory_mapview.event_count, 1);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_level_state.runtime_image_status, 'PROVIDED_NOT_USED');
  const row = getHeroInventoryMapViewCandidates(decoded)[0];
  assert.equal(row.slot_candidate, 0);
  assert.equal(row.item_id_candidate, 1102);
  assert.equal(row.participant_id_candidate, 1);
  assert.equal(row.confidence, 'CANDIDATE');
  assert.equal(row.raw_packet_ref.packet_id, 0x0420);
  assert.equal(row.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(row.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(Buffer.from('010203', 'hex')).digest('hex'));
  assert.equal(requests.length, 1);
  assert.match(requests[0].args[1], /decode_mapview_inventory_16_19\.py$/);
  assert.equal(requests[0].request.packets[0].raw_param, HERO_PARAM);
});

test('missing runtime image affects only the selected MapView capability', () => {
  const decoded = decodeSemanticReplay(replayWithMapView(), {
    capabilities: ['hero_inventory_mapview', 'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'MISSING_INPUT');
  assert.equal(decoded.capability_results.hero_inventory_mapview.missing_input, 'runtime_image');
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(getHeroInventoryMapViewCandidates(decoded), null);
  assert.equal(decoded.events.hero_level_state_candidates.length, 1);
});

test('wrong runtime image hash fails MapView while retaining level candidate', (t) => {
  const decoded = decodeSemanticReplay(replayWithMapView(), {
    capabilities: ['hero_inventory_mapview', 'hero_level_state'],
    runtimeImagePath: temporaryImage(t),
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'DECODE_FAILED');
  assert.equal(decoded.capability_results.hero_inventory_mapview.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(getHeroInventoryMapViewCandidates(decoded), null);
});

test('foreign MapView parameter stays profile-unavailable without invoking runtime', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run for a foreign route parameter');
  });
  const decoded = decodeSemanticReplay(replayWithMapView(0x40000020), {
    capabilities: ['hero_inventory_mapview', 'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results.hero_inventory_mapview.input_count, null);
  assert.equal(decoded.capability_results.hero_inventory_mapview.observed_raw_route_count, 1);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(invoke.mock.callCount(), 0);
});

test('absent MapView route is unavailable even without a runtime image', () => {
  const replay = replayFromChunks([{
    body: packet(0x02b3, HERO_PARAM, Buffer.from('5b', 'hex')),
  }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, () => ({ LEVEL: '1' }));
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['hero_inventory_mapview', 'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results.hero_inventory_mapview.input_count, null);
  assert.equal(decoded.capability_results.hero_inventory_mapview.event_count, null);
  assert.equal(decoded.capability_results.hero_inventory_mapview.observed_raw_route_count, 0);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
});

test('mutated Replay bytes or chunk layout cannot retain original candidate provenance', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run for changed Replay provenance');
  });
  for (const change of ['payload', 'chunk_layout']) {
    const replay = replayWithMapView();
    if (change === 'payload') {
      replay.buffer[replay.chunks[0].body_offset + 15] ^= 0xff;
    } else {
      replay.chunks[0].offset += 1;
    }
    const decoded = decodeSemanticReplay(replay, {
      capabilities: ['hero_inventory_mapview', 'hero_level_state'],
      runtimeImagePath: 'unused-image.bin',
    });
    assert.equal(decoded.status, 'DECODE_FAILED', change);
    assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'DECODE_FAILED', change);
    assert.equal(decoded.capability_results.hero_level_state.status, 'DECODE_FAILED', change);
    assert.equal(getHeroInventoryMapViewCandidates(decoded), null, change);
  }
  assert.equal(invoke.mock.callCount(), 0);
});

test('failed MapView packets preserve each raw ref without publishing partial item records', (t) => {
  const image = temporaryImage(t);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: request.packets.map((row, index) => ({ status: 'FAILED', input_index: index,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 0, bytes_consumed: row.payload_hex.length / 2,
        record_count: null, records: [], error: 'truncated payload' })),
    }) };
  });
  const decoded = decodeSemanticReplay(replayWithMapView(HERO_PARAM,
    [Buffer.from('010203', 'hex'), Buffer.from('040506', 'hex')]), {
    capabilities: ['hero_inventory_mapview', 'hero_level_state'],
    runtimeImagePath: image,
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_inventory_mapview.status, 'DECODE_FAILED');
  assert.equal(decoded.capability_results.hero_inventory_mapview.event_count, null);
  assert.equal(decoded.capability_results.hero_inventory_mapview.first_failed_packet_ref.packet_id,
    0x0420);
  assert.equal(decoded.capability_results.hero_inventory_mapview.failed_packet_count, 2);
  assert.deepEqual(decoded.capability_results.hero_inventory_mapview.failed_packet_results
    .map((row) => row.packet_index), [0, 1]);
  assert.notEqual(decoded.capability_results.hero_inventory_mapview.failed_packet_results[0]
    .raw_packet_ref.raw_payload_sha256,
  decoded.capability_results.hero_inventory_mapview.failed_packet_results[1]
    .raw_packet_ref.raw_payload_sha256);
  assert.equal(getHeroInventoryMapViewCandidates(decoded), null);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
});
