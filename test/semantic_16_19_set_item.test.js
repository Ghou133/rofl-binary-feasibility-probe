'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { decodeSemanticReplay, getHeroInventorySetItemCandidates } = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';

function packet(packetId, rawParam, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithSetItem(rows = [
  { param: 0x400000ae, payload: Buffer.from('01020304050607', 'hex') },
  { param: 0x400001b7, payload: Buffer.from('11121314151617', 'hex') },
]) {
  // Payloads are arbitrary orchestration bytes, not exact-runtime evidence.
  const replay = replayFromChunks([{ body: Buffer.concat([
    ...rows.map((row) => packet(0x03b7, row.param, row.payload)),
    packet(0x02b3, 0x400000ae, Buffer.from('5b', 'hex')),
  ]) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, () => ({ LEVEL: '1' }));
  return replay;
}

function temporaryImage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-set-item-integration-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function mockResult(request, status = 'DECODED') {
  return request.packets.map((row, index) => ({
    status, input_index: index, raw_param: row.raw_param,
    raw_payload_sha256: crypto.createHash('sha256')
      .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
    deserialize_return_al: status === 'DECODED' ? 1 : 0,
    bytes_consumed: row.payload_hex.length / 2,
    slot: status === 'DECODED' ? 8 : null,
    item_id: status === 'DECODED' ? 1200 + index : null,
    flag: status === 'DECODED' ? 1 : null,
    raw_slot_byte_hex: status === 'DECODED' ? 'a1' : null,
    raw_item_id_bytes_hex: status === 'DECODED' ? 'e786fcfc' : null,
    ...(status === 'FAILED' ? { error: 'truncated payload' } : {}),
  }));
}

test('SetItem exact runtime results remain candidate packet fields and leave foreign param unmapped', (t) => {
  const image = temporaryImage(t);
  const requests = [];
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const request = JSON.parse(options.input);
    requests.push({ args, request });
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockResult(request),
    }) };
  });
  const replay = replayWithSetItem();
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['hero_inventory_set_item', 'hero_level_state'],
    runtimeImagePath: image,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_inventory_set_item.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_inventory_set_item.input_count, 2);
  assert.equal(decoded.capability_results.hero_inventory_set_item.event_count, 2);
  assert.equal(decoded.capability_results.hero_inventory_set_item.unmapped_raw_param_count, 1);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  const events = getHeroInventorySetItemCandidates(decoded);
  assert.equal(events.length, 2);
  assert.equal(events[0].participant_id_candidate, 1);
  assert.equal(events[0].slot_candidate, 8);
  assert.equal(events[0].item_id_candidate, 1200);
  assert.equal(events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(events[1].participant_id_candidate, null);
  assert.equal(events[1].field_confidence.participant_id_candidate, 'UNAVAILABLE');
  assert.equal(events[1].item_id_candidate, 1201);
  assert.equal(requests.length, 1);
  assert.match(requests[0].args[1], /decode_setitem_16_19\.py$/);
});

test('SetItem missing or wrong image stays local to the capability', (t) => {
  const replay = replayWithSetItem();
  const absent = decodeSemanticReplay(replay, {
    capabilities: ['hero_inventory_set_item', 'hero_level_state'],
  });
  assert.equal(absent.status, 'PARTIAL');
  assert.equal(absent.capability_results.hero_inventory_set_item.status, 'MISSING_INPUT');
  assert.equal(absent.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(getHeroInventorySetItemCandidates(absent), null);

  const wrong = decodeSemanticReplay(replay, {
    capabilities: ['hero_inventory_set_item', 'hero_level_state'],
    runtimeImagePath: temporaryImage(t),
  });
  assert.equal(wrong.status, 'PARTIAL');
  assert.equal(wrong.capability_results.hero_inventory_set_item.status, 'DECODE_FAILED');
  assert.equal(wrong.capability_results.hero_inventory_set_item.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.capability_results.hero_level_state.status, 'CANDIDATE');
});

test('absent or foreign SetItem route cannot invoke runtime or publish candidates', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run for absent or foreign route');
  });
  const absent = decodeSemanticReplay(replayWithSetItem([]), {
    capabilities: ['hero_inventory_set_item'],
  });
  assert.equal(absent.capability_results.hero_inventory_set_item.status, 'PROFILE_UNAVAILABLE');
  assert.equal(absent.capability_results.hero_inventory_set_item.input_count, null);
  const foreign = decodeSemanticReplay(replayWithSetItem([
    { param: 0x40000020, payload: Buffer.alloc(7) },
  ]), { capabilities: ['hero_inventory_set_item'] });
  assert.equal(foreign.capability_results.hero_inventory_set_item.status, 'PROFILE_UNAVAILABLE');
  assert.equal(foreign.capability_results.hero_inventory_set_item.observed_raw_route_count, 1);
  assert.equal(invoke.mock.callCount(), 0);
});

test('failed SetItem packet retains raw failure and suppresses every candidate', (t) => {
  const image = temporaryImage(t);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    const results = mockResult(request);
    results[1] = mockResult({ packets: [request.packets[1]] }, 'FAILED')[0];
    results[1].input_index = 1;
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256, results,
    }) };
  });
  const decoded = decodeSemanticReplay(replayWithSetItem(), {
    capabilities: ['hero_inventory_set_item', 'hero_level_state'],
    runtimeImagePath: image,
  });
  const outcome = decoded.capability_results.hero_inventory_set_item;
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(outcome.status, 'DECODE_FAILED');
  assert.equal(outcome.event_count, null);
  assert.equal(outcome.failed_packet_count, 1);
  assert.equal(outcome.first_failed_packet_ref.packet_id, 0x03b7);
  assert.equal(getHeroInventorySetItemCandidates(decoded), null);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
});
