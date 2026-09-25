'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const SELECTED = ['objective_bounty_claimed_packet',
  'turret_plate_event_packet', 'turret_die_event_packet'];
const WORD = 0x40000097;

function sha(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(rawParam, payload, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function diePayload() {
  const payload = Buffer.alloc(116, 0xb3);
  Buffer.from('f01eb9b33d', 'hex').copy(payload, 0);
  Buffer.from('247152269566', 'hex').copy(payload, 110);
  return payload;
}

function replay({ includeClaim = true } = {}) {
  const packets = [
    packet(0x400001ae, Buffer.alloc(17, 0x07)),
    packet(0x400000bb, Buffer.alloc(20, 0x20)),
    packet(0x40000097, diePayload()),
    ...(includeClaim ? [
      packet(0x400000ae, Buffer.alloc(17, 0x13)),
      packet(0x400000ad, Buffer.alloc(17, 0x14), 2000),
    ] : []),
  ];
  return replayFromChunks([{ stream: 1, body: Buffer.concat(packets) }], BUILD);
}

function nativeResult(request, route) {
  const childIds = new Map([
    [0x400001ae, 0x0107], [0x400000ae, 0x0113],
    [0x400000ad, 0x0113], [0x40000097, 0x003b],
  ]);
  const rawIds = new Map([
    [0x0107, '0x09e8'], [0x0113, '0x09e5'], [0x003b, '0x4966'],
  ]);
  const selectedChild = route === 'plate' ? 0x0107
    : route === 'claim' ? 0x0113 : 0x003b;
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((input, inputIndex) => {
      const childId = childIds.get(input.raw_param);
      assert.ok(childId, `unknown native input ${input.raw_param}`);
      const word = input.raw_param === 0x400000ad ? 0x40010b5a : WORD;
      const blob = Buffer.alloc(route === 'die' ? 108 : 8);
      if (route === 'die') blob.writeUInt32LE(word, 12);
      else {
        blob.writeUInt32LE(469, 0);
        blob.writeUInt32LE(word, 4);
      }
      return {
        status: childId === selectedChild ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: inputIndex,
        raw_param: input.raw_param,
        raw_payload_sha256: sha(Buffer.from(input.payload_hex, 'hex')),
        deserialize_return_al: 1,
        bytes_consumed: route === 'die' ? 116 : 17,
        native_packet_id: 0x040a, native_raw_param: input.raw_param,
        event_id: childId, raw_event_id_hex: rawIds.get(childId),
        event_blob_length: blob.length, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: sha(blob),
        ...(route === 'die' ? {} : {
          event_schema_u32_0x00: 469,
          ...(route === 'plate' ? { event_u32_0x04: word }
            : { blob_u32_0x04: word }),
        }),
      };
    }),
  };
}

test('821 selected claim, plate, and die routes emit packet triple in API and CLI', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-objective-triple-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'image.bin');
  const replayPath = path.join(directory, 'sample.rofl');
  const input = replay();
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  fs.writeFileSync(replayPath, input.buffer);

  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const route = /decode_objective_bounty_claimed_packet_16_19_821\.py$/.test(args[1])
      ? 'claim' : /decode_turret_plate_event_packet_16_19_821\.py$/.test(args[1])
        ? 'plate' : /decode_turret_die_event_packet_16_19_821\.py$/.test(args[1])
          ? 'die' : null;
    assert.ok(route, `unexpected native helper ${args[1]}`);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.ok(request.packets.length >= 1);
    assert.ok(request.packets.every((row) => row.payload_hex.length / 2
      === (route === 'die' ? 116 : 17)));
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request, route)) };
  });

  const decoded = decodeSemanticReplay(input, {
    capabilities: SELECTED, runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  for (const capability of SELECTED) {
    assert.equal(decoded.capability_results[capability].status, 'CANDIDATE', capability);
  }
  const summary = decoded.candidate_associations.objective_bounty_turret_pair;
  assert.equal(summary.status, 'CANDIDATE', summary.error);
  assert.equal(summary.claim_packet_count, 2);
  assert.equal(summary.triple_count, 1);
  assert.equal(summary.unmatched_claim_count, 1);
  assert.equal(summary.unmatched_claims[0].reason, 'NO_SAME_KEY_PLATE_OR_DIE');
  assert.equal(decoded.events.objective_bounty_claimed_packet_candidates.length, 2);
  assert.equal(decoded.events.objective_bounty_turret_pair_candidates.length, 1);
  const triple = decoded.events.objective_bounty_turret_pair_candidates[0];
  assert.equal(triple.confidence, 'CANDIDATE');
  assert.equal(triple.claim_blob_u32_0x04, WORD);
  assert.deepEqual(triple.raw_packet_refs, [
    decoded.events.turret_plate_event_packet_candidates[0].raw_packet_ref,
    decoded.events.turret_die_event_packet_candidates[0].raw_packet_ref,
    decoded.events.objective_bounty_claimed_packet_candidates[0].raw_packet_ref,
  ]);

  const parsed = parseOne(replayPath, {
    semantic: true, events: SELECTED, runtimeImage: imagePath,
    strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.candidate_associations
    .objective_bounty_turret_pair.triple_count, 1);
  assert.equal(parsed.analysis.events.objective_bounty_turret_pair_candidates.length, 1);
  assert.equal(parsed.analysis.event_counts.objective_bounty_turret_pair_candidates, 1);

  const partial = decodeSemanticReplay(input, {
    capabilities: SELECTED.slice(1), runtimeImagePath: imagePath,
  });
  assert.equal(partial.candidate_associations.objective_bounty_turret_pair, undefined);
  assert.equal(partial.events.objective_bounty_turret_pair_candidates, undefined);

  const claimFree = decodeSemanticReplay(replay({ includeClaim: false }), {
    capabilities: SELECTED, runtimeImagePath: imagePath,
  });
  assert.equal(claimFree.capability_results.objective_bounty_claimed_packet.status,
    'PROFILE_UNAVAILABLE');
  assert.equal(claimFree.candidate_associations.objective_bounty_turret_pair.status,
    'MISSING_INPUT');
  assert.equal(claimFree.candidate_associations.objective_bounty_turret_pair
    .diagnostics.dependency_statuses.objective_bounty_claimed_packet,
  'PROFILE_UNAVAILABLE');
  assert.equal(claimFree.events?.objective_bounty_turret_pair_candidates, undefined);
  assert.equal(claimFree.events.turret_plate_event_packet_candidates.length, 1);
  assert.equal(claimFree.events.turret_die_event_packet_candidates.length, 1);
});
