'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const PROBE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'assist_821_probe', 'probe_040a.json');
const SCRIPT = path.resolve(__dirname, '..', 'scripts',
  'decode_assist_child_packet_16_19_821.py');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function firstObservedPair() {
  const probe = JSON.parse(fs.readFileSync(PROBE, 'utf8'));
  assert.equal(probe.image_sha256, IMAGE_SHA256);
  const [first, second] = probe.rows;
  assert.equal(first.replay_label, 'KR_8392938200');
  assert.equal(first.death_time_ms, 235570);
  assert.equal(second.death_time_ms, first.death_time_ms);
  assert.deepEqual([first.route, second.route], ['0x040a', '0x040a']);
  assert.deepEqual([first.payload_length, second.payload_length], [44, 44]);
  assert.ok(first.decompressed_payload_offset < second.decompressed_payload_offset);
  assert.equal(first.payload_hex.slice(10, -2), second.payload_hex.slice(10, -2));
  assert.equal(first.payload_hex.slice(2, 10), '35b94b3d');
  assert.equal(second.payload_hex.slice(2, 10), '350b4bb3');
  assert.equal(first.payload_hex.slice(-2), '14');
  assert.equal(second.payload_hex.slice(-2), 'd4');
  return [first, second].map((row) => ({
    packet_id: row.packet_id,
    stream_tag: 1,
    raw_param: row.param,
    payload_hex: row.payload_hex,
  }));
}

function invoke(packets, replayVersion = BUILD, image = IMAGE) {
  return childProcess.spawnSync(process.env.PYTHON || 'python', [
    '-B', SCRIPT, '--image', image,
  ], {
    input: JSON.stringify({ replay_version: replayVersion, packets }),
    encoding: 'utf8', timeout: 60000,
  });
}

function assertAtomicError(run, pattern) {
  assert.equal(run.status, 1, run.stderr || run.error?.message);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'ERROR');
  assert.deepEqual(output.results, []);
  assert.match(output.error, pattern);
}

test('821 native assist-child helper decodes an observed first/second OnEvent pair', {
  skip: !fs.existsSync(IMAGE) || !fs.existsSync(PROBE)
    ? 'requires the local exact-build runtime image and replay probe' : false,
}, () => {
  const packets = firstObservedPair();
  const run = invoke(packets);
  assert.equal(run.status, 0, run.stderr || run.error?.message);
  const output = JSON.parse(run.stdout);
  assert.equal(output.status, 'PASS');
  assert.equal(output.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(output.results.length, 2);

  const blobHashes = [
    '9190647c246f96edf5dc93d97a6c254bd8e31ac60951642ed425e3245c20690f',
    'a1084819fe1a7e8b34d12f27914a647f2eeb5764686bac2c0b9421fcbd33a898',
  ];
  for (const [index, row] of output.results.entries()) {
    const input = packets[index];
    assert.equal(row.status, 'DECODED');
    assert.equal(row.input_index, index);
    assert.equal(row.raw_param, input.raw_param);
    assert.equal(row.raw_payload_sha256, sha256(Buffer.from(input.payload_hex, 'hex')));
    assert.equal(row.deserialize_return_al, 1);
    assert.equal(row.bytes_consumed, 44);
    assert.equal(row.native_packet_id, 0x040a);
    assert.equal(row.native_raw_param, input.raw_param);
    assert.equal(row.event_id, [0x0056, 0x0057][index]);
    assert.equal(row.raw_event_id_hex, ['0x4914', '0x49d4'][index]);
    assert.equal(row.event_blob_length, 36);
    assert.equal(row.event_blob_sha256, blobHashes[index]);
    assert.equal(row.event_u32_0x04, 0x400000b3);
  }
  assert.equal(Object.hasOwn(output.results[0], 'event_u32_0x20'), false);
  assert.equal(output.results[1].event_u32_0x20, 0x400000af);
});

test('821 native assist-child helper rejects malformed and foreign packets atomically', {
  skip: !fs.existsSync(IMAGE) || !fs.existsSync(PROBE)
    ? 'requires the local exact-build runtime image and replay probe' : false,
}, () => {
  const [first, second] = firstObservedPair();
  // A real 17-byte OnEvent payload from the same Replay, padded to 44 bytes,
  // passes the length gate but its native cursor stops after byte 17.
  const foreignChild = { ...first, raw_param: 0x40000284,
    payload_hex: 'f4bdb94b3db3b350b38432eb01e94d0129' + '00'.repeat(27) };
  const controls = [
    [{ ...second, payload_hex: second.payload_hex.slice(0, -2) }, /payload|length|44/i],
    [{ ...second, payload_hex: `${second.payload_hex}a5` }, /payload|length|44/i],
    [{ ...second, packet_id: 0x0438 }, /packet\s*id|route/i],
    [{ ...second, stream_tag: 2 }, /stream/i],
    [foreignChild, /did not fully consume/i],
  ];
  for (const [control, pattern] of controls) {
    assertAtomicError(invoke([first, control]), pattern);
  }
  assertAtomicError(invoke([first, second], '16.19.820.7193'), /replay_version|build/i);
  assertAtomicError(invoke([first, second], BUILD, PROBE), /image|SHA-256/i);
});
