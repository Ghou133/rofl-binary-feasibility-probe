'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeNpcBuffRemovePacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_buff_remove_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const TABLE_SHA256 = profile.evidence_callback_table_sha256;
const PAYLOAD = Buffer.from('20411172836b', 'hex');

function packet(packetId = 0x047c, rawParam = 0x400000ae, payload = PAYLOAD) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithChunks(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream = 1, packets }) => ({
    stream, body: Buffer.concat(packets),
  })), build);
}

function fakeImage(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-buff-remove-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    callback_table_sha256: TABLE_SHA256,
    results: request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x047c, native_raw_param: input.raw_param,
      opaque_u32_0x10: 87336022 + inputIndex,
      opaque_u8_0x14: inputIndex,
      opaque_f32_0x18: 0,
      raw_u32_bytes_hex: '2ff5b770', raw_u8_byte_hex: '59',
      raw_f32_bytes_hex: '75757575',
    })),
  };
}

test('821 BuffRemove2 exposes only exact-image opaque packet fields through API and shared scan', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { packets: [packet()] },
    { packets: [packet(0x047c, 0x400000b4, Buffer.from('20411172836b71', 'hex'))] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_buff_remove_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag]),
      [[0x047c, 1], [0x047c, 1]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const token = collect821Routes(replay, ['npc_buff_remove_packet']);
  const direct = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(profile.packet_name, 'PKT_NPC_BuffRemove2_s');
  assert.equal(direct.status, 'CANDIDATE');
  assert.equal(direct.input_count, 2);
  assert.equal(direct.event_count, 2);
  assert.equal(direct.runtime_image_status, 'MATCHED_USED');
  assert.equal(direct.events[0].opaque_u32_0x10, 87336022);
  assert.equal(direct.events[1].opaque_u8_0x14, 1);
  assert.equal(direct.events[0].opaque_f32_0x18, 0);
  assert.equal(direct.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(direct.events[1].raw_packet_ref.raw_param, 0x400000b4);
  for (const field of ['owner', 'buff_identity', 'target', 'duration',
    'buff_lookup_token_u32_candidate', 'buff_slot_index_candidate']) {
    assert.equal(field in direct.events[0], false);
  }
  const api = decodeSemanticReplay(replay, {
    capabilities: ['npc_buff_remove_packet'], runtimeImagePath: image,
    candidate821Scan: token,
  });
  assert.equal(api.capability_results.npc_buff_remove_packet.status, 'CANDIDATE');
  assert.equal(api.events.npc_buff_remove_packet_candidates.length, 2);
  assert.equal(invoke.mock.callCount(), 2);
});

test('821 BuffRemove2 keeps absent route, missing image and wrong-build outcomes distinct', () => {
  const older = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(older).status, 'UNSUPPORTED');
  const absent = replayWithChunks([{ packets: [packet(0x01da)] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
});

test('821 BuffRemove2 rejects changed source and foreign stream or length before native decode', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  const wrongLength = replayWithChunks([{ packets: [packet(0x047c, 0x400000ae,
    Buffer.alloc(8))] }]);
  assert.equal(decode(wrongLength).status, 'DECODE_FAILED');
  const wrongStream = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(wrongStream).status, 'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 BuffRemove2 rejects wrong image and incomplete native consumption without events', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const mismatch = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: wrong image', stdout: '',
  }));
  const wrongImage = decode(replay, { runtimeImagePath: image });
  assert.equal(wrongImage.status, 'DECODE_FAILED');
  assert.equal(wrongImage.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrongImage.events, null);
  mismatch.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[0].bytes_consumed -= 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const incomplete = decode(replay, { runtimeImagePath: image });
  assert.equal(incomplete.status, 'DECODE_FAILED');
  assert.equal(incomplete.runtime_image_status, 'MATCHED_USED');
  assert.equal(incomplete.first_failed_packet_ref.packet_id, 0x047c);
  assert.equal(incomplete.events, null);
});

test('821 BuffRemove2 bounds direct and shared route retention above 50,000 packets', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const replay = replayWithChunks([{ packets: Array.from({ length: 50_001 }, () => packet()) }]);
  const direct = decode(replay);
  assert.equal(direct.status, 'UNSUPPORTED');
  assert.equal(direct.observed_packet_count_minimum, 50_001);
  assert.equal(direct.events, null);
  const token = collect821Routes(replay, ['npc_buff_remove_packet']);
  const shared = decode(replay, { precollected: token });
  assert.equal(shared.status, 'UNSUPPORTED');
  assert.equal(shared.observed_packet_count_minimum, 50_001);
  assert.equal(shared.events, null);
  assert.equal(invoke.mock.callCount(), 0);
});
