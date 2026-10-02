'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeAnonymous049cPacketCandidates821: decode } =
  require('../src/decoders/rofl_16_19_821_anonymous_049c_packet_candidate');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { resolveBuildProfile } = require('../src/build_registry');
const { capabilityQuery } = require('../src/cli');

const BUILD = '16.19.821.7343';
const CAP = 'anonymous_049c_packet';
function fixture() {
  // Framing/selection fixture only; these bytes are not a semantic/native packet.
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1); header.writeUInt32LE(5, 5);
  header.writeUInt16LE(0x049c, 9); header.writeUInt32LE(0x400000ae, 11);
  return replayFromChunks([{ stream: 1, body: Buffer.concat([header, Buffer.alloc(5)]) }], BUILD);
}

test('0x049c registers only the exact-821 opt-in candidate with explicit native preflight', () => {
  assert.ok(resolveBuildProfile(BUILD).profile.candidate_capabilities.includes(CAP));
  assert.ok(!resolveBuildProfile('16.19.820.7193').profile.candidate_capabilities.includes(CAP));
  const document = capabilityQuery(fixture(), { events: [CAP] });
  assert.equal(document.capabilities.length, 1);
  const selected = document.capabilities[0];
  assert.ok(selected.missing_inputs.includes('exact_runtime_image'));
  assert.ok(selected.required_inputs.some((input) => /python/i.test(input.name)));
  assert.equal(selected.output, 'anonymous_049c_packet_candidates');
});

test('0x049c rejects absent, foreign and wrong-size native inputs without emitting rows', (t) => {
  const replay = fixture();
  assert.equal(decode(replay).status, 'MISSING_INPUT');
  const foreign = fixture(); foreign.header.version = '16.19.820.7193';
  assert.equal(decode(foreign).status, 'UNSUPPORTED');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-049c-image-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'not-an-image.bin'); fs.writeFileSync(image, 'x');
  const wrong = decode(replay, { runtimeImagePath: image });
  assert.equal(wrong.status, 'INCONSISTENT');
  assert.equal(wrong.runtime_image_status, 'SIZE_MISMATCH');
  assert.equal(wrong.events, null); assert.equal(wrong.event_count, null);
  replay.buffer[0] ^= 1;
  assert.equal(decode(replay).status, 'DECODE_FAILED');
});

test('0x049c shared scan copies selected raw source and rejects foreign/unselected/mutated tokens', () => {
  const replay = fixture();
  const token = collect821Routes(replay, [CAP]);
  const selected = rowsFor821Capability(replay, token, CAP);
  assert.equal(selected.rows.length, 1);
  assert.equal(selected.rows[0].block.packet_id, 0x049c);
  selected.rows[0].block.payload[0] = 255;
  assert.equal(rowsFor821Capability(replay, token, CAP).rows[0].block.payload[0], 0);
  assert.ok(rowsFor821Capability(fixture(), token, CAP).error);
  const other = collect821Routes(replay, ['hero_death']);
  assert.ok(rowsFor821Capability(replay, other, CAP).error);
  replay.buffer[0] ^= 1;
  assert.ok(rowsFor821Capability(replay, token, CAP).error);
});

test('0x049c exact-build API propagates missing native dependency as unavailable data', () => {
  const decoded = decodeSemanticReplay(fixture(), { capabilities: [CAP] });
  assert.equal(decoded.capability_results[CAP].status, 'MISSING_INPUT');
  assert.equal(decoded.events, null);
  assert.equal(decoded.decoded_packet_count, 0);
});
