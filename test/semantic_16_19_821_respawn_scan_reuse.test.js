'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const zlib = require('node:zlib');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const {
  assessHeroRespawnDeadTimeTail821,
  assessHeroRespawnTail821,
  decodeHeroRespawnCandidates821,
} = require('../src/decoders/rofl_16_19_821_respawn_candidate');

function packet(id, timeMs, param, payloadLength) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timeMs / 1000, 1);
  header[5] = payloadLength;
  header.writeUInt16LE(id, 6);
  header.writeUInt32LE(param >>> 0, 8);
  return Buffer.concat([header, Buffer.alloc(payloadLength, id & 0xff)]);
}

function fixture() {
  const param = 0x400000ae;
  const body = Buffer.concat([
    packet(0x03d4, 1000, 0, 3),
    packet(0x031b, 1000, 0, 12),
    packet(0x0259, 1000, param, 5),
    packet(0x0438, 1000, param, 13),
    packet(0x018d, 11500, param, 55),
    packet(0x0048, 11500, param, 9),
  ]);
  const replay = replayFromChunks([{ body, compressed: true }], '16.19.821.7343');
  replay.tail.metadata.gameLength = 20000;
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
    TOTAL_TIME_SPENT_DEAD: index === 0 ? '10' : '0',
  }));
  return replay;
}

test('821 respawn-only scan retains its death dependency and decompresses once', (t) => {
  const replay = fixture();
  const independent = decodeHeroRespawnCandidates821(replay);
  assert.equal(independent.status, 'CANDIDATE');
  const original = zlib.zstdDecompressSync;
  let decompressions = 0;
  t.mock.method(zlib, 'zstdDecompressSync', (...args) => {
    decompressions += 1;
    return original(...args);
  });
  const token = collect821Routes(replay, ['hero_respawn']);
  const deathRows = rowsFor821Capability(replay, token, 'hero_death');
  const returnRows = rowsFor821Capability(replay, token, 'hero_respawn');
  assert.equal(deathRows.rows.length, 4);
  assert.equal(returnRows.rows.length, 2);
  assert.match(rowsFor821Capability(replay, token, 'hero_level_state').error,
    /not selected/);
  deathRows.rows[0].block.payload[0] ^= 1;
  returnRows.rows[0].block.payload[0] ^= 1;
  assert.deepEqual(decodeHeroRespawnCandidates821(replay, token), independent);
  assert.equal(decompressions, 1);
});

test('821 respawn scan token fails closed for foreign, unselected, and changed sources', () => {
  const replay = fixture();
  const token = collect821Routes(replay, ['hero_respawn']);
  const foreign = decodeHeroRespawnCandidates821(fixture(), token);
  assert.equal(foreign.status, 'DECODE_FAILED');
  assert.match(foreign.error, /different Replay/);
  const deathOnly = collect821Routes(replay, ['hero_death']);
  const unselected = decodeHeroRespawnCandidates821(replay, deathOnly);
  assert.equal(unselected.status, 'DECODE_FAILED');
  assert.match(unselected.error, /hero_respawn was not selected/);
  replay.buffer[0] ^= 1;
  const changed = decodeHeroRespawnCandidates821(replay, token);
  assert.equal(changed.status, 'DECODE_FAILED');
  assert.match(changed.error, /Replay source integrity failed/);
});

test('dead-time preflight remains independent of final-death gameLength', () => {
  const replay = fixture();
  replay.tail.metadata.gameLength = null;
  assert.deepEqual(assessHeroRespawnDeadTimeTail821(replay), {
    status: 'PASS', seconds: [10, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  });
  assert.equal(assessHeroRespawnTail821(replay).missing_input,
    'Replay tail gameLength for observed final deaths');
});
