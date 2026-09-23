'use strict';

// Generated container/framing fixtures, not replay evidence or semantic fixtures.
const { zstdCompressSync } = require('node:zlib');
const { parseReplayBuffer } = require('../../src/rofl');

function packet(sequence, payload = Buffer.from([sequence & 0xff])) {
  if (payload.length > 255) throw new RangeError('synthetic packet requires a u8 payload size');
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(sequence / 10, 1);
  header[5] = payload.length;
  header.writeUInt16LE(sequence & 0xffff, 6);
  header.writeUInt32LE(sequence >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function replayFromChunks(chunks = [], version = '16.15.801.3452') {
  const versionBytes = Buffer.from(version);
  const header = Buffer.alloc(15 + versionBytes.length);
  header.write('RIOT');
  header.writeUInt16LE(1, 4);
  header[14] = versionBytes.length;
  versionBytes.copy(header, 15);
  const records = chunks.map(({ body, stream = 1, compressed = false, declaredLength }, index) => {
    const encoded = compressed ? zstdCompressSync(body) : body;
    const chunk = Buffer.alloc(17);
    chunk.writeUInt32LE(index + 1, 0);
    chunk[4] = 1;
    chunk.writeUInt32LE((stream * 0x1000000 + index + 1) >>> 0, 5);
    chunk.writeUInt32LE(declaredLength ?? body.length, 9);
    chunk.writeUInt32LE(compressed ? encoded.length : 0, 13);
    return Buffer.concat([chunk, encoded]);
  });
  const metadata = Buffer.from(JSON.stringify({ gameLength: 600000, statsJson: '[]' }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return parseReplayBuffer(Buffer.concat([
    header, ...records, Buffer.alloc(256), metadata, trailer,
  ]), 'synthetic-test.rofl');
}

module.exports = { packet, replayFromChunks };
