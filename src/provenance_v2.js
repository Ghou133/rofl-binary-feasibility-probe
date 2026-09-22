'use strict';

const { sha256, walkBlocks } = require('./rofl');

function packetRefKey(chunkIndex, blockOffset, packetId) {
  if (!Number.isInteger(chunkIndex) || !Number.isInteger(blockOffset)
      || !Number.isInteger(packetId)) return null;
  return `${chunkIndex}:${blockOffset}:${packetId}`;
}

function buildReplayPacketIndex(replay, packetIds) {
  if (!replay?.source_sha256 || !Array.isArray(replay.chunks)) {
    throw new TypeError('parsed replay with source SHA and chunks is required');
  }
  const selected = packetIds ? new Set(packetIds) : null;
  const packets = new Map();
  const walk = walkBlocks(replay, (block, chunk) => {
    if (selected && !selected.has(block.packet_id)) return;
    const key = packetRefKey(chunk.index, block.offset, block.packet_id);
    packets.set(key, {
      replay_sha256: replay.source_sha256,
      chunk_index: chunk.index,
      decompressed_block_offset: block.offset,
      packet_id: block.packet_id,
      timestamp_ms: block.timestamp_ms,
      payload_length: block.payload_length,
      raw_param: block.param,
      raw_payload_sha256: sha256(block.payload),
    });
  }, { strict: true });
  if (walk.errors.length > 0) throw new Error('packet provenance indexing encountered framing errors');
  return packets;
}

function verifiedPacketRecord(replay, packetIndex, reference, expected = {}) {
  if (!replay?.source_sha256 || !(packetIndex instanceof Map)
      || !reference || typeof reference !== 'object'
      || reference.replay_sha256 !== replay.source_sha256
      || !Number.isInteger(reference.payload_length) || reference.payload_length < 0
      || !Number.isInteger(reference.raw_param)) return null;
  const key = packetRefKey(
    reference.chunk_index,
    reference.decompressed_block_offset,
    reference.packet_id,
  );
  const record = key ? packetIndex.get(key) : null;
  const payloadSha256 = reference.raw_payload_sha256 ?? reference.payload_sha256 ?? null;
  if (!record || record.replay_sha256 !== replay.source_sha256
      || typeof payloadSha256 !== 'string'
      || !/^[0-9a-f]{64}$/i.test(payloadSha256)
      || payloadSha256.toLowerCase() !== record.raw_payload_sha256) return null;
  if (reference.payload_length !== record.payload_length
      || reference.raw_param !== record.raw_param) return null;
  if (Number.isInteger(expected.packetId) && record.packet_id !== expected.packetId) return null;
  const expectedTimestampMs = Number.isFinite(expected.timestampMs)
    ? expected.timestampMs : reference.packet_timestamp_ms;
  if (!Number.isFinite(expectedTimestampMs) || record.timestamp_ms !== expectedTimestampMs) return null;
  if (Number.isFinite(reference.packet_timestamp_ms)
      && reference.packet_timestamp_ms !== record.timestamp_ms) return null;
  return record;
}

function artifactShaMatches(actualSha256, expectedSha256) {
  return typeof actualSha256 === 'string' && typeof expectedSha256 === 'string'
    && /^[0-9a-f]{64}$/i.test(actualSha256)
    && actualSha256.toLowerCase() === expectedSha256.toLowerCase();
}

module.exports = {
  packetRefKey,
  buildReplayPacketIndex,
  verifiedPacketRecord,
  artifactShaMatches,
};
