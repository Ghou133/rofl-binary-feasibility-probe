'use strict';

const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const { parseReplayBuffer } = require('../rofl');

// A byte-for-byte copy makes later checks much cheaper than reparsing and
// rehashing the same Replay for each selected capability. Limit retained
// memory for callers that keep unusually large Replay objects alive.
const MAX_CACHED_SOURCE_BYTES = 32 * 1024 * 1024;
const verifiedSources = new WeakMap();

function replaySourceError(replay) {
  const buffer = replay?.buffer;
  if (!Buffer.isBuffer(buffer)) return 'Replay source buffer is unavailable';
  const verified = verifiedSources.get(replay);
  if (verified) {
    if (replay.source_sha256 !== verified.source_sha256
        || replay.file_size !== verified.file_size) {
      return 'Replay source bytes differ from their parse-time identity';
    }
    if (!isDeepStrictEqual(replay.header, verified.header)
        || !isDeepStrictEqual(replay.chunks, verified.chunks)) {
      return 'Replay header or chunk layout differs from its source bytes';
    }
    // Metadata access can have side effects in a caller-supplied Replay.
    // Compare the bytes last so a mutation during those reads is rejected.
    if (!Buffer.isBuffer(replay.buffer) || !replay.buffer.equals(verified.bytes)) {
      return 'Replay source bytes differ from their parse-time identity';
    }
    return null;
  }
  const snapshot = buffer.length <= MAX_CACHED_SOURCE_BYTES ? Buffer.from(buffer) : null;
  let parsed;
  try {
    // Replay objects expose writable bytes and chunk metadata. Use the
    // container parser to check both against the parse-time source identity.
    parsed = parseReplayBuffer(snapshot ?? buffer, replay.source_path);
  } catch (error) {
    return `Replay source no longer parses: ${error.message}`;
  }
  const sourceSha256 = replay.source_sha256;
  const fileSize = replay.file_size;
  if (parsed.source_sha256 !== sourceSha256
      || parsed.file_size !== fileSize) {
    return 'Replay source bytes differ from their parse-time identity';
  }
  const replayHeader = replay.header;
  const replayChunks = replay.chunks;
  if (!isDeepStrictEqual(parsed.header, replayHeader)
      || !isDeepStrictEqual(parsed.chunks, replayChunks)) {
    return 'Replay header or chunk layout differs from its source bytes';
  }
  const header = snapshot ? structuredClone(replayHeader) : null;
  const chunks = snapshot ? structuredClone(replayChunks) : null;
  const current = replay.buffer;
  if (!Buffer.isBuffer(current) || (snapshot
    ? !current.equals(snapshot)
    : crypto.createHash('sha256').update(current).digest('hex') !== parsed.source_sha256)) {
    return 'Replay source bytes differ from their parse-time identity';
  }
  if (snapshot) {
    verifiedSources.set(replay, {
      bytes: snapshot,
      source_sha256: sourceSha256,
      file_size: fileSize,
      header,
      chunks,
    });
  }
  return null;
}

module.exports = { replaySourceError };
