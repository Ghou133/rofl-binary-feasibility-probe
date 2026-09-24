'use strict';

const { isDeepStrictEqual } = require('node:util');

const { parseReplayBuffer } = require('../rofl');

function replaySourceError(replay) {
  if (!Buffer.isBuffer(replay?.buffer)) return 'Replay source buffer is unavailable';
  let parsed;
  try {
    // Replay objects expose writable bytes and chunk metadata. Use the
    // container parser to check both against the parse-time source identity.
    parsed = parseReplayBuffer(replay.buffer, replay.source_path);
  } catch (error) {
    return `Replay source no longer parses: ${error.message}`;
  }
  if (parsed.source_sha256 !== replay.source_sha256
      || parsed.file_size !== replay.file_size) {
    return 'Replay source bytes differ from their parse-time identity';
  }
  if (!isDeepStrictEqual(parsed.header, replay.header)
      || !isDeepStrictEqual(parsed.chunks, replay.chunks)) {
    return 'Replay header or chunk layout differs from its source bytes';
  }
  return null;
}

module.exports = { replaySourceError };
