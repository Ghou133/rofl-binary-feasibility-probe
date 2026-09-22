const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const MAGIC = Buffer.from('RIOT', 'ascii');
const HEADER_PREFIX_SIZE = 0x0f;
const CHUNK_HEADER_SIZE = 0x11;
const SIGNATURE_SIZE = 0x100;
const MAX_METADATA_SIZE = 64 * 1024 * 1024;
const MAX_CHUNK_SIZE = 128 * 1024 * 1024;
const MAX_BLOCK_SIZE = 128 * 1024 * 1024;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024;

const STREAM_TAGS = Object.freeze({
  0x01: 'game_chunk',
  0x02: 'keyframe',
  0x03: 'start_keyframe',
  0x04: 'start_sentinel',
});

class RoflError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'RoflError';
    this.code = code;
    this.details = details;
  }
}

function fail(code, message, details) {
  throw new RoflError(code, message, details);
}

function requireRange(buffer, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0) {
    fail('INVALID_RANGE', `${label} has an invalid range`, { offset, length });
  }
  if (offset > buffer.length || length > buffer.length - offset) {
    fail('BOUNDS_ERROR', `${label} exceeds the available bytes`, {
      offset,
      length,
      available: buffer.length,
    });
  }
}

function readU16(buffer, offset, label) {
  requireRange(buffer, offset, 2, label);
  return buffer.readUInt16LE(offset);
}

function readU32(buffer, offset, label) {
  requireRange(buffer, offset, 4, label);
  return buffer.readUInt32LE(offset);
}

function decodeUtf8(buffer, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch (error) {
    fail('INVALID_UTF8', `${label} is not valid UTF-8`, { cause: error.message });
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function formatOpcode(packetId) {
  return `0x${packetId.toString(16).padStart(4, '0')}`;
}

function streamTagName(tag) {
  return STREAM_TAGS[tag] || `unknown_0x${tag.toString(16).padStart(2, '0')}`;
}

function shortPatch(version) {
  const parts = version.split('.');
  return parts.length >= 2 ? `${parts[0]}.${parts[1]}` : version;
}

function parseHeader(buffer) {
  requireRange(buffer, 0, HEADER_PREFIX_SIZE, 'file header prefix');
  if (!buffer.subarray(0, 4).equals(MAGIC)) {
    fail('INVALID_MAGIC', 'file does not start with RIOT magic', {
      actual: buffer.subarray(0, 4).toString('hex'),
    });
  }

  const versionLength = buffer[0x0e];
  const headerSize = HEADER_PREFIX_SIZE + versionLength;
  requireRange(buffer, 0, headerSize, 'version string');
  const versionBytes = buffer.subarray(0x0f, headerSize);
  const version = decodeUtf8(versionBytes, 'version string');
  if (version.length === 0 || version.length > 64 || !/^[0-9]+(?:\.[0-9A-Za-z]+)+$/.test(version)) {
    fail('INVALID_VERSION', 'version string has an unexpected shape', { version });
  }

  return {
    magic: 'RIOT',
    format_version: readU16(buffer, 0x04, 'format version'),
    field_u16_0x06: readU16(buffer, 0x06, 'header field 0x06'),
    field_bytes_0x08: buffer.subarray(0x08, 0x0e).toString('hex'),
    version_length: versionLength,
    version,
    patch: shortPatch(version),
    size: headerSize,
  };
}

function parseMetadataTail(buffer, headerSize) {
  if (buffer.length < 4) {
    fail('FILE_TOO_SHORT', 'file has no metadata-length trailer', { size: buffer.length });
  }
  const metadataLength = readU32(buffer, buffer.length - 4, 'metadata length trailer');
  if (metadataLength > MAX_METADATA_SIZE) {
    fail('METADATA_TOO_LARGE', 'metadata length exceeds the safety limit', {
      metadataLength,
      limit: MAX_METADATA_SIZE,
    });
  }

  const metadataEnd = buffer.length - 4;
  const metadataStart = metadataEnd - metadataLength;
  const signatureStart = metadataStart - SIGNATURE_SIZE;
  if (metadataStart < 0 || signatureStart < headerSize) {
    fail('INVALID_TAIL_LAYOUT', 'metadata/signature bounds are inconsistent', {
      headerSize,
      metadataLength,
      metadataStart,
      signatureStart,
      fileSize: buffer.length,
    });
  }
  requireRange(buffer, metadataStart, metadataLength, 'metadata JSON');
  requireRange(buffer, signatureStart, SIGNATURE_SIZE, 'signature block');
  const metadataText = decodeUtf8(buffer.subarray(metadataStart, metadataEnd), 'metadata JSON');
  let metadata;
  try {
    metadata = JSON.parse(metadataText);
  } catch (error) {
    fail('INVALID_METADATA_JSON', 'metadata JSON cannot be parsed', { cause: error.message });
  }

  let stats = null;
  let statsParseError = null;
  if (typeof metadata.statsJson === 'string') {
    try {
      stats = JSON.parse(metadata.statsJson);
    } catch (error) {
      statsParseError = error.message;
    }
  }

  return {
    metadata_length: metadataLength,
    metadata_start: metadataStart,
    metadata_end: metadataEnd,
    signature_start: signatureStart,
    signature_sha256: sha256(buffer.subarray(signatureStart, metadataStart)),
    metadata,
    stats,
    stats_parse_error: statsParseError,
  };
}

function parseChunks(buffer, start, end) {
  const chunks = [];
  let cursor = start;
  while (cursor < end) {
    requireRange(buffer, cursor, CHUNK_HEADER_SIZE, 'chunk header');
    const chunkId = readU32(buffer, cursor, 'chunk id');
    const chunkType = buffer[cursor + 4];
    const chunkId2 = readU32(buffer, cursor + 5, 'chunk stream id');
    const uncompressedLength = readU32(buffer, cursor + 9, 'chunk uncompressed length');
    const compressedLength = readU32(buffer, cursor + 13, 'chunk compressed length');
    const bodyLength = compressedLength > 0 ? compressedLength : uncompressedLength;
    if (bodyLength > MAX_CHUNK_SIZE) {
      fail('CHUNK_TOO_LARGE', 'chunk body exceeds the safety limit', {
        chunkId,
        bodyLength,
        limit: MAX_CHUNK_SIZE,
      });
    }
    const bodyStart = cursor + CHUNK_HEADER_SIZE;
    const bodyEnd = bodyStart + bodyLength;
    if (bodyEnd > end) {
      fail('CHUNK_BOUNDS_ERROR', 'chunk body exceeds the chunk region', {
        chunkId,
        offset: cursor,
        bodyStart,
        bodyEnd,
        regionEnd: end,
      });
    }
    const tag = (chunkId2 >>> 24) & 0xff;
    chunks.push({
      index: chunks.length,
      chunk_id: chunkId,
      chunk_type: chunkType,
      chunk_id_2: chunkId2,
      stream_tag: tag,
      stream: streamTagName(tag),
      uncompressed_length: uncompressedLength,
      compressed_length: compressedLength,
      offset: cursor,
      body_offset: bodyStart,
      body_end: bodyEnd,
      body_length: bodyLength,
      is_compressed: compressedLength > 0,
    });
    cursor = bodyEnd;
  }
  if (cursor !== end) {
    fail('CHUNK_REGION_NOT_CONSUMED', 'chunk iterator did not end on the region boundary', {
      cursor,
      end,
    });
  }
  return chunks;
}

function decompressChunk(buffer, chunk) {
  requireRange(buffer, chunk.body_offset, chunk.body_length, `chunk ${chunk.chunk_id} body`);
  if (!chunk.is_compressed) {
    const raw = buffer.subarray(chunk.body_offset, chunk.body_end);
    if (raw.length !== chunk.uncompressed_length) {
      fail('RAW_CHUNK_LENGTH_MISMATCH', 'raw chunk length does not match its header', {
        chunkId: chunk.chunk_id,
        expected: chunk.uncompressed_length,
        actual: raw.length,
      });
    }
    return raw;
  }
  if (typeof zlib.zstdDecompressSync !== 'function') {
    fail('ZSTD_UNAVAILABLE', 'this Node runtime does not provide native Zstandard decompression');
  }
  if (chunk.uncompressed_length > MAX_CHUNK_SIZE) {
    fail('CHUNK_TOO_LARGE', 'declared decompressed chunk exceeds the safety limit', {
      chunkId: chunk.chunk_id,
      uncompressedLength: chunk.uncompressed_length,
      limit: MAX_CHUNK_SIZE,
    });
  }
  let output;
  try {
    output = zlib.zstdDecompressSync(buffer.subarray(chunk.body_offset, chunk.body_end));
  } catch (error) {
    fail('ZSTD_DECOMPRESSION_ERROR', `Zstandard decompression failed for chunk ${chunk.chunk_id}`, {
      chunkId: chunk.chunk_id,
      cause: error.message,
    });
  }
  if (output.length !== chunk.uncompressed_length) {
    fail('DECOMPRESSED_LENGTH_MISMATCH', 'decompressed chunk length differs from the header', {
      chunkId: chunk.chunk_id,
      expected: chunk.uncompressed_length,
      actual: output.length,
    });
  }
  return output;
}

function parseBlockAt(body, cursor, state) {
  const start = cursor;
  requireRange(body, cursor, 1, 'block marker');
  const marker = body[cursor++];
  let timestamp;
  let timestamp_mode;
  if ((marker & 0x80) !== 0) {
    requireRange(body, cursor, 1, 'relative block timestamp');
    const deltaMs = body[cursor++];
    timestamp = state.timestamp + deltaMs / 1000;
    timestamp_mode = 'relative_ms';
  } else {
    requireRange(body, cursor, 4, 'absolute block timestamp');
    timestamp = body.readFloatLE(cursor);
    cursor += 4;
    timestamp_mode = 'absolute_f32';
  }
  if (!Number.isFinite(timestamp) || timestamp < -1 || timestamp > 24 * 60 * 60) {
    fail('INVALID_TIMESTAMP', 'block timestamp is outside the safety range', {
      offset: start,
      timestamp,
    });
  }

  let length;
  let length_mode;
  if ((marker & 0x10) !== 0) {
    requireRange(body, cursor, 1, 'u8 block length');
    length = body[cursor++];
    length_mode = 'u8';
  } else {
    requireRange(body, cursor, 4, 'u32 block length');
    length = body.readUInt32LE(cursor);
    cursor += 4;
    length_mode = 'u32';
  }
  if (length > MAX_BLOCK_SIZE) {
    fail('BLOCK_TOO_LARGE', 'block payload exceeds the safety limit', {
      offset: start,
      length,
      limit: MAX_BLOCK_SIZE,
    });
  }

  let packetId;
  const packetIdMode = (marker & 0x40) !== 0 ? 'reused' : 'absolute_u16';
  if ((marker & 0x40) !== 0) {
    packetId = state.packet_id;
  } else {
    requireRange(body, cursor, 2, 'block packet id');
    packetId = body.readUInt16LE(cursor);
    cursor += 2;
  }

  let param;
  const paramMode = (marker & 0x20) !== 0 ? 'relative_u8' : 'absolute_u32';
  if ((marker & 0x20) !== 0) {
    requireRange(body, cursor, 1, 'relative block param');
    param = (state.param + body[cursor++]) >>> 0;
  } else {
    requireRange(body, cursor, 4, 'block param');
    param = body.readUInt32LE(cursor);
    cursor += 4;
  }

  requireRange(body, cursor, length, 'block payload');
  const payloadStart = cursor;
  const payload = body.subarray(cursor, cursor + length);
  cursor += length;
  state.timestamp = timestamp;
  state.packet_id = packetId;
  state.param = param;

  return {
    offset: start,
    header_length: payloadStart - start,
    payload_offset: payloadStart,
    payload_length: length,
    payload,
    timestamp,
    timestamp_ms: Math.round(timestamp * 1000),
    timestamp_mode,
    marker,
    length_mode,
    packet_id: packetId,
    packet_type: formatOpcode(packetId),
    packet_id_mode: packetIdMode,
    param,
    param_mode: paramMode,
    next_offset: cursor,
  };
}

function walkBlocks(replay, callback, options = {}) {
  const includeStreams = new Set(options.includeStreams || [1, 2, 3]);
  const errors = [];
  let blockCount = 0;
  for (const chunk of replay.chunks) {
    if (!includeStreams.has(chunk.stream_tag)) {
      continue;
    }
    let body;
    try {
      body = decompressChunk(replay.buffer, chunk);
    } catch (error) {
      const item = {
        chunk_id: chunk.chunk_id,
        chunk_index: chunk.index,
        chunk_offset: chunk.offset,
        block_offset: null,
        code: error.code || 'CHUNK_DECODE_ERROR',
        message: error.message,
      };
      errors.push(item);
      if (options.strict) throw error;
      continue;
    }
    const state = { timestamp: 0, packet_id: 0, param: 0 };
    let cursor = 0;
    while (cursor < body.length) {
      try {
        const block = parseBlockAt(body, cursor, state);
        blockCount += 1;
        callback(block, chunk, body);
        cursor = block.next_offset;
      } catch (error) {
        const item = {
          chunk_id: chunk.chunk_id,
          chunk_index: chunk.index,
          chunk_offset: chunk.offset,
          block_offset: cursor,
          code: error.code || 'BLOCK_PARSE_ERROR',
          message: error.message,
        };
        errors.push(item);
        if (options.strict) {
          throw error;
        }
        break;
      }
    }
  }
  return { block_count: blockCount, errors };
}

function parseReplayBuffer(buffer, sourcePath = null) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }
  const header = parseHeader(buffer);
  const tail = parseMetadataTail(buffer, header.size);
  const chunks = parseChunks(buffer, header.size, tail.signature_start);
  const streamCounts = {};
  for (const chunk of chunks) {
    streamCounts[chunk.stream] = (streamCounts[chunk.stream] || 0) + 1;
  }
  return {
    buffer,
    source_path: sourcePath ? path.resolve(sourcePath) : null,
    source_sha256: sha256(buffer),
    file_size: buffer.length,
    header,
    tail,
    chunks,
    stream_counts: streamCounts,
  };
}

function parseReplayFile(filePath) {
  const resolved = path.resolve(filePath);
  let buffer;
  try {
    const stat = fs.statSync(resolved);
    if (stat.size > MAX_FILE_SIZE) {
      fail('FILE_TOO_LARGE', `Replay file exceeds the safety limit: ${resolved}`, {
        size: stat.size,
        limit: MAX_FILE_SIZE,
      });
    }
    buffer = fs.readFileSync(resolved);
  } catch (error) {
    if (error instanceof RoflError) throw error;
    fail('INPUT_READ_ERROR', `cannot read replay file: ${resolved}`, { cause: error.message });
  }
  return parseReplayBuffer(buffer, resolved);
}

function normalizeRole(value) {
  const normalized = String(value || '').toUpperCase();
  if (normalized === 'TOP') return 'top';
  if (normalized === 'JUNGLE') return 'jungle';
  if (normalized === 'MIDDLE' || normalized === 'MID') return 'mid';
  if (normalized === 'BOTTOM' || normalized === 'BOT' || normalized === 'ADC') return 'adc';
  if (normalized === 'UTILITY' || normalized === 'SUPPORT') return 'support';
  return null;
}

function normalizePlayers(replay, options = {}) {
  const stats = Array.isArray(replay.tail.stats) ? replay.tail.stats : [];
  return stats.map((player, index) => {
    const teamId = Number.parseInt(player.TEAM, 10);
    const role = normalizeRole(player.INDIVIDUAL_POSITION || player.TEAM_POSITION);
    const result = {
      metadata_index: index,
      champion: player.SKIN ?? null,
      team_id: Number.isFinite(teamId) ? teamId : null,
      team: teamId === 100 ? 'blue' : teamId === 200 ? 'red' : null,
      role,
      role_status: role === null ? 'UNAVAILABLE' : 'VERIFIED_FROM_METADATA',
      win: player.WIN === 'Win' ? true : player.WIN === 'Fail' ? false : null,
      metadata_player_id: player.ID ?? null,
      aggregate_stats: {
        kills: numberOrNull(player.CHAMPIONS_KILLED),
        deaths: numberOrNull(player.NUM_DEATHS),
        assists: numberOrNull(player.ASSISTS),
        total_damage_to_champions: numberOrNull(player.TOTAL_DAMAGE_DEALT_TO_CHAMPIONS),
        physical_damage_to_champions: numberOrNull(player.PHYSICAL_DAMAGE_DEALT_TO_CHAMPIONS),
        magic_damage_to_champions: numberOrNull(player.MAGIC_DAMAGE_DEALT_TO_CHAMPIONS),
        true_damage_to_champions: numberOrNull(player.TRUE_DAMAGE_DEALT_TO_CHAMPIONS),
        total_damage_taken: numberOrNull(player.TOTAL_DAMAGE_TAKEN),
        total_damage_taken_from_champions: numberOrNull(player.TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS),
        total_heal: numberOrNull(player.TOTAL_HEAL),
        total_heal_on_teammates: numberOrNull(player.TOTAL_HEAL_ON_TEAMMATES),
        total_damage_shielded_on_teammates: numberOrNull(player.TOTAL_DAMAGE_SHIELDED_ON_TEAMMATES),
        items_purchased: numberOrNull(player.ITEMS_PURCHASED),
        spell_casts: [1, 2, 3, 4].map((slot) => numberOrNull(player[`SPELL${slot}_CAST`])),
      },
      provenance: 'ROFL_METADATA_STATS_JSON',
      confidence: 'VERIFIED',
    };
    if (options.includePrivateMetadata) {
      result.riot_id_game_name = player.RIOT_ID_GAME_NAME ?? null;
      result.riot_id_tag_line = player.RIOT_ID_TAG_LINE ?? null;
      result.puuid = player.PUUID ?? null;
    }
    return result;
  });
}

function numberOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function metadataSummary(replay, options = {}) {
  const metadata = replay.tail.metadata;
  return {
    game_id: null,
    game_id_status: 'UNAVAILABLE',
    game_length_ms: numberOrNull(metadata.gameLength),
    last_game_chunk_id: numberOrNull(metadata.lastGameChunkId),
    last_key_frame_id: numberOrNull(metadata.lastKeyFrameId),
    metadata_keys: Object.keys(metadata),
    stats_player_count: Array.isArray(replay.tail.stats) ? replay.tail.stats.length : null,
    stats_json_parse_error: replay.tail.stats_parse_error,
    players: normalizePlayers(replay, options),
    source: {
      path: replay.source_path,
      sha256: replay.source_sha256,
      metadata_sha256: sha256(Buffer.from(JSON.stringify(metadata), 'utf8')),
      status: 'VERIFIED',
    },
  };
}

module.exports = {
  MAGIC,
  HEADER_PREFIX_SIZE,
  CHUNK_HEADER_SIZE,
  SIGNATURE_SIZE,
  STREAM_TAGS,
  RoflError,
  sha256,
  formatOpcode,
  streamTagName,
  parseHeader,
  parseMetadataTail,
  parseChunks,
  decompressChunk,
  parseBlockAt,
  walkBlocks,
  parseReplayBuffer,
  parseReplayFile,
  normalizePlayers,
  metadataSummary,
  numberOrNull,
};
