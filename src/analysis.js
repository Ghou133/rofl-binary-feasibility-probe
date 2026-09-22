const {
  formatOpcode,
  metadataSummary,
  sha256,
  walkBlocks,
} = require('./rofl');

const TOOL_VERSION = '0.1.0';
const PARSER_VERSION = '0.1.0-container-blocks';
const DEFAULT_TIMELINE_LIMIT = 250;
const DEFAULT_HEX_PREFIX_BYTES = 32;

function emptyEventSet() {
  return {
    damage_events: [],
    spell_events: [],
    death_events: [],
    position_events: [],
    item_events: [],
    buff_events: [],
    shield_events: [],
    heal_events: [],
    level_transition_events: [],
  };
}

function createCapabilityMatrix(replay, decoderProfile = null) {
  const semanticEvidence = decoderProfile
    ? 'A decoder profile was supplied, but this build does not assert semantic fields without independent event evidence.'
    : 'No patch-matched client decoder profile is configured; raw packet IDs are preserved without semantic guesses.';
  return [
    capability('replay metadata', 'VERIFIED', 'ROFL tail JSON parsed from real samples.'),
    capability('game duration', 'VERIFIED', 'metadata.gameLength parsed and checked against packet time bounds.'),
    capability('packet timestamps', 'VERIFIED', 'Block timestamp framing parsed across real samples with zero framing errors.'),
    capability('chunk and keyframe inventory', 'VERIFIED', '17-byte chunk records and stream tags parsed from real samples.'),
    capability('hero death', 'UNVERIFIED', semanticEvidence),
    capability('damage source', 'UNVERIFIED', semanticEvidence),
    capability('damage amount', 'UNVERIFIED', semanticEvidence),
    capability('damage type', 'UNVERIFIED', semanticEvidence),
    capability('basic attack', 'UNVERIFIED', semanticEvidence),
    capability('spell cast', 'UNVERIFIED', semanticEvidence),
    capability('position', 'UNVERIFIED', semanticEvidence),
    capability('shield', 'UNVERIFIED', semanticEvidence),
    capability('heal', 'UNVERIFIED', semanticEvidence),
    capability('buff', 'UNVERIFIED', semanticEvidence),
    capability('death combat window', 'UNAVAILABLE', 'Requires at least one independently decoded death and damage event.'),
    capability('Replay versus Match Details validation', 'UNAVAILABLE', 'No matching Details artifact was found for the local Replay filenames.'),
  ];
}

function capability(name, status, evidence) {
  return { capability: name, status, evidence };
}

function refFor(replay, chunk, block) {
  return {
    source_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    compressed_body_offset: chunk.body_offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    payload_length: block.payload_length,
  };
}

function sampleRecord(replay, chunk, block, kind, hexPrefixBytes) {
  const payload = block.payload;
  return {
    anchor_kind: kind,
    event_type: null,
    semantic_status: 'UNVERIFIED',
    replay_time_ms: block.timestamp_ms,
    replay_time_seconds: block.timestamp,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    packet_type: block.packet_type,
    packet_id: block.packet_id,
    packet_offset: block.payload_offset,
    packet_length: block.payload_length,
    raw_payload_sha256: sha256(payload),
    raw_payload_hex_prefix: payload.subarray(0, hexPrefixBytes).toString('hex'),
    raw_packet_ref: refFor(replay, chunk, block),
    decoder_status: 'RAW_ONLY',
    direction: null,
    category: null,
  };
}

function analyzeReplay(replay, options = {}) {
  const started = process.hrtime.bigint();
  const timelineLimit = options.timelineLimit ?? DEFAULT_TIMELINE_LIMIT;
  const hexPrefixBytes = options.hexPrefixBytes ?? DEFAULT_HEX_PREFIX_BYTES;
  const sampleStride = options.sampleStride ?? 10000;
  const packetStats = new Map();
  const timeline = [];
  const anchors = [];
  const chunkStats = new Map();
  let packetCount = 0;
  let decodedPacketCount = 0;
  let unknownPacketCount = 0;
  let largestBlock = null;
  let lastBlock = null;
  let firstNonZero = null;
  let firstByStream = new Set();

  const walk = walkBlocks(replay, (block, chunk) => {
    packetCount += 1;
    unknownPacketCount += 1;
    const existing = packetStats.get(block.packet_id) || {
      packet_id: block.packet_id,
      packet_type: formatOpcode(block.packet_id),
      count: 0,
      min_timestamp_ms: null,
      max_timestamp_ms: null,
      min_payload_length: null,
      max_payload_length: null,
      total_payload_length: 0,
      streams: new Set(),
      decoder_status: 'RAW_ONLY',
    };
    existing.count += 1;
    existing.min_timestamp_ms = existing.min_timestamp_ms === null
      ? block.timestamp_ms
      : Math.min(existing.min_timestamp_ms, block.timestamp_ms);
    existing.max_timestamp_ms = existing.max_timestamp_ms === null
      ? block.timestamp_ms
      : Math.max(existing.max_timestamp_ms, block.timestamp_ms);
    existing.min_payload_length = existing.min_payload_length === null
      ? block.payload_length
      : Math.min(existing.min_payload_length, block.payload_length);
    existing.max_payload_length = existing.max_payload_length === null
      ? block.payload_length
      : Math.max(existing.max_payload_length, block.payload_length);
    existing.total_payload_length += block.payload_length;
    existing.streams.add(chunk.stream);
    packetStats.set(block.packet_id, existing);

    const chunkEntry = chunkStats.get(chunk.index) || {
      ...chunk,
      block_count: 0,
      min_timestamp_ms: null,
      max_timestamp_ms: null,
      block_errors: 0,
    };
    chunkEntry.block_count += 1;
    chunkEntry.min_timestamp_ms = chunkEntry.min_timestamp_ms === null
      ? block.timestamp_ms
      : Math.min(chunkEntry.min_timestamp_ms, block.timestamp_ms);
    chunkEntry.max_timestamp_ms = chunkEntry.max_timestamp_ms === null
      ? block.timestamp_ms
      : Math.max(chunkEntry.max_timestamp_ms, block.timestamp_ms);
    chunkStats.set(chunk.index, chunkEntry);

    const shouldSample = timeline.length < timelineLimit || packetCount % sampleStride === 0;
    if (shouldSample) {
      timeline.push(sampleRecord(replay, chunk, block, 'timeline_sample', hexPrefixBytes));
    }
    if (!firstByStream.has(chunk.stream)) {
      firstByStream.add(chunk.stream);
      anchors.push(sampleRecord(replay, chunk, block, `first_${chunk.stream}`, hexPrefixBytes));
    }
    if (block.timestamp > 0 && firstNonZero === null) {
      firstNonZero = sampleRecord(replay, chunk, block, 'first_nonzero_timestamp', hexPrefixBytes);
      anchors.push(firstNonZero);
    }
    if (largestBlock === null || block.payload_length > largestBlock.packet_length) {
      largestBlock = sampleRecord(replay, chunk, block, 'largest_raw_payload', hexPrefixBytes);
    }
    lastBlock = sampleRecord(replay, chunk, block, 'last_raw_block', hexPrefixBytes);
  }, {
    includeStreams: options.includeStreams || [1, 2, 3],
    strict: Boolean(options.strict),
  });

  for (const chunk of replay.chunks) {
    if (!chunkStats.has(chunk.index)) {
      chunkStats.set(chunk.index, {
        ...chunk,
        block_count: 0,
        min_timestamp_ms: null,
        max_timestamp_ms: null,
        block_errors: 0,
      });
    }
  }
  for (const error of walk.errors) {
    const entry = chunkStats.get(error.chunk_index);
    if (entry) entry.block_errors += 1;
  }
  if (largestBlock) anchors.push(largestBlock);
  if (lastBlock) anchors.push(lastBlock);

  const packetTypeInventory = [...packetStats.values()]
    .map((entry) => ({
      ...entry,
      average_payload_length: Number((entry.total_payload_length / entry.count).toFixed(3)),
      streams: [...entry.streams].sort(),
    }))
    .sort((a, b) => b.count - a.count || a.packet_id - b.packet_id);

  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const eventCounts = Object.fromEntries(Object.keys(emptyEventSet()).map((key) => [key, 0]));
  const gameLengthMs = Number(replay.tail.metadata.gameLength);
  const maxPacketTime = [...chunkStats.values()]
    .map((chunk) => chunk.max_timestamp_ms)
    .filter((value) => value !== null)
    .reduce((max, value) => Math.max(max, value), 0);

  return {
    tool_version: TOOL_VERSION,
    parser_version: PARSER_VERSION,
    source_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    file_size: replay.file_size,
    replay_version: replay.header.version,
    patch: replay.header.patch,
    game_id: null,
    game_id_status: 'UNAVAILABLE',
    metadata: metadataSummary(replay, options),
    container: {
      header: replay.header,
      metadata_length: replay.tail.metadata_length,
      signature_start: replay.tail.signature_start,
      signature_sha256: replay.tail.signature_sha256,
      chunk_count: replay.chunks.length,
      stream_counts: replay.stream_counts,
      keyframe_count: replay.stream_counts.keyframe || 0,
      start_keyframe_count: replay.stream_counts.start_keyframe || 0,
      start_sentinel_count: replay.stream_counts.start_sentinel || 0,
      chunk_region_bytes: replay.tail.signature_start - replay.header.size,
    },
    packet_count: packetCount,
    decoded_packet_count: decodedPacketCount,
    unknown_packet_count: unknownPacketCount,
    block_errors: walk.errors,
    packet_type_inventory: packetTypeInventory,
    packet_timeline_sample: timeline.slice(0, timelineLimit),
    raw_anchors: dedupeAnchors(anchors),
    chunk_inventory: [...chunkStats.values()].sort((a, b) => a.index - b.index),
    events: emptyEventSet(),
    event_counts: eventCounts,
    adc_deaths: [],
    decoder: {
      profile: options.decoderProfile || null,
      status: options.decoderProfile ? 'UNVERIFIED' : 'UNSUPPORTED_REPLAY_VERSION',
      note: options.decoderProfile
        ? 'External decoder profile was named but no semantic decoder is bundled in this build.'
        : `No patch-matched client decoder profile is available for ${replay.header.patch}.`,
    },
    timing: {
      decode_elapsed_ms: Number(elapsedMs.toFixed(3)),
      observed_rss_bytes: process.memoryUsage().rss,
      metadata_game_length_ms: Number.isFinite(gameLengthMs) ? gameLengthMs : null,
      maximum_observed_packet_time_ms: maxPacketTime,
      timestamp_bound_check: Number.isFinite(gameLengthMs) && maxPacketTime <= gameLengthMs + 120000
        ? 'PASS'
        : 'UNVERIFIED',
    },
    capabilities: createCapabilityMatrix(replay, options.decoderProfile),
  };
}

function dedupeAnchors(anchors) {
  const seen = new Set();
  return anchors.filter((anchor) => {
    const key = `${anchor.anchor_kind}:${anchor.raw_packet_ref.chunk_index}:${anchor.raw_packet_ref.decompressed_block_offset}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = {
  TOOL_VERSION,
  PARSER_VERSION,
  analyzeReplay,
  emptyEventSet,
  createCapabilityMatrix,
};
