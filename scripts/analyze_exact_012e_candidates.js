#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');

const TABLE_RVA = 0x01b301c0;
const TABLE_LENGTH = 0x100;
const MAX_EVENT_SAMPLES = 24;

function parseArgs(argv) {
  const options = {
    image: null,
    emulation: null,
    anchors: null,
    output: null,
    replayFiles: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--image') options.image = path.resolve(argv[++index]);
    else if (value === '--emulation') options.emulation = path.resolve(argv[++index]);
    else if (value === '--anchors') options.anchors = path.resolve(argv[++index]);
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else options.replayFiles.push(path.resolve(value));
  }
  for (const field of ['image', 'emulation', 'anchors', 'output']) {
    if (!options[field]) throw new Error(`--${field} is required`);
  }
  if (options.replayFiles.length === 0) throw new Error('at least one Replay path is required');
  return options;
}

function rotateLeft8(value, count) {
  return ((value << count) | (value >>> (8 - count))) & 0xff;
}

function decodeNetworkId(payload, table) {
  let value = 0;
  let shift = 0;
  for (let index = 0; index < payload.length; index += 1) {
    let byte = table[(~payload[index]) & 0xff];
    byte = rotateLeft8((byte + 0x54) & 0xff, 1);
    byte = table[byte];
    byte = (byte - 0x4c) & 0xff;
    byte = table[byte];
    value = (value | ((byte & 0x7f) << (shift & 31))) >>> 0;
    if ((byte & 0x80) === 0) {
      return {
        success: true,
        bytes_consumed: index + 1,
        value: (value & 0x00ffffff) === 0 ? value : (value ^ 0x40000000) >>> 0,
      };
    }
    shift += 7;
  }
  return { success: false, bytes_consumed: payload.length, value: null };
}

function participantFromEntityValue(value) {
  if (!Number.isInteger(value)) return null;
  const participantId = (value & 0xff) - 0xad;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function nearestUpcomingDeath(deaths, timestampMs, windowMs = 10000) {
  let low = 0;
  let high = deaths.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (deaths[middle].timestamp_ms < timestampMs) low = middle + 1;
    else high = middle;
  }
  const death = deaths[low] || null;
  if (!death || death.timestamp_ms - timestampMs > windowMs) return null;
  return death;
}

function rawReference(replay, chunk, block) {
  return {
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    payload_length: block.payload_length,
    payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function emptyCandidate(packetId, payloadLength) {
  return {
    packet_id: packetId,
    payload_length: payloadLength,
    occurrence_count: 0,
    decode_failure_count: 0,
    partial_consume_count: 0,
    raw_param_participant_count: 0,
    decoded_participant_count: 0,
    both_participant_count: 0,
    opposing_team_pair_count: 0,
    within_10s_before_death_count: 0,
    raw_as_target_victim_count: 0,
    decoded_as_source_oracle_count: 0,
    raw_target_decoded_source_pair_count: 0,
    decoded_as_target_victim_count: 0,
    raw_as_source_oracle_count: 0,
    decoded_target_raw_source_pair_count: 0,
    decoded_values: new Map(),
    raw_params: new Map(),
    pair_match_samples: [],
  };
}

function increment(map, key) {
  map.set(key, (map.get(key) || 0) + 1);
}

function topValues(map, limit = 20) {
  return [...map.entries()]
    .map(([value, count]) => ({ value, value_hex: `0x${value.toString(16).padStart(8, '0')}`, count }))
    .sort((left, right) => right.count - left.count || left.value - right.value)
    .slice(0, limit);
}

function finalizeCandidate(candidate) {
  const count = Math.max(1, candidate.occurrence_count);
  return {
    ...candidate,
    decoded_values: topValues(candidate.decoded_values),
    raw_params: topValues(candidate.raw_params),
    raw_param_participant_ratio: candidate.raw_param_participant_count / count,
    decoded_participant_ratio: candidate.decoded_participant_count / count,
    both_participant_ratio: candidate.both_participant_count / count,
    raw_target_decoded_source_pair_ratio: candidate.raw_target_decoded_source_pair_count / count,
    decoded_target_raw_source_pair_ratio: candidate.decoded_target_raw_source_pair_count / count,
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const image = fs.readFileSync(options.image);
  const table = image.subarray(TABLE_RVA, TABLE_RVA + TABLE_LENGTH);
  if (table.length !== TABLE_LENGTH) throw new Error('decoder lookup table is outside the image');
  const emulation = JSON.parse(fs.readFileSync(options.emulation, 'utf8'));
  const anchors = JSON.parse(fs.readFileSync(options.anchors, 'utf8'));
  const candidateKeys = new Set(
    emulation.results
      .filter((result) => result.all_samples_fully_consumed)
      .map((result) => `${result.packet_id}/${result.payload_length}`),
  );
  const candidates = new Map();
  for (const key of candidateKeys) {
    const [packetId, payloadLength] = key.split('/').map(Number);
    candidates.set(key, emptyCandidate(packetId, payloadLength));
  }
  const anchorsByHash = new Map(anchors.replays.map((replay) => [replay.replay_sha256, replay]));
  const replaySummaries = [];

  for (const replayFile of options.replayFiles) {
    const replay = parseReplayFile(replayFile);
    const anchorSet = anchorsByHash.get(replay.source_sha256);
    if (!anchorSet) throw new Error(`no anchor set for ${replay.source_sha256}`);
    const participants = new Map(
      anchorSet.participants.map((participant) => [participant.participant_id, participant]),
    );
    const deaths = [...anchorSet.deaths].sort((left, right) => left.timestamp_ms - right.timestamp_ms);
    let candidateEventCount = 0;
    walkBlocks(replay, (block, chunk) => {
      if (chunk.stream_tag !== 1) return;
      const key = `${block.packet_id}/${block.payload_length}`;
      const candidate = candidates.get(key);
      if (!candidate) return;
      candidateEventCount += 1;
      candidate.occurrence_count += 1;
      increment(candidate.raw_params, block.param >>> 0);
      const decoded = decodeNetworkId(block.payload, table);
      if (!decoded.success) {
        candidate.decode_failure_count += 1;
        return;
      }
      if (decoded.bytes_consumed !== block.payload.length) candidate.partial_consume_count += 1;
      increment(candidate.decoded_values, decoded.value);
      const rawParticipant = participantFromEntityValue(block.param >>> 0);
      const decodedParticipant = participantFromEntityValue(decoded.value);
      if (rawParticipant !== null) candidate.raw_param_participant_count += 1;
      if (decodedParticipant !== null) candidate.decoded_participant_count += 1;
      if (rawParticipant !== null && decodedParticipant !== null) {
        candidate.both_participant_count += 1;
        if (participants.get(rawParticipant)?.team_id !== participants.get(decodedParticipant)?.team_id) {
          candidate.opposing_team_pair_count += 1;
        }
      }
      const death = nearestUpcomingDeath(deaths, block.timestamp_ms);
      if (!death) return;
      candidate.within_10s_before_death_count += 1;
      const attackers = new Set(
        death.damage_received
          .map((damage) => damage.source_participant_id)
          .filter((participantId) => participantId >= 1 && participantId <= 10),
      );
      const rawIsTarget = rawParticipant === death.victim_participant_id;
      const decodedIsSource = attackers.has(decodedParticipant);
      const decodedIsTarget = decodedParticipant === death.victim_participant_id;
      const rawIsSource = attackers.has(rawParticipant);
      if (rawIsTarget) candidate.raw_as_target_victim_count += 1;
      if (decodedIsSource) candidate.decoded_as_source_oracle_count += 1;
      if (rawIsTarget && decodedIsSource) candidate.raw_target_decoded_source_pair_count += 1;
      if (decodedIsTarget) candidate.decoded_as_target_victim_count += 1;
      if (rawIsSource) candidate.raw_as_source_oracle_count += 1;
      if (decodedIsTarget && rawIsSource) candidate.decoded_target_raw_source_pair_count += 1;
      if ((rawIsTarget && decodedIsSource) || (decodedIsTarget && rawIsSource)) {
        if (candidate.pair_match_samples.length < MAX_EVENT_SAMPLES) {
          candidate.pair_match_samples.push({
            replay_time_ms: block.timestamp_ms,
            death_time_ms: death.timestamp_ms,
            delta_to_death_ms: block.timestamp_ms - death.timestamp_ms,
            raw_param: block.param >>> 0,
            raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
            raw_participant_id: rawParticipant,
            decoded_value: decoded.value,
            decoded_value_hex: `0x${decoded.value.toString(16).padStart(8, '0')}`,
            decoded_participant_id: decodedParticipant,
            victim_participant_id: death.victim_participant_id,
            oracle_attacker_participant_ids: [...attackers].sort((left, right) => left - right),
            raw_packet_ref: rawReference(replay, chunk, block),
          });
        }
      }
    }, { includeStreams: [1], strict: true });
    replaySummaries.push({
      replay_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      game_id: anchorSet.game_id,
      candidate_event_count: candidateEventCount,
    });
  }

  const output = {
    schema_version: 1,
    status: 'EXACT_DECODER_CANDIDATE_ANALYSIS',
    target_replay_version: anchors.target_replay_version,
    image_path: options.image,
    image_sha256: crypto.createHash('sha256').update(image).digest('hex'),
    lookup_table_rva: `0x${TABLE_RVA.toString(16).padStart(8, '0')}`,
    lookup_table_sha256: crypto.createHash('sha256').update(table).digest('hex'),
    candidate_shape_count: candidateKeys.size,
    event_count: [...candidates.values()].reduce((sum, candidate) => sum + candidate.occurrence_count, 0),
    endpoint_mapping_warning: 'Low-byte participant mapping is a constraint probe, not yet a verified generic entity map.',
    replays: replaySummaries,
    candidates: [...candidates.values()]
      .map(finalizeCandidate)
      .sort((left, right) => right.raw_target_decoded_source_pair_count
        - left.raw_target_decoded_source_pair_count
        || right.decoded_target_raw_source_pair_count - left.decoded_target_raw_source_pair_count
        || right.occurrence_count - left.occurrence_count),
  };
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(output, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    output: options.output,
    candidate_shape_count: output.candidate_shape_count,
    event_count: output.event_count,
    top_candidates: output.candidates.slice(0, 10).map((candidate) => ({
      packet_id: candidate.packet_id,
      payload_length: candidate.payload_length,
      occurrence_count: candidate.occurrence_count,
      forward_pair_count: candidate.raw_target_decoded_source_pair_count,
      reverse_pair_count: candidate.decoded_target_raw_source_pair_count,
    })),
  }, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { decodeNetworkId, main, participantFromEntityValue };
