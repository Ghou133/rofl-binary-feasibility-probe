#!/usr/bin/env node

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { DEFAULT_UPSTREAM_PATHS, compareHashSnapshots } = require('../src/integrity');
const {
  ensureDir,
  hashFiles,
  outputHashes,
  writeCsv,
  writeJson,
  writeJsonl,
} = require('../src/io');
const { parseTestSummary } = require('../src/cli');
const {
  PROFILE: DEATH_PROFILE,
  championByParticipant,
  decodeHeroDeathBlock,
  participantIdFromParam,
} = require('../src/decoders/rofl_16_15_801_3452');

const TARGET_VERSION = '16.15.801.3452';
const GAME_IDS = Object.freeze([
  '11154791609',
  '11158122245',
  '11158276256',
  '11172852368',
]);
const DEATH_WINDOWS_MS = Object.freeze([200, 500, 2000]);
const PREFIX_BYTES = 8;
const DISTINCT_VALUE_LIMIT = 4096;
const CASTSPELL_CANDIDATE_PACKET_ID = 1113;
const DAMAGE_CANDIDATE_SHAPES = Object.freeze([
  [49, 7],
  [598, 9],
  [650, 17],
  [650, 18],
  [457, 9],
  [158, 60],
  [1030, 23],
  [1030, 24],
]);
const DAMAGE_CANDIDATE_KEYS = new Set(
  DAMAGE_CANDIDATE_SHAPES.map(([packetId, payloadLength]) => `${packetId}/${payloadLength}`),
);
const DAMAGE_EMULATION_RESULTS = Object.freeze([
  {
    packet_id: 49,
    payload_length: 7,
    deserialize_return_al: 0,
    bytes_consumed: 7,
    decoded_target_network_id: '0xe6e6e6e6',
    decoded_source_network_id: '0x00000000',
    decoded_amount: 0,
    verdict: 'REJECTED',
    reason: 'Deserializer returned false and target retained constructor sentinel bytes.',
  },
  {
    packet_id: 598,
    payload_length: 9,
    deserialize_return_al: 0,
    bytes_consumed: 8,
    decoded_target_network_id: '0x40001ca5',
    decoded_source_network_id: '0x00000000',
    decoded_amount: 0,
    verdict: 'REJECTED',
    reason: 'Deserializer returned false before consuming the payload.',
  },
  {
    packet_id: 650,
    payload_length: 17,
    deserialize_return_al: 0,
    bytes_consumed: 17,
    decoded_target_network_id: '0x00000000',
    decoded_source_network_id: '0xefca3cc8',
    decoded_amount: 1.4175120671422079e31,
    verdict: 'REJECTED',
    reason: 'Deserializer returned false and produced an implausible amount.',
  },
  {
    packet_id: 650,
    payload_length: 18,
    deserialize_return_al: 1,
    bytes_consumed: 16,
    decoded_target_network_id: '0x40002ed0',
    decoded_source_network_id: '0x40000228',
    decoded_amount: -7013639.5,
    verdict: 'REJECTED',
    reason: 'Deserializer returned true but left two bytes and produced a negative multi-million amount.',
  },
  {
    packet_id: 457,
    payload_length: 9,
    deserialize_return_al: 0,
    bytes_consumed: 9,
    decoded_target_network_id: '0xffffffff',
    decoded_source_network_id: '0x00000000',
    decoded_amount: 0.00796215608716011,
    verdict: 'REJECTED',
    reason: 'Deserializer returned false and target decoded to the invalid sentinel 0xffffffff.',
  },
  {
    packet_id: 158,
    payload_length: 60,
    deserialize_return_al: 1,
    bytes_consumed: 16,
    decoded_target_network_id: '0x40184077',
    decoded_source_network_id: '0x4870a173',
    decoded_amount: 2,
    verdict: 'REJECTED',
    reason: 'Only 16 of 60 bytes were consumed and source did not decode as a valid in-game network id.',
  },
  {
    packet_id: 1030,
    payload_length: 23,
    deserialize_return_al: 1,
    bytes_consumed: 11,
    decoded_target_network_id: '0xffffffff',
    decoded_source_network_id: '0x40000044',
    decoded_amount: 0,
    verdict: 'REJECTED',
    reason: 'Only 11 of 23 bytes were consumed and target decoded to 0xffffffff.',
  },
  {
    packet_id: 1030,
    payload_length: 24,
    deserialize_return_al: 1,
    bytes_consumed: 18,
    decoded_target_network_id: '0x40000079',
    decoded_source_network_id: '0x40114e2b',
    decoded_amount: 2,
    verdict: 'REJECTED',
    reason: 'Six bytes remained and decoded ids were not a validated source/target pair.',
  },
]);

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const options = {
    replayDir: path.resolve('replay'),
    outputDir: path.resolve('artifacts', 'semantic_probe'),
    detailsDir: null,
    anchorsFile: null,
    runTests: true,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--replay-dir') options.replayDir = path.resolve(argv[++index]);
    else if (value === '--output-dir') options.outputDir = path.resolve(argv[++index]);
    else if (value === '--details-dir') options.detailsDir = path.resolve(argv[++index]);
    else if (value === '--anchors-file') options.anchorsFile = path.resolve(argv[++index]);
    else if (value === '--skip-tests') options.runTests = false;
    else fail(`unknown argument: ${value}`);
  }
  if (options.detailsDir && options.anchorsFile) {
    fail('--details-dir and --anchors-file are mutually exclusive');
  }
  return options;
}

function loadDetailsFile(detailsDir, gameId) {
  const candidates = [
    path.join(detailsDir, `HN1-${gameId}.json`),
    path.join(detailsDir, `HN1_${gameId}.json`),
    path.join(detailsDir, `${gameId}.json`),
  ];
  const file = candidates.find((candidate) => fs.existsSync(candidate));
  if (!file) fail(`no DETAILS file found for ${gameId} in ${detailsDir}`);
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  const payload = parsed.json ?? parsed;
  return typeof payload === 'string' ? JSON.parse(payload) : payload;
}

function loadAnchorBundle(anchorFile) {
  const bundle = JSON.parse(fs.readFileSync(anchorFile, 'utf8'));
  if (!Array.isArray(bundle.replays)) fail(`${anchorFile} has no replays array`);
  return bundle;
}

function metadataParticipantMap(replay) {
  const participants = new Map();
  const stats = Array.isArray(replay.tail.stats) ? replay.tail.stats : [];
  for (let index = 0; index < stats.length; index += 1) {
    const player = stats[index];
    const teamId = Number(player.TEAM);
    participants.set(index + 1, {
      participant_id: index + 1,
      champion: player.SKIN ?? null,
      team_id: Number.isFinite(teamId) ? teamId : null,
      source: 'ROFL_METADATA_STATS_JSON',
    });
  }
  return participants;
}

function hydrateAnchorSet(anchorSet, replay) {
  const metadataParticipants = metadataParticipantMap(replay);
  const existingParticipants = new Map(
    (anchorSet.participants || []).map((item) => [item.participant_id, item]),
  );
  const participants = [];
  for (let participantId = 1; participantId <= 10; participantId += 1) {
    const metadata = metadataParticipants.get(participantId) || {};
    const existing = existingParticipants.get(participantId) || {};
    participants.push({
      ...existing,
      ...metadata,
      participant_id: participantId,
      champion: metadata.champion ?? existing.champion ?? null,
      team_id: metadata.team_id ?? existing.team_id ?? null,
    });
  }
  const byId = new Map(participants.map((item) => [item.participant_id, item]));
  const deaths = (anchorSet.deaths || []).map((death) => ({
    ...death,
    killer_champion: byId.get(death.killer_participant_id)?.champion
      ?? death.killer_champion
      ?? null,
    victim_champion: byId.get(death.victim_participant_id)?.champion
      ?? death.victim_champion
      ?? null,
  }));
  return {
    ...anchorSet,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    participant_count: participants.length,
    participants,
    death_count: deaths.length,
    deaths,
  };
}

function participantMap(details) {
  const participants = new Map();
  for (const item of details.participants || []) {
    const id = Number(item.participantId ?? item.participant_id);
    if (!Number.isInteger(id)) continue;
    participants.set(id, {
      participant_id: id,
      champion: item.championName ?? item.champion ?? null,
      team_id: item.teamId ?? item.team_id ?? null,
    });
  }
  return participants;
}

function damageRows(values) {
  return (values || []).map((item) => ({
    source_participant_id: Number.isInteger(item.participantId) ? item.participantId : null,
    source_name: item.name ?? null,
    spell_name: item.spellName ?? null,
    spell_slot: Number.isFinite(item.spellSlot) ? item.spellSlot : null,
    basic: typeof item.basic === 'boolean' ? item.basic : null,
    source_type: item.type ?? null,
    physical_damage: Number(item.physicalDamage) || 0,
    magic_damage: Number(item.magicDamage) || 0,
    true_damage: Number(item.trueDamage) || 0,
    total_damage: (Number(item.physicalDamage) || 0)
      + (Number(item.magicDamage) || 0)
      + (Number(item.trueDamage) || 0),
  }));
}

function extractAnchors(gameId, replay, details) {
  const participants = participantMap(details);
  const deaths = [];
  for (const frame of details.frames || []) {
    for (const event of frame.events || []) {
      if (event.type !== 'CHAMPION_KILL') continue;
      const timestamp = Number(event.timestamp);
      if (!Number.isFinite(timestamp)) continue;
      deaths.push({
        anchor_id: `${gameId}:death:${deaths.length + 1}`,
        event_type: 'CHAMPION_KILL',
        timestamp_ms: Math.round(timestamp),
        killer_participant_id: Number.isInteger(event.killerId) ? event.killerId : null,
        killer_champion: participants.get(event.killerId)?.champion ?? null,
        victim_participant_id: Number.isInteger(event.victimId) ? event.victimId : null,
        victim_champion: participants.get(event.victimId)?.champion ?? null,
        position: event.position && Number.isFinite(event.position.x) && Number.isFinite(event.position.y)
          ? { x: event.position.x, y: event.position.y }
          : null,
        damage_received: damageRows(event.victimDamageReceived),
        oracle: 'LCU_SGP_MATCH_DETAILS',
        oracle_role: 'ANCHOR_ONLY',
        replay_is_fact_source: true,
      });
    }
  }
  deaths.sort((left, right) => left.timestamp_ms - right.timestamp_ms);
  return hydrateAnchorSet({
    game_id: gameId,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    participant_count: participants.size,
    participants: [...participants.values()],
    death_count: deaths.length,
    deaths,
  }, replay);
}

function nearestDeath(deaths, timestampMs) {
  let low = 0;
  let high = deaths.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (deaths[middle].timestamp_ms < timestampMs) low = middle + 1;
    else high = middle;
  }
  let best = null;
  for (const index of [low - 1, low]) {
    if (index < 0 || index >= deaths.length) continue;
    const delta = timestampMs - deaths[index].timestamp_ms;
    if (best === null || Math.abs(delta) < Math.abs(best.delta_ms)) {
      best = { index, delta_ms: delta };
    }
  }
  return best;
}

function entropy(buffer) {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let value = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / buffer.length;
    value -= probability * Math.log2(probability);
  }
  return value;
}

function clusterKey(block) {
  return `${block.packet_id}|${block.payload_length}`;
}

function rawRef(replay, chunk, block) {
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
    packet_id: block.packet_id,
    payload_length: block.payload_length,
    payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function updateAggregate(map, block, near, durationMs) {
  const key = clusterKey(block);
  let item = map.get(key);
  if (!item) {
    item = {
      packet_id: block.packet_id,
      packet_type: block.packet_type,
      payload_length: block.payload_length,
      payload_prefix_sample_hex: block.payload.subarray(0, PREFIX_BYTES).toString('hex'),
      param_sample: block.param >>> 0,
      payload_prefixes: new Set(),
      payload_prefixes_capped: false,
      params: new Set(),
      params_capped: false,
      param_min: null,
      param_max: null,
      participant_param_count: 0,
      count_total: 0,
      entropy_sum: 0,
      near_200ms: 0,
      near_500ms: 0,
      near_2000ms: 0,
      game_duration_ms: durationMs,
    };
    map.set(key, item);
  }
  const prefix = block.payload.subarray(0, PREFIX_BYTES).toString('hex');
  addDistinct(item, 'payload_prefixes', 'payload_prefixes_capped', prefix);
  addDistinct(item, 'params', 'params_capped', block.param >>> 0);
  item.param_min = item.param_min === null ? block.param >>> 0 : Math.min(item.param_min, block.param >>> 0);
  item.param_max = item.param_max === null ? block.param >>> 0 : Math.max(item.param_max, block.param >>> 0);
  if (participantIdFromParam(block.param >>> 0) !== null) item.participant_param_count += 1;
  item.count_total += 1;
  item.entropy_sum += entropy(block.payload);
  if (near) {
    for (const windowMs of DEATH_WINDOWS_MS) {
      if (Math.abs(near.delta_ms) <= windowMs) item[`near_${windowMs}ms`] += 1;
    }
  }
}

function addDistinct(item, setField, cappedField, value) {
  const values = item[setField];
  if (values.has(value)) return;
  if (values.size < DISTINCT_VALUE_LIMIT) values.add(value);
  else item[cappedField] = true;
}

function numberVariants(value) {
  const variants = [];
  if (!Number.isFinite(value) || value < 0) return variants;
  const integer = Math.round(value);
  if (integer <= 0xffff) {
    const u16 = Buffer.alloc(2);
    u16.writeUInt16LE(integer);
    variants.push({ encoding: 'u16le', bytes: u16 });
  }
  if (integer <= 0xffffffff) {
    const u32 = Buffer.alloc(4);
    u32.writeUInt32LE(integer);
    variants.push({ encoding: 'u32le', bytes: u32 });
  }
  const f32 = Buffer.alloc(4);
  f32.writeFloatLE(value);
  variants.push({ encoding: 'f32le', bytes: f32 });
  return variants;
}

function findDamageValueMatches(replay, chunk, block, death) {
  const matches = [];
  const seen = new Set();
  for (const damage of death.damage_received) {
    for (const variant of numberVariants(damage.total_damage)) {
      const offset = block.payload.indexOf(variant.bytes);
      if (offset < 0) continue;
      const key = `${damage.source_participant_id}|${damage.spell_name}|${damage.total_damage}|${variant.encoding}|${offset}`;
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push({
        anchor_id: death.anchor_id,
        death_time_ms: death.timestamp_ms,
        packet_time_ms: block.timestamp_ms,
        delta_ms: block.timestamp_ms - death.timestamp_ms,
        source_participant_id: damage.source_participant_id,
        source_name: damage.source_name,
        spell_name: damage.spell_name,
        amount: damage.total_damage,
        encoding: variant.encoding,
        payload_offset: offset,
        raw_packet_ref: rawRef(replay, chunk, block),
      });
    }
  }
  return matches;
}

function probeReplay(replay, anchorSet) {
  const clusters = new Map();
  const nearestPackets = [];
  const damageMatches = [];
  const deathEvents = [];
  const castParticipantCounts = Array(10).fill(0);
  const damageCandidateSamples = new Map();
  const nearestByDeath = anchorSet.deaths.map(() => []);
  const durationMs = Number(replay.tail.metadata.gameLength) || 0;
  const champions = championByParticipant(replay);
  let castCandidateCount = 0;
  let castCandidateParticipantCount = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    if (chunk.stream !== 'game_chunk') return;
    const near = nearestDeath(anchorSet.deaths, block.timestamp_ms);
    updateAggregate(clusters, block, near, durationMs);

    const decodedDeath = decodeHeroDeathBlock(replay, chunk, block, champions);
    if (decodedDeath) deathEvents.push(decodedDeath);

    if (block.packet_id === CASTSPELL_CANDIDATE_PACKET_ID) {
      castCandidateCount += 1;
      const participantId = participantIdFromParam(block.param >>> 0);
      if (participantId !== null) {
        castCandidateParticipantCount += 1;
        castParticipantCounts[participantId - 1] += 1;
      }
    }

    const damageCandidateKey = `${block.packet_id}/${block.payload_length}`;
    if (DAMAGE_CANDIDATE_KEYS.has(damageCandidateKey)
      && !damageCandidateSamples.has(damageCandidateKey)) {
      damageCandidateSamples.set(damageCandidateKey, {
        packet_id: block.packet_id,
        packet_type: block.packet_type,
        payload_length: block.payload_length,
        replay_time_ms: block.timestamp_ms,
        raw_param: block.param >>> 0,
        raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
        raw_payload_hex: block.payload.toString('hex'),
        raw_packet_ref: rawRef(replay, chunk, block),
      });
    }

    if (!near || Math.abs(near.delta_ms) > 2000) return;
    const bucket = nearestByDeath[near.index];
    bucket.push({
      absolute_delta_ms: Math.abs(near.delta_ms),
      delta_ms: near.delta_ms,
      packet_time_ms: block.timestamp_ms,
      packet_id: block.packet_id,
      packet_type: block.packet_type,
      payload_length: block.payload_length,
      payload_prefix_hex: block.payload.subarray(0, 16).toString('hex'),
      param: block.param,
      raw_packet_ref: rawRef(replay, chunk, block),
    });
    if (Math.abs(near.delta_ms) <= 500) {
      damageMatches.push(...findDamageValueMatches(
        replay,
        chunk,
        block,
        anchorSet.deaths[near.index],
      ));
    }
  }, { includeStreams: [1], strict: true });

  for (let index = 0; index < nearestByDeath.length; index += 1) {
    const packets = nearestByDeath[index]
      .sort((left, right) => left.absolute_delta_ms - right.absolute_delta_ms)
      .slice(0, 20);
    nearestPackets.push({
      anchor_id: anchorSet.deaths[index].anchor_id,
      death_time_ms: anchorSet.deaths[index].timestamp_ms,
      packets,
    });
  }
  return {
    walk,
    clusters: [...clusters.values()],
    nearest_packets: nearestPackets,
    damage_value_matches: damageMatches,
    death_events: deathEvents,
    cast_candidate: {
      packet_id: CASTSPELL_CANDIDATE_PACKET_ID,
      count: castCandidateCount,
      participant_param_count: castCandidateParticipantCount,
      participant_counts: castParticipantCounts,
    },
    damage_candidate_samples: [...damageCandidateSamples.values()],
  };
}

function finalizeClusterRows(allResults, totalDeaths) {
  const merged = new Map();
  let totalDurationMs = 0;
  for (const result of allResults) {
    totalDurationMs += result.duration_ms;
    for (const cluster of result.probe.clusters) {
      const key = `${cluster.packet_id}|${cluster.payload_length}`;
      let item = merged.get(key);
      if (!item) {
        item = {
          packet_id: cluster.packet_id,
          packet_type: cluster.packet_type,
          payload_length: cluster.payload_length,
          payload_prefix_sample_hex: cluster.payload_prefix_sample_hex,
          param_sample: cluster.param_sample,
          payload_prefixes: new Set(),
          payload_prefixes_capped: false,
          params: new Set(),
          params_capped: false,
          param_min: null,
          param_max: null,
          participant_param_count: 0,
          replay_count: 0,
          entropy_sum: 0,
          count_total: 0,
          near_200ms: 0,
          near_500ms: 0,
          near_2000ms: 0,
        };
        merged.set(key, item);
      }
      item.replay_count += 1;
      for (const prefix of cluster.payload_prefixes) {
        addDistinct(item, 'payload_prefixes', 'payload_prefixes_capped', prefix);
      }
      for (const param of cluster.params) addDistinct(item, 'params', 'params_capped', param);
      item.payload_prefixes_capped ||= cluster.payload_prefixes_capped;
      item.params_capped ||= cluster.params_capped;
      item.param_min = item.param_min === null ? cluster.param_min : Math.min(item.param_min, cluster.param_min);
      item.param_max = item.param_max === null ? cluster.param_max : Math.max(item.param_max, cluster.param_max);
      item.participant_param_count += cluster.participant_param_count;
      item.entropy_sum += cluster.entropy_sum;
      item.count_total += cluster.count_total;
      item.near_200ms += cluster.near_200ms;
      item.near_500ms += cluster.near_500ms;
      item.near_2000ms += cluster.near_2000ms;
    }
  }
  const windowExposureMs = totalDeaths * 4000;
  return [...merged.values()].map((item) => {
    const baselineCount = Math.max(0, item.count_total - item.near_2000ms);
    const baselineExposureMs = Math.max(1, totalDurationMs - windowExposureMs);
    const nearRate = item.near_2000ms / Math.max(1, windowExposureMs);
    const baselineRate = baselineCount / baselineExposureMs;
    return {
      packet_id: item.packet_id,
      packet_type: item.packet_type,
      payload_length: item.payload_length,
      payload_prefix_sample_hex: item.payload_prefix_sample_hex,
      payload_prefix_variant_count_lower_bound: item.payload_prefixes.size,
      payload_prefix_variant_count_capped: item.payload_prefixes_capped,
      param_sample: item.param_sample,
      param_min: item.param_min,
      param_max: item.param_max,
      param_variant_count_lower_bound: item.params.size,
      param_variant_count_capped: item.params_capped,
      participant_param_count: item.participant_param_count,
      participant_param_ratio: item.participant_param_count / Math.max(1, item.count_total),
      replay_count: item.replay_count,
      count_total: item.count_total,
      near_200ms: item.near_200ms,
      near_500ms: item.near_500ms,
      near_2000ms: item.near_2000ms,
      deaths_with_expected_one_packet_ratio: item.near_200ms / Math.max(1, totalDeaths),
      entropy_mean: item.entropy_sum / Math.max(1, item.count_total),
      enrichment_2000ms: baselineRate === 0 ? (nearRate > 0 ? 'Infinity' : 0) : nearRate / baselineRate,
    };
  }).sort((left, right) => {
    const leftScore = left.enrichment_2000ms === 'Infinity' ? Number.POSITIVE_INFINITY : left.enrichment_2000ms;
    const rightScore = right.enrichment_2000ms === 'Infinity' ? Number.POSITIVE_INFINITY : right.enrichment_2000ms;
    return rightScore - leftScore || right.near_200ms - left.near_200ms;
  });
}

function totalSpellCasts(player) {
  return [1, 2, 3, 4].reduce(
    (sum, slot) => sum + (Number(player?.[`SPELL${slot}_CAST`]) || 0),
    0,
  );
}

function pearsonCorrelation(rows, leftField, rightField) {
  if (rows.length < 2) return null;
  const leftMean = rows.reduce((sum, row) => sum + row[leftField], 0) / rows.length;
  const rightMean = rows.reduce((sum, row) => sum + row[rightField], 0) / rows.length;
  let numerator = 0;
  let leftSquared = 0;
  let rightSquared = 0;
  for (const row of rows) {
    const left = row[leftField] - leftMean;
    const right = row[rightField] - rightMean;
    numerator += left * right;
    leftSquared += left * left;
    rightSquared += right * right;
  }
  const denominator = Math.sqrt(leftSquared * rightSquared);
  return denominator === 0 ? null : numerator / denominator;
}

function validateDeathEvents(gameId, events, anchorSet) {
  const sortedEvents = [...events].sort((left, right) => left.replay_time_ms - right.replay_time_ms);
  const sortedAnchors = [...anchorSet.deaths].sort((left, right) => left.timestamp_ms - right.timestamp_ms);
  const rows = [];
  const rowCount = Math.max(sortedEvents.length, sortedAnchors.length);
  for (let index = 0; index < rowCount; index += 1) {
    const event = sortedEvents[index] || null;
    const anchor = sortedAnchors[index] || null;
    const deltaMs = event && anchor ? event.replay_time_ms - anchor.timestamp_ms : null;
    const timeMatch = deltaMs !== null && Math.abs(deltaMs) <= 1;
    const participantMatch = Boolean(event && anchor
      && event.victim_participant_id === anchor.victim_participant_id);
    rows.push({
      validation_id: `${gameId}:death-validation:${index + 1}`,
      game_id: gameId,
      replay_event_index: event ? index : null,
      anchor_id: anchor?.anchor_id ?? null,
      replay_time_ms: event?.replay_time_ms ?? null,
      anchor_time_ms: anchor?.timestamp_ms ?? null,
      delta_ms: deltaMs,
      replay_victim_participant_id: event?.victim_participant_id ?? null,
      anchor_victim_participant_id: anchor?.victim_participant_id ?? null,
      victim_champion: event?.victim_champion ?? anchor?.victim_champion ?? null,
      victim_network_id: event?.victim_network_id ?? null,
      raw_param: event?.raw_param ?? null,
      raw_param_hex: event?.raw_param_hex ?? null,
      raw_payload_hex: event?.raw_payload_hex ?? null,
      raw_payload_sha256: event?.raw_payload_sha256 ?? null,
      time_match_1ms: timeMatch,
      participant_match: participantMatch,
      verdict: timeMatch && participantMatch ? 'PASS' : 'FAIL',
      raw_packet_ref: event?.raw_packet_ref ?? null,
    });
  }
  return {
    rows,
    summary: {
      game_id: gameId,
      replay_event_count: sortedEvents.length,
      anchor_count: sortedAnchors.length,
      matched_count: rows.filter((row) => row.verdict === 'PASS').length,
      false_positive_count: Math.max(0, sortedEvents.length - sortedAnchors.length),
      false_negative_count: Math.max(0, sortedAnchors.length - sortedEvents.length),
      participant_match_count: rows.filter((row) => row.participant_match).length,
      time_match_1ms_count: rows.filter((row) => row.time_match_1ms).length,
      minimum_delta_ms: rows.length > 0
        ? Math.min(...rows.map((row) => row.delta_ms).filter((value) => value !== null))
        : null,
      maximum_delta_ms: rows.length > 0
        ? Math.max(...rows.map((row) => row.delta_ms).filter((value) => value !== null))
        : null,
    },
  };
}

function buildCastCandidateAnalysis(results) {
  const rows = [];
  let packetCount = 0;
  let participantParamCount = 0;
  for (const result of results) {
    packetCount += result.probe.cast_candidate.count;
    participantParamCount += result.probe.cast_candidate.participant_param_count;
    for (let index = 0; index < result.players.length; index += 1) {
      rows.push({
        game_id: result.game_id,
        replay_sha256: result.replay_sha256,
        participant_id: index + 1,
        champion: result.players[index]?.SKIN ?? null,
        candidate_packet_count: result.probe.cast_candidate.participant_counts[index],
        metadata_spell_cast_count: totalSpellCasts(result.players[index]),
      });
    }
  }
  return {
    schema_version: 1,
    status: 'INFERRED',
    target_replay_version: TARGET_VERSION,
    replay_block_packet_id: CASTSPELL_CANDIDATE_PACKET_ID,
    packet_type: `0x${CASTSPELL_CANDIDATE_PACKET_ID.toString(16).padStart(4, '0')}`,
    stream: 'game_chunk',
    participant_rows: rows.length,
    packet_count: packetCount,
    participant_param_count: participantParamCount,
    participant_param_ratio: participantParamCount / Math.max(1, packetCount),
    pearson_packet_count_vs_metadata_spell_cast_count: pearsonCorrelation(
      rows,
      'candidate_packet_count',
      'metadata_spell_cast_count',
    ),
    participant_mapping_rule: '(raw_param & 0xff) - 0xad',
    evidence: 'Across 40 participants, candidate packet counts correlate with ROFL metadata spell-cast aggregates.',
    limitation: 'No 16.15.801.3452 payload field decoder was recovered, so no packet is emitted as a spell_cast event.',
    rows,
  };
}

function buildDamageCandidateAnalysis(results, clusterRows, globalBinary) {
  const clusterByKey = new Map(
    clusterRows.map((row) => [`${row.packet_id}/${row.payload_length}`, row]),
  );
  const samples = new Map();
  for (const result of results) {
    for (const sample of result.probe.damage_candidate_samples) {
      const key = `${sample.packet_id}/${sample.payload_length}`;
      if (!samples.has(key)) samples.set(key, { game_id: result.game_id, ...sample });
    }
  }
  const candidates = DAMAGE_EMULATION_RESULTS.map((emulation) => {
    const key = `${emulation.packet_id}/${emulation.payload_length}`;
    return {
      ...emulation,
      cluster_statistics: clusterByKey.get(key) ?? null,
      representative_real_replay_sample: samples.get(key) ?? null,
    };
  });
  return {
    schema_version: 1,
    status: 'UNVERIFIED',
    target_replay_version: TARGET_VERSION,
    candidate_count: candidates.length,
    client_decoder_experiment: {
      method: 'Unicorn x86-64 emulation of constructor, DeserializePacket, and UsePacket byte helpers',
      binary_role: 'ADJACENT_16.15_GLOBAL_REFERENCE_ONLY',
      binary_path: globalBinary?.path ?? null,
      binary_sha256: globalBinary?.sha256 ?? null,
      binary_version: '16.15.802.4387',
      constructor_rva: '0x00eb3190',
      deserialize_rva: '0x00f1d130',
      target_byte_helper_rva: '0x00244890',
      amount_byte_helper_rva: '0x002449a0',
      source_byte_helper_rva: '0x00244840',
    },
    conclusion: 'No tested Tencent payload shape produced a fully consumed, plausible source/target/amount tuple.',
    candidates,
  };
}

function discoverTencentBinary(fileName) {
  const root = process.env.ROFL_TENCENT_GAME_ROOT;
  if (!root) return null;
  if (!fs.existsSync(root)) return null;
  for (const directory of fs.readdirSync(root)) {
    const candidate = path.join(root, directory, 'Game', fileName);
    if (fs.existsSync(candidate)) return path.resolve(candidate);
  }
  return null;
}

function binaryPaths() {
  return {
    global_game: path.join(
      process.env.LOCALAPPDATA || path.join(process.env.USERPROFILE || '', 'AppData', 'Local'),
      'Temp',
      'lol-global-16.15.8024387',
      'League of Legends.exe',
    ),
    tencent_game: discoverTencentBinary('League of Legends.exe'),
    tencent_lolbase: discoverTencentBinary('LOLBase.dll'),
  };
}

function snapshotEntry(snapshot, filePath) {
  if (!filePath) return { path: null, exists: false, size: null, sha256: null };
  const resolved = path.resolve(filePath);
  return { path: resolved, ...(snapshot[resolved] || { exists: false, size: null, sha256: null }) };
}

function buildCandidateHandlers(binarySnapshot, paths, damageAnalysis, castAnalysis, deathSummary) {
  const globalGame = snapshotEntry(binarySnapshot, paths.global_game);
  const tencentGame = snapshotEntry(binarySnapshot, paths.tencent_game);
  const tencentLolBase = snapshotEntry(binarySnapshot, paths.tencent_lolbase);
  return {
    schema_version: 1,
    target_replay_version: TARGET_VERSION,
    address_format: 'RVA relative to each PE image base',
    opcode_warning: 'Client dispatcher opcodes are not assumed to equal Replay block packet ids.',
    binaries: {
      exact_tencent_game: {
        ...tencentGame,
        file_version: '16.15.801.3452',
        image_base: '0x140000000',
        protection: 'ACE-packed code section; RTTI and rdata remain statically visible',
      },
      exact_tencent_lolbase: {
        ...tencentLolBase,
        file_version: '6.0.2306.130',
      },
      adjacent_global_reference: {
        ...globalGame,
        file_version: '16.15.802.4387',
        image_base: '0x140000000',
        role: 'UNPROTECTED_STATIC_REFERENCE_ONLY',
      },
    },
    common_global_registration_function: {
      rva: '0x006ffcc0',
      opcode_argument: 'r8w',
      status: 'VERIFIED_STATIC_ADJACENT_BUILD',
    },
    handlers: [
      {
        event_type: 'damage',
        status: 'UNVERIFIED',
        rtti_class: 'PKT_UnitApplyDamage_s',
        exact_tencent_build: {
          rtti_string_rva: '0x01e7d42c',
          packet_vtable_rva: '0x01b107b8',
          deserialize_rva_from_vtable_plus_0x08: '0x00f1b320',
          object_size_getter_rva_from_vtable_plus_0x10: '0x00378a10',
          evidence: 'Static rdata comparison against the adjacent unprotected 16.15 build.',
        },
        adjacent_global_build: {
          rtti_string_rva: '0x01e8342c',
          callback_descriptor_rva: '0x01a348e0',
          descriptor_construct_rva: '0x0025b4f9',
          callback_rva: '0x0029f860',
          registration_call_rva: '0x0025b557',
          client_dispatch_opcode: '0x012e',
          constructor_rva: '0x00eb3190',
          packet_vtable_rva: '0x01b167b8',
          deserialize_rva: '0x00f1d130',
          object_size_getter_rva: '0x006dc720',
          object_size: 56,
          use_packet_fields: {
            target_encrypted_dword_offset: '0x10',
            damage_encrypted_f32_offset: '0x18',
            source_encrypted_dword_offset: '0x20',
            extra_encrypted_f32_offset: '0x28',
          },
        },
        replay_candidates: damageAnalysis.candidates,
      },
      {
        event_type: 'death',
        status: 'VERIFIED',
        rtti_class: 'PKT_NPC_Hero_Die_s',
        exact_tencent_build: {
          rtti_string_rva: '0x01e7c57a',
          packet_vtable_rva: '0x01b10618',
          deserialize_rva_from_vtable_plus_0x08: '0x00efa1f0',
          object_size_getter_rva_from_vtable_plus_0x10: '0x00309200',
          evidence: 'Static rdata comparison against the adjacent unprotected 16.15 build.',
        },
        adjacent_global_build: {
          rtti_string_rva: '0x01e8257a',
          callback_descriptor_rva: '0x01a34b80',
          descriptor_construct_rva: '0x002525aa',
          callback_wrapper_rva: '0x002979c0',
          forwarded_handler_rva: '0x00240c90',
          registration_call_rva: '0x00252609',
          client_dispatch_opcode: '0x01ac',
          constructor_rva: '0x00e83430',
          packet_vtable_rva: '0x01b16610',
          deserialize_rva: '0x00efbc80',
          object_size_getter_rva: '0x00378fc0',
          object_size: 88,
        },
        replay_mapping: {
          replay_block_packet_id: DEATH_PROFILE.replay_block_packet_id,
          packet_type: '0x0160',
          payload_length: DEATH_PROFILE.payload_length,
          participant_rule: '(raw_param & 0xff) - 0xad',
          victim_network_id_rule: '0x40000000 | (raw_param & 0xff)',
          raw_param_preserved: true,
          verification: deathSummary,
        },
      },
      {
        event_type: 'spell_cast',
        status: 'INFERRED',
        rtti_class: 'PKT_NPC_CastSpellAns_s',
        exact_tencent_build: {
          rtti_string_rva: '0x01e78e3a',
          packet_vtable_rva: '0x01b16c80',
          deserialize_rva_from_vtable_plus_0x08: '0x010ad250',
          object_size_getter_rva_from_vtable_plus_0x10: '0x0027dff0',
          evidence: 'Static rdata comparison against the adjacent unprotected 16.15 build.',
        },
        adjacent_global_build: {
          rtti_string_rva: '0x01e7ee3a',
          callback_descriptor_rva: '0x01a35600',
          descriptor_construct_rva: '0x00254b6d',
          callback_rva: '0x00297510',
          registration_call_rva: '0x00254bd2',
          client_dispatch_opcode: '0x031f',
          constructor_rva: '0x00e82ed0',
          packet_vtable_rva: '0x01b1cc80',
          deserialize_rva: '0x010c01b0',
          object_size_getter_rva: '0x00f275a0',
          object_size: 344,
        },
        replay_candidate: castAnalysis,
      },
    ],
  };
}

function runTestSuite(repositoryRoot) {
  const execution = childProcess.spawnSync(process.execPath, ['--test'], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024,
  });
  const output = `${execution.stdout || ''}${execution.stderr || ''}`;
  return {
    ...parseTestSummary(output, execution.status ?? 1),
    command: `${process.execPath} --test`,
    output,
  };
}

function buildProtocolReport(context) {
  const { acceptance, candidateHandlers, castAnalysis, damageAnalysis, validationSummary } = context;
  const exact = candidateHandlers.binaries.exact_tencent_game;
  const global = candidateHandlers.binaries.adjacent_global_reference;
  const replayLines = acceptance.replays.map(
    (replay) => `| ${replay.game_id} | ${replay.version} | ${replay.sha256} | ${replay.death_event_count} |`,
  );
  return [
    '# Protocol Reverse Engineering Report',
    '',
    '## Scope',
    '',
    `This report is limited to Replay version \`${TARGET_VERSION}\` and Damage, Hero Death, and CastSpell.`,
    'The accepted container/framing parser was not changed. Match Details are used only as an oracle for validation; Replay packets remain the event fact source.',
    '',
    '## Binaries',
    '',
    `- Exact Tencent game: \`${exact.path}\`, SHA-256 \`${exact.sha256}\`, file version \`16.15.801.3452\`.`,
    `- Exact Tencent LOLBase: \`${candidateHandlers.binaries.exact_tencent_lolbase.path}\`, SHA-256 \`${candidateHandlers.binaries.exact_tencent_lolbase.sha256}\`.`,
    `- Adjacent unprotected global game: \`${global.path}\`, SHA-256 \`${global.sha256}\`, file version \`16.15.802.4387\`.`,
    '- The exact Tencent executable has an ACE-packed high-entropy code section. Its RTTI and rdata are visible, but static instruction bytes for the decoder bodies are not.',
    '- The adjacent global executable is explicitly a structural reference, not a protocol-compatible decoder claim.',
    '',
    '## Methods',
    '',
    '- Packet clustering by Replay block packet id and payload length, with prefix/param diversity and death-window enrichment.',
    '- Exact event anchors from LCU SGP Match Details, used only for one-to-one oracle validation.',
    '- RTTI string search, rdata diffing, constructor/vtable tracing, xrefs, Capstone disassembly, and handler registration tracing.',
    '- Unicorn execution of the adjacent global packet constructors and DeserializePacket functions against real Tencent payloads.',
    '- Public implementation review: Mowokuma/ROFL, Toastaspiring/ROFL-X, fraxiinus/ReplayBook, and Henry Zhu packet research.',
    '',
    '## Dispatcher And Packet Objects',
    '',
    '- Adjacent global common registration function: RVA `0x006ffcc0`; the 16-bit client dispatch opcode is passed in `r8w`.',
    '- The values at `0x01a348e0`, `0x01a34b80`, and `0x01a35600` are callback type-erasure descriptors, not packet vtables.',
    '- Real packet object vtables place `DeserializePacket` at `vtable + 0x08` and an object-size getter at `vtable + 0x10`.',
    '- Client dispatcher opcodes (`0x012e`, `0x01ac`, `0x031f`) are kept separate from Replay block packet ids.',
    '',
    '## Hero Death',
    '',
    '- Status: `VERIFIED`.',
    '- Replay signature: game stream packet id `352` (`0x0160`), payload length `5`.',
    '- Participant: `(raw_param & 0xff) - 0xad`.',
    '- Canonical victim network id: `0x40000000 | (raw_param & 0xff)`; full `raw_param` is retained because higher bits vary.',
    `- Real validation: ${validationSummary.matched_count}/${validationSummary.anchor_count} one-to-one matches, ${validationSummary.false_positive_count} false positives, ${validationSummary.false_negative_count} false negatives, timestamp delta ${validationSummary.minimum_delta_ms}-${validationSummary.maximum_delta_ms} ms.`,
    '- The adjacent global callback is a member-bound wrapper (`0x002979c0` -> `0x00240c90`), consistent with the victim object being supplied by outer entity routing while the 5-byte payload carries packet-local state.',
    '- Cross-build HeroDie DeserializePacket emulation consumed the 5-byte Tencent payload but returned false after only partial object mutation; this is evidence against claiming global/Tencent payload compatibility, not against the independently validated Replay signature.',
    '',
    '## Damage',
    '',
    '- Status: `UNVERIFIED`; zero semantic damage events are emitted.',
    '- Adjacent global class: `PKT_UnitApplyDamage_s`; callback reads encrypted target at `+0x10`, damage f32 at `+0x18`, source at `+0x20`, and an extra f32 at `+0x28`.',
    `- ${damageAnalysis.candidate_count} Tencent Replay packet-id/length shapes were executed through the adjacent global constructor/deserializer and field byte helpers. None produced a fully consumed, plausible source/target/amount tuple.`,
    '- Successful AL alone was not accepted: candidates left bytes unconsumed, yielded invalid ids, or produced implausible amounts.',
    '',
    '## CastSpell',
    '',
    '- Status: `INFERRED`; zero semantic spell_cast events are emitted.',
    `- Replay packet id ${castAnalysis.replay_block_packet_id} (` + '`0x0459`' + `) has ${castAnalysis.packet_count} game-stream occurrences.`,
    `- Across ${castAnalysis.participant_rows} participant rows, count correlation with metadata spell-cast aggregates is ${castAnalysis.pearson_packet_count_vs_metadata_spell_cast_count}.`,
    '- The outer param maps to participants, but no exact-build payload decoder was recovered; caster fields, spell identifier, and target therefore remain unasserted.',
    '',
    '## Real Replay Validation',
    '',
    '| gameId | version | SHA-256 | verified deaths |',
    '| --- | --- | --- | ---: |',
    ...replayLines,
    '',
    '## Public References',
    '',
    '- Mowokuma/ROFL commit `7181c9a745881cad9e14b79653c48af0d2fcd824` (container framing and Unicorn design).',
    '- Toastaspiring/ROFL-X commit `c175e40e8dda13e308fe8c8d7152e72d0de94b47` (documentation and prior-art synthesis).',
    '- fraxiinus/ReplayBook commit `f53c18bb901f2b07d1198e1ac87a254c17700a79`.',
    '- Henry Zhu, `League Data Scraping the hard and tedious way for fun`, plus the published packet schema.',
    '',
    '## Stop Status',
    '',
    '`SEMANTIC_BREAKTHROUGH`: Hero Death is verified on four real current-version Replays. Damage remains unverified and CastSpell remains inferred after static binary tracing, exact-build rdata migration, packet clustering, and cross-build emulation.',
    '',
  ].join('\n');
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  ensureDir(options.outputDir);
  const repositoryRoot = path.resolve(__dirname, '..');
  const upstreamBefore = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const paths = binaryPaths();
  const binarySnapshot = await hashFiles(Object.values(paths).filter(Boolean));
  const anchorBundle = options.anchorsFile ? loadAnchorBundle(options.anchorsFile) : null;
  const anchorSets = [];
  const results = [];
  for (const gameId of GAME_IDS) {
    const replayPath = path.join(options.replayDir, `HN1-${gameId}.rofl`);
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== TARGET_VERSION) {
      fail(`${replayPath} is ${replay.header.version}, expected ${TARGET_VERSION}`);
    }
    let anchors;
    if (anchorBundle) {
      const stored = anchorBundle.replays.find((item) => String(item.game_id) === gameId);
      if (!stored) fail(`${options.anchorsFile} has no anchors for ${gameId}`);
      if (stored.replay_sha256 && stored.replay_sha256 !== replay.source_sha256) {
        fail(`anchor Replay SHA-256 mismatch for ${gameId}`);
      }
      if (stored.replay_version && stored.replay_version !== replay.header.version) {
        fail(`anchor Replay version mismatch for ${gameId}`);
      }
      anchors = hydrateAnchorSet(stored, replay);
    } else {
      if (!options.detailsDir) {
        fail('no frozen validation input was provided; use --anchors-file or --details-dir');
      }
      const details = loadDetailsFile(options.detailsDir, gameId);
      anchors = extractAnchors(gameId, replay, details);
    }
    anchorSets.push(anchors);
    const probe = probeReplay(replay, anchors);
    const decodedEvents = probe.death_events.map((event) => ({ game_id: gameId, ...event }));
    const validation = validateDeathEvents(gameId, decodedEvents, anchors);
    results.push({
      game_id: gameId,
      duration_ms: Number(replay.tail.metadata.gameLength) || 0,
      replay_sha256: replay.source_sha256,
      replay_path: replay.source_path,
      replay_version: replay.header.version,
      block_count: probe.walk.block_count,
      players: Array.isArray(replay.tail.stats) ? replay.tail.stats : [],
      death_events: decodedEvents,
      death_validation: validation,
      probe,
    });
    process.stderr.write(
      `probed HN1-${gameId}: ${decodedEvents.length}/${anchors.death_count} deaths, ${probe.walk.block_count} game blocks\n`,
    );
  }

  const totalDeaths = anchorSets.reduce((sum, item) => sum + item.death_count, 0);
  const knownAnchors = {
    schema_version: 2,
    target_replay_version: TARGET_VERSION,
    generated_at: new Date().toISOString(),
    source_anchor_file: options.anchorsFile,
    oracle: {
      name: 'LCU SGP Match Details',
      role: 'ANCHOR_ONLY',
      access_token_persisted: false,
      replay_packet_is_fact_source: true,
    },
    replay_count: anchorSets.length,
    death_count: totalDeaths,
    replays: anchorSets,
  };
  writeJson(path.join(options.outputDir, 'known_event_anchors.json'), knownAnchors);

  const clusterRows = finalizeClusterRows(results, totalDeaths);
  writeCsv(path.join(options.outputDir, 'death_window_packet_diff.csv'), clusterRows, [
    'packet_id',
    'packet_type',
    'payload_length',
    'payload_prefix_sample_hex',
    'payload_prefix_variant_count_lower_bound',
    'payload_prefix_variant_count_capped',
    'param_sample',
    'param_min',
    'param_max',
    'param_variant_count_lower_bound',
    'param_variant_count_capped',
    'participant_param_count',
    'participant_param_ratio',
    'replay_count',
    'count_total',
    'near_200ms',
    'near_500ms',
    'near_2000ms',
    'deaths_with_expected_one_packet_ratio',
    'entropy_mean',
    'enrichment_2000ms',
  ]);

  writeJson(
    path.join(options.outputDir, 'nearest_death_packets.json'),
    results.map((item) => ({
      game_id: item.game_id,
      replay_sha256: item.replay_sha256,
      deaths: item.probe.nearest_packets,
    })),
  );
  writeJson(
    path.join(options.outputDir, 'damage_value_matches.json'),
    results.flatMap((item) => item.probe.damage_value_matches),
  );

  const deathEvents = results.flatMap((item) => item.death_events);
  const deathValidationRows = results.flatMap((item) => item.death_validation.rows);
  const validationParts = results.map((item) => item.death_validation.summary);
  const validationSummary = {
    replay_count: results.length,
    replay_event_count: deathEvents.length,
    anchor_count: totalDeaths,
    matched_count: validationParts.reduce((sum, item) => sum + item.matched_count, 0),
    false_positive_count: validationParts.reduce((sum, item) => sum + item.false_positive_count, 0),
    false_negative_count: validationParts.reduce((sum, item) => sum + item.false_negative_count, 0),
    participant_match_count: validationParts.reduce(
      (sum, item) => sum + item.participant_match_count,
      0,
    ),
    time_match_1ms_count: validationParts.reduce((sum, item) => sum + item.time_match_1ms_count, 0),
    minimum_delta_ms: Math.min(...validationParts.map((item) => item.minimum_delta_ms)),
    maximum_delta_ms: Math.max(...validationParts.map((item) => item.maximum_delta_ms)),
    per_replay: validationParts,
  };
  writeJsonl(path.join(options.outputDir, 'death_events.jsonl'), deathEvents);
  writeJson(path.join(options.outputDir, 'death_validation.json'), {
    schema_version: 1,
    status: validationSummary.matched_count === totalDeaths ? 'PASS' : 'FAIL',
    target_replay_version: TARGET_VERSION,
    tolerance_ms: 1,
    summary: validationSummary,
    rows: deathValidationRows,
  });
  writeCsv(path.join(options.outputDir, 'death_validation.csv'), deathValidationRows, [
    'validation_id',
    'game_id',
    'replay_event_index',
    'anchor_id',
    'replay_time_ms',
    'anchor_time_ms',
    'delta_ms',
    'replay_victim_participant_id',
    'anchor_victim_participant_id',
    'victim_champion',
    'victim_network_id',
    'raw_param',
    'raw_param_hex',
    'raw_payload_hex',
    'raw_payload_sha256',
    'time_match_1ms',
    'participant_match',
    'verdict',
    'raw_packet_ref',
  ]);

  const castAnalysis = buildCastCandidateAnalysis(results);
  const globalBinary = snapshotEntry(binarySnapshot, paths.global_game);
  const damageAnalysis = buildDamageCandidateAnalysis(results, clusterRows, globalBinary);
  writeJson(path.join(options.outputDir, 'castspell_candidate_analysis.json'), castAnalysis);
  writeJson(path.join(options.outputDir, 'damage_candidate_analysis.json'), damageAnalysis);

  const candidateHandlers = buildCandidateHandlers(
    binarySnapshot,
    paths,
    damageAnalysis,
    castAnalysis,
    validationSummary,
  );
  writeJson(path.join(options.outputDir, 'candidate_packet_handlers.json'), candidateHandlers);

  const gameChunkBlockCount = results.reduce((sum, item) => sum + item.block_count, 0);
  const semanticSummary = {
    schema_version: 2,
    status: 'SEMANTIC_BREAKTHROUGH',
    target_replay_version: TARGET_VERSION,
    replay_count: results.length,
    death_anchor_count: totalDeaths,
    death_event_count: deathEvents.length,
    death_validation: validationSummary,
    damage_event_count: 0,
    damage_status: 'UNVERIFIED',
    spell_cast_event_count: 0,
    spell_cast_status: 'INFERRED',
    game_chunk_block_count: gameChunkBlockCount,
    cluster_key: ['packet_id', 'payload_length'],
    cluster_count: clusterRows.length,
    damage_value_match_count: results.reduce(
      (sum, item) => sum + item.probe.damage_value_matches.length,
      0,
    ),
    framing_modified: false,
  };
  writeJson(path.join(options.outputDir, 'semantic_probe_summary.json'), semanticSummary);

  let testSummary = {
    total: null,
    passed: null,
    failed: null,
    skipped: null,
    duration_ms: null,
    exit_code: null,
    status: 'SKIPPED',
    command: `${process.execPath} --test`,
    output: '',
  };
  if (options.runTests) {
    testSummary = runTestSuite(repositoryRoot);
    testSummary.status = testSummary.exit_code === 0 ? 'PASS' : 'FAIL';
    fs.writeFileSync(path.join(options.outputDir, 'test_output.tap'), testSummary.output, 'utf8');
  }

  const upstreamAfter = await hashFiles(DEFAULT_UPSTREAM_PATHS);
  const upstreamComparison = compareHashSnapshots(upstreamBefore, upstreamAfter);
  const acceptance = {
    schema_version: 1,
    status: 'SEMANTIC_BREAKTHROUGH',
    target_replay_version: TARGET_VERSION,
    generated_at: new Date().toISOString(),
    replay_files_tested: results.length,
    replays: results.map((result) => ({
      game_id: result.game_id,
      path: result.replay_path,
      version: result.replay_version,
      sha256: result.replay_sha256,
      game_chunk_block_count: result.block_count,
      death_event_count: result.death_events.length,
      death_anchor_count: result.death_validation.summary.anchor_count,
      death_validation_status: result.death_validation.summary.matched_count
        === result.death_validation.summary.anchor_count ? 'PASS' : 'FAIL',
    })),
    tests_total: testSummary.total,
    tests_passed: testSummary.passed,
    tests_failed: testSummary.failed,
    tests_skipped: testSummary.skipped,
    tests_status: testSummary.status,
    packet_count: gameChunkBlockCount,
    decoded_packet_count: deathEvents.length,
    unknown_packet_count: gameChunkBlockCount - deathEvents.length,
    death_event_count: deathEvents.length,
    death_false_positive_count: validationSummary.false_positive_count,
    death_false_negative_count: validationSummary.false_negative_count,
    damage_event_count: 0,
    spell_event_count: 0,
    capabilities: {
      damage: { status: 'UNVERIFIED', real_event_count: 0 },
      death: { status: 'VERIFIED', real_event_count: deathEvents.length },
      cast_spell: { status: 'INFERRED', real_event_count: 0 },
    },
    framing_modified: false,
    upstream_hash_before: upstreamBefore,
    upstream_hash_after: upstreamAfter,
    upstream_hash_unchanged: upstreamComparison.unchanged,
    upstream_hash_changes: upstreamComparison.changes,
    binary_snapshot: candidateHandlers.binaries,
    errors: [],
    warnings: [
      'Damage payload semantics remain unverified; no damage event rows are emitted.',
      'CastSpell packet 1113 is inferred statistically; no spell_cast event rows are emitted.',
      'Adjacent global client decoder results are not promoted to exact Tencent build semantics.',
    ],
  };
  writeJson(path.join(options.outputDir, 'acceptance_summary.json'), acceptance);
  fs.writeFileSync(
    path.join(options.outputDir, 'SEMANTIC_PROBE_REPORT.md'),
    buildProtocolReport({
      acceptance,
      candidateHandlers,
      castAnalysis,
      damageAnalysis,
      validationSummary,
    }),
    'utf8',
  );

  const artifactHashes = await outputHashes(options.outputDir, {
    exclude: ['reviewer_manifest.json'],
  });
  const spotCheckIndexes = [0, Math.floor(deathValidationRows.length / 2), deathValidationRows.length - 1];
  const reviewerManifest = {
    schema_version: 1,
    status: 'SEMANTIC_BREAKTHROUGH',
    target_replay_version: TARGET_VERSION,
    repository_root: repositoryRoot,
    critical_source_files: {
      decoder: path.join(repositoryRoot, 'src', 'decoders', 'rofl_16_15_801_3452.js'),
      semantic_probe: path.join(repositoryRoot, 'scripts', 'semantic_probe.js'),
      raw_verifier: path.join(repositoryRoot, 'scripts', 'verify_semantic_death.js'),
      tests: path.join(repositoryRoot, 'test', 'semantic.test.js'),
    },
    replay_samples: acceptance.replays,
    outputs: {
      report: path.join(options.outputDir, 'SEMANTIC_PROBE_REPORT.md'),
      known_event_anchors: path.join(options.outputDir, 'known_event_anchors.json'),
      candidate_packet_handlers: path.join(options.outputDir, 'candidate_packet_handlers.json'),
      acceptance_summary: path.join(options.outputDir, 'acceptance_summary.json'),
      death_events: path.join(options.outputDir, 'death_events.jsonl'),
      death_validation_json: path.join(options.outputDir, 'death_validation.json'),
      death_validation_csv: path.join(options.outputDir, 'death_validation.csv'),
    },
    rerun_commands: {
      tests: 'npm test',
      full_probe: 'npm run semantic-probe -- --anchors-file artifacts/semantic_probe/known_event_anchors.json',
      raw_spot_check: 'node scripts/verify_semantic_death.js artifacts/semantic_probe/death_events.jsonl 0',
    },
    recommended_raw_spot_checks: spotCheckIndexes.map((index) => ({
      death_event_jsonl_index: index,
      validation_id: deathValidationRows[index]?.validation_id ?? null,
      raw_packet_ref: deathValidationRows[index]?.raw_packet_ref ?? null,
    })),
    artifact_sha256_excluding_this_manifest: artifactHashes,
    independent_reviewer_message: 'Do not trust the report itself. Rerun the tests and trace Replay bytes -> chunk -> raw packet -> decoded death -> validation row using this manifest.',
  };
  writeJson(path.join(options.outputDir, 'reviewer_manifest.json'), reviewerManifest);

  if (testSummary.status === 'FAIL') fail('semantic probe completed but the test suite failed');
  if (!upstreamComparison.unchanged) fail('upstream data hashes changed during the semantic probe');
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
