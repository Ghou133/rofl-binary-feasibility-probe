'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { resolveBuildProfile } = require('./build_registry');
const { registeredDecoders } = require('./packet_coverage_inventory');
const { formatOpcode, parseReplayFile, walkBlocks } = require('./rofl');

const COMBAT_CANDIDATE_SCHEMA_VERSION = 'COMBAT_STATE_CANDIDATE_REPORT_V1';
const ANALYZER_VERSION = 'combat-state-candidate-probe-v1';
const TARGET_BUILD = '16.15.801.3452';
const CHAMPION_NETWORK_ID_MIN = 0x400000ae;
const CHAMPION_NETWORK_ID_MAX = 0x400000b7;

const RUNTIME_NAME_CANDIDATES = Object.freeze([
  'PKT_CombatStateChanged_s',
  'PKT_NPC_BuffUpdateStatAdjustments_s',
  'PKT_S2C_HeroStats_s',
  'PKT_S2C_StatFormulaOutputs_s',
  'PKT_SetAbilityResourceState_s',
]);

const STRUCTURAL_SHORTLIST_16_15 = Object.freeze([
  Object.freeze({
    packet_id: 0x03da,
    priority: 'P0',
    hypothesis: 'HERO_BOUND_MIXED_STREAM_STATE_FAMILY_CANDIDATE',
    rationale: 'Champion-bound observations occur in keyframes and sparse live game chunks; this is structural evidence only.',
  }),
  Object.freeze({
    packet_id: 0x0439,
    priority: 'P0',
    hypothesis: 'HERO_BOUND_WIDE_KEYFRAME_SNAPSHOT_CANDIDATE',
    rationale: 'A recurring wide payload is observed per champion in keyframes; no field has been identified.',
  }),
  Object.freeze({
    packet_id: 0x003d,
    priority: 'P0',
    hypothesis: 'HERO_BOUND_LARGE_KEYFRAME_SNAPSHOT_CANDIDATE',
    rationale: 'A large recurring champion-bound keyframe payload is a strong state-snapshot shape, not proof of HP or stats.',
  }),
  Object.freeze({
    packet_id: 0x0298,
    priority: 'P0',
    hypothesis: 'HERO_BOUND_DENSE_KEYFRAME_COMPONENT_CANDIDATE',
    rationale: 'High-volume champion-bound keyframe components may belong to replicated state; payload semantics are unknown.',
  }),
  Object.freeze({
    packet_id: 0x00e7,
    priority: 'P0',
    hypothesis: 'GENERIC_ENTITY_HIGH_FREQUENCY_LIVE_FAMILY_CANDIDATE',
    rationale: 'High-frequency live entity-linked observations include champion IDs, but the two-byte payload is not decoded.',
  }),
]);

const COMBAT_ANCHOR_CAPABILITIES = Object.freeze([
  'hero_damage',
  'hero_death',
  'level_transition',
  'buff_add',
  'buff_remove',
  'buff_update_count',
  'protection',
  'shield_damage',
]);

function strictCompare(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function roundRatio(numerator, denominator) {
  return denominator === 0 ? 0 : Number((numerator / denominator).toFixed(6));
}

function increment(map, key, amount = 1) {
  map.set(key, (map.get(key) ?? 0) + amount);
}

function isChampionNetworkId(value) {
  return Number.isInteger(value)
    && value >= CHAMPION_NETWORK_ID_MIN
    && value <= CHAMPION_NETWORK_ID_MAX;
}

function newRouteAccumulator(build, packetId) {
  return {
    build,
    packet_id: packetId,
    count: 0,
    stream_counts: new Map(),
    payload_lengths: new Map(),
    raw_params: new Set(),
    champion_params: new Set(),
    other_nonzero_params: new Set(),
    zero_param_count: 0,
    champion_param_count: 0,
    other_nonzero_param_count: 0,
    champion_counts: new Map(),
    replay_keys: new Set(),
    replay_counts: new Map(),
    keyframe_chunks: new Set(),
    first_time_ms: null,
    last_time_ms: null,
    samples: new Map(),
  };
}

function observePacket(accumulator, record) {
  accumulator.count += 1;
  const stream = record.chunk_stream ?? record.stream ?? 'unknown';
  increment(accumulator.stream_counts, stream);
  const payloadLength = Number(record.payload_length);
  if (Number.isSafeInteger(payloadLength) && payloadLength >= 0) {
    increment(accumulator.payload_lengths, payloadLength);
  }
  const rawParam = Number(record.raw_param);
  if (Number.isSafeInteger(rawParam) && rawParam >= 0) {
    accumulator.raw_params.add(rawParam);
    if (rawParam === 0) accumulator.zero_param_count += 1;
    else if (isChampionNetworkId(rawParam)) {
      accumulator.champion_param_count += 1;
      accumulator.champion_params.add(rawParam);
      increment(accumulator.champion_counts, rawParam);
    } else {
      accumulator.other_nonzero_param_count += 1;
      accumulator.other_nonzero_params.add(rawParam);
    }
  }
  const replayKey = record.replay_key ?? record.replay_sha256 ?? record.source_path ?? 'unknown-replay';
  accumulator.replay_keys.add(replayKey);
  increment(accumulator.replay_counts, replayKey);
  if (stream === 'keyframe' || stream === 'start_keyframe') {
    const keyframeKey = record.keyframe_key ?? `${replayKey}:${record.chunk_index ?? 'unknown'}`;
    accumulator.keyframe_chunks.add(keyframeKey);
  }
  const time = Number(record.replay_time_ms);
  if (Number.isFinite(time)) {
    accumulator.first_time_ms = accumulator.first_time_ms === null
      ? Math.round(time) : Math.min(accumulator.first_time_ms, Math.round(time));
    accumulator.last_time_ms = accumulator.last_time_ms === null
      ? Math.round(time) : Math.max(accumulator.last_time_ms, Math.round(time));
  }
  if (!accumulator.samples.has(stream)) {
    const payload = Buffer.isBuffer(record.payload)
      ? record.payload
      : typeof record.raw_payload_hex === 'string'
        ? Buffer.from(record.raw_payload_hex, 'hex')
        : null;
    accumulator.samples.set(stream, {
      replay_key: replayKey,
      replay_time_ms: Number.isFinite(time) ? Math.round(time) : null,
      raw_param: Number.isSafeInteger(rawParam) && rawParam >= 0 ? rawParam : null,
      payload_length: Number.isSafeInteger(payloadLength) && payloadLength >= 0 ? payloadLength : null,
      payload_prefix_hex: payload ? payload.subarray(0, 32).toString('hex') : null,
      payload_sha256: payload ? crypto.createHash('sha256').update(payload).digest('hex') : null,
    });
  }
  return accumulator;
}

function classifyRouteCandidate(row) {
  if (row.currently_decoded_as_status !== 'UNREGISTERED_EXACT_BUILD_RAW_ONLY') return null;
  const championOnly = row.param_evidence.champion_range_observations === row.count
    && row.param_evidence.distinct_champion_network_ids > 0;
  const allChampionsObserved = row.param_evidence.distinct_champion_network_ids === 10;
  const keyframeCount = (row.stream_counts.keyframe ?? 0) + (row.stream_counts.start_keyframe ?? 0);
  const gameCount = row.stream_counts.game_chunk ?? 0;
  const keyframeRatio = roundRatio(keyframeCount, row.count);
  const gameRatio = roundRatio(gameCount, row.count);
  if (championOnly && allChampionsObserved && keyframeCount > 0 && gameCount > 0) {
    return 'HERO_BOUND_MIXED_STREAM_STATE_FAMILY_CANDIDATE';
  }
  if (championOnly && allChampionsObserved && keyframeRatio >= 0.95) {
    return 'HERO_BOUND_KEYFRAME_SNAPSHOT_CANDIDATE';
  }
  if (championOnly && allChampionsObserved && gameRatio >= 0.8) {
    return 'HERO_BOUND_LIVE_DELTA_CANDIDATE';
  }
  if (row.param_evidence.champion_range_observations > 0
      && gameRatio >= 0.8
      && row.count >= 10000) {
    return 'GENERIC_ENTITY_HIGH_FREQUENCY_LIVE_FAMILY_CANDIDATE';
  }
  if (row.param_evidence.champion_range_observations > 0 && keyframeRatio >= 0.8) {
    return 'MIXED_ENTITY_KEYFRAME_FAMILY_CANDIDATE';
  }
  return null;
}

function candidateScore(row) {
  if (!row.structural_candidate_class) return 0;
  const keyframeCount = (row.stream_counts.keyframe ?? 0) + (row.stream_counts.start_keyframe ?? 0);
  const gameCount = row.stream_counts.game_chunk ?? 0;
  const championOnly = row.param_evidence.champion_range_observations === row.count;
  const maxPayloadLength = row.payload_size_distribution.at(-1)?.payload_length ?? 0;
  let score = 20;
  if (championOnly) score += 35;
  if (row.param_evidence.distinct_champion_network_ids === 10) score += 15;
  if (row.replay_count === row.probe_replay_count) score += 10;
  if (keyframeCount > 0) score += 10;
  if (keyframeCount > 0 && gameCount > 0) score += 20;
  if (gameCount / row.count >= 0.8) score += 10;
  if (row.count >= 10000) score += 10;
  if (maxPayloadLength >= 64) score += 10;
  if (maxPayloadLength >= 512) score += 10;
  return score;
}

function finalizeRouteAccumulator(accumulator, probeReplayCount) {
  const decodedAs = registeredDecoders(accumulator.build, accumulator.packet_id);
  const known = decodedAs.filter((entry) => entry.capability !== null);
  const streamCounts = Object.fromEntries([...accumulator.stream_counts.entries()].sort((a, b) => strictCompare(a[0], b[0])));
  const row = {
    build: accumulator.build,
    packet_id: accumulator.packet_id,
    packet_discriminator: formatOpcode(accumulator.packet_id),
    count: accumulator.count,
    probe_replay_count: probeReplayCount,
    replay_count: accumulator.replay_keys.size,
    replay_counts: Object.fromEntries([...accumulator.replay_counts.entries()].sort((a, b) => strictCompare(a[0], b[0]))),
    stream_counts: streamCounts,
    stream_ratios: Object.fromEntries(Object.entries(streamCounts).map(([key, count]) => [key, roundRatio(count, accumulator.count)])),
    payload_size_distribution: [...accumulator.payload_lengths.entries()]
      .map(([payload_length, count]) => ({ payload_length, count }))
      .sort((left, right) => left.payload_length - right.payload_length),
    param_evidence: {
      status: 'STRUCTURAL_OBSERVATION_ONLY',
      champion_range_observations: accumulator.champion_param_count,
      distinct_champion_network_ids: accumulator.champion_params.size,
      other_nonzero_observations: accumulator.other_nonzero_param_count,
      distinct_other_nonzero_params: accumulator.other_nonzero_params.size,
      zero_observations: accumulator.zero_param_count,
      distinct_raw_params: accumulator.raw_params.size,
    },
    keyframe_chunk_count_with_route: accumulator.keyframe_chunks.size,
    first_observed_time_ms: accumulator.first_time_ms,
    last_observed_time_ms: accumulator.last_time_ms,
    currently_decoded_as_status: known.length > 0
      ? 'REGISTERED_EXACT_BUILD_ROUTE'
      : 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
    decoded_as: decodedAs,
    samples: Object.fromEntries([...accumulator.samples.entries()].sort((a, b) => strictCompare(a[0], b[0]))),
    evidence_grade: 'CANDIDATE',
    semantic_warning: 'Packet shape, entity-linked raw_param, frequency, and cadence do not identify HP or any combat-stat field.',
  };
  row.structural_candidate_class = classifyRouteCandidate(row);
  row.candidate_score = candidateScore(row);
  return row;
}

function scanRuntimeNameBuffer(buffer, names = RUNTIME_NAME_CANDIDATES) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('runtime image must be a Buffer');
  return [...names].sort(strictCompare).map((name) => {
    const needle = Buffer.from(name, 'ascii');
    const offsets = [];
    let cursor = 0;
    while (cursor <= buffer.length - needle.length) {
      const offset = buffer.indexOf(needle, cursor);
      if (offset < 0) break;
      offsets.push(offset);
      cursor = offset + 1;
    }
    return {
      name,
      occurrence_count: offsets.length,
      file_offsets: offsets,
      file_offsets_hex: offsets.map((offset) => `0x${offset.toString(16).padStart(8, '0')}`),
      evidence_grade: offsets.length > 0 ? 'CANDIDATE' : 'UNVERIFIED',
      semantic_status: offsets.length > 0
        ? 'NAME_ONLY_CANDIDATE_NO_PACKET_ROUTE_OR_FIELD_MAPPING'
        : 'NAME_NOT_OBSERVED_IN_THIS_IMAGE',
    };
  });
}

function scanRuntimeImage(runtimeImagePath, options = {}) {
  if (!runtimeImagePath) return null;
  const resolved = path.resolve(runtimeImagePath);
  const buffer = fs.readFileSync(resolved);
  const sourceSha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  if (options.expectedSha256 && sourceSha256 !== options.expectedSha256) {
    throw new Error(`runtime image SHA-256 does not match the exact ${options.expectedBuild ?? 'target'} build profile`);
  }
  return {
    source_path: resolved,
    source_sha256: sourceSha256,
    source_size: buffer.length,
    expected_build: options.expectedBuild ?? TARGET_BUILD,
    expected_source_sha256: options.expectedSha256 ?? null,
    source_sha256_matches_profile: options.expectedSha256 ? true : null,
    evidence_boundary: 'STATIC_STRING_OCCURRENCE_ONLY; NO REGISTRATION, DESERIALIZER, OR FIELD SEMANTIC IS ESTABLISHED',
    names: scanRuntimeNameBuffer(buffer),
  };
}

function routeAccumulatorsFromReplayFiles(replayPaths, options = {}) {
  if (!Array.isArray(replayPaths) || replayPaths.length === 0) {
    throw new TypeError('at least one .rofl input is required');
  }
  const targetBuild = options.targetBuild ?? TARGET_BUILD;
  const routes = new Map();
  const sources = [];
  let blockCount = 0;
  let keyframeChunkCount = 0;
  for (const replayPath of [...replayPaths].map((item) => path.resolve(item)).sort(strictCompare)) {
    const replay = parseReplayFile(replayPath);
    if (replay.header.version !== targetBuild) {
      throw new Error(`exact-build probe expected ${targetBuild}; got ${replay.header.version} for ${replayPath}`);
    }
    const replayKey = replay.source_sha256;
    const observedKeyframeChunks = new Set();
    const walked = walkBlocks(replay, (block, chunk) => {
      blockCount += 1;
      if (chunk.stream_tag === 2 || chunk.stream_tag === 3) {
        observedKeyframeChunks.add(`${replayKey}:${chunk.index}`);
      }
      let accumulator = routes.get(block.packet_id);
      if (!accumulator) {
        accumulator = newRouteAccumulator(targetBuild, block.packet_id);
        routes.set(block.packet_id, accumulator);
      }
      observePacket(accumulator, {
        chunk_stream: chunk.stream,
        chunk_index: chunk.index,
        keyframe_key: `${replayKey}:${chunk.index}`,
        replay_key: replayKey,
        replay_sha256: replayKey,
        replay_time_ms: block.timestamp_ms,
        payload_length: block.payload_length,
        raw_param: block.param,
        payload: block.payload,
      });
    }, { includeStreams: [1, 2, 3], strict: options.strict !== false });
    if (walked.errors.length > 0) {
      throw new Error(`strict packet walk failed for ${replayPath}: ${walked.errors.length} error(s)`);
    }
    keyframeChunkCount += observedKeyframeChunks.size;
    sources.push({
      source_path: replay.source_path,
      source_sha256: replay.source_sha256,
      game_version: replay.header.version,
      framed_block_count: walked.block_count,
      observed_keyframe_chunk_count: observedKeyframeChunks.size,
    });
  }
  return { targetBuild, routes, sources, blockCount, keyframeChunkCount };
}

function capabilityFindings(shortlist) {
  const routeIds = shortlist.map((item) => item.packet_discriminator);
  const common = {
    release_status: 'UNAVAILABLE',
    direct_value: null,
    research_status: 'STRUCTURAL_CANDIDATES_IDENTIFIED_FIELDS_UNVERIFIED',
    candidate_routes: routeIds,
    warning: 'Candidate routes are not field mappings and must not populate canonical values.',
  };
  return {
    CURRENT_HP: { ...common },
    MAX_HP: { ...common },
    ARMOR: { ...common },
    MAGIC_RESIST: { ...common },
  };
}

function createCombatStateCandidateReport({ replayPaths, runtimeImagePath = null, targetBuild = TARGET_BUILD } = {}) {
  if (targetBuild !== TARGET_BUILD) {
    throw new Error(`combat-state candidate profile is registered only for exact build ${TARGET_BUILD}`);
  }
  const resolution = resolveBuildProfile(targetBuild);
  if (!resolution.profile || resolution.status === 'UNSUPPORTED_BUILD') {
    throw new Error(`no exact build profile registered for ${targetBuild}`);
  }
  const observed = routeAccumulatorsFromReplayFiles(replayPaths, { targetBuild, strict: true });
  const rows = [...observed.routes.values()]
    .map((accumulator) => finalizeRouteAccumulator(accumulator, observed.sources.length))
    .sort((left, right) => left.packet_id - right.packet_id);
  const byId = new Map(rows.map((row) => [row.packet_id, row]));
  const shortlist = STRUCTURAL_SHORTLIST_16_15.map((candidate) => ({
    ...candidate,
    packet_discriminator: formatOpcode(candidate.packet_id),
    observation: byId.get(candidate.packet_id) ?? null,
    evidence_grade: 'CANDIDATE',
    semantic_status: 'NO_HP_OR_COMBAT_STAT_FIELD_IDENTIFIED',
  }));
  const ranked = rows.filter((row) => row.structural_candidate_class)
    .sort((left, right) => right.candidate_score - left.candidate_score || left.packet_id - right.packet_id)
    .slice(0, 25);
  const anchors = COMBAT_ANCHOR_CAPABILITIES.map((capability) => {
    const route = resolution.profile.packet_routes[capability] ?? null;
    const row = route === null ? null : byId.get(route) ?? null;
    return {
      capability,
      packet_id: route,
      packet_discriminator: route === null ? null : formatOpcode(route),
      observed_count: row?.count ?? 0,
      stream_counts: row?.stream_counts ?? {},
      role: 'KNOWN_EXACT_BUILD_SEMANTIC_ANCHOR_FOR_FUTURE_CORRELATION',
    };
  });
  return {
    schema: COMBAT_CANDIDATE_SCHEMA_VERSION,
    schema_version: 1,
    analyzer_version: ANALYZER_VERSION,
    target_build: targetBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    probe_status: 'PARTIAL',
    semantic_result: 'NO_CURRENT_HP_MAX_HP_ARMOR_OR_MAGIC_RESIST_FIELD_VERIFIED',
    input: {
      replay_count: observed.sources.length,
      framed_block_count: observed.blockCount,
      packet_type_count: rows.length,
      keyframe_chunk_count: observed.keyframeChunkCount,
      replays: observed.sources,
      runtime_image: scanRuntimeImage(runtimeImagePath, {
        expectedBuild: targetBuild,
        expectedSha256: resolution.profile.runtime_profile.image_sha256,
      }),
    },
    capability_findings: capabilityFindings(shortlist),
    known_combat_anchors: anchors,
    priority_route_candidates: shortlist,
    ranked_structural_candidates: ranked,
    negative_evidence: [
      'No decoded current_hp, max_hp, armor, or magic_resist field was recovered in this probe.',
      'Static packet-class names are name-only evidence and are not linked to a packet ID, registration route, deserializer, or field offset.',
      'Champion-bound raw_param values, packet cadence, payload size, and keyframe density are structural evidence only.',
      'Keyframe-only candidates cannot provide a continuous 5/10/15-second combat timeline.',
      'A fixed-offset float scan is not a valid decoder for variable/encoded packet payloads and was not promoted.',
      'No HP-before/damage/heal/shield/HP-after residual validation can run until a direct HP field is decoded.',
    ],
    next_experiment: {
      priority: 'P0',
      action: 'Recover exact runtime registration, constructor, and deserializer chains for the name-only HeroStats/StatFormulaOutputs candidates; bind them to observed packet routes before decoding fields.',
      validation_anchors: ['0x028a damage', '0x0160 death', '0x009e protection', '0x025a level transition', 'keyframe cadence'],
      promotion_gate: 'Require exact-build route plus stable decoded field plus positive/negative examples and cross-event validation before changing canonical capability status.',
    },
  };
}

function writeCombatStateCandidateReport(outputPath, report) {
  const target = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  return target;
}

module.exports = {
  ANALYZER_VERSION,
  CHAMPION_NETWORK_ID_MAX,
  CHAMPION_NETWORK_ID_MIN,
  COMBAT_CANDIDATE_SCHEMA_VERSION,
  RUNTIME_NAME_CANDIDATES,
  STRUCTURAL_SHORTLIST_16_15,
  TARGET_BUILD,
  candidateScore,
  classifyRouteCandidate,
  createCombatStateCandidateReport,
  finalizeRouteAccumulator,
  isChampionNetworkId,
  newRouteAccumulator,
  observePacket,
  routeAccumulatorsFromReplayFiles,
  scanRuntimeImage,
  scanRuntimeNameBuffer,
  strictCompare,
  writeCombatStateCandidateReport,
};
