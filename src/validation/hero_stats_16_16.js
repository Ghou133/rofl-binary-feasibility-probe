'use strict';

const HERO_STATS_16_16_BUILD = '16.16.805.0442';
const HERO_STATS_16_16_PACKET_ID = 0x010c;
const HERO_STATS_16_16_PACKET_HEX = '0x010c';
const HERO_STATS_16_16_RUNTIME_IMAGE_SHA256 =
  '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const HERO_STATS_16_16_PROFILE_SHA256 =
  'e00e4766a032a5ebd3c5caa4bd030e2ed1256cf59ff63d8f3e9aeef286e523ef';
const PARTICIPANT_NETWORK_LOW_BYTE_BASE = 0xad;
const EXPECTED_PACKET_COUNT = 1390;
const EXPECTED_DETAILS_ROW_COUNT = 1430;
const EXPECTED_BLOB_LENGTH = 1476;
const EXPECTED_PAYLOAD_LENGTH = 1479;

const EXPECTED_SAFE_SAMPLES = Object.freeze({
  '11191024308': Object.freeze({
    replay_sha256: '1ff3b2d4321bbe4f6bf79bff767305bbf4fa59e42c9524c91f3c3b9421733349',
    details_sha256: '8838ecff8cd95dd722870c59a9d9d7da2471a9288d93f50d4a9479eaa8dab023',
    packet_count: 330,
    frame_count: 34,
  }),
  '11191203388': Object.freeze({
    replay_sha256: 'e54e1950949761bb75df509bd91a6823c3d08569a1f530410cb38fb5e07e3633',
    details_sha256: '637f6b5dde4ce34dea7b3b2f2bac34e9e855beca5150bd66ec7f38ad74ab11d7',
    packet_count: 300,
    frame_count: 31,
  }),
  '11191271422': Object.freeze({
    replay_sha256: 'a5a5580f1a4546fb627b53cf3921a9cf0f3086f15964410e054809a87a3be399',
    details_sha256: 'd5d128c9b76017cd268a48afed1e06383aaaa865f2c998751365539f5d3935cf',
    packet_count: 350,
    frame_count: 36,
  }),
  '11191336852': Object.freeze({
    replay_sha256: '25dff9e58855cfc2afdca6b1df2cc43aaa2da1ddc9823b63993ecfc456eb0e75',
    details_sha256: '368f1bc1b125fd9a09328eb32ab7541980f5e8355598f6ca33316c590c5fcc7d',
    packet_count: 410,
    frame_count: 42,
  }),
});

const EXPECTED_SAFE_GAME_IDS = Object.freeze(Object.keys(EXPECTED_SAFE_SAMPLES).sort());

const FIELD_SPECS = Object.freeze([
  Object.freeze({
    key: 'lane_minions_killed',
    details_key: 'minionsKilled',
    offset_bytes: 60,
  }),
  Object.freeze({
    key: 'xp',
    details_key: 'xp',
    offset_bytes: 40,
  }),
  Object.freeze({
    key: 'total_gold',
    details_key: 'totalGold',
    offset_bytes: 56,
  }),
  Object.freeze({
    key: 'jungle_minions_killed',
    details_key: 'jungleMinionsKilled',
    offset_bytes: 64,
  }),
]);

const ABSOLUTE_TOLERANCES = Object.freeze([
  0,
  0.000001,
  0.0001,
  0.001,
  0.01,
  0.1,
  0.25,
  0.5,
  1,
]);

function fail(message) {
  throw new Error(`16.16 HeroStats validation: ${message}`);
}

function assertCondition(condition, message) {
  if (!condition) fail(message);
}

function isSha256(value) {
  return /^[0-9a-f]{64}$/.test(String(value ?? ''));
}

function exactSet(values, expected) {
  if (!Array.isArray(values)) return false;
  const normalized = [...new Set(values.map((value) => String(value)))].sort();
  return normalized.length === expected.length
    && normalized.every((value, index) => value === expected[index]);
}

function replayGameIdFromPath(filePath) {
  const match = String(filePath ?? '').replace(/\\/g, '/').match(/\/([0-9]+)\.rofl$/i);
  return match ? match[1] : null;
}

function comparablePath(value) {
  return String(value ?? '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
}

function participantIdFromHeroStatsParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const participantId = (rawParam & 0xff) - PARTICIPANT_NETWORK_LOW_BYTE_BASE;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function decodeHeroStatsCandidateFields(blobHex) {
  assertCondition(typeof blobHex === 'string' && /^[0-9a-f]+$/i.test(blobHex),
    'decoded blob_hex must be non-empty hexadecimal');
  assertCondition(blobHex.length === EXPECTED_BLOB_LENGTH * 2,
    `decoded blob length must be ${EXPECTED_BLOB_LENGTH} bytes`);
  const blob = Buffer.from(blobHex, 'hex');
  const result = {};
  for (const spec of FIELD_SPECS) {
    const rawValue = blob.readFloatLE(spec.offset_bytes);
    assertCondition(Number.isFinite(rawValue), `${spec.key} f32 at ${spec.offset_bytes} is not finite`);
    result[spec.key] = rawValue;
  }
  return result;
}

function validatePacketManifest(packetManifest) {
  assertCondition(packetManifest?.schema_version === 1, 'packet manifest schema_version must be 1');
  assertCondition(packetManifest.target_replay_version === HERO_STATS_16_16_BUILD,
    'packet manifest target build mismatch');
  assertCondition(packetManifest.max_time_ms === null
      && packetManifest.max_per_packet_per_replay === null
      && packetManifest.sample_every === 1,
  'packet manifest must attest an unsampled full route export');
  assertCondition(Array.isArray(packetManifest.packet_ids)
      && packetManifest.packet_ids.length === 1
      && packetManifest.packet_ids[0] === HERO_STATS_16_16_PACKET_ID,
  'packet manifest must contain only route 0x010c');
  assertCondition(Array.isArray(packetManifest.stream_tags)
      && packetManifest.stream_tags.length === 1
      && packetManifest.stream_tags[0] === 2,
  'packet manifest must contain only keyframe stream tag 2');
  assertCondition(packetManifest.selected_packet_count === EXPECTED_PACKET_COUNT,
    `packet manifest selected count must be ${EXPECTED_PACKET_COUNT}`);
  assertCondition(packetManifest.packet_counts?.[String(HERO_STATS_16_16_PACKET_ID)]
      === EXPECTED_PACKET_COUNT,
  'packet manifest per-route count mismatch');
  assertCondition(packetManifest.replay_count === EXPECTED_SAFE_GAME_IDS.length
      && Array.isArray(packetManifest.replays)
      && packetManifest.replays.length === EXPECTED_SAFE_GAME_IDS.length,
  'packet manifest must contain exactly four P0 replays');

  const gameIds = packetManifest.replays.map((entry) => replayGameIdFromPath(entry.path));
  assertCondition(exactSet(gameIds, EXPECTED_SAFE_GAME_IDS),
    'packet manifest replay identities are not the exact safe P0 set');
  for (const entry of packetManifest.replays) {
    const gameId = replayGameIdFromPath(entry.path);
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    assertCondition(entry.version === HERO_STATS_16_16_BUILD,
      `packet manifest Replay build mismatch for ${gameId}`);
    assertCondition(entry.sha256 === expected.replay_sha256,
      `packet manifest Replay SHA-256 mismatch for ${gameId}`);
    assertCondition(entry.selected_packet_count === expected.packet_count,
      `packet manifest packet count mismatch for ${gameId}`);
    assertCondition(entry.parser_error_count === 0,
      `packet manifest parser errors are not zero for ${gameId}`);
  }
}

function validateDecodeSummary(summary) {
  assertCondition(summary?.schema_version === 1, 'decode summary schema_version must be 1');
  assertCondition(summary.runtime_profile === HERO_STATS_16_16_BUILD,
    'decode summary runtime profile mismatch');
  assertCondition(summary.image_sha256 === HERO_STATS_16_16_RUNTIME_IMAGE_SHA256,
    'decode summary exact runtime image SHA-256 mismatch');
  assertCondition(summary.profile_sha256 === HERO_STATS_16_16_PROFILE_SHA256,
    'decode summary exact packet profile SHA-256 mismatch');
  assertCondition(summary.client_opcode === HERO_STATS_16_16_PACKET_HEX,
    'decode summary client opcode mismatch');
  assertCondition(summary.profile_source?.evidence_status === 'STATIC_RUNTIME_VERIFIED',
    'decode summary profile is not static/runtime verified');
  assertCondition(summary.profile_source?.profile?.constructor_rva === '0x00e8cf30'
      && summary.profile_source?.profile?.vtable_rva === '0x01b11128'
      && summary.profile_source?.profile?.deserialize_rva === '0x00f0a220'
      && summary.profile_source?.profile?.object_size === '0x28',
  'decode summary runtime constructor/vtable/deserializer/object identity mismatch');
  assertCondition(summary.event_count === EXPECTED_PACKET_COUNT
      && summary.deserialize_success_count === EXPECTED_PACKET_COUNT
      && summary.fully_consumed_count === EXPECTED_PACKET_COUNT
      && summary.successful_full_consume_count === EXPECTED_PACKET_COUNT,
  `decode summary must attest ${EXPECTED_PACKET_COUNT}/${EXPECTED_PACKET_COUNT} full consumption`);
  assertCondition(summary.payload_length_counts?.[String(EXPECTED_PAYLOAD_LENGTH)]
      === EXPECTED_PACKET_COUNT,
  'decode summary payload length distribution mismatch');
  assertCondition(summary.stream_counts?.keyframe === EXPECTED_PACKET_COUNT,
    'decode summary keyframe count mismatch');
  assertCondition(summary.emulation_errors
      && Object.keys(summary.emulation_errors).length === 0,
  'decode summary contains emulation errors');
  for (const expected of Object.values(EXPECTED_SAFE_SAMPLES)) {
    assertCondition(summary.replay_event_counts?.[expected.replay_sha256] === expected.packet_count,
      `decode summary count mismatch for Replay SHA ${expected.replay_sha256}`);
  }
}

function validateDetailsManifest(detailsManifest) {
  assertCondition(detailsManifest?.schema_version === 'DETAILS_P0_GROUND_TRUTH_MANIFEST_V1',
    'DETAILS manifest schema mismatch');
  assertCondition(detailsManifest.target?.replay_header_build === HERO_STATS_16_16_BUILD
      && detailsManifest.target?.exact_build_required === true
      && detailsManifest.target?.nearest_build_fallback_allowed === false,
  'DETAILS manifest exact-build policy mismatch');
  assertCondition(detailsManifest.scope?.source === 'EXPLICIT_PAIRED_DETAILS_INPUTS_ONLY'
      && detailsManifest.scope?.protected_holdout_enumerated === false
      && detailsManifest.scope?.protected_holdout_read === false,
  'DETAILS manifest source/holdout boundary mismatch');
  assertCondition(detailsManifest.replay_count === EXPECTED_SAFE_GAME_IDS.length
      && Array.isArray(detailsManifest.replays)
      && detailsManifest.replays.length === EXPECTED_SAFE_GAME_IDS.length,
  'DETAILS manifest must contain exactly four P0 replays');
  assertCondition(detailsManifest.record_count === EXPECTED_DETAILS_ROW_COUNT,
    `DETAILS manifest record count must be ${EXPECTED_DETAILS_ROW_COUNT}`);
  assertCondition(exactSet(detailsManifest.included_key_game_ids, EXPECTED_SAFE_GAME_IDS),
    'DETAILS manifest included game ids are not the exact safe P0 set');
  assertCondition(exactSet(detailsManifest.required_key_game_ids, EXPECTED_SAFE_GAME_IDS),
    'DETAILS manifest required game ids are not the exact safe P0 set');
  assertCondition(exactSet(detailsManifest.replays.map((entry) => String(entry.game_id)),
    EXPECTED_SAFE_GAME_IDS), 'DETAILS manifest replay identities mismatch');
  for (const entry of detailsManifest.replays) {
    const gameId = String(entry.game_id);
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    assertCondition(entry.replay_build === HERO_STATS_16_16_BUILD,
      `DETAILS manifest Replay build mismatch for ${gameId}`);
    assertCondition(entry.replay?.sha256 === expected.replay_sha256,
      `DETAILS manifest Replay SHA-256 mismatch for ${gameId}`);
    assertCondition(entry.details?.sha256 === expected.details_sha256,
      `DETAILS manifest DETAILS SHA-256 mismatch for ${gameId}`);
    assertCondition(entry.frame_count === expected.frame_count
        && entry.participant_count === 10
        && entry.anchor_count === expected.frame_count * 10,
    `DETAILS manifest frame/participant counts mismatch for ${gameId}`);
  }
}

function validateSourceAttestations(sourceAttestations, packetManifest) {
  assertCondition(Array.isArray(sourceAttestations)
      && sourceAttestations.length === EXPECTED_SAFE_GAME_IDS.length,
  'four DETAILS source attestations are required');
  const packetByGameId = new Map(packetManifest.replays
    .map((entry) => [replayGameIdFromPath(entry.path), entry]));
  assertCondition(exactSet(sourceAttestations.map((entry) => String(entry.game_id)),
    EXPECTED_SAFE_GAME_IDS), 'DETAILS source attestations are not the exact safe P0 set');
  for (const source of sourceAttestations) {
    const gameId = String(source.game_id);
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    assertCondition(source.actual_details_sha256 === expected.details_sha256,
      `actual DETAILS SHA-256 mismatch for ${gameId}`);
    assertCondition(source.details_sha256_verification_method === 'SHA256_OF_EXPLICIT_FILE_BYTES',
      `DETAILS SHA-256 verification method mismatch for ${gameId}`);
    assertCondition(source.replay_sha256 === expected.replay_sha256,
      `source Replay SHA-256 mismatch for ${gameId}`);
    assertCondition(source.replay_build === HERO_STATS_16_16_BUILD,
      `source Replay build mismatch for ${gameId}`);
    assertCondition(comparablePath(source.replay_path)
        === comparablePath(packetByGameId.get(gameId)?.path),
    `packet/DETAILS manifest Replay path mismatch for ${gameId}`);
  }
}

function canonicalPacketRows(decodedRows, packetManifest) {
  assertCondition(Array.isArray(decodedRows), 'decodedRows must be an array');
  assertCondition(decodedRows.length === EXPECTED_PACKET_COUNT,
    `decoded row count must be ${EXPECTED_PACKET_COUNT}`);
  const replayManifestByGameId = new Map(packetManifest.replays
    .map((entry) => [replayGameIdFromPath(entry.path), entry]));
  const seen = new Set();
  const counts = new Map();
  const rows = decodedRows.map((row, rowIndex) => {
    const gameId = String(row?.replay_label ?? '');
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    assertCondition(expected, `decoded row ${rowIndex} has non-P0 replay label ${gameId}`);
    assertCondition(row.replay_version === HERO_STATS_16_16_BUILD,
      `decoded row ${rowIndex} build mismatch`);
    assertCondition(row.replay_sha256 === expected.replay_sha256,
      `decoded row ${rowIndex} Replay SHA-256 mismatch`);
    assertCondition(comparablePath(row.replay_path)
        === comparablePath(replayManifestByGameId.get(gameId)?.path),
    `decoded row ${rowIndex} Replay path mismatch`);
    assertCondition(row.packet_id === HERO_STATS_16_16_PACKET_ID
        && row.packet_type === HERO_STATS_16_16_PACKET_HEX,
    `decoded row ${rowIndex} route mismatch`);
    assertCondition(row.chunk_stream === 'keyframe',
      `decoded row ${rowIndex} is not a keyframe packet`);
    assertCondition(row.payload_length === EXPECTED_PAYLOAD_LENGTH,
      `decoded row ${rowIndex} payload length mismatch`);
    assertCondition(row.deserialize_return_al === 1
        && row.fully_consumed === true
        && row.bytes_consumed === EXPECTED_PAYLOAD_LENGTH + 4,
    `decoded row ${rowIndex} is not fully consumed`);
    assertCondition(row.wrapper_return_al === 1
        && row.wrapper_bytes_consumed === 2
        && row.decoded_opcode === HERO_STATS_16_16_PACKET_ID
        && row.opcode_matches_profile === true,
    `decoded row ${rowIndex} wrapper/opcode attestation mismatch`);
    assertCondition(row.decoder_runtime_image_sha256 === HERO_STATS_16_16_RUNTIME_IMAGE_SHA256
        && row.decoder_profile_sha256 === HERO_STATS_16_16_PROFILE_SHA256,
    `decoded row ${rowIndex} runtime/profile SHA-256 mismatch`);
    assertCondition(Number.isInteger(row.replay_time_ms) && row.replay_time_ms >= 0,
      `decoded row ${rowIndex} timestamp is invalid`);
    const participantId = participantIdFromHeroStatsParam(row.raw_param);
    assertCondition(participantId !== null,
      `decoded row ${rowIndex} raw_param does not map to participant 1..10`);
    assertCondition(isSha256(row.raw_payload_sha256),
      `decoded row ${rowIndex} raw payload SHA-256 is invalid`);
    const identity = `${row.replay_sha256}:${row.chunk_index}:${row.decompressed_block_offset}`;
    assertCondition(!seen.has(identity), `duplicate decoded packet identity at row ${rowIndex}`);
    seen.add(identity);
    counts.set(gameId, (counts.get(gameId) ?? 0) + 1);
    return {
      row_index: rowIndex,
      game_id: gameId,
      replay_sha256: row.replay_sha256,
      replay_build: row.replay_version,
      timestamp_ms: row.replay_time_ms,
      participant_id: participantId,
      raw_param: row.raw_param >>> 0,
      raw_param_hex: `0x${(row.raw_param >>> 0).toString(16).padStart(8, '0')}`,
      chunk_index: row.chunk_index,
      decompressed_block_offset: row.decompressed_block_offset,
      occurrence_index: row.occurrence_index,
      payload_length: row.payload_length,
      raw_payload_sha256: row.raw_payload_sha256,
      candidate_fields: decodeHeroStatsCandidateFields(row.decoded_fields?.blob_hex),
    };
  });
  for (const gameId of EXPECTED_SAFE_GAME_IDS) {
    assertCondition(counts.get(gameId) === EXPECTED_SAFE_SAMPLES[gameId].packet_count,
      `decoded packet count mismatch for ${gameId}`);
  }
  return rows;
}

function canonicalDetailsRows(detailsRows) {
  assertCondition(Array.isArray(detailsRows), 'detailsRows must be an array');
  assertCondition(detailsRows.length === EXPECTED_DETAILS_ROW_COUNT,
    `DETAILS row count must be ${EXPECTED_DETAILS_ROW_COUNT}`);
  const seen = new Set();
  const counts = new Map();
  const rows = detailsRows.map((row, rowIndex) => {
    const gameId = String(row?.game_id ?? '');
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    assertCondition(expected, `DETAILS row ${rowIndex} has non-P0 game id ${gameId}`);
    assertCondition(row.replay_build === HERO_STATS_16_16_BUILD,
      `DETAILS row ${rowIndex} Replay build mismatch`);
    assertCondition(row.replay_sha256 === expected.replay_sha256,
      `DETAILS row ${rowIndex} Replay SHA-256 mismatch`);
    assertCondition(row.details_sha256 === expected.details_sha256,
      `DETAILS row ${rowIndex} DETAILS SHA-256 mismatch`);
    assertCondition(Number.isInteger(row.timestamp_ms) && row.timestamp_ms >= 0,
      `DETAILS row ${rowIndex} timestamp is invalid`);
    assertCondition(Number.isInteger(row.participant_id)
        && row.participant_id >= 1 && row.participant_id <= 10,
    `DETAILS row ${rowIndex} participant is invalid`);
    const identity = `${row.replay_sha256}:${row.timestamp_ms}:${row.participant_id}`;
    assertCondition(!seen.has(identity), `duplicate DETAILS identity at row ${rowIndex}`);
    seen.add(identity);
    const fields = {};
    for (const spec of FIELD_SPECS) {
      const value = row.fields?.[spec.details_key];
      assertCondition(Number.isFinite(value),
        `DETAILS row ${rowIndex} ${spec.details_key} is not finite`);
      fields[spec.key] = value;
    }
    counts.set(gameId, (counts.get(gameId) ?? 0) + 1);
    return {
      row_index: rowIndex,
      game_id: gameId,
      replay_sha256: row.replay_sha256,
      replay_build: row.replay_build,
      details_sha256: row.details_sha256,
      frame_index: row.frame_index,
      timestamp_ms: row.timestamp_ms,
      participant_id: row.participant_id,
      source_json_paths: row.source_json_paths,
      fields,
      identity,
    };
  });
  for (const gameId of EXPECTED_SAFE_GAME_IDS) {
    assertCondition(counts.get(gameId) === EXPECTED_SAFE_SAMPLES[gameId].frame_count * 10,
      `DETAILS participant-frame count mismatch for ${gameId}`);
  }
  return rows;
}

function fieldComparison(rawValue, detailsValue) {
  const residual = rawValue - detailsValue;
  return {
    raw_value: rawValue,
    details_value: detailsValue,
    residual,
    exact_match: rawValue === detailsValue,
    floor_value: Math.floor(rawValue),
    floor_match: Math.floor(rawValue) === detailsValue,
    trunc_value: Math.trunc(rawValue),
    trunc_match: Math.trunc(rawValue) === detailsValue,
    round_value: Math.round(rawValue),
    round_match: Math.round(rawValue) === detailsValue,
    ceil_value: Math.ceil(rawValue),
    ceil_match: Math.ceil(rawValue) === detailsValue,
  };
}

function matchPacketRowsToDetails(packetRows, detailsRows, windowMs = 1) {
  assertCondition(Number.isFinite(windowMs) && windowMs >= 0,
    'timestamp window must be non-negative');
  const detailsByEntity = new Map();
  for (const row of detailsRows) {
    const key = `${row.replay_sha256}:${row.participant_id}`;
    const values = detailsByEntity.get(key) ?? [];
    values.push(row);
    detailsByEntity.set(key, values);
  }
  for (const rows of detailsByEntity.values()) rows.sort((left, right) => left.timestamp_ms - right.timestamp_ms);

  const usedDetails = new Set();
  const matches = [];
  const unmatchedPackets = [];
  const ambiguousPackets = [];
  const reusedDetails = [];
  for (const packet of packetRows) {
    const key = `${packet.replay_sha256}:${packet.participant_id}`;
    const candidates = (detailsByEntity.get(key) ?? [])
      .filter((details) => Math.abs(packet.timestamp_ms - details.timestamp_ms) <= windowMs);
    if (candidates.length === 0) {
      unmatchedPackets.push(packet);
      continue;
    }
    if (candidates.length !== 1) {
      ambiguousPackets.push({ packet, candidate_details_identities: candidates.map((row) => row.identity) });
      continue;
    }
    const details = candidates[0];
    if (usedDetails.has(details.identity)) {
      reusedDetails.push({ packet, details_identity: details.identity });
      continue;
    }
    usedDetails.add(details.identity);
    const fields = {};
    for (const spec of FIELD_SPECS) {
      fields[spec.key] = fieldComparison(
        packet.candidate_fields[spec.key],
        details.fields[spec.key],
      );
    }
    matches.push({
      game_id: packet.game_id,
      replay_sha256: packet.replay_sha256,
      replay_build: packet.replay_build,
      participant_id: packet.participant_id,
      participant_mapping: {
        rule: '(raw_param & 0xff) - 0xad',
        exact_build_only: true,
        raw_param: packet.raw_param,
        raw_param_hex: packet.raw_param_hex,
        raw_param_upper_bytes_semantics: 'UNKNOWN_RETAINED_RAW',
      },
      packet_timestamp_ms: packet.timestamp_ms,
      details_timestamp_ms: details.timestamp_ms,
      timestamp_delta_ms: packet.timestamp_ms - details.timestamp_ms,
      packet_ref: {
        row_index: packet.row_index,
        chunk_index: packet.chunk_index,
        decompressed_block_offset: packet.decompressed_block_offset,
        occurrence_index: packet.occurrence_index,
        packet_id: HERO_STATS_16_16_PACKET_ID,
        packet_id_hex: HERO_STATS_16_16_PACKET_HEX,
        payload_length: packet.payload_length,
        raw_payload_sha256: packet.raw_payload_sha256,
      },
      details_ref: {
        row_index: details.row_index,
        frame_index: details.frame_index,
        details_sha256: details.details_sha256,
        source_json_paths: details.source_json_paths,
      },
      fields,
    });
  }
  return {
    matches,
    unmatched_packets: unmatchedPackets,
    ambiguous_packets: ambiguousPackets,
    reused_details: reusedDetails,
    unmatched_details: detailsRows.filter((row) => !usedDetails.has(row.identity)),
  };
}

function finiteOrNull(value) {
  return Number.isFinite(value) ? value : null;
}

function quantile(sorted, percentile) {
  if (sorted.length === 0) return null;
  const position = (sorted.length - 1) * percentile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + ((sorted[upper] - sorted[lower]) * (position - lower));
}

function summarizeComparisons(matches, fieldKey, options = {}) {
  const selected = matches.filter((row) => (!options.gameId || row.game_id === options.gameId)
    && (!options.participantId || row.participant_id === options.participantId));
  const comparisons = selected.map((row) => row.fields[fieldKey]);
  const count = comparisons.length;
  const residuals = comparisons.map((row) => row.residual);
  const sortedResiduals = [...residuals].sort((left, right) => left - right);
  const absoluteResiduals = residuals.map(Math.abs);
  const rawValues = comparisons.map((row) => row.raw_value);
  const detailsValues = comparisons.map((row) => row.details_value);
  const sum = (values) => values.reduce((total, value) => total + value, 0);
  const meanResidual = count ? sum(residuals) / count : null;
  const meanRaw = count ? sum(rawValues) / count : null;
  const meanDetails = count ? sum(detailsValues) / count : null;
  let covariance = 0;
  let rawVariance = 0;
  let detailsVariance = 0;
  for (let index = 0; index < count; index += 1) {
    const rawDelta = rawValues[index] - meanRaw;
    const detailsDelta = detailsValues[index] - meanDetails;
    covariance += rawDelta * detailsDelta;
    rawVariance += rawDelta * rawDelta;
    detailsVariance += detailsDelta * detailsDelta;
  }
  const correlation = rawVariance > 0 && detailsVariance > 0
    ? covariance / Math.sqrt(rawVariance * detailsVariance)
    : null;
  const countTransform = (key) => comparisons.filter((row) => row[key]).length;
  const transformSummary = (name) => {
    const matchCount = countTransform(`${name}_match`);
    return {
      match_count: matchCount,
      mismatch_count: count - matchCount,
      match_rate: count ? matchCount / count : null,
    };
  };
  const exactCount = countTransform('exact_match');
  const tolerance = {};
  for (const threshold of ABSOLUTE_TOLERANCES) {
    const matchCount = absoluteResiduals.filter((value) => value <= threshold).length;
    tolerance[String(threshold)] = {
      match_count: matchCount,
      mismatch_count: count - matchCount,
      match_rate: count ? matchCount / count : null,
    };
  }
  const floorMismatchMatches = selected.filter((row) => !row.fields[fieldKey].floor_match);
  return {
    count,
    exact: {
      match_count: exactCount,
      mismatch_count: count - exactCount,
      match_rate: count ? exactCount / count : null,
    },
    transforms: {
      floor: transformSummary('floor'),
      trunc: transformSummary('trunc'),
      round: transformSummary('round'),
      ceil: transformSummary('ceil'),
    },
    absolute_residual_lte: tolerance,
    residual: {
      min: count ? Math.min(...residuals) : null,
      max: count ? Math.max(...residuals) : null,
      mean: finiteOrNull(meanResidual),
      mean_absolute: count ? sum(absoluteResiduals) / count : null,
      root_mean_square: count
        ? Math.sqrt(sum(residuals.map((value) => value * value)) / count)
        : null,
      negative_count: residuals.filter((value) => value < 0).length,
      zero_count: residuals.filter((value) => value === 0).length,
      positive_count: residuals.filter((value) => value > 0).length,
      percentiles: {
        p00: quantile(sortedResiduals, 0),
        p25: quantile(sortedResiduals, 0.25),
        p50: quantile(sortedResiduals, 0.5),
        p75: quantile(sortedResiduals, 0.75),
        p100: quantile(sortedResiduals, 1),
      },
    },
    pearson_correlation: finiteOrNull(correlation),
    floor_mismatch_evidence: floorMismatchMatches.slice(0, 20).map((row) => ({
      game_id: row.game_id,
      replay_sha256: row.replay_sha256,
      participant_id: row.participant_id,
      packet_timestamp_ms: row.packet_timestamp_ms,
      details_timestamp_ms: row.details_timestamp_ms,
      packet_ref: row.packet_ref,
      details_ref: row.details_ref,
      comparison: row.fields[fieldKey],
    })),
    floor_mismatch_evidence_truncated: floorMismatchMatches.length > 20,
  };
}

function fieldEvidenceReport(matches, spec) {
  const aggregate = summarizeComparisons(matches, spec.key);
  let evidenceStatus = 'CANDIDATE';
  let promotion = {
    allowed: false,
    reason: 'correlation/candidate evidence is insufficient for semantic promotion',
  };
  if (spec.key === 'lane_minions_killed' && aggregate.exact.match_count === EXPECTED_PACKET_COUNT) {
    evidenceStatus = 'VERIFIED_DIRECT';
    promotion = {
      allowed: true,
      semantic_output: 'lane_minions_killed',
      replay_value: `f32_le(blob_hex, ${spec.offset_bytes})`,
      transformation: 'identity',
      provenance: 'DIRECT_REPLAY_FIELD_INDEPENDENTLY_VALIDATED_AGAINST_DETAILS',
    };
  } else if (spec.key === 'xp'
      && aggregate.transforms.floor.match_count === EXPECTED_PACKET_COUNT) {
    evidenceStatus = 'VERIFIED_DIRECT_RAW_PLUS_VERIFIED_DERIVED_INTEGER';
    promotion = {
      allowed: true,
      semantic_outputs: [
        {
          name: 'xp_raw',
          replay_value: `f32_le(blob_hex, ${spec.offset_bytes})`,
          transformation: 'identity',
          provenance: 'DIRECT_REPLAY_FIELD_INDEPENDENTLY_VALIDATED_AGAINST_DETAILS',
        },
        {
          name: 'xp_integer',
          source: 'xp_raw',
          transformation: 'Math.floor(xp_raw)',
          provenance: 'DERIVED_EXACT_MATCH_TO_DETAILS_INTEGER_ON_1390_OF_1390',
        },
      ],
    };
  } else if (spec.key === 'total_gold') {
    promotion = {
      allowed: false,
      reason: 'CANDIDATE_ONLY: floor(raw) has one preserved mismatch; no correction, fallback, or silent anomaly discard is allowed',
    };
  } else if (spec.key === 'jungle_minions_killed') {
    promotion = {
      allowed: false,
      reason: 'CANDIDATE_ONLY: residual/transform agreement is not exact; semantic relation remains unresolved',
    };
  }
  return {
    blob_offset_bytes: spec.offset_bytes,
    wire_representation: 'IEEE754_FLOAT32_LITTLE_ENDIAN',
    details_oracle_field: spec.details_key,
    evidence_status: evidenceStatus,
    promotion,
    aggregate,
    by_replay: EXPECTED_SAFE_GAME_IDS.map((gameId) => ({
      game_id: gameId,
      statistics: summarizeComparisons(matches, spec.key, { gameId }),
    })),
    by_replay_participant: EXPECTED_SAFE_GAME_IDS.flatMap((gameId) => (
      Array.from({ length: 10 }, (_, index) => ({
        game_id: gameId,
        participant_id: index + 1,
        statistics: summarizeComparisons(matches, spec.key, {
          gameId,
          participantId: index + 1,
        }),
      }))
    )),
  };
}

function createHeroStatsScoreboardValidation(input, options = {}) {
  const windowMs = options.windowMs ?? 1;
  validatePacketManifest(input.packetManifest);
  validateDecodeSummary(input.decodeSummary);
  validateDetailsManifest(input.detailsManifest);
  validateSourceAttestations(input.sourceAttestations, input.packetManifest);
  const packetRows = canonicalPacketRows(input.decodedRows, input.packetManifest);
  const detailsRows = canonicalDetailsRows(input.detailsRows);
  const matching = matchPacketRowsToDetails(packetRows, detailsRows, windowMs);
  const fields = Object.fromEntries(FIELD_SPECS.map((spec) => [
    spec.key,
    fieldEvidenceReport(matching.matches, spec),
  ]));
  const timestampDeltas = matching.matches.map((row) => row.timestamp_delta_ms);
  const replaySummaries = EXPECTED_SAFE_GAME_IDS.map((gameId) => {
    const expected = EXPECTED_SAFE_SAMPLES[gameId];
    const matches = matching.matches.filter((row) => row.game_id === gameId);
    const deltas = matches.map((row) => row.timestamp_delta_ms);
    return {
      game_id: gameId,
      replay_sha256: expected.replay_sha256,
      details_sha256: expected.details_sha256,
      decoded_packet_count: packetRows.filter((row) => row.game_id === gameId).length,
      details_participant_frame_count: detailsRows.filter((row) => row.game_id === gameId).length,
      matched_count: matches.length,
      unmatched_details_count: matching.unmatched_details.filter((row) => row.game_id === gameId).length,
      timestamp_delta_counts: Object.fromEntries([-1, 0, 1].map((delta) => [
        String(delta), deltas.filter((value) => value === delta).length,
      ])),
    };
  });

  const gates = {
    exact_safe_p0_identity_attested: true,
    exact_replay_build_attested: true,
    replay_sha256_cross_manifest_and_every_decoded_row_attested: true,
    details_sha256_rehashed_and_verified: true,
    static_runtime_profile_and_image_sha256_verified: true,
    decoded_full_consume_1390_of_1390: packetRows.length === EXPECTED_PACKET_COUNT,
    participant_mapping_valid_1390_of_1390:
      packetRows.every((row) => row.participant_id >= 1 && row.participant_id <= 10),
    packet_details_match_1390_of_1390: matching.matches.length === EXPECTED_PACKET_COUNT,
    timestamp_absolute_delta_lte_1ms_1390_of_1390:
      timestampDeltas.length === EXPECTED_PACKET_COUNT
      && timestampDeltas.every((value) => Math.abs(value) <= 1),
    one_to_one_no_unmatched_ambiguous_or_reused_packet:
      matching.unmatched_packets.length === 0
      && matching.ambiguous_packets.length === 0
      && matching.reused_details.length === 0,
    lane_minions_killed_direct_exact_1390_of_1390:
      fields.lane_minions_killed.aggregate.exact.match_count === EXPECTED_PACKET_COUNT,
    xp_floor_derived_integer_exact_1390_of_1390:
      fields.xp.aggregate.transforms.floor.match_count === EXPECTED_PACKET_COUNT,
    total_gold_remains_candidate_with_one_preserved_floor_anomaly:
      fields.total_gold.evidence_status === 'CANDIDATE'
      && fields.total_gold.aggregate.transforms.floor.match_count === EXPECTED_PACKET_COUNT - 1
      && fields.total_gold.aggregate.transforms.floor.mismatch_count === 1
      && fields.total_gold.aggregate.floor_mismatch_evidence.length === 1,
    jungle_minions_killed_remains_candidate: fields.jungle_minions_killed.evidence_status === 'CANDIDATE',
    no_candidate_silent_promotion_or_fallback:
      fields.total_gold.promotion.allowed === false
      && fields.jungle_minions_killed.promotion.allowed === false,
  };
  const status = Object.values(gates).every(Boolean) ? 'PASS' : 'FAIL';
  return {
    schema: 'ROFL_16_16_HERO_STATS_SCOREBOARD_VALIDATION_V1',
    schema_version: 1,
    status,
    exact_build: HERO_STATS_16_16_BUILD,
    packet_id: HERO_STATS_16_16_PACKET_ID,
    packet_id_hex: HERO_STATS_16_16_PACKET_HEX,
    runtime_type_name: 'PKT_S2C_HeroStats_s',
    route_classification: 'KEYFRAME_SCOREBOARD_SNAPSHOT_NOT_COMBAT_CURRENT_STATE',
    evidence_scope: {
      verified_direct: [
        'participant_id=(raw_param & 0xff)-0xad',
        'lane_minions_killed=f32_le(blob_hex,60)',
        'xp_raw=f32_le(blob_hex,40)',
      ],
      verified_derived: ['xp_integer=Math.floor(xp_raw)'],
      candidate_only: [
        'total_gold_candidate=f32_le(blob_hex,56)',
        'jungle_minions_killed_candidate=f32_le(blob_hex,64)',
      ],
      unknown_or_unavailable: [
        'all unprofiled blob offsets',
        'current combat HP/maximum HP/armor/magic resistance semantics on route 0x010c',
        'a deterministic correction or fallback for the total_gold anomaly',
        'a deterministic transform for jungle_minions_killed',
        'raw_param upper-byte semantics',
      ],
    },
    promotion_policy: {
      allowed_only_if_status_pass: [
        'lane_minions_killed direct replay value at f32 offset 60',
        'xp_raw direct replay value at f32 offset 40',
        'xp_integer derived only as Math.floor(xp_raw)',
      ],
      forbidden: [
        'do not promote total_gold from offset 56',
        'do not promote jungle_minions_killed from offset 64',
        'do not round, patch, suppress, or silently discard the total_gold anomaly',
        'do not treat missing/null/UNKNOWN values as zero',
        'do not treat route 0x010c as a live combat-state route',
        'do not generalize beyond exact build 16.16.805.0442',
      ],
    },
    details_role: 'INDEPENDENT_VALIDATION_ORACLE_ONLY_NOT_A_REPLAY_SEMANTIC_SOURCE',
    matching_policy: {
      replay_identity: 'exact hard-coded safe P0 game id and Replay SHA-256',
      participant: '(raw_param & 0xff) - 0xad, exact build only',
      timestamp_absolute_window_ms: windowMs,
      one_to_one: true,
      unmatched_details_frames_allowed: true,
      unmatched_details_frames_meaning:
        'DETAILS oracle frames without a corresponding 0x010c keyframe packet; never synthesized as replay events',
    },
    gates,
    decoded_packet_count: packetRows.length,
    details_participant_frame_count: detailsRows.length,
    matched_count: matching.matches.length,
    unmatched_packet_count: matching.unmatched_packets.length,
    ambiguous_packet_count: matching.ambiguous_packets.length,
    reused_details_count: matching.reused_details.length,
    unmatched_details_count: matching.unmatched_details.length,
    timestamp_delta_ms: {
      min: timestampDeltas.length ? Math.min(...timestampDeltas) : null,
      max: timestampDeltas.length ? Math.max(...timestampDeltas) : null,
      absolute_max: timestampDeltas.length
        ? Math.max(...timestampDeltas.map((value) => Math.abs(value))) : null,
      counts: Object.fromEntries([-1, 0, 1].map((delta) => [
        String(delta), timestampDeltas.filter((value) => value === delta).length,
      ])),
    },
    fields,
    replay_summaries: replaySummaries,
    comparison_rows: matching.matches,
    unmatched_packets: matching.unmatched_packets,
    ambiguous_packets: matching.ambiguous_packets,
    reused_details: matching.reused_details,
    unmatched_details: matching.unmatched_details.map((row) => ({
      game_id: row.game_id,
      replay_sha256: row.replay_sha256,
      participant_id: row.participant_id,
      timestamp_ms: row.timestamp_ms,
      details_sha256: row.details_sha256,
      frame_index: row.frame_index,
    })),
    provenance: input.provenance ?? {},
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

module.exports = {
  ABSOLUTE_TOLERANCES,
  EXPECTED_BLOB_LENGTH,
  EXPECTED_DETAILS_ROW_COUNT,
  EXPECTED_PACKET_COUNT,
  EXPECTED_SAFE_GAME_IDS,
  EXPECTED_SAFE_SAMPLES,
  FIELD_SPECS,
  HERO_STATS_16_16_BUILD,
  HERO_STATS_16_16_PACKET_HEX,
  HERO_STATS_16_16_PACKET_ID,
  HERO_STATS_16_16_PROFILE_SHA256,
  HERO_STATS_16_16_RUNTIME_IMAGE_SHA256,
  createHeroStatsScoreboardValidation,
  decodeHeroStatsCandidateFields,
  fieldComparison,
  matchPacketRowsToDetails,
  participantIdFromHeroStatsParam,
  summarizeComparisons,
  validateDecodeSummary,
  validateDetailsManifest,
  validatePacketManifest,
};
