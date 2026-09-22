'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { writeJson, writeJsonl } = require('./io');
const { parseReplayFile } = require('./rofl');

const ANCHOR_SCHEMA_VERSION = 'DETAILS_P0_GROUND_TRUTH_V1';
const MANIFEST_SCHEMA_VERSION = 'DETAILS_P0_GROUND_TRUTH_MANIFEST_V1';
const ANCHOR_TYPE = 'GROUND_TRUTH_FRAME_SNAPSHOT';
const TARGET_PATCH = '16.16';
const TARGET_REPLAY_BUILD = '16.16.805.0442';
const TARGET_SUMMARY_BUILD = '16.16.805.442';

const KEY_SAMPLE_EXPECTATIONS = Object.freeze({
  '11191024308': Object.freeze({
    role: 'PERSISTENT_MAX_HP_PURCHASE',
    hashes: Object.freeze({
      replay: '1ff3b2d4321bbe4f6bf79bff767305bbf4fa59e42c9524c91f3c3b9421733349',
      details: '8838ecff8cd95dd722870c59a9d9d7da2471a9288d93f50d4a9479eaa8dab023',
      summary: 'de3ba4fb69a8613cfabcbc5f9143b05a92f4185365243ca945fbd5de42e7efe0',
    }),
    participant_id: 5,
    champion: 'Alistar',
    event: Object.freeze({ type: 'ITEM_PURCHASED', timestamp_ms: 1659401, item_id: 1028 }),
    frames: Object.freeze([
      Object.freeze({ timestamp_ms: 1620476, current_hp: 3064, max_hp: 3064, armor: 121, magic_resist: 104 }),
      Object.freeze({ timestamp_ms: 1680488, current_hp: 3214, max_hp: 3214, armor: 121, magic_resist: 104 }),
    ]),
  }),
  '11191271422': Object.freeze({
    role: 'PERSISTENT_MAGIC_RESIST_PURCHASE',
    hashes: Object.freeze({
      replay: 'a5a5580f1a4546fb627b53cf3921a9cf0f3086f15964410e054809a87a3be399',
      details: 'd5d128c9b76017cd268a48afed1e06383aaaa865f2c998751365539f5d3935cf',
      summary: '697119f2478485c0bf9fc0dd17d268b27182df36699c360b79c5eef0636a1d71',
    }),
    participant_id: 1,
    champion: 'Yone',
    event: Object.freeze({ type: 'ITEM_PURCHASED', timestamp_ms: 1126858, item_id: 1033 }),
    frames: Object.freeze([
      Object.freeze({ timestamp_ms: 1080427, current_hp: 1834, max_hp: 1834, armor: 83, magic_resist: 54 }),
      Object.freeze({ timestamp_ms: 1140428, current_hp: 1834, max_hp: 1834, armor: 83, magic_resist: 74 }),
    ]),
  }),
  '11191336852': Object.freeze({
    role: 'PERSISTENT_ARMOR_PURCHASE',
    hashes: Object.freeze({
      replay: '25dff9e58855cfc2afdca6b1df2cc43aaa2da1ddc9823b63993ecfc456eb0e75',
      details: '368f1bc1b125fd9a09328eb32ab7541980f5e8355598f6ca33316c590c5fcc7d',
      summary: '707147dfa8a50cf07d95dc99cd33a905003ccc05f48e504663923ce9eda90f68',
    }),
    participant_id: 5,
    champion: 'Alistar',
    event: Object.freeze({ type: 'ITEM_PURCHASED', timestamp_ms: 298307, item_id: 1029 }),
    frames: Object.freeze([
      Object.freeze({ timestamp_ms: 240161, current_hp: 980, max_hp: 987, armor: 46, magic_resist: 35 }),
      Object.freeze({ timestamp_ms: 300165, current_hp: 1017, max_hp: 1017, armor: 61, magic_resist: 35 }),
    ]),
  }),
  '11191203388': Object.freeze({
    role: 'DAMAGE_DEATH_RESPAWN_FRAME_BOUND',
    hashes: Object.freeze({
      replay: 'e54e1950949761bb75df509bd91a6823c3d08569a1f530410cb38fb5e07e3633',
      details: '637f6b5dde4ce34dea7b3b2f2bac34e9e855beca5150bd66ec7f38ad74ab11d7',
      summary: 'cd7069ad8ade662a60f0a6a139fae1c390a8da8091f433682ecd758fa3163f3a',
    }),
    participant_id: 2,
    champion: 'Talon',
    event: Object.freeze({
      type: 'CHAMPION_KILL',
      timestamp_ms: 238172,
      killer_participant_id: 8,
      victim_participant_id: 2,
      source_champion: 'Locke',
      magic_damage: 42,
    }),
    frames: Object.freeze([
      Object.freeze({ timestamp_ms: 180029, current_hp: 568, max_hp: 883, armor: 36, magic_resist: 39 }),
      Object.freeze({ timestamp_ms: 240042, current_hp: 0, max_hp: 883, armor: 36, magic_resist: 39 }),
      Object.freeze({ timestamp_ms: 300059, current_hp: 764, max_hp: 969, armor: 40, magic_resist: 40 }),
    ]),
  }),
});

const REQUIRED_KEY_GAME_IDS = Object.freeze(Object.keys(KEY_SAMPLE_EXPECTATIONS).sort());

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function fail(message) {
  throw new Error(`DETAILS P0 ground truth: ${message}`);
}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  return value;
}

function requireInteger(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) fail(`${label} must be a safe integer`);
  return number;
}

function requireFiniteNumber(value, label) {
  const number = Number(value);
  if (!Number.isFinite(number)) fail(`${label} must be finite`);
  return number;
}

function normalizeGameId(value) {
  const gameId = String(value ?? '').trim();
  if (!/^[0-9]+$/.test(gameId)) fail(`invalid game id: ${value}`);
  return gameId;
}

function unwrapSgpDocument(document, label, expectedInfoType) {
  requireObject(document, `${label} wrapper`);
  if (!Object.hasOwn(document, 'json') || !Object.hasOwn(document, 'metadata')) {
    fail(`${label} must use the top-level {json, metadata} SGP wrapper`);
  }
  const metadata = requireObject(document.metadata, `${label}.metadata`);
  let payload = document.json;
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload);
    } catch (error) {
      fail(`${label}.json is an invalid encoded JSON document: ${error.message}`);
    }
  }
  requireObject(payload, `${label}.json`);
  if (String(metadata.info_type ?? '').toLowerCase() !== expectedInfoType) {
    fail(`${label}.metadata.info_type must be ${expectedInfoType}`);
  }
  if (String(metadata.data_version ?? '') !== '2') fail(`${label}.metadata.data_version must be 2`);
  if (String(metadata.product ?? '').toLowerCase() !== 'lol') fail(`${label}.metadata.product must be lol`);
  return { metadata, payload };
}

function validateWrapperIdentity(document, gameId, platformId, label) {
  const expectedMatchId = `${platformId}_${gameId}`;
  if (String(document.metadata.match_id) !== expectedMatchId) {
    fail(`${label}.metadata.match_id ${document.metadata.match_id} does not match ${expectedMatchId}`);
  }
  if (String(document.payload.gameId) !== gameId) {
    fail(`${label}.json.gameId ${document.payload.gameId} does not match ${gameId}`);
  }
}

function participantMapping(summary) {
  if (!Array.isArray(summary.participants) || summary.participants.length === 0) {
    fail('SUMMARY participants are required');
  }
  const mapping = [];
  const seen = new Set();
  for (let index = 0; index < summary.participants.length; index += 1) {
    const participant = requireObject(summary.participants[index], `SUMMARY participant ${index}`);
    const participantId = requireInteger(participant.participantId, `SUMMARY participant ${index}.participantId`);
    if (seen.has(participantId)) fail(`duplicate participantId ${participantId} in SUMMARY`);
    seen.add(participantId);
    const champion = String(participant.championName ?? '').trim();
    if (!champion) fail(`SUMMARY participant ${participantId} has no championName`);
    mapping.push({
      participant_id: participantId,
      champion,
      team_id: requireInteger(participant.teamId, `SUMMARY participant ${participantId}.teamId`),
      summary_json_path: `$.json.participants[${index}]`,
    });
  }
  mapping.sort((left, right) => left.participant_id - right.participant_id);
  return mapping;
}

function collectEvents(details) {
  const events = [];
  for (let frameIndex = 0; frameIndex < details.frames.length; frameIndex += 1) {
    const frameEvents = details.frames[frameIndex].events ?? [];
    if (!Array.isArray(frameEvents)) fail(`DETAILS frame ${frameIndex}.events must be an array`);
    for (let eventIndex = 0; eventIndex < frameEvents.length; eventIndex += 1) {
      const event = requireObject(frameEvents[eventIndex], `DETAILS frame ${frameIndex} event ${eventIndex}`);
      if (!Number.isFinite(Number(event.timestamp))) continue;
      events.push({
        event,
        timestamp_ms: Math.round(Number(event.timestamp)),
        source_json_path: `$.json.frames[${frameIndex}].events[${eventIndex}]`,
      });
    }
  }
  events.sort((left, right) => left.timestamp_ms - right.timestamp_ms
    || left.source_json_path.localeCompare(right.source_json_path));
  return events;
}

function healthTransition(previousHp, currentHp) {
  if (previousHp === null) return 'INITIAL_FRAME';
  if (previousHp > 0 && currentHp === 0) return 'POSITIVE_TO_ZERO';
  if (previousHp === 0 && currentHp > 0) return 'ZERO_TO_POSITIVE';
  if (previousHp === 0 && currentHp === 0) return 'ZERO_TO_ZERO';
  return 'POSITIVE_TO_POSITIVE';
}

function extractDetailsCombatStateAnchors(input) {
  const gameId = normalizeGameId(input.gameId);
  if (input.replayBuild !== TARGET_REPLAY_BUILD) {
    fail(`Replay ${gameId} build ${input.replayBuild} is not exact target ${TARGET_REPLAY_BUILD}`);
  }
  if (!/^[0-9a-f]{64}$/.test(String(input.replaySha256 ?? ''))) {
    fail(`Replay ${gameId} SHA256 is missing or invalid`);
  }

  const detailsDocument = unwrapSgpDocument(input.detailsDocument, 'DETAILS', 'details');
  const summaryDocument = unwrapSgpDocument(input.summaryDocument, 'SUMMARY', 'summary');
  const summary = summaryDocument.payload;
  const details = detailsDocument.payload;
  if (summary.gameVersion !== TARGET_SUMMARY_BUILD) {
    fail(`SUMMARY ${gameId} build ${summary.gameVersion} is not exact target ${TARGET_SUMMARY_BUILD}`);
  }
  if (String(summary.gameVersion).split('.').slice(0, 2).join('.') !== TARGET_PATCH) {
    fail(`SUMMARY ${gameId} is outside patch ${TARGET_PATCH}`);
  }
  const platformId = String(summary.platformId ?? '').trim();
  if (!platformId) fail(`SUMMARY ${gameId} has no platformId`);
  validateWrapperIdentity(detailsDocument, gameId, platformId, 'DETAILS');
  validateWrapperIdentity(summaryDocument, gameId, platformId, 'SUMMARY');
  const participants = participantMapping(summary);
  const participantById = new Map(participants.map((row) => [row.participant_id, row]));

  if (!Array.isArray(details.frames) || details.frames.length === 0) fail(`DETAILS ${gameId} has no frames`);
  const events = collectEvents(details);
  const deathsByVictim = new Map();
  for (const row of events) {
    if (row.event.type !== 'CHAMPION_KILL' || !Number.isInteger(row.event.victimId)) continue;
    const values = deathsByVictim.get(row.event.victimId) ?? [];
    values.push(row);
    deathsByVictim.set(row.event.victimId, values);
  }

  const records = [];
  const previousByParticipant = new Map();
  let previousFrameTimestamp = -1;
  for (let frameIndex = 0; frameIndex < details.frames.length; frameIndex += 1) {
    const frame = requireObject(details.frames[frameIndex], `DETAILS frame ${frameIndex}`);
    const timestampMs = requireInteger(frame.timestamp, `DETAILS frame ${frameIndex}.timestamp`);
    if (timestampMs <= previousFrameTimestamp) fail(`DETAILS ${gameId} frame timestamps are not strictly increasing`);
    previousFrameTimestamp = timestampMs;
    const participantFrames = requireObject(frame.participantFrames, `DETAILS frame ${frameIndex}.participantFrames`);
    for (const participant of participants) {
      const participantKey = String(participant.participant_id);
      const participantFrame = requireObject(
        participantFrames[participantKey],
        `DETAILS frame ${frameIndex}.participantFrames[${JSON.stringify(participantKey)}]`,
      );
      const championStats = requireObject(
        participantFrame.championStats,
        `DETAILS frame ${frameIndex} participant ${participantKey}.championStats`,
      );
      const currentHp = requireFiniteNumber(championStats.health, `frame ${frameIndex} participant ${participantKey} health`);
      const maxHp = requireFiniteNumber(championStats.healthMax, `frame ${frameIndex} participant ${participantKey} healthMax`);
      const armor = requireFiniteNumber(championStats.armor, `frame ${frameIndex} participant ${participantKey} armor`);
      const magicResist = requireFiniteNumber(
        championStats.magicResist,
        `frame ${frameIndex} participant ${participantKey} magicResist`,
      );
      if (currentHp < 0) fail(`frame ${frameIndex} participant ${participantKey} health cannot be negative`);
      if (maxHp <= 0) fail(`frame ${frameIndex} participant ${participantKey} healthMax must be positive`);
      const level = requireInteger(participantFrame.level, `frame ${frameIndex} participant ${participantKey} level`);
      const previous = previousByParticipant.get(participant.participant_id) ?? null;
      const transition = healthTransition(previous?.current_hp ?? null, currentHp);
      const matchingDeaths = previous
        ? (deathsByVictim.get(participant.participant_id) ?? []).filter((row) => (
          row.timestamp_ms > previous.timestamp_ms && row.timestamp_ms <= timestampMs
        ))
        : [];
      const associatedDeath = matchingDeaths.length > 0 ? matchingDeaths.at(-1) : null;
      const statsPath = `$.json.frames[${frameIndex}].participantFrames[${JSON.stringify(participantKey)}].championStats`;
      const record = {
        schema_version: ANCHOR_SCHEMA_VERSION,
        anchor_type: ANCHOR_TYPE,
        anchor_id: `${gameId}:${timestampMs}:${participant.participant_id}:p0`,
        evidence_grade: ANCHOR_TYPE,
        semantic_scope: 'P0_HERO_COMBAT_STATE',
        game_id: gameId,
        replay_sha256: input.replaySha256,
        replay_build: input.replayBuild,
        timestamp_ms: timestampMs,
        timestamp_kind: 'DETAILS_MINUTE_FRAME_TIMESTAMP_MS',
        entity: {
          id_kind: 'DETAILS_PARTICIPANT_ID',
          participant_id: participant.participant_id,
          champion: participant.champion,
          team_id: participant.team_id,
        },
        participant_id: participant.participant_id,
        champion: participant.champion,
        level,
        current_hp: currentHp,
        max_hp: maxHp,
        armor,
        magic_resist: magicResist,
        health_state: currentHp === 0 ? 'ZERO_HEALTH' : 'POSITIVE_HEALTH',
        frame_boundary_evidence: {
          previous_frame_timestamp_ms: previous?.timestamp_ms ?? null,
          previous_current_hp: previous?.current_hp ?? null,
          health_transition: transition,
          associated_death_event_timestamp_ms: associatedDeath?.timestamp_ms ?? null,
          associated_death_event_json_path: associatedDeath?.source_json_path ?? null,
          respawn_lower_bound_timestamp_ms: transition === 'ZERO_TO_POSITIVE' ? previous.timestamp_ms : null,
          respawn_upper_bound_timestamp_ms: transition === 'ZERO_TO_POSITIVE' ? timestampMs : null,
          exact_respawn_timestamp_available: transition === 'ZERO_TO_POSITIVE' ? false : null,
        },
        source: {
          fact_source: 'LCU_SGP_MATCH_DETAILS_PARTICIPANT_FRAME',
          oracle_role: 'GROUND_TRUTH_FRAME_SNAPSHOT',
          details_sha256: input.detailsSha256,
          summary_sha256: input.summarySha256,
          champion_mapping_source: 'LCU_SGP_MATCH_SUMMARY',
          champion_mapping_json_path: participant.summary_json_path,
          participant_frame_json_path: `$.json.frames[${frameIndex}].participantFrames[${JSON.stringify(participantKey)}]`,
          champion_stats_json_path: statsPath,
          field_json_paths: {
            current_hp: `${statsPath}.health`,
            max_hp: `${statsPath}.healthMax`,
            armor: `${statsPath}.armor`,
            magic_resist: `${statsPath}.magicResist`,
          },
          field_keys: {
            current_hp: 'health',
            max_hp: 'healthMax',
            armor: 'armor',
            magic_resist: 'magicResist',
          },
        },
      };
      records.push(record);
      previousByParticipant.set(participant.participant_id, {
        timestamp_ms: timestampMs,
        current_hp: currentHp,
      });
    }
  }

  const keySampleValidation = validateKeySample(gameId, details, participants, records, events);
  const transitionCounts = {};
  for (const record of records) {
    const key = record.frame_boundary_evidence.health_transition;
    transitionCounts[key] = (transitionCounts[key] ?? 0) + 1;
  }
  return {
    records,
    provenance: {
      game_id: gameId,
      target_patch: TARGET_PATCH,
      replay_build: input.replayBuild,
      summary_game_version: summary.gameVersion,
      replay: {
        path: path.resolve(input.replayPath),
        sha256: input.replaySha256,
        byte_size: input.replayByteSize,
      },
      details: {
        path: path.resolve(input.detailsPath),
        sha256: input.detailsSha256,
        byte_size: input.detailsByteSize,
        wrapper_metadata: sanitizedWrapperMetadata(detailsDocument.metadata),
      },
      summary: {
        path: path.resolve(input.summaryPath),
        sha256: input.summarySha256,
        byte_size: input.summaryByteSize,
        wrapper_metadata: sanitizedWrapperMetadata(summaryDocument.metadata),
      },
      frame_count: details.frames.length,
      participant_count: participants.length,
      anchor_count: records.length,
      zero_health_anchor_count: records.filter((record) => record.current_hp === 0).length,
      health_transition_counts: transitionCounts,
      participant_mapping: participants,
      key_sample_validation: keySampleValidation,
    },
  };
}

function sanitizedWrapperMetadata(metadata) {
  return {
    data_version: metadata.data_version,
    info_type: metadata.info_type,
    match_id: metadata.match_id,
    private: metadata.private,
    product: metadata.product,
    tags: Array.isArray(metadata.tags) ? [...metadata.tags] : [],
    timestamp: metadata.timestamp,
    participant_count: Array.isArray(metadata.participants) ? metadata.participants.length : null,
  };
}

function locateExpectedEvent(events, expectation) {
  return events.find((row) => {
    const event = row.event;
    if (event.type !== expectation.type || row.timestamp_ms !== expectation.timestamp_ms) return false;
    if (expectation.item_id !== undefined && event.itemId !== expectation.item_id) return false;
    if (expectation.victim_participant_id !== undefined && event.victimId !== expectation.victim_participant_id) return false;
    if (expectation.killer_participant_id !== undefined && event.killerId !== expectation.killer_participant_id) return false;
    return true;
  }) ?? null;
}

function validateExpectedP0(record, expected, gameId) {
  if (!record) fail(`key sample ${gameId} is missing frame ${expected.timestamp_ms}`);
  for (const key of ['current_hp', 'max_hp', 'armor', 'magic_resist']) {
    if (record[key] !== expected[key]) {
      fail(`key sample ${gameId} frame ${expected.timestamp_ms} ${key}=${record[key]} expected ${expected[key]}`);
    }
  }
}

function validateKeySample(gameId, details, participants, records, events) {
  const expectation = KEY_SAMPLE_EXPECTATIONS[gameId];
  if (!expectation) return null;
  const participant = participants.find((row) => row.participant_id === expectation.participant_id);
  if (!participant || participant.champion !== expectation.champion) {
    fail(`key sample ${gameId} participant ${expectation.participant_id} champion mismatch`);
  }
  const eventRow = locateExpectedEvent(events, expectation.event);
  if (!eventRow) fail(`key sample ${gameId} expected ${expectation.event.type} event is missing`);
  const frameRows = expectation.frames.map((expected) => {
    const record = records.find((row) => row.participant_id === expectation.participant_id
      && row.timestamp_ms === expected.timestamp_ms);
    validateExpectedP0(record, expected, gameId);
    return record;
  });

  const result = {
    status: 'VALIDATED',
    role: expectation.role,
    participant_id: expectation.participant_id,
    champion: expectation.champion,
    event: {
      type: expectation.event.type,
      timestamp_ms: expectation.event.timestamp_ms,
      source_json_path: eventRow.source_json_path,
    },
    frame_anchor_ids: frameRows.map((row) => row.anchor_id),
    frame_p0: frameRows.map((row) => ({
      timestamp_ms: row.timestamp_ms,
      current_hp: row.current_hp,
      max_hp: row.max_hp,
      armor: row.armor,
      magic_resist: row.magic_resist,
      health_transition: row.frame_boundary_evidence.health_transition,
    })),
  };

  if (expectation.event.type === 'ITEM_PURCHASED') {
    const event = eventRow.event;
    if (event.participantId !== expectation.participant_id) fail(`key sample ${gameId} item participant mismatch`);
    result.event.item_id = event.itemId;
    const nextFrameTimestamp = expectation.frames.at(-1).timestamp_ms;
    const postEvents = events.filter((row) => row.timestamp_ms > eventRow.timestamp_ms
      && row.timestamp_ms <= nextFrameTimestamp);
    const forbidden = postEvents.filter((row) => ['ITEM_SOLD', 'ITEM_UNDO', 'LEVEL_UP', 'CHAMPION_KILL'].includes(row.event.type));
    if (forbidden.length > 0) fail(`key sample ${gameId} has forbidden post-purchase events before the target frame`);
    result.post_purchase_to_target_frame = {
      target_frame_timestamp_ms: nextFrameTimestamp,
      interval_ms: nextFrameTimestamp - eventRow.timestamp_ms,
      event_count: postEvents.length,
      forbidden_event_count: forbidden.length,
    };
  } else {
    const event = eventRow.event;
    const damage = event.victimDamageReceived;
    const teamfightDamage = event.victimTeamfightDamageReceived;
    if (!Array.isArray(damage) || damage.length !== 1
      || !Array.isArray(teamfightDamage) || teamfightDamage.length !== 1) {
      fail(`key sample ${gameId} death damage rows are no longer strict singletons`);
    }
    const row = damage[0];
    if (row.participantId !== expectation.event.killer_participant_id
      || row.name !== expectation.event.source_champion
      || row.magicDamage !== expectation.event.magic_damage) {
      fail(`key sample ${gameId} singleton damage evidence changed`);
    }
    result.event.killer_participant_id = event.killerId;
    result.event.victim_participant_id = event.victimId;
    result.event.damage_received_json_path = `${eventRow.source_json_path}.victimDamageReceived[0]`;
    result.event.damage_received = {
      source_participant_id: row.participantId,
      source_champion: row.name,
      spell_name: row.spellName,
      physical_damage: row.physicalDamage,
      magic_damage: row.magicDamage,
      true_damage: row.trueDamage,
    };
    const zeroFrame = frameRows.find((record) => record.current_hp === 0);
    const positiveAfterZero = zeroFrame
      ? frameRows.find((record) => record.timestamp_ms > zeroFrame.timestamp_ms && record.current_hp > 0)
      : null;
    if (!zeroFrame || !positiveAfterZero) fail(`key sample ${gameId} death/respawn frame boundary is missing`);
    result.death_respawn_frame_bound = {
      death_event_timestamp_ms: eventRow.timestamp_ms,
      zero_health_frame_timestamp_ms: zeroFrame.timestamp_ms,
      respawn_lower_bound_timestamp_ms: zeroFrame.timestamp_ms,
      respawn_upper_bound_timestamp_ms: positiveAfterZero.timestamp_ms,
      exact_respawn_timestamp_available: false,
    };
  }
  return result;
}

function readJsonFileWithHash(filePath, label) {
  const resolved = path.resolve(filePath);
  let buffer;
  try {
    buffer = fs.readFileSync(resolved);
  } catch (error) {
    fail(`cannot read ${label} ${resolved}: ${error.message}`);
  }
  let document;
  try {
    document = JSON.parse(buffer.toString('utf8'));
  } catch (error) {
    fail(`${label} ${resolved} is invalid JSON: ${error.message}`);
  }
  return { path: resolved, buffer, document, sha256: sha256Buffer(buffer), byte_size: buffer.length };
}

function assertExpectedHash(gameId, kind, actual) {
  const expected = KEY_SAMPLE_EXPECTATIONS[gameId]?.hashes?.[kind];
  if (expected && actual !== expected) fail(`key sample ${gameId} ${kind} SHA256 ${actual} does not match ${expected}`);
}

function loadSample(sample) {
  const gameId = normalizeGameId(sample.gameId);
  const replayPath = path.resolve(sample.replayPath);
  const replay = parseReplayFile(replayPath);
  assertExpectedHash(gameId, 'replay', replay.source_sha256);
  const details = readJsonFileWithHash(sample.detailsPath, 'DETAILS');
  const summary = readJsonFileWithHash(sample.summaryPath, 'SUMMARY');
  assertExpectedHash(gameId, 'details', details.sha256);
  assertExpectedHash(gameId, 'summary', summary.sha256);
  return extractDetailsCombatStateAnchors({
    gameId,
    replayPath,
    replaySha256: replay.source_sha256,
    replayByteSize: replay.file_size,
    replayBuild: replay.header.version,
    detailsPath: details.path,
    detailsSha256: details.sha256,
    detailsByteSize: details.byte_size,
    detailsDocument: details.document,
    summaryPath: summary.path,
    summarySha256: summary.sha256,
    summaryByteSize: summary.byte_size,
    summaryDocument: summary.document,
  });
}

function assertRequiredKeySamples(gameIds) {
  const included = new Set(gameIds.map(normalizeGameId));
  const missing = REQUIRED_KEY_GAME_IDS.filter((gameId) => !included.has(gameId));
  if (missing.length > 0) fail(`required key samples are missing: ${missing.join(', ')}`);
}

function buildDetailsCombatStateArtifacts(samples, options = {}) {
  if (!Array.isArray(samples) || samples.length === 0) fail('at least one explicit sample is required');
  const gameIds = samples.map((sample) => normalizeGameId(sample.gameId));
  if (new Set(gameIds).size !== gameIds.length) fail('duplicate sample game ids are not allowed');
  if (options.requireKeySamples !== false) assertRequiredKeySamples(gameIds);
  const loaded = samples.map(loadSample).sort((left, right) => (
    Number(left.provenance.game_id) - Number(right.provenance.game_id)
  ));
  const records = loaded.flatMap((entry) => entry.records).sort((left, right) => (
    Number(left.game_id) - Number(right.game_id)
    || left.timestamp_ms - right.timestamp_ms
    || left.participant_id - right.participant_id
  ));
  const jsonlPath = path.resolve(options.jsonlPath);
  const manifestPath = path.resolve(options.manifestPath);
  writeJsonl(jsonlPath, records);
  const jsonlBuffer = fs.readFileSync(jsonlPath);
  const manifest = {
    schema_version: MANIFEST_SCHEMA_VERSION,
    anchor_schema_version: ANCHOR_SCHEMA_VERSION,
    anchor_type: ANCHOR_TYPE,
    deterministic: true,
    generated_at_omitted_for_reproducibility: true,
    target: {
      patch: TARGET_PATCH,
      replay_header_build: TARGET_REPLAY_BUILD,
      summary_game_version: TARGET_SUMMARY_BUILD,
      exact_build_required: true,
      nearest_build_fallback_allowed: false,
    },
    scope: {
      source: 'EXPLICIT_PAIRED_DETAILS_INPUTS_ONLY',
      protected_holdout_enumerated: false,
      protected_holdout_read: false,
      network_acquisition_performed: false,
    },
    record_schema: {
      unit: 'MINUTE_FRAME_X_PARTICIPANT',
      required_p0_fields: ['current_hp', 'max_hp', 'armor', 'magic_resist'],
      source_json_path_template: '$.json.frames[FRAME_INDEX].participantFrames["PARTICIPANT_ID"].championStats',
      source_keys: {
        current_hp: 'health',
        max_hp: 'healthMax',
        armor: 'armor',
        magic_resist: 'magicResist',
      },
    },
    replay_count: loaded.length,
    record_count: records.length,
    zero_health_record_count: records.filter((record) => record.current_hp === 0).length,
    positive_to_zero_transition_count: records.filter((record) => (
      record.frame_boundary_evidence.health_transition === 'POSITIVE_TO_ZERO'
    )).length,
    zero_to_positive_transition_count: records.filter((record) => (
      record.frame_boundary_evidence.health_transition === 'ZERO_TO_POSITIVE'
    )).length,
    required_key_game_ids: REQUIRED_KEY_GAME_IDS,
    included_key_game_ids: loaded
      .map((entry) => entry.provenance.game_id)
      .filter((gameId) => KEY_SAMPLE_EXPECTATIONS[gameId])
      .sort(),
    jsonl: {
      path: jsonlPath,
      sha256: sha256Buffer(jsonlBuffer),
      byte_size: jsonlBuffer.length,
      line_count: records.length,
    },
    replays: loaded.map((entry) => entry.provenance),
  };
  writeJson(manifestPath, manifest);
  return { jsonlPath, manifestPath, records, manifest };
}

module.exports = {
  ANCHOR_SCHEMA_VERSION,
  ANCHOR_TYPE,
  KEY_SAMPLE_EXPECTATIONS,
  MANIFEST_SCHEMA_VERSION,
  REQUIRED_KEY_GAME_IDS,
  TARGET_PATCH,
  TARGET_REPLAY_BUILD,
  TARGET_SUMMARY_BUILD,
  assertRequiredKeySamples,
  buildDetailsCombatStateArtifacts,
  extractDetailsCombatStateAnchors,
  healthTransition,
  loadSample,
  normalizeGameId,
  participantMapping,
  sha256Buffer,
  unwrapSgpDocument,
  validateKeySample,
};
