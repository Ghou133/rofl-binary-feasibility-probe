const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  BUFF_PROFILES,
  CAST_SPELL_PROFILE,
  DAMAGE_PROFILE,
  LEVEL_UP_PROFILE,
  ON_EVENT_PROFILE,
  PROFILE: DEATH_PROFILE,
  SHIELD_DAMAGE_PROFILE,
  buffEventFromDecodedRow,
  damageEventFromDecodedRow,
  decodeHeroDeaths,
  isOnEventDecodedRow,
  isLevelTransitionDecodedRow,
  isShieldDamageDecodedRow,
  participantIdFromChampionNetworkId,
  participantMetadata,
  levelTransitionEventFromDecodedRow,
  protectionEventFromDecodedRow,
  shieldAbsorptionProtectionEventFromDecodedRow,
  spellEventFromDecodedRow,
} = require('./decoders/rofl_16_15_801_3452');
const { buildAdcDeathRecord, buildCombatWindow, protectionEvent } = require('./events');
const { queryLevelTransitions, summarizeLevelSequences } = require('./level_transition');
const { normalizePlayers, sha256, walkBlocks } = require('./rofl');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const DEFAULT_DECODER_IMAGE = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'runtime_probe',
  'league_16.15.801.3452.memory.bin',
);
const DEFAULT_SPELL_DICTIONARY = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'runtime_probe',
  'spell_dictionary_16.15.json',
);
const DAMAGE_GAP_MS = 2500;
const COMBAT_RULE_VERSION = 'victim-champion-damage-gap-v1';

function gameIdFromReplayPath(filePath) {
  return /(?:^|[-_])([0-9]+)\.rofl$/i.exec(path.basename(filePath))?.[1] ?? null;
}

function damageExportRow(replay, chunk, block, occurrenceIndex) {
  return {
    schema_version: 1,
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    replay_label: path.basename(replay.source_path, path.extname(replay.source_path)),
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    compressed_body_offset: chunk.body_offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    replay_time_ms: block.timestamp_ms,
    occurrence_index: occurrenceIndex,
    packet_id: block.packet_id,
    packet_type: block.packet_type,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_param_hex: `0x${(block.param >>> 0).toString(16).padStart(8, '0')}`,
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: sha256(block.payload),
  };
}

function exportProfilePackets(replay, outputPath, profile, options = {}) {
  const output = fs.openSync(outputPath, 'w');
  let count = 0;
  let walk;
  try {
    walk = walkBlocks(replay, (block, chunk) => {
      if (chunk.stream_tag !== profile.stream_tag
          || block.packet_id !== profile.replay_block_packet_id
          || (Number.isFinite(options.maxTimeMs) && block.timestamp_ms > options.maxTimeMs)) return;
      fs.writeSync(output, `${JSON.stringify(damageExportRow(replay, chunk, block, count))}\n`);
      count += 1;
    }, { includeStreams: [profile.stream_tag], strict: true });
  } finally {
    fs.closeSync(output);
  }
  if (walk.errors.length > 0) throw new Error('semantic packet export encountered framing errors');
  const resolvedOutput = path.resolve(outputPath);
  const replayPath = replay.source_path || `<memory:${replay.source_sha256}>`;
  const packetId = profile.replay_block_packet_id;
  const manifest = {
    schema_version: 1,
    target_replay_version: profile.replay_version,
    output: resolvedOutput,
    packet_ids: [packetId],
    selected_packet_count: count,
    packet_counts: { [packetId]: count },
    replay_count: 1,
    replays: [{
      path: replayPath,
      sha256: replay.source_sha256,
      version: replay.header.version,
      selected_packet_count: count,
      parser_error_count: 0,
    }],
    max_time_ms: Number.isFinite(options.maxTimeMs) ? options.maxTimeMs : null,
  };
  fs.writeFileSync(`${resolvedOutput}.manifest.json`, `${JSON.stringify(manifest, null, 2)}\n`);
  return count;
}

function exportDamagePackets(replay, outputPath) {
  return exportProfilePackets(replay, outputPath, DAMAGE_PROFILE);
}

function exportCastSpellPackets(replay, outputPath) {
  return exportProfilePackets(replay, outputPath, CAST_SPELL_PROFILE);
}

function exportShieldDamagePackets(replay, outputPath) {
  return exportProfilePackets(replay, outputPath, SHIELD_DAMAGE_PROFILE);
}

function exportLevelTransitionPackets(replay, outputPath, options = {}) {
  return exportProfilePackets(replay, outputPath, LEVEL_UP_PROFILE, options);
}

function sha256FileSync(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function verifiedDecoderImage(options = {}) {
  const imagePath = path.resolve(options.decoderImage || DEFAULT_DECODER_IMAGE);
  if (!fs.existsSync(imagePath)) {
    const error = new Error(`required decoder image is missing: ${imagePath}`);
    error.code = 'MISSING_DECODER_IMAGE';
    throw error;
  }
  const imageSha256 = sha256FileSync(imagePath);
  if (imageSha256 !== DAMAGE_PROFILE.runtime_image_sha256) {
    const error = new Error(
      `decoder image SHA-256 mismatch: expected ${DAMAGE_PROFILE.runtime_image_sha256}, got ${imageSha256}`,
    );
    error.code = 'DECODER_IMAGE_MISMATCH';
    throw error;
  }
  return { imagePath, imageSha256 };
}

function runLevelTransitionDecoder(replay, options = {}) {
  if (replay.header.version !== LEVEL_UP_PROFILE.replay_version) {
    const error = new Error(
      `decoder ${LEVEL_UP_PROFILE.id} only supports ${LEVEL_UP_PROFILE.replay_version}; got ${replay.header.version}`,
    );
    error.code = 'UNSUPPORTED_REPLAY_VERSION';
    throw error;
  }
  const { imagePath } = verifiedDecoderImage(options);
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-analyzer-'));
  const exportedPath = path.join(temporaryDirectory, 'level_transition_packets.jsonl');
  const decodedPath = path.join(temporaryDirectory, 'level_transition_decoded.jsonl');
  const summaryPath = path.join(temporaryDirectory, 'level_transition_summary.json');
  try {
    const exportedPacketCount = exportLevelTransitionPackets(replay, exportedPath, options);
    const sourceRows = fs.readFileSync(exportedPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    if (sourceRows.length !== exportedPacketCount) {
      const error = new Error('LevelUp source packet export failed structural verification');
      error.code = 'LEVEL_TRANSITION_SOURCE_VERIFICATION_FAILED';
      throw error;
    }
    const python = options.python || process.env.ROFL_ANALYZER_PYTHON || 'python';
    const script = path.join(REPOSITORY_ROOT, 'scripts', 'decode_level_transition.py');
    const result = childProcess.spawnSync(python, [
      script,
      '--image', imagePath,
      '--events', exportedPath,
      '--output', decodedPath,
      '--summary', summaryPath,
      '--progress-every', '0',
    ], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      timeout: options.decoderTimeoutMs || 120000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const error = new Error(
        `Unicorn LevelUp decoder failed: ${(result.stderr || result.error?.message || '').trim()}`,
      );
      error.code = 'LEVEL_TRANSITION_DECODER_FAILED';
      throw error;
    }

    const decoderSummary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    if (decoderSummary.event_count !== exportedPacketCount
        || decoderSummary.successful_full_consume_count !== exportedPacketCount
        || decoderSummary.output_event_count !== exportedPacketCount
        || decoderSummary.decoder_profile !== LEVEL_UP_PROFILE.id
        || decoderSummary.image_sha256 !== LEVEL_UP_PROFILE.runtime_image_sha256
        || decoderSummary.events_sha256 !== sha256FileSync(exportedPath)
        || decoderSummary.output_sha256 !== sha256FileSync(decodedPath)
        || decoderSummary.decoder_script_sha256 !== sha256FileSync(script)
        || decoderSummary.client_opcode !== '0x025a'
        || decoderSummary.constructor_rva !== '0x00e82060'
        || decoderSummary.deserialize_rva !== '0x00efaa50'
        || decoderSummary.object_size !== LEVEL_UP_PROFILE.object_size) {
      const error = new Error('LevelUp decoder summary failed structural verification');
      error.code = 'LEVEL_TRANSITION_DECODER_VERIFICATION_FAILED';
      throw error;
    }

    const rows = fs.readFileSync(decodedPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    const invalidRowIndex = rows.findIndex((row, index) => !isLevelTransitionDecodedRow(
      replay,
      row,
      sourceRows[index],
    ));
    if (rows.length !== exportedPacketCount || invalidRowIndex !== -1) {
      const error = new Error(
        `decoded LevelUp rows failed structural verification (row ${invalidRowIndex})`,
      );
      error.code = 'LEVEL_TRANSITION_EVENT_BUILD_FAILED';
      throw error;
    }

    const participants = participantMetadata(replay);
    const events = rows
      .map((row, index) => levelTransitionEventFromDecodedRow(
        replay,
        row,
        participants,
        sourceRows[index],
      ))
      .filter(Boolean);
    const heroPacketCount = rows.filter(
      (row) => participantIdFromChampionNetworkId(row.raw_param) !== null,
    ).length;
    if (events.length !== heroPacketCount) {
      const error = new Error('hero LevelTransition event selection failed verification');
      error.code = 'LEVEL_TRANSITION_EVENT_BUILD_FAILED';
      throw error;
    }
    const sequence = summarizeLevelSequences(events);
    const initializationCount = events.filter((event) => event.is_initialization).length;
    const mappedEvents = events.filter((event) => Number.isInteger(event.level_after));
    const mappedLevelCounts = Object.fromEntries(
      [...new Set(mappedEvents.map((event) => event.level_after))]
        .sort((left, right) => left - right)
        .map((level) => [level, mappedEvents.filter((event) => event.level_after === level).length]),
    );
    return {
      rows,
      events,
      summary: {
        ...decoderSummary,
        exported_packet_count: exportedPacketCount,
        hero_transition_packet_count: events.length,
        non_hero_packet_count: rows.length - events.length,
        initialization_event_count: initializationCount,
        mapped_level_event_count: mappedEvents.length,
        unmapped_non_initialization_event_count: events.length
          - initializationCount - mappedEvents.length,
        mapped_level_counts: mappedLevelCounts,
        sequence,
        packet_structure_status: 'VERIFIED_DIRECT',
        transition_status: 'VERIFIED_DIRECT',
        level_after_mapping_status: 'VERIFIED_DERIVED',
        level_after_mapping_version: LEVEL_UP_PROFILE.level_mapping_version,
        version_qualification: `PATCH_BOUND_TO_${LEVEL_UP_PROFILE.level_mapping_version}`,
        max_time_ms: Number.isFinite(options.maxTimeMs) ? options.maxTimeMs : null,
        decoder_image_path: imagePath,
      },
    };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function runDamageDecoder(replay, options = {}) {
  const { imagePath } = verifiedDecoderImage(options);

  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-analyzer-'));
  const exportedPath = path.join(temporaryDirectory, 'damage_packets.jsonl');
  const decodedPath = path.join(temporaryDirectory, 'damage_decoded.jsonl');
  const summaryPath = path.join(temporaryDirectory, 'damage_summary.json');
  try {
    const exportedPacketCount = exportDamagePackets(replay, exportedPath);
    const python = options.python || process.env.ROFL_ANALYZER_PYTHON || 'python';
    const script = path.join(REPOSITORY_ROOT, 'scripts', 'emulate_selected_packet_decoder.py');
    const result = childProcess.spawnSync(python, [
      script,
      '--image', imagePath,
      '--events', exportedPath,
      '--profile', 'unit_apply_damage',
      '--output', decodedPath,
      '--summary', summaryPath,
      '--output-scope', 'hero-pair-positive',
      '--progress-every', '0',
    ], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
      timeout: options.decoderTimeoutMs || 120000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const error = new Error(
        `Unicorn damage decoder failed: ${(result.stderr || result.error?.message || '').trim()}`,
      );
      error.code = 'DAMAGE_DECODER_FAILED';
      throw error;
    }
    const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    if (summary.event_count !== exportedPacketCount
        || summary.successful_full_consume_count !== exportedPacketCount
        || summary.image_sha256 !== DAMAGE_PROFILE.runtime_image_sha256) {
      const error = new Error('damage decoder summary failed structural verification');
      error.code = 'DAMAGE_DECODER_VERIFICATION_FAILED';
      throw error;
    }

    const participants = participantMetadata(replay);
    const events = fs.readFileSync(decodedPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => damageEventFromDecodedRow(replay, JSON.parse(line), participants));
    if (events.some((event) => event === null)
        || events.length !== summary.champion_pair_positive_amount_count
        || events.length !== summary.output_event_count) {
      const error = new Error('decoded damage event selection failed verification');
      error.code = 'DAMAGE_EVENT_BUILD_FAILED';
      throw error;
    }
    return {
      events,
      summary: {
        ...summary,
        exported_packet_count: exportedPacketCount,
        semantic_output_event_count: events.length,
        decoder_image_path: imagePath,
      },
    };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function runCastSpellDecoder(replay, options = {}) {
  const { imagePath } = verifiedDecoderImage(options);
  const dictionaryPath = path.resolve(options.spellDictionary || DEFAULT_SPELL_DICTIONARY);
  if (!fs.existsSync(dictionaryPath)) {
    const error = new Error(`required spell dictionary is missing: ${dictionaryPath}`);
    error.code = 'MISSING_SPELL_DICTIONARY';
    throw error;
  }
  const dictionarySha256 = sha256FileSync(dictionaryPath);
  if (dictionarySha256 !== CAST_SPELL_PROFILE.spell_dictionary_sha256) {
    const error = new Error(
      `spell dictionary SHA-256 mismatch: expected ${CAST_SPELL_PROFILE.spell_dictionary_sha256}, got ${dictionarySha256}`,
    );
    error.code = 'SPELL_DICTIONARY_MISMATCH';
    throw error;
  }
  const dictionary = JSON.parse(fs.readFileSync(dictionaryPath, 'utf8'));
  if (dictionary.patch !== '16.15' || dictionary.details_or_oracle_input !== false) {
    const error = new Error('spell dictionary metadata failed structural verification');
    error.code = 'SPELL_DICTIONARY_VERIFICATION_FAILED';
    throw error;
  }

  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-analyzer-'));
  const exportedPath = path.join(temporaryDirectory, 'cast_spell_packets.jsonl');
  const decodedPath = path.join(temporaryDirectory, 'cast_spell_decoded.jsonl');
  const summaryPath = path.join(temporaryDirectory, 'cast_spell_summary.json');
  try {
    const exportedPacketCount = exportCastSpellPackets(replay, exportedPath);
    const python = options.python || process.env.ROFL_ANALYZER_PYTHON || 'python';
    const script = path.join(REPOSITORY_ROOT, 'scripts', 'emulate_selected_packet_decoder.py');
    const result = childProcess.spawnSync(python, [
      script,
      '--image', imagePath,
      '--events', exportedPath,
      '--profile', 'cast_spell',
      '--output', decodedPath,
      '--summary', summaryPath,
      '--progress-every', '0',
    ], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      timeout: options.decoderTimeoutMs || 120000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const error = new Error(
        `Unicorn CastSpell decoder failed: ${(result.stderr || result.error?.message || '').trim()}`,
      );
      error.code = 'CAST_SPELL_DECODER_FAILED';
      throw error;
    }
    const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    if (summary.event_count !== exportedPacketCount
        || summary.successful_full_consume_count !== exportedPacketCount
        || summary.image_sha256 !== CAST_SPELL_PROFILE.runtime_image_sha256) {
      const error = new Error('CastSpell decoder summary failed structural verification');
      error.code = 'CAST_SPELL_DECODER_VERIFICATION_FAILED';
      throw error;
    }

    const participants = participantMetadata(replay);
    const rows = fs.readFileSync(decodedPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    const events = rows
      .map((row) => spellEventFromDecodedRow(replay, row, dictionary, participants))
      .filter(Boolean);
    annotatePlayerCastGroups(events);
    const heroCasterRowCount = rows.filter((row) => participantIdFromChampionNetworkId(
      row.decoded_fields?.caster_network_id,
    ) !== null).length;
    if (rows.length !== exportedPacketCount || events.length !== heroCasterRowCount) {
      const error = new Error('decoded CastSpell row count failed verification');
      error.code = 'CAST_SPELL_EVENT_BUILD_FAILED';
      throw error;
    }
    return {
      events,
      summary: {
        ...summary,
        exported_packet_count: exportedPacketCount,
        semantic_output_event_count: events.length,
        non_champion_caster_count: rows.length - heroCasterRowCount,
        primary_player_ability_count: events.filter(
          (event) => event.is_primary_player_ability,
        ).length,
        primary_player_cast_count: events.filter(
          (event) => event.is_player_cast_group_leader,
        ).length,
        decoder_image_path: imagePath,
        spell_dictionary_path: dictionaryPath,
        spell_dictionary_sha256: dictionarySha256,
      },
    };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function buffEventOrder(left, right) {
  return left.replay_time_ms - right.replay_time_ms
    || left.raw_packet_ref.chunk_index - right.raw_packet_ref.chunk_index
    || left.raw_packet_ref.decompressed_block_offset
      - right.raw_packet_ref.decompressed_block_offset;
}

function buffLifecycleId(event) {
  const raw = event.raw_packet_ref;
  return [
    raw.replay_sha256,
    raw.chunk_index,
    raw.decompressed_block_offset,
  ].join(':');
}

function annotateBuffLifecycles(events, options = {}) {
  const durationToleranceSeconds = options.durationToleranceSeconds ?? 0.25;
  const active = new Map();
  const latestByHash = new Map();
  const summary = {
    event_count: events.length,
    add_count: 0,
    remove_count: 0,
    update_count: 0,
    remove_target_slot_match_count: 0,
    remove_active_hash_match_count: 0,
    remove_hash_match_count: 0,
    update_target_slot_match_count: 0,
    update_caster_match_count: 0,
    update_duration_sum_test_count: 0,
    update_duration_sum_match_count: 0,
    superseded_add_count: 0,
    active_at_replay_end_count: 0,
    duration_tolerance_seconds: durationToleranceSeconds,
  };

  events.sort(buffEventOrder);
  for (const event of events) {
    const slotKey = `${event.target_network_id}:${event.buff_slot}`;
    event.lifecycle_match_status = 'UNMATCHED';
    event.matched_add_raw_packet_ref = null;
    event.duration_sum_delta_seconds = null;
    if (event.buff_operation === 'ADD') {
      summary.add_count += 1;
      const previous = active.get(slotKey);
      if (previous && previous.lifecycle_match_status === 'OPEN') {
        previous.lifecycle_match_status = 'SUPERSEDED_BY_ADD';
        summary.superseded_add_count += 1;
      }
      event.lifecycle_id = buffLifecycleId(event);
      event.lifecycle_match_status = 'OPEN';
      active.set(slotKey, event);
      latestByHash.set(`${slotKey}:${event.buff_name_hash}`, event);
      continue;
    }

    if (event.buff_operation === 'UPDATE_COUNT') {
      summary.update_count += 1;
      const add = active.get(slotKey);
      if (!add) continue;
      summary.update_target_slot_match_count += 1;
      event.lifecycle_id = add.lifecycle_id;
      event.matched_add_raw_packet_ref = add.raw_packet_ref;
      const casterMatches = add.source_network_id === event.source_network_id;
      event.lifecycle_match_status = casterMatches
        ? 'MATCHED_TARGET_SLOT_CASTER'
        : 'MATCHED_TARGET_SLOT_ONLY';
      if (casterMatches) {
        summary.update_caster_match_count += 1;
        event.buff_name_hash = add.buff_name_hash;
        event.buff_name_hash_hex = add.buff_name_hash_hex;
        event.buff_type = add.buff_type;
        event.field_confidence.buff_name_hash = 'VERIFIED_DERIVED';
        event.field_confidence.buff_type = 'VERIFIED_DERIVED';
      }
      const durationSum = event.duration_seconds + event.running_time_seconds;
      if (Number.isFinite(durationSum) && Number.isFinite(add.duration_seconds)) {
        summary.update_duration_sum_test_count += 1;
        event.duration_sum_delta_seconds = durationSum - add.duration_seconds;
        if (Math.abs(event.duration_sum_delta_seconds) <= durationToleranceSeconds) {
          summary.update_duration_sum_match_count += 1;
        }
      }
      continue;
    }

    summary.remove_count += 1;
    const current = active.get(slotKey);
    if (current) summary.remove_target_slot_match_count += 1;
    if (current?.buff_name_hash === event.buff_name_hash) {
      summary.remove_active_hash_match_count += 1;
    }
    const add = current?.buff_name_hash === event.buff_name_hash
      ? current
      : latestByHash.get(`${slotKey}:${event.buff_name_hash}`) ?? null;
    if (!add) continue;
    summary.remove_hash_match_count += 1;
    event.lifecycle_id = add.lifecycle_id;
    event.lifecycle_match_status = current === add
      ? 'MATCHED_ACTIVE_ADD_HASH'
      : 'MATCHED_RECENT_ADD_HASH';
    event.matched_add_raw_packet_ref = add.raw_packet_ref;
    add.lifecycle_match_status = 'CLOSED_BY_REMOVE';
    add.matched_remove_raw_packet_ref = event.raw_packet_ref;
    if (current === add) active.delete(slotKey);
  }

  for (const event of active.values()) {
    if (event.lifecycle_match_status === 'OPEN') {
      event.lifecycle_match_status = 'ACTIVE_AT_REPLAY_END';
      summary.active_at_replay_end_count += 1;
    }
  }
  summary.remove_hash_match_rate = summary.remove_count === 0
    ? null
    : summary.remove_hash_match_count / summary.remove_count;
  summary.remove_active_hash_consistency = summary.remove_target_slot_match_count === 0
    ? null
    : summary.remove_active_hash_match_count / summary.remove_target_slot_match_count;
  summary.update_caster_match_rate = summary.update_target_slot_match_count === 0
    ? null
    : summary.update_caster_match_count / summary.update_target_slot_match_count;
  summary.update_duration_sum_match_rate = summary.update_duration_sum_test_count === 0
    ? null
    : summary.update_duration_sum_match_count / summary.update_duration_sum_test_count;
  return summary;
}

function annotateBuffSpellCorrelations(buffEvents, spellEvents) {
  const byCasterTargetTime = new Map();
  for (const spell of spellEvents) {
    if (!spell.is_player_cast_group_leader) continue;
    for (const target of spell.targets || []) {
      const key = `${spell.replay_time_ms}:${spell.caster_network_id}:${target.network_id}`;
      let candidates = byCasterTargetTime.get(key);
      if (!candidates) {
        candidates = [];
        byCasterTargetTime.set(key, candidates);
      }
      candidates.push(spell);
    }
  }
  const summary = {
    add_event_count: 0,
    exact_timestamp_caster_target_match_count: 0,
    protection_buff_match_count: 0,
    ambiguous_match_count: 0,
    spell_buff_hashes: {},
  };
  for (const event of buffEvents) {
    event.origin_spell_cast_group_id = null;
    event.origin_spell_identifier = null;
    event.origin_spell_slot = null;
    event.protection_cast_kind = null;
    event.spell_correlation_status = 'UNMATCHED';
    if (event.buff_operation !== 'ADD') continue;
    summary.add_event_count += 1;
    const key = `${event.replay_time_ms}:${event.source_network_id}:${event.target_network_id}`;
    const candidates = byCasterTargetTime.get(key) || [];
    const unique = [...new Map(candidates.map((spell) => [
      spell.player_cast_group_id,
      spell,
    ])).values()];
    if (unique.length !== 1) {
      if (unique.length > 1) {
        summary.ambiguous_match_count += 1;
        event.spell_correlation_status = 'AMBIGUOUS';
      }
      continue;
    }
    const spell = unique[0];
    summary.exact_timestamp_caster_target_match_count += 1;
    event.origin_spell_cast_group_id = spell.player_cast_group_id;
    event.origin_spell_identifier = spell.spell_identifier;
    event.origin_spell_slot = spell.spell_slot;
    event.protection_cast_kind = spell.protection_cast_kind;
    event.spell_correlation_status = 'EXACT_TIMESTAMP_CASTER_TARGET';
    event.field_confidence.origin_spell_identifier = spell.spell_identifier
      ? 'VERIFIED_DERIVED'
      : 'UNAVAILABLE';
    event.field_confidence.origin_spell_slot = spell.spell_slot
      ? 'VERIFIED_DERIVED'
      : 'UNAVAILABLE';
    event.field_confidence.protection_cast_kind = spell.protection_cast_kind
      ? 'VERIFIED_DERIVED'
      : 'UNAVAILABLE';
    if (spell.protection_cast_kind) {
      summary.protection_buff_match_count += 1;
      const spellName = spell.spell_identifier || spell.spell_key_hex;
      const hashes = summary.spell_buff_hashes[spellName] || new Set();
      hashes.add(event.buff_name_hash_hex);
      summary.spell_buff_hashes[spellName] = hashes;
    }
  }
  summary.spell_buff_hashes = Object.fromEntries(
    Object.entries(summary.spell_buff_hashes).map(([spell, hashes]) => (
      [spell, [...hashes].sort()]
    )),
  );
  return summary;
}

function runBuffDecoder(replay, options = {}) {
  const { imagePath } = verifiedDecoderImage(options);
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-analyzer-'));
  const events = [];
  const profiles = {};
  try {
    for (const [name, profile] of Object.entries(BUFF_PROFILES)) {
      const exportedPath = path.join(temporaryDirectory, `buff_${name}_packets.jsonl`);
      const decodedPath = path.join(temporaryDirectory, `buff_${name}_decoded.jsonl`);
      const summaryPath = path.join(temporaryDirectory, `buff_${name}_summary.json`);
      const exportedPacketCount = exportProfilePackets(replay, exportedPath, profile);
      const python = options.python || process.env.ROFL_ANALYZER_PYTHON || 'python';
      const script = path.join(REPOSITORY_ROOT, 'scripts', 'emulate_selected_packet_decoder.py');
      const result = childProcess.spawnSync(python, [
        script,
        '--image', imagePath,
        '--events', exportedPath,
        '--profile', profile.emulator_profile,
        '--output', decodedPath,
        '--summary', summaryPath,
        '--progress-every', '0',
      ], {
        cwd: REPOSITORY_ROOT,
        encoding: 'utf8',
        maxBuffer: 8 * 1024 * 1024,
        timeout: options.decoderTimeoutMs || 120000,
        windowsHide: true,
      });
      if (result.error || result.status !== 0) {
        const error = new Error(
          `Unicorn ${profile.emulator_profile} decoder failed: ${(
            result.stderr || result.error?.message || ''
          ).trim()}`,
        );
        error.code = 'BUFF_DECODER_FAILED';
        throw error;
      }
      const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
      if (summary.event_count !== exportedPacketCount
          || summary.successful_full_consume_count !== exportedPacketCount
          || summary.output_event_count !== exportedPacketCount
          || summary.image_sha256 !== profile.runtime_image_sha256) {
        const error = new Error(`${profile.emulator_profile} summary failed structural verification`);
        error.code = 'BUFF_DECODER_VERIFICATION_FAILED';
        throw error;
      }
      const participants = participantMetadata(replay);
      const profileEvents = fs.readFileSync(decodedPath, 'utf8')
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => buffEventFromDecodedRow(
          replay,
          JSON.parse(line),
          profile,
          participants,
        ));
      if (profileEvents.some((event) => event === null)
          || profileEvents.length !== exportedPacketCount) {
        const error = new Error(`${profile.emulator_profile} event build failed verification`);
        error.code = 'BUFF_EVENT_BUILD_FAILED';
        throw error;
      }
      events.push(...profileEvents);
      profiles[name] = {
        ...summary,
        exported_packet_count: exportedPacketCount,
        semantic_output_event_count: profileEvents.length,
        decoder_image_path: imagePath,
      };
    }
    const lifecycle = annotateBuffLifecycles(events);
    return {
      events,
      summary: {
        event_count: events.length,
        successful_full_consume_count: Object.values(profiles).reduce(
          (sum, profile) => sum + profile.successful_full_consume_count,
          0,
        ),
        profiles,
        lifecycle,
        decoder_image_path: imagePath,
      },
    };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function compareRawPacketRefs(left, right) {
  return (left?.chunk_index ?? 0) - (right?.chunk_index ?? 0)
    || (left?.decompressed_block_offset ?? 0) - (right?.decompressed_block_offset ?? 0)
    || (left?.decompressed_payload_offset ?? 0) - (right?.decompressed_payload_offset ?? 0);
}

function protectionEventOrder(left, right) {
  return (left.replay_time_ms ?? 0) - (right.replay_time_ms ?? 0)
    || compareRawPacketRefs(left.raw_packet_ref, right.raw_packet_ref);
}

function logicalShieldId(event, ordinal) {
  const identity = [
    event.raw_packet_ref?.replay_sha256,
    event.replay_time_ms,
    event.source_network_id,
    event.target_network_id,
    event.amount_bits_hex,
    ordinal,
  ].join('|');
  return `shield:${crypto.createHash('sha256').update(identity).digest('hex').slice(0, 24)}`;
}

function shieldRouteKey(event) {
  return [
    event.raw_packet_ref?.replay_sha256,
    event.replay_time_ms,
    event.source_network_id,
    event.target_network_id,
    event.amount_bits_hex,
    event.event_params_sha256,
  ].join(':');
}

function deduplicateShieldRoutes(rawEvents) {
  const groups = new Map();
  for (const event of [...rawEvents].sort(protectionEventOrder)) {
    const key = shieldRouteKey(event);
    let group = groups.get(key);
    if (!group) {
      group = { target: [], source: [] };
      groups.set(key, group);
    }
    if (event.protocol_event_id === ON_EVENT_PROFILE.events.shield_target_route.event_id) {
      group.target.push(event);
    } else {
      group.source.push(event);
    }
  }

  const events = [];
  const summary = {
    raw_route_event_count: rawEvents.length,
    raw_target_route_count: rawEvents.filter(
      (event) => event.protocol_event_id
        === ON_EVENT_PROFILE.events.shield_target_route.event_id,
    ).length,
    raw_source_route_count: rawEvents.filter(
      (event) => event.protocol_event_id
        === ON_EVENT_PROFILE.events.shield_source_route.event_id,
    ).length,
    paired_route_count: 0,
    unpaired_target_route_count: 0,
    unpaired_source_route_count: 0,
    logical_shield_event_count: 0,
  };
  for (const group of groups.values()) {
    const unusedSources = new Set(group.source);
    const logicalRoutes = group.target.map((targetRoute) => {
      const targetOccurrence = targetRoute.raw_packet_ref?.occurrence_index;
      const sourceRoute = Number.isInteger(targetOccurrence)
        ? group.source.find((candidate) => (
          unusedSources.has(candidate)
          && candidate.raw_packet_ref?.occurrence_index === targetOccurrence - 1
        )) ?? null
        : null;
      if (sourceRoute) unusedSources.delete(sourceRoute);
      return [targetRoute, sourceRoute];
    });
    for (const sourceRoute of unusedSources) logicalRoutes.push([null, sourceRoute]);
    logicalRoutes.forEach(([targetRoute, sourceRoute], index) => {
      const routeEvents = [targetRoute, sourceRoute].filter(Boolean);
      const canonical = targetRoute ?? sourceRoute;
      const rawPacketRefs = routeEvents
        .flatMap((event) => event.raw_packet_refs || [event.raw_packet_ref])
        .filter(Boolean)
        .sort(compareRawPacketRefs);
      const paired = targetRoute !== null && sourceRoute !== null;
      if (paired) summary.paired_route_count += 1;
      else if (targetRoute) summary.unpaired_target_route_count += 1;
      else summary.unpaired_source_route_count += 1;
      const shieldInstanceId = logicalShieldId(canonical, index);
      events.push({
        ...canonical,
        protection_event_id: shieldInstanceId,
        shield_instance_id: shieldInstanceId,
        raw_packet_ref: rawPacketRefs[0] ?? canonical.raw_packet_ref,
        raw_packet_refs: rawPacketRefs,
        raw_route_occurrences: routeEvents.map((event) => ({
          protocol_event_id: event.protocol_event_id,
          protocol_event_id_hex: event.protocol_event_id_hex,
          route_kind: event.route_kind,
          event_params_sha256: event.event_params_sha256,
          raw_payload_sha256: event.raw_payload_sha256,
          raw_packet_ref: event.raw_packet_ref,
        })),
        route_event_ids: routeEvents.map((event) => event.protocol_event_id),
        route_kinds: routeEvents.map((event) => event.route_kind),
        route_count: routeEvents.length,
        route_kind: paired ? 'SOURCE_AND_TARGET_ROUTES' : canonical.route_kind,
        deduplication_status: paired
          ? 'PAIRED_SOURCE_AND_TARGET_ROUTES'
          : targetRoute ? 'UNPAIRED_TARGET_ROUTE' : 'UNPAIRED_SOURCE_ROUTE',
        field_confidence: {
          ...canonical.field_confidence,
          route_pairing: paired ? 'VERIFIED_DERIVED' : 'PARTIAL',
        },
      });
    });
  }
  events.sort(protectionEventOrder);
  summary.logical_shield_event_count = events.length;
  summary.route_deduplication_reduction_count = rawEvents.length - events.length;
  return { events, summary };
}

function compatibleProtectionCast(event, spell) {
  const kind = spell.protection_cast_kind;
  if (event.event_type === 'shield') {
    return kind === 'SHIELD_CAST'
      || kind === 'SHIELD_OR_HEAL_CAST'
      || kind === 'HEAL_AND_SHIELD_CAST';
  }
  return kind === 'HEAL_CAST'
    || kind === 'SHIELD_OR_HEAL_CAST'
    || kind === 'HEAL_AND_SHIELD_CAST';
}

function spellTargetsNetworkId(spell, networkId) {
  return Array.isArray(spell.targets)
    && spell.targets.some((target) => target.network_id === networkId);
}

function annotateProtectionCorrelations(shieldEvents, healEvents, spellEvents, buffEvents) {
  const events = [...shieldEvents, ...healEvents];
  const playerCasts = spellEvents.filter((event) => event.is_player_cast_group_leader === true);
  const buffAdds = buffEvents.filter((event) => event.buff_operation === 'ADD');
  const summary = {
    event_count: events.length,
    exact_spell_match_count: 0,
    ambiguous_spell_match_count: 0,
    no_exact_spell_match_count: 0,
    exact_buff_match_event_count: 0,
    shield_exact_spell_match_count: 0,
    heal_exact_spell_match_count: 0,
  };
  for (const event of events) {
    const matches = playerCasts.filter((spell) => (
      spell.replay_time_ms === event.replay_time_ms
      && spell.caster_network_id === event.source_network_id
      && spellTargetsNetworkId(spell, event.target_network_id)
      && compatibleProtectionCast(event, spell)
    ));
    if (matches.length === 1) {
      const spell = matches[0];
      event.spell_identifier = spell.spell_identifier;
      event.spell_name = spell.spell_name;
      event.spell_slot = spell.spell_slot;
      event.protection_cast_kind = spell.protection_cast_kind;
      event.origin_player_cast_group_id = spell.player_cast_group_id;
      event.matched_spell_raw_packet_ref = spell.raw_packet_ref;
      event.spell_correlation_status = 'MATCHED_EXACT_TIMESTAMP_CASTER_TARGET';
      event.field_confidence.spell_identifier = 'VERIFIED_DERIVED';
      summary.exact_spell_match_count += 1;
      if (event.event_type === 'shield') summary.shield_exact_spell_match_count += 1;
      else summary.heal_exact_spell_match_count += 1;
    } else if (matches.length > 1) {
      event.spell_correlation_status = 'AMBIGUOUS_EXACT_TIMESTAMP_CASTER_TARGET';
      summary.ambiguous_spell_match_count += 1;
    } else {
      event.spell_correlation_status = 'NO_EXACT_TIMESTAMP_CASTER_TARGET_MATCH';
      summary.no_exact_spell_match_count += 1;
    }

    const matchedBuffs = buffAdds.filter((buff) => (
      buff.replay_time_ms === event.replay_time_ms
      && buff.source_network_id === event.source_network_id
      && buff.target_network_id === event.target_network_id
    ));
    event.matched_buff_count = matchedBuffs.length;
    event.matched_buff_raw_packet_refs = matchedBuffs.map((buff) => buff.raw_packet_ref);
    event.matched_buff_name_hashes = [...new Set(
      matchedBuffs.map((buff) => buff.buff_name_hash_hex).filter(Boolean),
    )].sort();
    event.buff_correlation_status = matchedBuffs.length > 0
      ? 'MATCHED_EXACT_TIMESTAMP_CASTER_TARGET'
      : 'NO_EXACT_TIMESTAMP_CASTER_TARGET_MATCH';
    if (matchedBuffs.length > 0) summary.exact_buff_match_event_count += 1;
  }
  return summary;
}

function healDuplicateSummary(events) {
  const counts = new Map();
  for (const event of events) {
    const key = [
      event.replay_time_ms,
      event.source_network_id,
      event.target_network_id,
      event.amount_bits_hex,
      event.event_params_sha256,
    ].join(':');
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const duplicateGroups = [...counts.values()].filter((count) => count > 1);
  return {
    raw_heal_event_count: events.length,
    exact_identity_count: counts.size,
    exact_duplicate_group_count: duplicateGroups.length,
    exact_duplicate_excess_count: duplicateGroups.reduce((sum, count) => sum + count - 1, 0),
    deduplication_status: 'NOT_DEDUPLICATED_SEMANTICS_UNPROVEN',
  };
}

function asUnifiedProtectionEvent(event) {
  const { event_type: sourceEventType, ...fields } = event;
  return protectionEvent({
    ...fields,
    source_event_type: sourceEventType,
    protection_type: sourceEventType === 'shield'
      ? 'SHIELD_GENERATED'
      : 'HEAL_DIRECT_REPORTED',
    protection_start_ms: sourceEventType === 'shield'
      ? event.apply_time_ms
      : event.replay_time_ms,
    protection_end_ms: sourceEventType === 'shield' ? event.remove_time_ms : event.replay_time_ms,
  });
}

function runShieldDamageDecoderWithImage(replay, imagePath, options = {}) {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-analyzer-'));
  const exportedPath = path.join(temporaryDirectory, 'shield_damage_packets.jsonl');
  const decodedPath = path.join(temporaryDirectory, 'shield_damage_decoded.jsonl');
  const summaryPath = path.join(temporaryDirectory, 'shield_damage_summary.json');
  try {
    const exportedPacketCount = exportShieldDamagePackets(replay, exportedPath);
    const python = options.python || process.env.ROFL_ANALYZER_PYTHON || 'python';
    const script = path.join(REPOSITORY_ROOT, 'scripts', 'decode_shield_damage_v4.py');
    const result = childProcess.spawnSync(python, [
      script,
      '--image', imagePath,
      '--events', exportedPath,
      '--output', decodedPath,
      '--summary', summaryPath,
    ], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: options.decoderTimeoutMs || 120000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const error = new Error(
        `shield-damage decoder failed: ${(result.stderr || result.error?.message || '').trim()}`,
      );
      error.code = 'SHIELD_DAMAGE_DECODER_FAILED';
      throw error;
    }

    const decoderSummary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    const selfTestPassed = decoderSummary.self_test
      && Object.values(decoderSummary.self_test).every((value) => value === true);
    if (decoderSummary.input_event_count !== exportedPacketCount
        || decoderSummary.deserialize_success_count !== exportedPacketCount
        || decoderSummary.fully_consumed_count !== exportedPacketCount
        || decoderSummary.network_fields_agree_count !== exportedPacketCount
        || decoderSummary.target_matches_raw_param_count !== exportedPacketCount
        || decoderSummary.decoder_profile !== SHIELD_DAMAGE_PROFILE.id
        || decoderSummary.client_opcode !== '0x0017'
        || decoderSummary.image_sha256 !== SHIELD_DAMAGE_PROFILE.runtime_image_sha256
        || decoderSummary.output_sha256 !== sha256FileSync(decodedPath)
        || !selfTestPassed) {
      const error = new Error('shield-damage decoder summary failed structural verification');
      error.code = 'SHIELD_DAMAGE_DECODER_VERIFICATION_FAILED';
      throw error;
    }

    const rows = fs.readFileSync(decodedPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    if (rows.length !== exportedPacketCount
        || rows.some((row) => !isShieldDamageDecodedRow(replay, row))) {
      const error = new Error('decoded shield-damage rows failed structural verification');
      error.code = 'SHIELD_DAMAGE_EVENT_BUILD_FAILED';
      throw error;
    }

    const participants = participantMetadata(replay);
    const events = rows.map((row) => (
      shieldAbsorptionProtectionEventFromDecodedRow(replay, row, participants)
    ));
    if (events.some((event) => event === null) || events.length !== rows.length) {
      const error = new Error('decoded shield-damage event selection failed verification');
      error.code = 'SHIELD_DAMAGE_EVENT_BUILD_FAILED';
      throw error;
    }
    events.sort(protectionEventOrder);
    return {
      rows,
      events,
      summary: {
        ...decoderSummary,
        event_count: exportedPacketCount,
        output_event_count: rows.length,
        semantic_output_event_count: events.length,
        exported_packet_count: exportedPacketCount,
        decoder_route_status: events.length > 0 ? 'DECODED' : 'NO_PROTECTION_EVENT',
        decoder_image_path: imagePath,
      },
    };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function runShieldDamageDecoder(replay, options = {}) {
  const { imagePath } = verifiedDecoderImage(options);
  return runShieldDamageDecoderWithImage(replay, imagePath, options);
}

function runProtectionV4Decoder(replay, spellEvents = [], buffEvents = [], options = {}) {
  const { imagePath } = verifiedDecoderImage(options);
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-analyzer-'));
  const exportedPath = path.join(temporaryDirectory, 'on_event_packets.jsonl');
  const decodedPath = path.join(temporaryDirectory, 'on_event_decoded.jsonl');
  const summaryPath = path.join(temporaryDirectory, 'on_event_summary.json');
  try {
    const exportedPacketCount = exportProfilePackets(replay, exportedPath, ON_EVENT_PROFILE);
    const python = options.python || process.env.ROFL_ANALYZER_PYTHON || 'python';
    const script = path.join(REPOSITORY_ROOT, 'scripts', 'decode_on_event_protection_v4.py');
    const result = childProcess.spawnSync(python, [
      script,
      '--image', imagePath,
      '--events', exportedPath,
      '--output', decodedPath,
      '--summary', summaryPath,
      '--progress-every', '0',
    ], {
      cwd: REPOSITORY_ROOT,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: options.decoderTimeoutMs || 120000,
      windowsHide: true,
    });
    if (result.error || result.status !== 0) {
      const error = new Error(
        `Unicorn OnEvent decoder failed: ${(result.stderr || result.error?.message || '').trim()}`,
      );
      error.code = 'PROTECTION_DECODER_FAILED';
      throw error;
    }
    const decoderSummary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    if (decoderSummary.input_event_count !== exportedPacketCount
        || decoderSummary.deserialize_success_count !== exportedPacketCount
        || decoderSummary.fully_consumed_count !== exportedPacketCount
        || (decoderSummary.schema_mismatch_count !== undefined
          && decoderSummary.schema_mismatch_count !== 0)
        || (decoderSummary.parameter_size_mismatch_count !== undefined
          && decoderSummary.parameter_size_mismatch_count !== 0)
        || decoderSummary.image_sha256 !== ON_EVENT_PROFILE.runtime_image_sha256) {
      const error = new Error('OnEvent decoder summary failed structural verification');
      error.code = 'PROTECTION_DECODER_VERIFICATION_FAILED';
      throw error;
    }
    const rows = fs.readFileSync(decodedPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    if (rows.length !== decoderSummary.output_event_count
        || rows.some((row) => !isOnEventDecodedRow(replay, row))) {
      const error = new Error('decoded OnEvent rows failed structural verification');
      error.code = 'PROTECTION_EVENT_BUILD_FAILED';
      throw error;
    }
    const shieldDamage = runShieldDamageDecoderWithImage(replay, imagePath, options);
    const participants = participantMetadata(replay);
    const rawProtectionEvents = rows
      .map((row) => protectionEventFromDecodedRow(replay, row, participants))
      .filter(Boolean);
    const rawShieldEvents = rawProtectionEvents.filter((event) => event.event_type === 'shield');
    const healEvents = rawProtectionEvents.filter((event) => event.event_type === 'heal');
    const shield = deduplicateShieldRoutes(rawShieldEvents);
    const correlation = annotateProtectionCorrelations(
      shield.events,
      healEvents,
      spellEvents,
      buffEvents,
    );
    const protectionEvents = [...shield.events, ...healEvents]
      .map(asUnifiedProtectionEvent)
      .concat(shieldDamage.events)
      .sort(protectionEventOrder);
    const eventIdCounts = decoderSummary.event_counts;
    const onEventRecognizedCount = rawProtectionEvents.length;
    return {
      shieldEvents: shield.events,
      shieldAbsorptionEvents: shieldDamage.events,
      healEvents,
      protectionEvents,
      summary: {
        ...decoderSummary,
        event_count: decoderSummary.input_event_count + shieldDamage.summary.event_count,
        input_event_count: decoderSummary.input_event_count
          + shieldDamage.summary.input_event_count,
        deserialize_success_count: decoderSummary.deserialize_success_count
          + shieldDamage.summary.deserialize_success_count,
        fully_consumed_count: decoderSummary.fully_consumed_count
          + shieldDamage.summary.fully_consumed_count,
        successful_full_consume_count: decoderSummary.fully_consumed_count
          + shieldDamage.summary.fully_consumed_count,
        output_event_count: decoderSummary.output_event_count
          + shieldDamage.summary.output_event_count,
        exported_packet_count: exportedPacketCount
          + shieldDamage.summary.exported_packet_count,
        semantic_output_event_count: protectionEvents.length,
        recognized_raw_protection_event_count: onEventRecognizedCount
          + shieldDamage.events.length,
        event_id_counts: eventIdCounts,
        shield: shield.summary,
        shield_absorption: {
          event_count: shieldDamage.events.length,
          amount_total: shieldDamage.events.reduce(
            (sum, event) => sum + event.absorbed_amount,
            0,
          ),
          attribution_status: 'UNATTRIBUTED_TARGET_TOTAL',
          decoder_route_status: shieldDamage.summary.decoder_route_status,
        },
        heal: healDuplicateSummary(healEvents),
        correlation,
        damage_shielded_event_count: eventIdCounts['0x00ef'] ?? 0,
        required_decoder_routes: ['0x009e', '0x0017'],
        verified_decoder_route_count: 2,
        required_decoder_routes_verified: true,
        decoder_route_status: 'BOTH_REQUIRED_ROUTES_VERIFIED',
        decoder_routes: {
          on_event: {
            decoder_profile: ON_EVENT_PROFILE.id,
            client_opcode: '0x009e',
            input_event_count: decoderSummary.input_event_count,
            output_event_count: decoderSummary.output_event_count,
            semantic_output_event_count: shield.events.length + healEvents.length,
            exported_packet_count: exportedPacketCount,
            decoder_route_status: onEventRecognizedCount > 0
              ? 'DECODED'
              : 'NO_PROTECTION_EVENT',
          },
          shield_damage: shieldDamage.summary,
        },
        decoder_image_path: imagePath,
      },
    };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function annotatePlayerCastGroups(events) {
  const groups = new Map();
  for (const event of events) {
    event.player_cast_group_id = null;
    event.player_cast_group_size = null;
    event.is_player_cast_group_leader = false;
    if (!event.is_primary_player_ability) continue;
    const groupId = [
      event.raw_packet_ref?.replay_sha256,
      event.replay_time_ms,
      event.caster_network_id,
      event.spell_key_hex,
    ].join(':');
    event.player_cast_group_id = groupId;
    let group = groups.get(groupId);
    if (!group) {
      group = [];
      groups.set(groupId, group);
    }
    group.push(event);
  }
  for (const group of groups.values()) {
    group.forEach((event, index) => {
      event.player_cast_group_size = group.length;
      event.is_player_cast_group_leader = index === 0;
    });
  }
  return events;
}

function aggregateAttackers(events) {
  const attackers = new Map();
  for (const event of events) {
    const key = event.source_participant_id;
    let attacker = attackers.get(key);
    if (!attacker) {
      attacker = {
        participant_id: event.source_participant_id,
        champion: event.source_champion,
        network_id: event.source_network_id,
        hit_count: 0,
        damage_amount: 0,
        displayed_floor_damage: 0,
        first_hit_time_ms: event.replay_time_ms,
        last_hit_time_ms: event.replay_time_ms,
        confidence: 'VERIFIED_DERIVED',
      };
      attackers.set(key, attacker);
    }
    attacker.hit_count += 1;
    attacker.damage_amount += event.amount;
    attacker.displayed_floor_damage += Math.floor(event.amount);
    attacker.last_hit_time_ms = event.replay_time_ms;
  }
  return [...attackers.values()].sort(
    (left, right) => right.damage_amount - left.damage_amount || left.participant_id - right.participant_id,
  );
}

function buildAdcDeathRecords(
  replay,
  deathEvents,
  damageEvents,
  spellEvents = [],
  positionEvents = [],
  buffEvents = [],
  protectionEvents = [],
) {
  const roster = normalizePlayers(replay);
  const byParticipant = new Map(roster.map((player) => [player.metadata_index + 1, player]));
  const supportsByTeam = new Map(
    roster
      .filter((player) => player.role === 'support')
      .map((player) => [player.team_id, { ...player, participant_id: player.metadata_index + 1 }]),
  );
  const gameId = gameIdFromReplayPath(replay.source_path);
  const records = [];
  for (const death of deathEvents) {
    const victim = byParticipant.get(death.victim_participant_id);
    if (victim?.role !== 'adc') continue;
    const window = buildCombatWindow(death, damageEvents, spellEvents, positionEvents, {
      damageGapMs: DAMAGE_GAP_MS,
    });
    const sequence = window.heuristic.damage_events;
    const attackers = aggregateAttackers(sequence);
    const support = supportsByTeam.get(victim.team_id) || null;
    const finalDamage = sequence.at(-1) || null;
    const supportSpellCasts = window.heuristic.spell_events.filter(
      (event) => event.source_participant_id === support?.participant_id,
    );
    const supportPrimarySpellCasts = supportSpellCasts.filter(
      (event) => event.is_player_cast_group_leader,
    );
    const supportProtectionCasts = supportPrimarySpellCasts.filter(
      (event) => event.protection_cast_kind !== null,
    );
    const supportBuffEvents = buffEvents.filter((event) => (
      window.heuristic.start_ms !== null
      &&
      event.buff_operation === 'ADD'
      && event.source_participant_id === support?.participant_id
      && event.target_participant_id === death.victim_participant_id
      && event.replay_time_ms >= window.heuristic.start_ms
      && event.replay_time_ms <= death.replay_time_ms
    ));
    const supportProtectionBuffEvents = supportBuffEvents.filter(
      (event) => event.protection_cast_kind !== null,
    );
    const protectionContextAvailable = window.heuristic.start_ms !== null;
    const targetShieldAbsorptionEvents = protectionContextAvailable
      ? protectionEvents.filter((event) => (
        event.protection_type === 'SHIELD_ABSORBED'
        && event.target_network_id === death.victim_network_id
        && event.replay_time_ms >= window.heuristic.start_ms
        && event.replay_time_ms <= death.replay_time_ms
      ))
      : [];
    const externalProtectionEvents = protectionContextAvailable
      ? protectionEvents.filter((event) => (
        event.target_participant_id === death.victim_participant_id
        && event.source_participant_id !== null
        && event.source_participant_id !== death.victim_participant_id
        && event.source_team_id === victim.team_id
        && event.replay_time_ms >= window.heuristic.start_ms
        && event.replay_time_ms <= death.replay_time_ms
      ))
      : [];
    const supportProtectionEvents = externalProtectionEvents.filter(
      (event) => event.source_participant_id === support?.participant_id,
    );
    const externalShieldEvents = externalProtectionEvents.filter(
      (event) => event.protection_type === 'SHIELD_GENERATED',
    );
    const externalHealEvents = externalProtectionEvents.filter(
      (event) => event.protection_type === 'HEAL_DIRECT_REPORTED',
    );
    const externalShieldGenerated = externalShieldEvents.reduce(
      (sum, event) => sum + event.generated_amount,
      0,
    );
    const externalDirectHealAmount = externalHealEvents.reduce(
      (sum, event) => sum + event.direct_heal_amount,
      0,
    );
    const supportShieldGenerated = supportProtectionEvents
      .filter((event) => event.protection_type === 'SHIELD_GENERATED')
      .reduce((sum, event) => sum + event.generated_amount, 0);
    const supportDirectHealAmount = supportProtectionEvents
      .filter((event) => event.protection_type === 'HEAL_DIRECT_REPORTED')
      .reduce((sum, event) => sum + event.direct_heal_amount, 0);
    const targetTotalShieldAbsorbed = targetShieldAbsorptionEvents.reduce(
      (sum, event) => sum + event.absorbed_amount,
      0,
    );
    records.push(buildAdcDeathRecord({
      match_id: gameId,
      game_id: gameId,
      replay_path: replay.source_path,
      replay_sha256: replay.source_sha256,
      patch: replay.header.version,
      adc: victim.champion,
      adc_participant_id: death.victim_participant_id,
      support: support?.champion ?? null,
      support_participant_id: support?.participant_id ?? null,
      death_time_ms: death.replay_time_ms,
      combat_start_ms: window.heuristic.start_ms,
      combat_duration_ms: window.heuristic.duration_ms,
      combat_rule_version: COMBAT_RULE_VERSION,
      combat_rule: window.heuristic.rule,
      killer: finalDamage?.source_champion ?? null,
      killer_participant_id: finalDamage?.source_participant_id ?? null,
      killer_confidence: finalDamage ? 'VERIFIED_DERIVED' : 'UNAVAILABLE',
      attackers,
      attacker_count: attackers.length,
      hit_count: sequence.length,
      total_incoming_champion_damage: sequence.reduce((sum, event) => sum + event.amount, 0),
      displayed_floor_incoming_champion_damage: sequence.reduce(
        (sum, event) => sum + Math.floor(event.amount),
        0,
      ),
      damage_events: sequence,
      fixed_windows: window.fixed,
      support_spell_casts: supportSpellCasts,
      support_primary_spell_casts: supportPrimarySpellCasts,
      support_protection_casts: supportProtectionCasts,
      support_spell_cast_count: supportSpellCasts.length,
      support_primary_spell_cast_count: supportPrimarySpellCasts.length,
      support_protection_cast_count: supportProtectionCasts.length,
      support_buff_events: supportBuffEvents,
      support_buff_event_count: supportBuffEvents.length,
      support_protection_buff_events: supportProtectionBuffEvents,
      support_protection_buff_event_count: supportProtectionBuffEvents.length,
      protection_context_status: protectionContextAvailable
        ? externalProtectionEvents.length > 0 || targetShieldAbsorptionEvents.length > 0
          ? 'PROTECTION_EVENTS_OBSERVED'
          : 'NO_PROTECTION_EVENT'
        : 'UNAVAILABLE_NO_COMBAT_WINDOW',
      protection_capability_status:
        'PROTECTION_V4_DIRECT_AMOUNTS_AND_TARGET_TOTAL_ABSORPTION_AVAILABLE',
      external_protection_events: externalProtectionEvents,
      external_protection_event_count: externalProtectionEvents.length,
      support_protection_events: supportProtectionEvents,
      support_protection_event_count: supportProtectionEvents.length,
      external_shield_generated: protectionContextAvailable ? externalShieldGenerated : null,
      external_shield_absorbed: null,
      external_shield_absorption_attribution_status: 'UNAVAILABLE_SOURCE_ATTRIBUTION',
      external_shield_unused: null,
      target_total_shield_absorbed: protectionContextAvailable
        ? targetTotalShieldAbsorbed
        : null,
      target_shield_absorption_events: targetShieldAbsorptionEvents,
      target_shield_absorption_event_count: targetShieldAbsorptionEvents.length,
      target_shield_absorption_attribution_status: protectionContextAvailable
        ? 'UNATTRIBUTED_TARGET_TOTAL'
        : 'UNAVAILABLE_NO_COMBAT_WINDOW',
      external_direct_heal_amount: protectionContextAvailable ? externalDirectHealAmount : null,
      external_healing: null,
      temporary_hp: null,
      total_external_protection: null,
      support_shield_generated: protectionContextAvailable ? supportShieldGenerated : null,
      support_direct_heal_amount: protectionContextAvailable ? supportDirectHealAmount : null,
      shield_generated_aggregation_status: 'LOGICAL_ROUTE_DEDUPLICATED_SUM',
      shield_absorption_aggregation_status: protectionContextAvailable
        ? 'DIRECT_TARGET_TOTAL_SUM_UNATTRIBUTED'
        : 'UNAVAILABLE_NO_COMBAT_WINDOW',
      heal_aggregation_status: 'RAW_OCCURRENCE_SUM_NOT_DEDUPLICATED_SEMANTICS_UNPROVEN',
      incoming_physical: null,
      incoming_magic: null,
      incoming_true: null,
      identified_basic_damage: sequence
        .filter((event) => event.is_basic_attack === true)
        .reduce((sum, event) => sum + event.amount, 0),
      identified_spell_damage: sequence
        .filter((event) => event.spell !== null)
        .reduce((sum, event) => sum + event.amount, 0),
      confidence: 'VERIFIED_DERIVED',
      raw_death_event: death,
    }));
  }
  return records;
}

function semanticCapabilities() {
  return [
    { capability: 'replay metadata', status: 'VERIFIED_DIRECT' },
    { capability: 'packet timestamps', status: 'VERIFIED_DIRECT' },
    { capability: 'hero death', status: 'VERIFIED_DIRECT' },
    {
      capability: 'hero death scope',
      status: 'VERIFIED_DIRECT',
      evidence: '0x0160 is verified for heroes only; ordinary-monster death is not established.',
    },
    { capability: 'damage source', status: 'VERIFIED_DIRECT' },
    { capability: 'damage target', status: 'VERIFIED_DIRECT' },
    { capability: 'damage amount', status: 'VERIFIED_DIRECT' },
    { capability: 'entity mapping', status: 'VERIFIED_DERIVED' },
    {
      capability: 'level transition occurrence',
      status: 'VERIFIED_DIRECT',
      version: LEVEL_UP_PROFILE.replay_version,
    },
    {
      capability: 'level after',
      status: 'VERIFIED_DERIVED',
      version: LEVEL_UP_PROFILE.level_mapping_version,
      evidence: 'field_10 mapping is build-bound and never inherited by another version.',
    },
    {
      capability: 'SKILL_LEVEL_UP as hero level time',
      status: 'UNAVAILABLE',
      evidence: 'Rejected proxy: observed delays p50=1103 ms, p90=6179.6 ms, max=34286 ms.',
    },
    { capability: 'damage type', status: 'UNAVAILABLE' },
    { capability: 'basic attack', status: 'UNAVAILABLE' },
    { capability: 'spell cast', status: 'VERIFIED_DIRECT' },
    { capability: 'position', status: 'UNAVAILABLE' },
    { capability: 'health state', status: 'UNAVAILABLE' },
    { capability: 'shield', status: 'PARTIAL' },
    { capability: 'shield generated amount', status: 'VERIFIED_DIRECT' },
    { capability: 'shield remaining', status: 'UNAVAILABLE' },
    { capability: 'shield absorbed', status: 'VERIFIED_DIRECT_TARGET_TOTAL' },
    { capability: 'shield absorbed source attribution', status: 'UNAVAILABLE' },
    { capability: 'shield instance attribution', status: 'UNAVAILABLE' },
    { capability: 'shield unused', status: 'UNAVAILABLE' },
    { capability: 'heal', status: 'PARTIAL' },
    { capability: 'direct reported heal amount', status: 'VERIFIED_DIRECT' },
    { capability: 'raw heal amount', status: 'UNAVAILABLE' },
    { capability: 'effective heal amount', status: 'UNAVAILABLE' },
    { capability: 'overheal amount', status: 'UNAVAILABLE' },
    { capability: 'temporary HP', status: 'UNAVAILABLE' },
    { capability: 'buff', status: 'VERIFIED_DIRECT' },
    { capability: 'ADC death combat timeline', status: 'VERIFIED_DERIVED' },
    {
      capability: 'UnitApplyDamage camp clear',
      status: 'UNAVAILABLE',
      evidence: 'Combat amount is direct; ordinary-monster identity, HP, death and lifecycle are absent.',
    },
    { capability: 'camp contact', status: 'NOT_PROTOCOL_CAPABILITY' },
    { capability: 'camp clear', status: 'UNAVAILABLE' },
    { capability: 'ordinary monster entity mapping', status: 'UNAVAILABLE' },
    { capability: 'XP', status: 'UNAVAILABLE' },
    { capability: 'jungle CS', status: 'UNAVAILABLE' },
    { capability: 'current gold', status: 'UNAVAILABLE' },
    { capability: 'total gold', status: 'UNAVAILABLE' },
  ];
}

function decodeSemanticReplay(replay, options = {}) {
  if (replay.header.version !== DAMAGE_PROFILE.replay_version) {
    return {
      status: 'UNSUPPORTED_REPLAY_VERSION',
      profile: null,
      events: null,
      adc_deaths: [],
      capabilities: null,
      decoded_packet_count: 0,
      note: `No semantic profile is available for ${replay.header.version}.`,
    };
  }
  const deaths = decodeHeroDeaths(replay, { strict: true });
  const levelTransition = runLevelTransitionDecoder(replay, options);
  const damage = runDamageDecoder(replay, options);
  const castSpell = runCastSpellDecoder(replay, options);
  const buff = runBuffDecoder(replay, options);
  const buffSpellCorrelation = annotateBuffSpellCorrelations(buff.events, castSpell.events);
  buff.summary.spell_correlation = buffSpellCorrelation;
  const protection = runProtectionV4Decoder(
    replay,
    castSpell.events,
    buff.events,
    options,
  );
  const events = {
    damage_events: damage.events,
    spell_events: castSpell.events,
    death_events: deaths.events,
    position_events: [],
    item_events: [],
    buff_events: buff.events,
    health_state_events: [],
    shield_events: protection.shieldEvents,
    heal_events: protection.healEvents,
    temporary_hp_events: [],
    protection_events: protection.protectionEvents,
    level_transition_events: levelTransition.events,
  };
  const adcDeaths = buildAdcDeathRecords(
    replay,
    events.death_events,
    events.damage_events,
    events.spell_events,
    events.position_events,
    events.buff_events,
    events.protection_events,
  );
  return {
    status: 'RESEARCH_READY_COMPLETE',
    profile: {
      replay_version: replay.header.version,
      death: DEATH_PROFILE,
      damage: DAMAGE_PROFILE,
      level_transition: LEVEL_UP_PROFILE,
      cast_spell: CAST_SPELL_PROFILE,
      buff: BUFF_PROFILES,
      protection: {
        on_event: ON_EVENT_PROFILE,
        shield_damage: SHIELD_DAMAGE_PROFILE,
        required_decoder_routes: ['0x009e', '0x0017'],
      },
    },
    events,
    adc_deaths: adcDeaths,
    capabilities: semanticCapabilities(),
    decoded_packet_count: deaths.events.length
      + levelTransition.summary.event_count
      + damage.summary.event_count
      + castSpell.summary.event_count
      + buff.summary.event_count
      + protection.summary.event_count,
    damage_decode: damage.summary,
    level_transition_decode: levelTransition.summary,
    cast_spell_decode: castSpell.summary,
    buff_decode: buff.summary,
    protection_decode: protection.summary,
    protection_status: protection.summary.required_decoder_routes_verified
      ? 'PROTECTION_V4_COMPLETE'
      : 'PROTECTION_V4_DECODER_ROUTE_INCOMPLETE',
    death_decode: {
      event_count: deaths.events.length,
      signature_count: deaths.signature_count,
      rejected_signature_count: deaths.rejected_signature_count,
    },
    combat_rule: {
      version: COMBAT_RULE_VERSION,
      damage_gap_ms: DAMAGE_GAP_MS,
      fixed_windows_seconds: [5, 10, 15],
    },
  };
}

module.exports = {
  COMBAT_RULE_VERSION,
  DAMAGE_GAP_MS,
  DEFAULT_DECODER_IMAGE,
  DEFAULT_SPELL_DICTIONARY,
  aggregateAttackers,
  annotateProtectionCorrelations,
  annotatePlayerCastGroups,
  annotateBuffLifecycles,
  annotateBuffSpellCorrelations,
  buildAdcDeathRecords,
  damageExportRow,
  decodeSemanticReplay,
  exportDamagePackets,
  exportCastSpellPackets,
  exportShieldDamagePackets,
  exportLevelTransitionPackets,
  gameIdFromReplayPath,
  deduplicateShieldRoutes,
  runDamageDecoder,
  runLevelTransitionDecoder,
  runCastSpellDecoder,
  runBuffDecoder,
  runProtectionV4Decoder,
  runShieldDamageDecoder,
  semanticCapabilities,
  queryLevelTransitions,
  summarizeLevelSequences,
};
