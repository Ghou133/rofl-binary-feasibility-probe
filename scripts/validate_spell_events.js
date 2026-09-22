#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const {
  CAST_SPELL_PROFILE,
  participantIdFromChampionNetworkId,
} = require('../src/decoders/rofl_16_15_801_3452');
const { sha256File, writeCsv, writeJson } = require('../src/io');
const { normalizePlayers, parseReplayFile } = require('../src/rofl');

const SLOT_NAMES = Object.freeze(['Q', 'W', 'E', 'R']);
const PROTECTION_VALIDATION_SLOTS = Object.freeze({
  Janna: new Set(['E', 'R']),
  Karma: new Set(['E']),
  Lulu: new Set(['E', 'R']),
  Seraphine: new Set(['W']),
  Soraka: new Set(['W', 'R']),
});

function parseArgs(argv) {
  const options = {
    events: null,
    eventManifest: null,
    decodeSummary: null,
    replayDir: path.resolve('replay'),
    replayFiles: [],
    outputDir: null,
    label: 'development',
    aggregateMode: 'strict',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--events') options.events = path.resolve(argv[++index]);
    else if (value === '--event-manifest') options.eventManifest = path.resolve(argv[++index]);
    else if (value === '--decode-summary') options.decodeSummary = path.resolve(argv[++index]);
    else if (value === '--replay-dir') options.replayDir = path.resolve(argv[++index]);
    else if (value === '--replay') options.replayFiles.push(path.resolve(argv[++index]));
    else if (value === '--output-dir') options.outputDir = path.resolve(argv[++index]);
    else if (value === '--label') options.label = argv[++index];
    else if (value === '--aggregate-mode') options.aggregateMode = argv[++index];
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.events) throw new Error('--events is required');
  if (!options.outputDir) throw new Error('--output-dir is required');
  if (!['strict', 'holdout'].includes(options.aggregateMode)) {
    throw new Error('--aggregate-mode must be strict or holdout');
  }
  return options;
}

function loadReplays(directory, replayFiles = []) {
  const files = replayFiles.length > 0
    ? [...new Set(replayFiles)].sort()
    : fs.readdirSync(directory)
      .filter((item) => item.toLowerCase().endsWith('.rofl'))
      .sort()
      .map((name) => path.join(directory, name));
  const bySha256 = new Map();
  for (const file of files) {
    const replay = parseReplayFile(file);
    if (replay.header.version !== CAST_SPELL_PROFILE.replay_version) continue;
    bySha256.set(replay.source_sha256, {
      replay,
      players: normalizePlayers(replay),
    });
  }
  return bySha256;
}

function coreEventValidation(event, context) {
  const participantId = participantIdFromChampionNetworkId(event.caster_network_id);
  const player = participantId === null ? null : context.players[participantId - 1];
  const targets = Array.isArray(event.targets) ? event.targets : [];
  const targetMappingConsistent = targets.every((target) => {
    const targetParticipantId = participantIdFromChampionNetworkId(target.network_id);
    if (targetParticipantId === null) {
      return target.participant_id === null && target.champion === null;
    }
    return target.participant_id === targetParticipantId
      && target.champion === context.players[targetParticipantId - 1]?.champion;
  });
  const casterMappingConsistent = participantId !== null
    && event.caster_participant_id === participantId
    && event.source_participant_id === participantId
    && event.caster_champion === player?.champion
    && event.source_champion === player?.champion;
  const rawProvenanceValid = event.raw_packet_ref?.replay_sha256 === context.replay.source_sha256
    && event.raw_packet_ref?.packet_id === CAST_SPELL_PROFILE.replay_block_packet_id
    && Number.isInteger(event.raw_packet_ref?.chunk_index)
    && Number.isInteger(event.raw_packet_ref?.decompressed_block_offset)
    && /^[0-9a-f]{64}$/.test(event.raw_packet_ref?.payload_sha256 || '');
  const directFieldsValid = Number.isFinite(event.replay_time_ms)
    && event.replay_time_ms >= 0
    && Number.isInteger(event.caster_network_id)
    && Number.isInteger(event.spell_key)
    && /^0x[0-9a-f]{8}$/.test(event.spell_key_hex || '')
    && Number.isFinite(event.internal_cast_time_ms)
    && casterMappingConsistent
    && targetMappingConsistent
    && rawProvenanceValid
    && event.field_confidence?.replay_time_ms === 'VERIFIED_DIRECT'
    && event.field_confidence?.caster_network_id === 'VERIFIED_DIRECT'
    && event.field_confidence?.spell_key === 'VERIFIED_DIRECT'
    && event.field_confidence?.targets === 'VERIFIED_DIRECT';
  const deltaMs = event.internal_cast_time_ms - event.replay_time_ms;
  return {
    participantId,
    casterMappingConsistent,
    targetMappingConsistent,
    rawProvenanceValid,
    directFieldsValid,
    deltaMs,
    alignedWithin1Ms: Math.abs(deltaMs) <= 1,
  };
}

function isProtectionValidationSlot(champion, slot) {
  return PROTECTION_VALIDATION_SLOTS[champion]?.has(slot) ?? false;
}

function aggregateRowPass(row, mode) {
  if (mode === 'strict') return row.within_1;
  return row.metadata_aggregate_cast_count > 0
    && row.replay_player_cast_group_count > 0
    && row.replay_to_metadata_ratio >= 0.75
    && row.replay_to_metadata_ratio <= 1.30;
}

function percentile(values, ratio) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * ratio))];
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const contexts = loadReplays(options.replayDir, options.replayFiles);
  if (contexts.size === 0) {
    throw new Error(`no ${CAST_SPELL_PROFILE.replay_version} Replay found`);
  }
  const eventsByReplay = new Map([...contexts.keys()].map((sha256) => [sha256, []]));
  const eventsInput = readline.createInterface({
    input: fs.createReadStream(options.events),
    crlfDelay: Infinity,
  });
  for await (const line of eventsInput) {
    if (!line.trim()) continue;
    const event = JSON.parse(line);
    const replaySha256 = event.raw_packet_ref?.replay_sha256;
    if (!contexts.has(replaySha256)) {
      throw new Error(`spell event references an unknown Replay: ${replaySha256}`);
    }
    eventsByReplay.get(replaySha256).push(event);
  }

  const eventRows = [];
  const aggregateRows = [];
  const perReplayRows = [];
  const directDeltas = [];
  const participantCoverage = new Set();
  let directValidCount = 0;
  let alignedWithin1MsCount = 0;
  let mappedTargetCount = 0;
  let directTargetCount = 0;
  let dictionaryResolvedCount = 0;

  for (const [replaySha256, context] of contexts) {
    const events = eventsByReplay.get(replaySha256) || [];
    events.sort((left, right) => left.replay_time_ms - right.replay_time_ms);
    let replayDirectValid = 0;
    let replayAligned = 0;
    let replayTargets = 0;
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      const validation = coreEventValidation(event, context);
      directValidCount += Number(validation.directFieldsValid);
      replayDirectValid += Number(validation.directFieldsValid);
      alignedWithin1MsCount += Number(validation.alignedWithin1Ms);
      replayAligned += Number(validation.alignedWithin1Ms);
      directDeltas.push(validation.deltaMs);
      participantCoverage.add(`${replaySha256}:${event.caster_participant_id}`);
      dictionaryResolvedCount += Number(event.spell_identifier !== null);
      replayTargets += event.targets.length;
      directTargetCount += event.targets.length;
      mappedTargetCount += event.targets.filter((target) => target.participant_id !== null).length;
      eventRows.push({
        validation_id: `${replaySha256}:spell:${index + 1}`,
        validation_label: options.label,
        replay_sha256: replaySha256,
        replay_time_ms: event.replay_time_ms,
        internal_cast_time_ms: event.internal_cast_time_ms,
        internal_delta_ms: validation.deltaMs,
        aligned_within_1ms: validation.alignedWithin1Ms,
        caster_network_id: event.caster_network_id,
        caster_participant_id: event.caster_participant_id,
        caster_champion: event.caster_champion,
        spell_key_hex: event.spell_key_hex,
        spell_identifier: event.spell_identifier,
        spell_slot: event.spell_slot,
        target_count: event.target_count,
        target_network_ids: event.targets.map((target) => target.network_id),
        target_participant_ids: event.targets.map((target) => target.participant_id),
        player_cast_group_id: event.player_cast_group_id,
        player_cast_group_size: event.player_cast_group_size,
        is_player_cast_group_leader: event.is_player_cast_group_leader,
        protection_cast_kind: event.protection_cast_kind,
        caster_mapping_consistent: validation.casterMappingConsistent,
        target_mapping_consistent: validation.targetMappingConsistent,
        raw_provenance_valid: validation.rawProvenanceValid,
        direct_fields_valid: validation.directFieldsValid,
        verdict: validation.directFieldsValid ? 'CORE_MATCH' : 'MISMATCH',
      });
    }

    const replayAggregateRows = [];
    for (const player of context.players) {
      const participantId = player.metadata_index + 1;
      for (let slotIndex = 0; slotIndex < SLOT_NAMES.length; slotIndex += 1) {
        const slot = SLOT_NAMES[slotIndex];
        const slotEvents = events.filter((event) => event.caster_participant_id === participantId
          && event.spell_slot === slot
          && event.is_primary_player_ability);
        const playerCasts = slotEvents.filter((event) => event.is_player_cast_group_leader);
        const metadataCount = player.aggregate_stats.spell_casts[slotIndex];
        const delta = playerCasts.length - metadataCount;
        const replayToMetadataRatio = metadataCount === 0
          ? null
          : playerCasts.length / metadataCount;
        const aggregateRow = {
          validation_label: options.label,
          replay_sha256: replaySha256,
          participant_id: participantId,
          champion: player.champion,
          role: player.role,
          spell_slot: slot,
          metadata_aggregate_cast_count: metadataCount,
          replay_primary_engine_row_count: slotEvents.length,
          replay_player_cast_group_count: playerCasts.length,
          absolute_delta: Math.abs(delta),
          signed_delta: delta,
          replay_to_metadata_ratio: replayToMetadataRatio,
          exact_match: delta === 0,
          within_1: Math.abs(delta) <= 1,
          selected_protection_validation_case: isProtectionValidationSlot(player.champion, slot),
          comparison_role: 'AGGREGATE_VALIDATION_ONLY',
        };
        aggregateRows.push(aggregateRow);
        replayAggregateRows.push(aggregateRow);
      }
    }
    const selected = replayAggregateRows.filter((row) => row.selected_protection_validation_case);
    const selectedPassing = selected.filter((row) => aggregateRowPass(row, options.aggregateMode));
    perReplayRows.push({
      validation_label: options.label,
      replay_path: context.replay.source_path,
      replay_sha256: replaySha256,
      replay_version: context.replay.header.version,
      hero_spell_event_count: events.length,
      direct_valid_event_count: replayDirectValid,
      aligned_within_1ms_count: replayAligned,
      aligned_within_1ms_ratio: events.length === 0 ? null : replayAligned / events.length,
      target_entry_count: replayTargets,
      primary_engine_row_count: events.filter((event) => event.is_primary_player_ability).length,
      player_cast_group_count: events.filter((event) => event.is_player_cast_group_leader).length,
      protection_cast_count: events.filter((event) => event.is_player_cast_group_leader
        && event.protection_cast_kind !== null).length,
      selected_protection_aggregate_case_count: selected.length,
      selected_protection_within_1_count: selected.filter((row) => row.within_1).length,
      selected_protection_gate_pass_count: selectedPassing.length,
      status: replayDirectValid === events.length
        && selectedPassing.length === selected.length ? 'PASS' : 'FAIL',
    });
  }

  const eventManifest = options.eventManifest
    ? JSON.parse(fs.readFileSync(options.eventManifest, 'utf8'))
    : null;
  const decodeSummary = options.decodeSummary
    ? JSON.parse(fs.readFileSync(options.decodeSummary, 'utf8'))
    : null;
  const selectedAggregateRows = aggregateRows.filter(
    (row) => row.selected_protection_validation_case,
  );
  const structuralPass = (!eventManifest || (
    eventManifest.status === 'PASS'
    && eventManifest.details_or_oracle_input === false
    && eventManifest.counts.semantic_hero_rows === eventRows.length
    && eventManifest.spell_dictionary_sha256 === CAST_SPELL_PROFILE.spell_dictionary_sha256
  )) && (!decodeSummary || (
    decodeSummary.event_count === decodeSummary.successful_full_consume_count
    && decodeSummary.image_sha256 === CAST_SPELL_PROFILE.runtime_image_sha256
  ));
  const directPass = eventRows.length > 0
    && directValidCount === eventRows.length
    && participantCoverage.size === contexts.size * 10;
  const alignedRatio = eventRows.length === 0 ? null : alignedWithin1MsCount / eventRows.length;
  const medianAbsoluteDelta = percentile(directDeltas.map(Math.abs), 0.5);
  const timestampPass = alignedRatio >= 0.90
    && medianAbsoluteDelta <= 1
    && Math.max(...directDeltas) <= 1;
  const aggregatePass = selectedAggregateRows.length > 0
    && selectedAggregateRows.every((row) => aggregateRowPass(row, options.aggregateMode));
  const status = structuralPass && directPass && timestampPass && aggregatePass
    && perReplayRows.every((row) => row.status === 'PASS') ? 'PASS' : 'FAIL';
  const summary = {
    schema_version: 1,
    status,
    validation_label: options.label,
    aggregate_validation_mode: options.aggregateMode,
    capability: 'CastSpell timestamp + caster + spell key + target list',
    confidence: status === 'PASS' ? 'VERIFIED_DIRECT' : 'UNVERIFIED',
    decoder_is_oracle_independent: eventManifest?.details_or_oracle_input !== true,
    match_details_input: false,
    validation_sources: [
      'Replay packet framing and timestamp',
      'decoded client CastSpell object fields',
      'ROFL metadata Q/W/E/R aggregate counts',
    ],
    replay_count: contexts.size,
    patch: CAST_SPELL_PROFILE.replay_version,
    hero_spell_event_count: eventRows.length,
    direct_valid_event_count: directValidCount,
    unique_replay_participant_casters: participantCoverage.size,
    target_entry_count: directTargetCount,
    champion_target_entry_count: mappedTargetCount,
    dictionary_resolved_event_count: dictionaryResolvedCount,
    dictionary_resolved_event_ratio: eventRows.length === 0
      ? null
      : dictionaryResolvedCount / eventRows.length,
    timestamp_alignment: {
      aligned_within_1ms_count: alignedWithin1MsCount,
      aligned_within_1ms_ratio: alignedRatio,
      minimum_delta_ms: directDeltas.length ? Math.min(...directDeltas) : null,
      maximum_delta_ms: directDeltas.length ? Math.max(...directDeltas) : null,
      median_absolute_delta_ms: medianAbsoluteDelta,
      p95_absolute_delta_ms: percentile(directDeltas.map(Math.abs), 0.95),
      note: 'Negative outliers are delayed engine rows whose embedded cast start predates packet emission.',
    },
    aggregate_validation: {
      role: 'VALIDATION_ONLY',
      all_slot_row_count: aggregateRows.length,
      exact_slot_row_count: aggregateRows.filter((row) => row.exact_match).length,
      within_1_slot_row_count: aggregateRows.filter((row) => row.within_1).length,
      selected_protection_case_count: selectedAggregateRows.length,
      selected_protection_exact_count: selectedAggregateRows.filter((row) => row.exact_match).length,
      selected_protection_within_1_count: selectedAggregateRows.filter((row) => row.within_1).length,
      selected_protection_gate_pass_count: selectedAggregateRows.filter(
        (row) => aggregateRowPass(row, options.aggregateMode),
      ).length,
      selected_cases: selectedAggregateRows,
      note: options.aggregateMode === 'strict'
        ? 'Development protection cases require an absolute aggregate delta no greater than one.'
        : 'Blind holdout cases require a nonzero independently decoded count within 0.75x to 1.30x of metadata; exact equality is not assumed for cast attempts, recasts, echoes, or fan-out.',
    },
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      caster_network_id: 'VERIFIED_DIRECT',
      spell_key: 'VERIFIED_DIRECT',
      targets: 'VERIFIED_DIRECT',
      caster_participant_id: 'VERIFIED_DERIVED',
      spell_identifier: 'VERIFIED_DERIVED',
      spell_slot: 'VERIFIED_DERIVED',
      protection_cast_kind: 'VERIFIED_DERIVED',
      shield_amount: 'UNAVAILABLE',
      healing_amount: 'UNAVAILABLE',
    },
    gates: {
      structural_pass: structuralPass,
      direct_fields_and_mapping_pass: directPass,
      timestamp_alignment_pass: timestampPass,
      selected_protection_aggregate_pass: aggregatePass,
      per_replay_pass: perReplayRows.every((row) => row.status === 'PASS'),
    },
    inputs: {
      events: options.events,
      events_sha256: await sha256File(options.events),
      event_manifest: options.eventManifest,
      decode_summary: options.decodeSummary,
    },
    per_replay: perReplayRows,
  };

  fs.mkdirSync(options.outputDir, { recursive: true });
  writeJson(path.join(options.outputDir, 'spell_validation_summary.json'), summary);
  writeJson(path.join(options.outputDir, 'spell_validation_all.json'), {
    summary,
    aggregate_rows: aggregateRows,
    event_rows: eventRows,
  });
  writeCsv(path.join(options.outputDir, 'spell_validation_all.csv'), eventRows);
  writeCsv(path.join(options.outputDir, 'spell_aggregate_validation.csv'), aggregateRows);
  writeCsv(path.join(options.outputDir, 'per_replay_spell_validation.csv'), perReplayRows);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  PROTECTION_VALIDATION_SLOTS,
  aggregateRowPass,
  coreEventValidation,
  isProtectionValidationSlot,
  main,
  parseArgs,
  percentile,
};
