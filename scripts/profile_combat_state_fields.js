#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  TYPED_FIELD_SCHEMA_VERSION,
  createFieldBehaviorProfile,
  createTypedFieldBehaviorProfile,
  numericPacketId,
  packetRecordsFromHexField,
  typedPacketRecordsFromDecodedFields,
  writeFieldBehaviorProfile,
} = require('../src/field_behavior_profiler');

function requireValue(argv, index, option) {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${option} requires a value`);
  return value;
}

function positiveInteger(value, option) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${option} requires a positive integer`);
  return parsed;
}

function parseAnchorSpec(value) {
  const match = /^([a-z_-]+)=(.+)$/i.exec(value);
  if (!match) throw new Error('--anchor requires KIND=FILE, for example damage=damage_events.jsonl');
  return { eventType: match[1], filePath: path.resolve(match[2]) };
}

function parseArgs(argv) {
  const options = {
    output: path.resolve('artifacts', 'hero_combat_state_v2', 'profiler', 'field_behavior_profile.json'),
    replayPaths: [],
    packetRecordPaths: [],
    routeIds: [],
    candidateReportPath: null,
    anchorSpecs: [],
    targetBuild: null,
    maxRoutes: 5,
    maxObservationsPerRoute: 25000,
    maxPayloadBytes: 2048,
    maxCandidatesPerType: 64,
    maxPackedCarrierOffsets: 64,
    maxReportedEntities: 100,
    maxRankedCandidates: 500,
    medianSampleLimit: 512,
    anchorWindowMs: 5000,
    offsetStride: 1,
    hexField: null,
    fieldSchemaPath: null,
    requireFullyConsumed: true,
    routeRole: 'CANDIDATE',
    knownRouteSemantics: null,
    maxTrajectoryFields: 0,
    maxTrajectoryPointsPerEntity: 0,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(requireValue(argv, index++, value));
    else if (value === '--replay') options.replayPaths.push(path.resolve(requireValue(argv, index++, value)));
    else if (value === '--packet-records') options.packetRecordPaths.push(path.resolve(requireValue(argv, index++, value)));
    else if (value === '--hex-field') options.hexField = requireValue(argv, index++, value);
    else if (value === '--field-schema') options.fieldSchemaPath = path.resolve(requireValue(argv, index++, value));
    else if (value === '--allow-partial-decodes') options.requireFullyConsumed = false;
    else if (value === '--route') options.routeIds.push(numericPacketId(requireValue(argv, index++, value)));
    else if (value === '--candidate-report') options.candidateReportPath = path.resolve(requireValue(argv, index++, value));
    else if (value === '--anchor') options.anchorSpecs.push(parseAnchorSpec(requireValue(argv, index++, value)));
    else if (value === '--anchors') options.anchorSpecs.push({ eventType: null, filePath: path.resolve(requireValue(argv, index++, value)) });
    else if (value === '--build') options.targetBuild = requireValue(argv, index++, value);
    else if (value === '--max-routes') options.maxRoutes = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-observations-per-route') options.maxObservationsPerRoute = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-payload-bytes') options.maxPayloadBytes = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-candidates-per-type') options.maxCandidatesPerType = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-packed-carriers') options.maxPackedCarrierOffsets = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-reported-entities') options.maxReportedEntities = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-ranked-candidates') options.maxRankedCandidates = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--median-sample-limit') options.medianSampleLimit = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--anchor-window-ms') options.anchorWindowMs = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--offset-stride') options.offsetStride = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--route-role') options.routeRole = requireValue(argv, index++, value).toUpperCase();
    else if (value === '--known-route-semantics') options.knownRouteSemantics = requireValue(argv, index++, value);
    else if (value === '--max-trajectory-fields') options.maxTrajectoryFields = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--max-trajectory-points-per-entity') options.maxTrajectoryPointsPerEntity = positiveInteger(requireValue(argv, index++, value), value);
    else if (value === '--help' || value === '-h') options.help = true;
    else if (value.startsWith('-')) throw new Error(`unknown option: ${value}`);
    else if (value.toLowerCase().endsWith('.rofl')) options.replayPaths.push(path.resolve(value));
    else throw new Error(`expected a .rofl path or option; got ${value}`);
  }
  if (!options.help && options.replayPaths.length === 0 && options.packetRecordPaths.length === 0) {
    throw new Error('supply at least one exact-build .rofl input or --packet-records JSONL');
  }
  if (!options.help && options.replayPaths.length > 0 && options.packetRecordPaths.length > 0) {
    throw new Error('raw Replay walking and decoded --packet-records are separate input modes');
  }
  if (!options.help && options.packetRecordPaths.length > 0 && !options.hexField && !options.fieldSchemaPath) {
    throw new Error('--packet-records requires --hex-field or an explicit --field-schema');
  }
  if (!options.help && !['CANDIDATE', 'NEGATIVE_CONTROL'].includes(options.routeRole)) {
    throw new Error('--route-role must be CANDIDATE or NEGATIVE_CONTROL');
  }
  if (!options.help && options.replayPaths.length > 0
      && options.routeIds.length === 0 && !options.candidateReportPath) {
    throw new Error('supply --route or --candidate-report');
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/profile_combat_state_fields.js [options] replay.rofl ...',
    '  --route OPCODE                    Explicit candidate route; repeatable',
    '  --candidate-report FILE           Existing combat candidate report or packet inventory',
    '  --packet-records FILE             Decoded/emulated JSON or JSONL packet rows; repeatable',
    '  --hex-field PATH                  Hex payload field, including dotted paths such as decoded_fields.blob_hex',
    '  --field-schema FILE               Explicit raw-bit or typed decoded-field schema; required for non-byte values',
    '  --allow-partial-decodes           Include rows explicitly marked fully_consumed=false',
    '  --anchor KIND=FILE                JSON/JSONL anchors; damage/heal/shield/death/respawn/level/item_change/cast/ward/movement',
    '  --anchors FILE                    JSON/JSONL anchors with event_type in each row',
    '  --build BUILD                     Require one exact Replay build',
    '  --output FILE                     Deterministic JSON report path',
    '  --max-routes N                    Candidate-report route cap (default 5)',
    '  --max-observations-per-route N    Deterministic reservoir cap (default 25000)',
    '  --max-payload-bytes N             Per-payload scan cap (default 2048)',
    '  --max-candidates-per-type N       Full profiles retained per primitive type (default 64)',
    '  --max-packed-carriers N           Byte offsets expanded into bit/packed candidates (default 64)',
    '  --anchor-window-ms N              Maximum distance on each side of an anchor (default 5000)',
    '  --offset-stride N                 Offset scan stride (default 1, including unaligned fields)',
    '  --route-role ROLE                 CANDIDATE or NEGATIVE_CONTROL',
    '  --known-route-semantics TEXT      Exact recovered route meaning; does not name fields',
    '  --max-trajectory-fields N         Include bounded entity trajectories for top N fields',
    '  --max-trajectory-points-per-entity N  Deterministic trajectory point cap',
    '',
    'All scores and correlations are candidate-ranking evidence only; this command never names or promotes a semantic field.',
  ].join('\n');
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function rowsFromJson(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return [];
  for (const key of [
    'anchors',
    'events',
    'rows',
    'damage_events',
    'death_events',
    'heal_events',
    'shield_events',
    'respawn_events',
    'level_events',
    'item_events',
    'item_change_events',
    'cast_events',
    'ward_events',
    'movement_events',
    'position_events',
  ]) {
    if (Array.isArray(value[key])) return value[key];
  }
  return [value];
}

function loadAnchorFile(spec) {
  const source = fs.readFileSync(spec.filePath);
  const text = source.toString('utf8');
  let rows;
  if (spec.filePath.toLowerCase().endsWith('.jsonl')) {
    rows = text.split(/\r?\n/).filter((line) => line.trim().length > 0).map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`invalid JSONL at ${spec.filePath}:${index + 1}: ${error.message}`);
      }
    });
  } else {
    rows = rowsFromJson(JSON.parse(text));
  }
  const anchors = rows.map((row) => spec.eventType ? { ...row, event_type: spec.eventType } : row);
  return {
    anchors,
    source: {
      source_path: spec.filePath,
      source_sha256: sha256Buffer(source),
      declared_event_type: spec.eventType,
      input_row_count: rows.length,
    },
  };
}

function loadPacketRecordFile(filePath) {
  const source = fs.readFileSync(filePath);
  const text = source.toString('utf8');
  let rows;
  if (filePath.toLowerCase().endsWith('.jsonl')) {
    rows = text.split(/\r?\n/).filter((line) => line.trim().length > 0).map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`invalid JSONL at ${filePath}:${index + 1}: ${error.message}`);
      }
    });
  } else {
    rows = rowsFromJson(JSON.parse(text));
  }
  return {
    rows,
    source: {
      source_path: filePath,
      source_sha256: sha256Buffer(source),
      input_row_count: rows.length,
      source_kind: 'DECODED_OR_EMULATED_PACKET_RECORDS',
    },
  };
}

function main(argv = process.argv.slice(2)) {
  const cli = parseArgs(argv);
  if (cli.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  let candidateReport = null;
  if (cli.candidateReportPath) {
    candidateReport = JSON.parse(fs.readFileSync(cli.candidateReportPath, 'utf8'));
    if (!cli.targetBuild) {
      cli.targetBuild = candidateReport.target_build
        ?? candidateReport.builds?.[0]?.game_version
      ?? null;
    }
  }
  let fieldSchema = null;
  let fieldSchemaSource = null;
  if (cli.fieldSchemaPath) {
    const source = fs.readFileSync(cli.fieldSchemaPath);
    fieldSchema = JSON.parse(source.toString('utf8'));
    fieldSchemaSource = {
      source_path: cli.fieldSchemaPath,
      source_sha256: sha256Buffer(source),
      schema: fieldSchema?.schema ?? null,
    };
  }
  const typedMode = fieldSchema?.schema === TYPED_FIELD_SCHEMA_VERSION;
  if (typedMode && cli.replayPaths.length > 0) {
    throw new Error('typed decoded-field schemas require --packet-records and cannot read raw Replay packets');
  }
  if (typedMode && cli.hexField) {
    throw new Error('--hex-field and a typed decoded-field schema are separate input adapters');
  }
  if (!typedMode && cli.packetRecordPaths.length > 0 && !cli.hexField) {
    throw new Error('raw field schemas over decoded packet records still require --hex-field');
  }
  const loadedAnchors = cli.anchorSpecs.map(loadAnchorFile);
  const loadedPacketFiles = cli.packetRecordPaths.map(loadPacketRecordFile);
  const rawPacketRecords = loadedPacketFiles.flatMap((entry) => entry.rows);
  if (!cli.targetBuild && rawPacketRecords.length > 0) {
    cli.targetBuild = rawPacketRecords[0].replay_version
      ?? rawPacketRecords[0].game_version
      ?? rawPacketRecords[0].build
      ?? null;
  }
  const extracted = rawPacketRecords.length > 0
    ? typedMode
      ? typedPacketRecordsFromDecodedFields(rawPacketRecords, fieldSchema, {
        targetBuild: cli.targetBuild,
        requireFullyConsumed: cli.requireFullyConsumed,
      })
      : packetRecordsFromHexField(rawPacketRecords, cli.hexField, {
      targetBuild: cli.targetBuild,
      requireFullyConsumed: cli.requireFullyConsumed,
      })
    : null;
  if (extracted && extracted.records.length === 0) {
    throw new Error(`no usable ${typedMode ? 'typed decoded-field' : cli.hexField} values remained after exact-build/full-consume validation`);
  }
  const commonArguments = {
    replayPaths: cli.replayPaths,
    packetRecords: extracted?.records ?? null,
    packetRecordSources: loadedPacketFiles.map((entry) => ({
      ...entry.source,
      hex_field: typedMode ? null : cli.hexField,
      typed_field_schema: typedMode ? fieldSchemaSource : null,
    })),
    packetRecordExtraction: extracted ? {
      input_row_count: extracted.input_row_count,
      accepted_row_count: extracted.accepted_row_count,
      rejected_row_count: extracted.rejected_row_count,
      rejected: extracted.rejected,
      hex_field: extracted.hex_field ?? null,
      require_fully_consumed: extracted.require_fully_consumed,
      champion_mapping: extracted.champion_mapping,
    } : null,
    routeIds: cli.routeIds,
    candidateReport,
    candidateReportPath: cli.candidateReportPath,
    anchors: loadedAnchors.flatMap((entry) => entry.anchors),
    anchorSources: loadedAnchors.map((entry) => entry.source),
    targetBuild: cli.targetBuild,
    options: {
      maxRoutes: cli.maxRoutes,
      maxObservationsPerRoute: cli.maxObservationsPerRoute,
      maxPayloadBytes: cli.maxPayloadBytes,
      maxCandidatesPerType: cli.maxCandidatesPerType,
      maxPackedCarrierOffsets: cli.maxPackedCarrierOffsets,
      maxReportedEntities: cli.maxReportedEntities,
      maxRankedCandidates: cli.maxRankedCandidates,
      medianSampleLimit: cli.medianSampleLimit,
      anchorWindowMs: cli.anchorWindowMs,
      offsetStride: cli.offsetStride,
      routeRole: cli.routeRole,
      knownRouteSemantics: cli.knownRouteSemantics,
      maxTrajectoryFields: cli.maxTrajectoryFields,
      maxTrajectoryPointsPerEntity: cli.maxTrajectoryPointsPerEntity,
      configuredFields: typedMode ? null : fieldSchema,
    },
  };
  const report = typedMode
    ? createTypedFieldBehaviorProfile({
      ...commonArguments,
      fieldSchema,
      fieldSchemaSource,
    })
    : createFieldBehaviorProfile(commonArguments);
  const output = writeFieldBehaviorProfile(cli.output, report);
  process.stdout.write(`${JSON.stringify({
    output,
    schema: report.schema,
    input_mode: report.input.input_mode,
    target_build: report.target_build,
    replay_count: report.input.replay_count,
    selected_routes: report.input.selected_routes.map((row) => row.packet_discriminator),
    profiled_routes: report.route_profiles.filter((row) => row.profiled_record_count > 0).length,
    ranked_candidate_count: report.ranked_candidates.length,
    anchor_counts: report.input.anchors.counts,
    semantic_status: report.semantic_status,
  }, null, 2)}\n`);
  return report;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  loadAnchorFile,
  loadPacketRecordFile,
  main,
  parseAnchorSpec,
  parseArgs,
  rowsFromJson,
  usage,
};
