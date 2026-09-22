'use strict';

// Builds a bounded audit from the published special-slot ItemState artifact.  The
// script does not run a decoder or reinterpret any raw protocol field.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { createCapabilityManifest, queryCapability } = require('../src/capability_manifest');
const { EXACT_BUILD, assertSafeArtifactPath, inventoryStateIndex, inventory_state_at } = require('../src/inventory_state_at');

const ROOT = path.resolve(__dirname, '..');
const INPUTS = Object.freeze({
  itemSet: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'entity_item', 'packet_006c_native_decoded_16_16.jsonl'),
  inventorySummary: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'entity_item', 'entity_item_deep_recovery_summary_16_16.json'),
});
const DEFAULT_OUTPUT = path.join(ROOT, '.omo', 'evidence', 'stat_semantic_mapping_v1', 'inventory_state');
const ITEM_SET_ROUTE = 0x006c;
const ITEM_SET_ROUTE_LABEL = '0x006c';

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJsonl(filePath) {
  return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort()
    .map((key) => [key, stableValue(value[key])]));
  return value;
}

function stableJson(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function uniqueRequired(rows, field, label) {
  const values = [...new Set(rows.map((row) => row[field]).filter((value) => typeof value === 'string' && value.length > 0))];
  if (values.length !== 1 || rows.some((row) => row[field] !== values[0])) {
    throw new Error(`governed item-set ${label} must have exactly one non-empty value`);
  }
  return values[0];
}

function validateGovernedItemSet(rows, summary) {
  if (!Array.isArray(rows) || rows.length === 0) throw new Error('governed item-set input is empty');
  if (!summary || summary.build !== EXACT_BUILD) throw new Error('inventory summary exact build mismatch');
  const directRows = rows.filter((row) => row.fully_consumed === true);
  if (directRows.length !== rows.length) throw new Error('item-set input contains non-full-consume rows');
  for (const row of directRows) {
    if (row.replay_version !== EXACT_BUILD || row.packet_id !== ITEM_SET_ROUTE
        || String(row.packet_type).toLowerCase() !== ITEM_SET_ROUTE_LABEL) {
      throw new Error('item-set route/build/opcode provenance mismatch');
    }
    if (!row.decoded_fields || !Number.isInteger(row.decoded_fields.item_id_0x1c)
        || !Number.isInteger(row.decoded_fields.slot_index_0x22)
        || !Number.isInteger(row.decoded_fields.stack_count_0x78)) {
      throw new Error('item-set direct field provenance is incomplete');
    }
  }
  const runtimeImageSha256 = uniqueRequired(directRows, 'decoder_runtime_image_sha256', 'runtime image SHA-256');
  const decoderProfileId = uniqueRequired(directRows, 'decoder_profile', 'decoder profile ID');
  const decoderProfileSha256 = uniqueRequired(directRows, 'decoder_profile_sha256', 'decoder profile SHA-256');
  if (summary.runtime_image_sha256 !== runtimeImageSha256) throw new Error('summary/runtime image SHA-256 mismatch');
  if (summary.set_item_special_slot?.event_count !== directRows.length
      || summary.set_item_special_slot?.native_full_consume_count !== directRows.length) {
    throw new Error('summary/item-set row count mismatch');
  }
  return Object.freeze({
    exact_build: EXACT_BUILD,
    route: ITEM_SET_ROUTE_LABEL,
    opcode: ITEM_SET_ROUTE,
    decoder_profile_id: decoderProfileId,
    decoder_profile_sha256: decoderProfileSha256,
    runtime_image_sha256: runtimeImageSha256,
    input_row_count: directRows.length,
  });
}

function eventFromDirectItemSet(row, sourcePath, binding) {
  if (row.replay_version !== EXACT_BUILD || row.packet_id !== ITEM_SET_ROUTE || row.fully_consumed !== true) return null;
  if (binding && (row.decoder_profile !== binding.decoder_profile_id
      || row.decoder_profile_sha256 !== binding.decoder_profile_sha256
      || row.decoder_runtime_image_sha256 !== binding.runtime_image_sha256)) {
    throw new Error('item-set row does not match governed decoder provenance binding');
  }
  const fields = row.decoded_fields;
  if (!fields || !Number.isInteger(fields.item_id_0x1c) || !Number.isInteger(fields.slot_index_0x22)
      || !Number.isInteger(fields.stack_count_0x78)) return null;
  return {
    event_type: 'ITEM_STATE_SET',
    exact_build: row.replay_version,
    replay_sha256: row.replay_sha256,
    replay_time_ms: row.replay_time_ms,
    occurrence_index: row.occurrence_index,
    subject_entity_id: row.raw_param >>> 0,
    slot_index: fields.slot_index_0x22,
    item_id: fields.item_id_0x1c,
    stack_count: fields.stack_count_0x78,
    semantic_status: 'VERIFIED_DIRECT',
    decoder_profile: row.decoder_profile,
    raw_payload_sha256: row.raw_payload_sha256,
    raw_packet_ref: {
      replay_sha256: row.replay_sha256,
      packet_id: row.packet_id,
      chunk_index: row.chunk_index,
      decompressed_block_offset: row.decompressed_block_offset,
      payload_length: row.payload_length,
      raw_param: row.raw_param,
      packet_timestamp_ms: row.replay_time_ms,
    },
    source_artifact_path: sourcePath,
  };
}

function runeInputAudit() {
  const manifest = createCapabilityManifest();
  return ['RUNE_STATE', 'RUNE_PROC'].map((capability) => {
    const result = queryCapability(manifest, { build: EXACT_BUILD, capability });
    return {
      capability,
      exact_build: EXACT_BUILD,
      published_status: result.status,
      evidence_grade: result.record?.evidence_grade ?? 'UNAVAILABLE',
      source: 'src/capability_manifest.js public capability interface',
      default_assumption: 'NO_DEFAULT_APPLIED',
      inventory_state_effect: 'RUNE_INPUTS_UNKNOWN_NOT_TREATED_AS_ABSENT',
    };
  });
}

function build(outputDirectory = DEFAULT_OUTPUT) {
  const safeInputs = Object.fromEntries(Object.entries(INPUTS).map(([name, input]) => [name, assertSafeArtifactPath(input)]));
  const rows = readJsonl(safeInputs.itemSet);
  const summary = JSON.parse(fs.readFileSync(safeInputs.inventorySummary, 'utf8'));
  const binding = validateGovernedItemSet(rows, summary);
  const inputSha256 = sha256File(safeInputs.itemSet);
  const events = rows.map((row) => eventFromDirectItemSet(row, safeInputs.itemSet, binding)).filter(Boolean);
  const index = inventoryStateIndex(events, { exact_build: EXACT_BUILD });
  const sampleQueries = events.slice(0, 10).map((event) => inventory_state_at(
    index,
    event.subject_entity_id,
    event.replay_time_ms,
    { exact_build: EXACT_BUILD },
  ));
  const artifact = {
    schema: 'ROFL_INVENTORY_STATE_AT_AUDIT_V1',
    exact_build: EXACT_BUILD,
    nearest_build_fallback: 'FORBIDDEN',
    input_mode: 'EXPLICIT_PUBLISHED_ARTIFACT_ALLOWLIST',
    governed_input_binding: {
      ...binding,
      item_set_input_sha256: inputSha256,
      inventory_summary_sha256: sha256File(safeInputs.inventorySummary),
    },
    inputs: Object.fromEntries(Object.entries(safeInputs).map(([name, input]) => [name, {
      path: input,
      sha256: sha256File(input),
    }])),
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
    published_event_audit: {
      ITEM_STATE_SET: {
        route: ITEM_SET_ROUTE_LABEL,
        direct_rows_observed: events.length,
        corpus_summary_declared_rows: summary.set_item_special_slot?.event_count ?? null,
        emitted_layer_records: events.length,
        scope: 'special slot 8 only; incomplete inventory state remains partial',
      },
      ITEM_STATE_SNAPSHOT: {
        status: 'PUBLISHED_LAYOUT_ARTIFACT_EXISTS_BUT_NO_CANONICAL_EVENT_STREAM_INPUT',
        route: '0x0311 / 0x02ea',
        action: 'NOT_REDECODED_OR_REIMPLEMENTED_BY_THIS_CONSUMER_LAYER',
      },
      ITEM_SWAP: {
        status: 'PUBLISHED_DIRECT_CARRIER_BUT_NO_CANONICAL_EVENT_STREAM_INPUT',
        route: '0x01e8',
        fail_closed_behavior_when_supplied: 'INVALIDATES_CARRIED_STATE_BECAUSE_ITEM_IDENTITY_IS_NOT_PUBLISHED',
      },
      ITEM_SUBSTITUTION_MAP: {
        status: 'PUBLISHED_DIRECT_MAP_BUT_NO_CANONICAL_EVENT_STREAM_INPUT',
        route: '0x005a',
        fail_closed_behavior_when_supplied: 'NEVER_TREATED_AS_AN_INVENTORY_TRANSFORM',
      },
      SUPPORT_QUEST_ITEM_STAGE: {
        status: 'PUBLISHED_DERIVED_CAPABILITY_BUT_NO_CANONICAL_EVENT_STREAM_INPUT',
        route: '0x0064',
        fail_closed_behavior_when_supplied: 'RETAINED_AS_STAGE_OBSERVATION_NOT_INVENTORY_MEMBERSHIP',
      },
    },
    result: {
      index_source_event_count: index.source_event_count,
      sample_query_count: sampleQueries.length,
      sample_query_status_counts: sampleQueries.reduce((acc, row) => {
        acc[row.status] = (acc[row.status] ?? 0) + 1;
        return acc;
      }, {}),
      sample_queries: sampleQueries,
    },
    rune_input_availability: runeInputAudit(),
  };
  const output = path.resolve(outputDirectory);
  assertSafeArtifactPath(output);
  fs.mkdirSync(output, { recursive: true });
  const outputPath = path.join(output, 'inventory_state_at_audit.json');
  fs.writeFileSync(outputPath, stableJson(artifact));
  const auditStat = fs.statSync(outputPath);
  const manifest = {
    schema: 'ROFL_INVENTORY_STATE_AT_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    nearest_build_fallback: 'FORBIDDEN',
    governed_input_binding: artifact.governed_input_binding,
    artifacts: [{
      path: path.basename(outputPath),
      bytes: auditStat.size,
      sha256: sha256File(outputPath),
    }],
  };
  const manifestPath = path.join(output, 'artifact_manifest.json');
  fs.writeFileSync(manifestPath, stableJson(manifest));
  return {
    outputPath,
    manifestPath,
    manifestSha256: sha256File(manifestPath),
    artifact,
    manifest,
  };
}

if (require.main === module) {
  const outputIndex = process.argv.indexOf('--output');
  const output = outputIndex >= 0 ? process.argv[outputIndex + 1] : DEFAULT_OUTPUT;
  if (!output) throw new Error('--output requires a path');
  process.stdout.write(`${JSON.stringify(build(output), null, 2)}\n`);
}

module.exports = {
  DEFAULT_OUTPUT,
  INPUTS,
  ITEM_SET_ROUTE,
  build,
  eventFromDirectItemSet,
  runeInputAudit,
  stableJson,
  validateGovernedItemSet,
};
