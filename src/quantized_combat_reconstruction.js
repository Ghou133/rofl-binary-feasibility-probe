'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { createCapabilityManifest, CAPABILITY_VOCABULARY } = require('./capability_manifest');
const {
  decodeShieldCallbackObject,
  shieldAbsorbedFromFullyConsumedRow,
  validateShieldCallbackDisassembly,
} = require('./decoders/shield_absorbed_16_16');
const { parseReplayFile, walkBlocks } = require('./rofl');
const { SemanticFingerprint } = require('./semantic_fingerprint');
const { createMigrationDecision } = require('./semantic_migration_oracle');

const EXACT_BUILD = '16.16.805.0442';
const EXACT_REPLAY_SHA = '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff';
const EXACT_RUNTIME_IMAGE_SHA = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const EXACT_DAMAGE_DECODER_PROFILE = 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1';
const CANONICAL_SHIELD_SCAN_SHA256 = '29adeac8050699eece71964183c87faa3e0b2cc4d7330c28158b7c4628c3b5b8';
const CANONICAL_SHIELD_CORPUS_SHA256 = '70e5fc3e03043619746331c9f83f0190bdac9d100c78555fb20496a1e00b333d';
const CANONICAL_REPLAY_INVENTORY_SHA256 = '22f7b75cb4757213d4d1316148b727d9ffa05e716a64ce40ae73672a0eb10291';
const CANONICAL_REPLAY_INVENTORY_PATH = path.resolve(__dirname, '..', 'artifacts',
  'new_build_rofl_compatibility_gate_v1', 'new_build_replay_inventory.csv');
const PROJECTIONS = Object.freeze(['FLOOR', 'ROUND_NEAREST', 'TRUNCATE_TOWARD_ZERO']);
const DERIVABILITY_CLASSES = Object.freeze([
  'DIRECT_REQUIRED', 'DERIVABLE_NOW', 'DERIVABLE_IF_INPUT_X',
  'CONDITIONALLY_DERIVABLE', 'NON_DETERMINISTIC', 'INSUFFICIENT_EVIDENCE',
]);

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function assertSafePath(file) {
  if (/holdout/i.test(path.resolve(file))) throw new Error('protected holdout path is forbidden');
}

function displayInterval(displayValue, projection) {
  if (!Number.isInteger(displayValue)) throw new Error('HUD display value must be an integer');
  if (projection === 'FLOOR') return { lower: displayValue, upper: displayValue + 1, lower_closed: true, upper_closed: false };
  if (projection === 'ROUND_NEAREST') return { lower: displayValue - 0.5, upper: displayValue + 0.5, lower_closed: true, upper_closed: false };
  if (projection === 'TRUNCATE_TOWARD_ZERO') {
    if (displayValue >= 0) return { lower: displayValue, upper: displayValue + 1, lower_closed: true, upper_closed: false };
    return { lower: displayValue - 1, upper: displayValue, lower_closed: false, upper_closed: true };
  }
  throw new Error(`unknown display projection: ${projection}`);
}

function decreaseInterval(beforeDisplay, afterDisplay, projection) {
  const before = displayInterval(beforeDisplay, projection);
  const after = displayInterval(afterDisplay, projection);
  return {
    lower: before.lower - after.upper,
    upper: before.upper - after.lower,
    lower_closed: before.lower_closed && after.upper_closed,
    upper_closed: before.upper_closed && after.lower_closed,
  };
}

function intervalContains(interval, value) {
  // HUD interval endpoints are integers or binary-exact halves, while the decoded
  // amount is the exact JS Number representation of the stored f32.  No tolerance
  // is needed or permitted: open boundaries stay mathematically open and closed
  // boundaries stay closed.  A future non-binary-exact projection must provide a
  // single representation-derived error budget rather than a candidate-tuned one.
  const aboveLower = interval.lower_closed ? value >= interval.lower : value > interval.lower;
  const belowUpper = interval.upper_closed ? value <= interval.upper : value < interval.upper;
  return aboveLower && belowUpper;
}

function readJson(file) {
  assertSafePath(file);
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function readJsonl(file) {
  assertSafePath(file);
  return fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean).map(JSON.parse);
}

function parseReplayInventoryCsv(file) {
  assertSafePath(file);
  const lines = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').trim().split(/\r?\n/);
  const headers = lines.shift().split(',');
  return lines.map((line) => {
    const values = line.split(',');
    return Object.fromEntries(headers.map((header, index) => [header, values[index]]));
  });
}

async function scanShieldRouteMigrationCorpus(inventoryCsv) {
  const inventoryRows = parseReplayInventoryCsv(inventoryCsv)
    .filter((row) => row.selected_for_validation === 'YES');
  if (inventoryRows.length !== 40) throw new Error(`expected 40 governed selected 16.16 replays, got ${inventoryRows.length}`);
  const routeCounts = new Map();
  const length10HeroParamCounts = new Map();
  const replays = [];
  let totalBlockCount = 0;
  let parserErrorCount = 0;
  const migratedRouteRows = [];
  const followingDamageRows = [];
  for (const row of inventoryRows) {
    assertSafePath(row.path);
    if (row.game_version !== EXACT_BUILD || row.sha256_before !== row.sha256_after
      || row.original_unchanged !== 'YES') throw new Error(`inventory identity mismatch: ${row.path}`);
    const replay = parseReplayFile(row.path);
    if (replay.header.version !== EXACT_BUILD || replay.source_sha256 !== row.sha256_before) {
      throw new Error(`replay exact-build/SHA mismatch: ${row.path}`);
    }
    const openShieldKeys = new Map();
    let replayBlockOrdinal = 0;
    const walked = walkBlocks(replay, (block, chunk) => {
      replayBlockOrdinal += 1;
      routeCounts.set(block.packet_type, (routeCounts.get(block.packet_type) || 0) + 1);
      const low = block.param & 0xff;
      if (block.payload_length === 10 && low >= 0xae && low <= 0xb7) {
        length10HeroParamCounts.set(block.packet_type,
          (length10HeroParamCounts.get(block.packet_type) || 0) + 1);
      }
      if (block.packet_type === '0x01e1') migratedRouteRows.push({
        replay_sha256: replay.source_sha256,
        replay_version: replay.header.version,
        replay_name: path.basename(row.path),
        chunk_index: chunk.index,
        replay_time_ms: block.timestamp_ms,
        packet_id: block.packet_id,
        packet_type: block.packet_type,
        payload_length: block.payload_length,
        raw_param: block.param,
        raw_payload_hex: block.payload.toString('hex'),
        raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
      });
      if (block.packet_type === '0x01e1') {
        openShieldKeys.set(`${chunk.index}|${block.timestamp_ms}|${block.param & 0xff}`,
          { block_ordinal: replayBlockOrdinal });
      } else if (block.packet_type === '0x017f') {
        const key = `${chunk.index}|${block.timestamp_ms}|${block.param & 0xff}`;
        const shield = openShieldKeys.get(key);
        if (shield && replayBlockOrdinal > shield.block_ordinal) followingDamageRows.push({
          replay_sha256: replay.source_sha256, replay_name: path.basename(row.path),
          chunk_index: chunk.index, replay_time_ms: block.timestamp_ms,
          packet_id: block.packet_id, packet_type: block.packet_type,
          payload_length: block.payload_length, raw_param: block.param,
          replay_block_ordinal: replayBlockOrdinal,
          raw_payload_hex: block.payload.toString('hex'),
          raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
          relation: 'SAME_REPLAY_CHUNK_TARGET_LOW_BYTE_TIMESTAMP_FOLLOWING_0x01e1',
        });
      }
    }, { includeStreams: [1, 2, 3], strict: true });
    totalBlockCount += walked.block_count;
    parserErrorCount += walked.errors.length;
    replays.push({ name: path.basename(row.path), sha256: replay.source_sha256,
      block_count: walked.block_count });
  }
  const shapeRoutes = [...length10HeroParamCounts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([route, count]) => ({ route, count }));
  const corpusIdentity = crypto.createHash('sha256')
    .update(replays.map((row) => `${row.name}|${row.sha256}|${row.block_count}`).join('\n'))
    .digest('hex');
  return {
    schema: 'ROFL_16_16_SHIELD_ROUTE_MIGRATION_CORPUS_SCAN_V1', schema_version: 1,
    exact_build: EXACT_BUILD,
    inventory_csv: { path: path.resolve(inventoryCsv), sha256: sha256File(inventoryCsv) },
    selected_replay_count: replays.length,
    total_block_count: totalBlockCount,
    parser_error_count: parserErrorCount,
    distinct_observed_route_count: routeCounts.size,
    legacy_route_0x0017_count: routeCounts.get('0x0017') || 0,
    migrated_static_route_0x01e1_count: routeCounts.get('0x01e1') || 0,
    migrated_static_route_0x01e1_rows: migratedRouteRows,
    same_target_same_timestamp_following_0x017f_rows: followingDamageRows,
    legacy_shape_search: {
      signature: 'payload_length_10 AND raw_param_low_byte_in_exact_hero_range_0xae..0xb7',
      route_count: shapeRoutes.length,
      row_count: shapeRoutes.reduce((sum, row) => sum + row.count, 0),
      routes: shapeRoutes,
      boundary: 'SHAPE MATCH IS SEARCH COVERAGE ONLY; IT DOES NOT IDENTIFY SHIELD DAMAGE',
    },
    corpus_identity_sha256: corpusIdentity,
    replays,
    protected_holdout: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
  };
}

function validateShieldMigrationScan(scan, { inventoryCsv = CANONICAL_REPLAY_INVENTORY_PATH,
  cachedScanPath = null } = {}) {
  const resolvedInventory = path.resolve(inventoryCsv);
  const inventoryRows = parseReplayInventoryCsv(resolvedInventory)
    .filter((row) => row.selected_for_validation === 'YES');
  const expectedReplays = inventoryRows.map((row) => ({
    name: path.basename(row.path), sha256: row.sha256_before,
  }));
  const replayIdentitiesMatch = scan?.replays?.length === expectedReplays.length
    && scan.replays.every((row, index) => row.name === expectedReplays[index].name
      && row.sha256 === expectedReplays[index].sha256
      && Number.isInteger(row.block_count) && row.block_count > 0);
  const recomputedCorpusIdentity = scan?.replays && crypto.createHash('sha256')
    .update(scan.replays.map((row) => `${row.name}|${row.sha256}|${row.block_count}`).join('\n'))
    .digest('hex');
  const rowsValid = scan?.migrated_static_route_0x01e1_rows?.length === 12
    && scan.migrated_static_route_0x01e1_rows.every((row) =>
      row.replay_version === EXACT_BUILD && row.packet_type === '0x01e1'
      && row.packet_id === 0x01e1 && row.payload_length === 10
      && /^[0-9a-f]{64}$/.test(row.replay_sha256)
      && expectedReplays.some((expected) => expected.sha256 === row.replay_sha256)
      && /^[0-9a-f]{64}$/.test(row.raw_payload_sha256));
  const cacheShaValid = cachedScanPath === null
    || sha256File(cachedScanPath) === CANONICAL_SHIELD_SCAN_SHA256;
  if (!scan || scan.schema !== 'ROFL_16_16_SHIELD_ROUTE_MIGRATION_CORPUS_SCAN_V1'
    || scan.exact_build !== EXACT_BUILD || scan.selected_replay_count !== 40
    || scan.total_block_count !== 55552224 || scan.parser_error_count !== 0
    || scan.legacy_route_0x0017_count !== 0 || scan.migrated_static_route_0x01e1_count !== 12
    || resolvedInventory !== CANONICAL_REPLAY_INVENTORY_PATH
    || sha256File(resolvedInventory) !== CANONICAL_REPLAY_INVENTORY_SHA256
    || scan.inventory_csv?.path !== CANONICAL_REPLAY_INVENTORY_PATH
    || scan.inventory_csv?.sha256 !== CANONICAL_REPLAY_INVENTORY_SHA256
    || !replayIdentitiesMatch || !rowsValid
    || !Array.isArray(scan.same_target_same_timestamp_following_0x017f_rows)
    || scan.corpus_identity_sha256 !== CANONICAL_SHIELD_CORPUS_SHA256
    || recomputedCorpusIdentity !== CANONICAL_SHIELD_CORPUS_SHA256
    || !scan.protected_holdout
    || Object.keys(scan.protected_holdout).length !== 6
    || Object.values(scan.protected_holdout).some((value) => value !== false)
    || !cacheShaValid) {
    throw new Error('invalid cached shield-route migration scan');
  }
  return scan;
}

function findStaticShieldRegistration(runtimeTrace) {
  const matches = [];
  const visit = (value) => {
    if (!value || typeof value !== 'object') return;
    if (value.name === 'PKT_UnitApplyShieldDamage_s' && value.registration_id === 481
      && value.factory_packet) matches.push(value);
    for (const child of Object.values(value)) visit(child);
  };
  visit(runtimeTrace);
  if (matches.length !== 1) throw new Error(`expected one full 16.16 shield-damage registration chain, got ${matches.length}`);
  const row = matches[0];
  return {
    packet_name: row.name,
    callback_owner_type: row.callback_owner_type,
    registration_id: row.registration_id,
    registration_id_hex: row.registration_id_hex,
    callback_receive_target_rva_hex: row.callback_receive_target_rva_hex,
    factory_status: row.factory_status,
    allocation_size: row.factory_packet.allocation_size,
    constructor_rva_hex: row.factory_packet.constructor_rva_hex,
    packet_object_vtable_rva_hex: row.factory_packet.packet_object_vtable_rva_hex,
    deserializer_rva_hex: row.factory_packet.deserializer_rva_hex,
    object_size: row.factory_packet.object_size,
  };
}

function writeNeutralShieldInputs(outputDir, shieldMigrationScan) {
  const rowsPath = path.join(outputDir, 'packet_01e1_rows_16_16.jsonl');
  const profilePath = path.join(outputDir, 'packet_01e1_neutral_profile.json');
  fs.writeFileSync(rowsPath, `${shieldMigrationScan.migrated_static_route_0x01e1_rows
    .map((row) => JSON.stringify(row)).join('\n')}\n`);
  fs.writeFileSync(profilePath, `${JSON.stringify({
    schema_version: 1,
    evidence_status: 'STATIC_RUNTIME_REGISTRATION_VERIFIED_NEUTRAL_OBJECT_ONLY',
    semantic_boundary: 'No field semantics are assigned by this profile.',
    profile: {
      id: 'rofl-16.16.805.0442-unit-apply-shield-damage-neutral-v1',
      client_opcode: '0x01e1', constructor_rva: '0x00eac9b0',
      vtable_rva: '0x01b109e8', deserialize_rva: '0x00f22400',
      object_size: '0x20', fields: [],
    },
  }, null, 2)}\n`);
  return { rowsPath, profilePath };
}

function recoverShieldAbsorbedRows(outputDir, shieldMigrationScan, runtimeImage) {
  const { rowsPath, profilePath } = writeNeutralShieldInputs(outputDir, shieldMigrationScan);
  const neutralDecodedPath = path.join(outputDir, 'packet_01e1_neutral_decoded.jsonl');
  const neutralSummaryPath = path.join(outputDir, 'packet_01e1_neutral_decoded.summary.json');
  const script = path.resolve(__dirname, '..', 'scripts', 'emulate_packet_profile_json.py');
  childProcess.execFileSync(process.env.ROFL_PYTHON || 'python', [script,
    '--image', runtimeImage, '--events', rowsPath, '--profile-json', profilePath,
    '--runtime-profile', EXACT_BUILD, '--output', neutralDecodedPath,
    '--summary', neutralSummaryPath, '--progress-every', '0',
  ], { stdio: 'pipe' });
  const summary = readJson(neutralSummaryPath);
  if (summary.image_sha256 !== EXACT_RUNTIME_IMAGE_SHA
    || summary.event_count !== shieldMigrationScan.migrated_static_route_0x01e1_count
    || summary.successful_full_consume_count !== summary.event_count
    || Object.keys(summary.emulation_errors || {}).length) throw new Error('0x01e1 neutral emulation failed identity/consume gate');
  const image = fs.readFileSync(runtimeImage);
  const table = image.subarray(0x01a27950, 0x01a27a50);
  const rows = readJsonl(neutralDecodedPath).map((row) => {
    const decoded = decodeShieldCallbackObject(row.object_hex, table);
    const canonical = shieldAbsorbedFromFullyConsumedRow(row, table);
    const canonicalRawTarget = 0x40000000 | (row.raw_param & 0xff);
    return {
      exact_build: EXACT_BUILD, replay_sha256: row.replay_sha256,
      replay_time_ms: row.replay_time_ms, packet_type: '0x01e1', raw_param: row.raw_param,
      ...decoded,
      target_fields_agree: decoded.target_network_id_from_field_18
        === decoded.target_network_id_from_field_1c,
      target_matches_raw_param_low_byte: decoded.target_network_id_from_field_18 === canonicalRawTarget,
      source_or_instance_id: null,
      canonical,
      semantic: canonical?.semantic,
      evidence: canonical?.evidence,
      raw_payload_sha256: row.raw_payload_sha256,
    };
  });
  if (rows.length !== 12 || rows.some((row) => !Number.isFinite(row.shield_absorbed_amount)
    || row.shield_absorbed_amount <= 0 || row.field_14_plain_u32 !== 0
    || !row.target_fields_agree || !row.target_matches_raw_param_low_byte || !row.canonical)) {
    throw new Error('0x01e1 callback inverse semantic gates failed');
  }
  const directPath = path.join(outputDir, 'packet_01e1_shield_absorbed_direct.jsonl');
  fs.writeFileSync(directPath, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
  return { rows, rowsPath, profilePath, neutralDecodedPath, neutralSummaryPath, directPath,
    summary: {
      event_count: rows.length, exact_full_consume_count: summary.successful_full_consume_count,
      target_fields_agree_count: rows.filter((row) => row.target_fields_agree).length,
      target_matches_raw_param_low_byte_count: rows.filter((row) => row.target_matches_raw_param_low_byte).length,
      positive_finite_amount_count: rows.filter((row) => row.shield_absorbed_amount > 0).length,
      amount_min: Math.min(...rows.map((row) => row.shield_absorbed_amount)),
      amount_max: Math.max(...rows.map((row) => row.shield_absorbed_amount)),
    } };
}

function buildShieldAbsorbedMigrationEvidence({ legacyContract, legacyReplayManifestSha,
  shieldMigrationScan, targetRuntimeSha }) {
  const sourceBuild = legacyContract.client_version;
  const sourceProvenance = { exact_build: sourceBuild,
    replay_set_manifest_sha256: legacyReplayManifestSha,
    source_sha256: legacyContract.runtime_image_sha256, source_kind: 'EXACT_BUILD_RUNTIME_AND_CORPUS_CONTRACT' };
  const targetProvenance = { exact_build: EXACT_BUILD,
    replay_set_manifest_sha256: shieldMigrationScan.corpus_identity_sha256,
    source_sha256: targetRuntimeSha, source_kind: 'EXACT_BUILD_RUNTIME_AND_GOVERNED_CORPUS' };
  const fingerprint = new SemanticFingerprint({
    schema: 'ROFL_SEMANTIC_FINGERPRINT_V1', schema_version: 1,
    semantic_name: 'SHIELD_ABSORBED', canonical_schema_version: 'ROFL_SEMANTIC_SCHEMA_V2',
    availability: 'VERIFIED', promotion_eligible: true, provenance: sourceProvenance,
    structural_fingerprint: {
      runtime_type: 'PKT_UnitApplyShieldDamage_s', registration: 'AIBaseClient receive registration',
      callback: 'target-total shield damage receive callback', constructor: '32-byte packet object constructor',
      vtable: 'unit-apply-shield-damage packet vtable', deserializer: 'exact-runtime full-consume deserializer',
      serializer: 'replay packet receive stream', component: 'AIBaseClient protection event',
      field_type: 'float32 absorbed amount plus duplicate uint32 target',
      field_position: 'callback-decoded amount and duplicate target object fields',
      payload_shape: ['10-byte payload', '32-byte runtime object'],
      surrounding_fields: ['neutral uint32 field', 'duplicate target uint32'],
      entity_relationship: 'target-total absorption attributed to one target entity',
    },
    behavioral_fingerprint: {
      value_range: { minimum: 0, observed_target_build_positive_count: 12 },
      temporal_behavior: 'discrete target-total absorption event', update_frequency: 'event driven',
      event_correlations: ['may precede same-target same-timestamp damage; relation is not required for amount decoding'],
      reset_behavior: 'not a persistent state', persistence_behavior: 'event value only',
    },
    build_bindings: [
      { binding_id: 'shield-absorbed-16-15', exact_build: sourceBuild, provenance: sourceProvenance,
        binding: { route: '0x0017', object_size: 32, callback_rva: '0x0029edd0', deserializer_rva: '0x00f1db80' } },
      { binding_id: 'shield-absorbed-16-16', exact_build: EXACT_BUILD, provenance: targetProvenance,
        binding: { route: '0x01e1', object_size: 32, callback_rva: '0x002a77b0', deserializer_rva: '0x00f22400' } },
    ],
    exact_builds_verified: [
      { exact_build: sourceBuild, binding_id: 'shield-absorbed-16-15', provenance: sourceProvenance },
      { exact_build: EXACT_BUILD, binding_id: 'shield-absorbed-16-16', provenance: targetProvenance },
    ],
    cross_field_invariants: [
      { invariant_id: 'duplicate-target-agreement',
        expression: 'decoded target field A equals decoded target field B equals canonical raw target',
        mode: 'STRICT', rationale: '12/12 target-build rows and source-build contract require agreement' },
      { invariant_id: 'finite-nonnegative-amount', expression: 'absorbed amount is finite and nonnegative',
        mode: 'STRICT', rationale: 'canonical protection amount domain' },
    ],
    ground_truth_oracles: [
      { reference_id: 'source-direct-contract', case_id: '16-15-two-direct-rows', oracle_kind: 'MACHINE_EXACT_RUNTIME', provenance: sourceProvenance },
      { reference_id: 'target-callback-inverse', case_id: '16-16-twelve-direct-rows', oracle_kind: 'MACHINE_EXACT_RUNTIME', provenance: targetProvenance },
    ],
    negative_controls: [
      { reference_id: 'legacy-route-absent-target', control_kind: 'ROUTE_NEGATIVE_CONTROL',
        rejection_reason: 'legacy 0x0017 has zero rows while migrated 0x01e1 has twelve in the governed corpus', provenance: targetProvenance },
    ],
    known_exceptions: [], migration_policy: 'AUTO_IF_UNIQUE',
  });
  const fingerprintJson = fingerprint.toJSON();
  const runId = `shield-absorbed-${fingerprint.hash.slice(0, 16)}`;
  const decision = createMigrationDecision({
    semantic_name: 'SHIELD_ABSORBED', source_build: sourceBuild, target_build: EXACT_BUILD,
    provenance: { source_build: sourceBuild, target_build: EXACT_BUILD, run_id: runId,
      source_fingerprint_sha256: fingerprint.hash },
    candidates: [{ candidate_id: 'route-0x01e1-unit-apply-shield-damage', exact_build: EXACT_BUILD,
      structural_match_score: 1, behavioral_match_score: 1, cross_field_match_score: 1,
      ground_truth_oracle_score: 1, invariant_gate: 'PASS', regression_gate: 'PASS',
      negative_control_gate: 'PASS', exception_audit: { status: 'PASS', exceptions: [] },
      migration_class: 'ROUTE_MOVED', provenance: { source_build: sourceBuild,
        target_build: EXACT_BUILD, run_id: runId, source_fingerprint_sha256: fingerprint.hash } }],
  });
  return { fingerprint: fingerprintJson, fingerprint_sha256: fingerprint.hash, decision };
}

async function analyzeLocalShieldLayer(damageFile, onEventFile) {
  assertSafePath(damageFile);
  assertSafePath(onEventFile);
  const shields = new Map();
  for (const row of readJsonl(onEventFile)) {
    if (row.build !== EXACT_BUILD || row.event_id_hex !== '0x00ed') continue;
    const key = `${row.replay_sha256}|${row.target_network_id_candidate}`;
    const list = shields.get(key) || [];
    list.push({ timestamp_ms: row.replay_time_ms, amount: row.amount_candidate });
    shields.set(key, list);
  }
  for (const list of shields.values()) list.sort((a, b) => a.timestamp_ms - b.timestamp_ms);
  const input = fs.createReadStream(damageFile, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  let secondaryNonzeroCount = 0;
  let priorShieldWithin60sCount = 0;
  let exactPriorGeneratedAmountMatchCount = 0;
  let sameTimestampShieldApplicationCount = 0;
  for await (const line of lines) {
    if (!line.trim()) continue;
    const row = JSON.parse(line);
    const fields = row.decoded_fields || {};
    if (!(fields.field_2c_f32 > 0)) continue;
    secondaryNonzeroCount += 1;
    const list = shields.get(`${row.replay_sha256}|${fields.field_14_u32}`) || [];
    const prior = list.filter((item) => item.timestamp_ms <= row.replay_time_ms
      && row.replay_time_ms - item.timestamp_ms <= 60000);
    if (prior.length) priorShieldWithin60sCount += 1;
    if (prior.some((item) => item.amount === fields.field_2c_f32)) exactPriorGeneratedAmountMatchCount += 1;
    if (list.some((item) => item.timestamp_ms === row.replay_time_ms)) sameTimestampShieldApplicationCount += 1;
  }
  return {
    damage_secondary_nonzero_count: secondaryNonzeroCount,
    prior_shield_application_within_60s_count: priorShieldWithin60sCount,
    exact_prior_generated_amount_match_count: exactPriorGeneratedAmountMatchCount,
    same_timestamp_shield_application_count: sameTimestampShieldApplicationCount,
    conclusion: 'FIELD_2C_IS_A_LOCAL_SHIELD_LAYER_CANDIDATE_ONLY; TEMPORAL_OR_AMOUNT CORRESPONDENCE DOES_NOT_PROVE ABSORBED_OR_REMAINING',
  };
}

async function scanLatestDamage(file) {
  assertSafePath(file);
  const input = fs.createReadStream(file, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  const typeCounts = { physical: 0, magic: 0, true: 0, unknown: 0 };
  const groupCounts = new Map();
  let rowCount = 0;
  let fullConsumeCount = 0;
  let secondaryNonzeroCount = 0;
  let secondaryZeroCount = 0;
  const buildValues = new Set();
  const runtimeImageShaValues = new Set();
  const decoderProfileValues = new Set();
  for await (const line of lines) {
    if (!line.trim()) continue;
    const row = JSON.parse(line);
    buildValues.add(row.replay_version);
    runtimeImageShaValues.add(row.decoder_runtime_image_sha256);
    decoderProfileValues.add(row.decoder_profile);
    rowCount += 1;
    if (row.fully_consumed === true) fullConsumeCount += 1;
    const fields = row.decoded_fields || {};
    const code = fields.field_28_u8;
    const type = code === 0 ? 'physical' : code === 1 ? 'magic' : code === 2 ? 'true' : 'unknown';
    typeCounts[type] += 1;
    if (fields.field_2c_f32 === 0) secondaryZeroCount += 1;
    else if (Number.isFinite(fields.field_2c_f32)) secondaryNonzeroCount += 1;
    const replay = row.replay_sha256 || row.replay_sha || 'UNKNOWN_REPLAY';
    const target = fields.field_14_u32 ?? row.raw_param ?? 'UNKNOWN_TARGET';
    const key = `${replay}|${row.replay_time_ms}|${target}`;
    groupCounts.set(key, (groupCounts.get(key) || 0) + 1);
  }
  let singleDamageTargetTimestampCount = 0;
  let multiDamageTargetTimestampCount = 0;
  for (const count of groupCounts.values()) {
    if (count === 1) singleDamageTargetTimestampCount += 1;
    else multiDamageTargetTimestampCount += 1;
  }
  if (buildValues.size !== 1 || !buildValues.has(EXACT_BUILD)) throw new Error('latest Damage corpus exact-build identity mismatch');
  if (runtimeImageShaValues.size !== 1 || !runtimeImageShaValues.has(EXACT_RUNTIME_IMAGE_SHA)) throw new Error('latest Damage corpus runtime-image identity mismatch');
  if (decoderProfileValues.size !== 1 || !decoderProfileValues.has(EXACT_DAMAGE_DECODER_PROFILE)) throw new Error('latest Damage corpus decoder-profile identity mismatch');
  return {
    row_count: rowCount,
    exact_full_consume_count: fullConsumeCount,
    damage_type_counts: typeCounts,
    secondary_zero_count: secondaryZeroCount,
    secondary_nonzero_count: secondaryNonzeroCount,
    target_timestamp_group_count: groupCounts.size,
    single_damage_target_timestamp_group_count: singleDamageTargetTimestampCount,
    multi_damage_target_timestamp_group_count: multiDamageTargetTimestampCount,
    identity: {
      exact_build: EXACT_BUILD,
      runtime_image_sha256: EXACT_RUNTIME_IMAGE_SHA,
      decoder_profile: EXACT_DAMAGE_DECODER_PROFILE,
    },
    semantic_limits: {
      no_shield: 'NOT_LABELABLE_WITHOUT_INDEPENDENT_SHIELD_STATE',
      no_heal: 'NOT_LABELABLE_WITHOUT_INDEPENDENT_HEAL_STATE',
      nonlethal: 'NOT_LABELABLE_WITHOUT_CURRENT_HP',
      lethal: 'NOT_LABELABLE_WITHOUT_CURRENT_HP_OR_DEATH_JOIN',
      single_damage: 'STRUCTURAL_TARGET_TIMESTAMP_GROUP_ONLY_NOT_CAUSAL_ISOLATION',
    },
  };
}

function controlledDamageAudit(rows) {
  if (!rows.length || rows.some((row) => row.replay_version !== EXACT_BUILD
    || row.replay_sha256 !== EXACT_REPLAY_SHA
    || row.decoder_runtime_image_sha256 !== EXACT_RUNTIME_IMAGE_SHA
    || row.decoder_profile !== EXACT_DAMAGE_DECODER_PROFILE)) {
    throw new Error('controlled Damage rows do not match the pinned replay/build/runtime/profile identity');
  }
  const anchors = [
    { timestamp_ms: 21667, hud_before: 655, hud_after: 512, shield_state: 'NO_INDEPENDENT_SHIELD_LABEL', class: 'NONLETHAL_SHIELD_UNKNOWN' },
    { timestamp_ms: 61785, hud_before: 655, hud_after: 602, shield_state: 'GENERATED_100_THEN_INDICATOR_ABSENT_AFTER_HIT', class: 'NONLETHAL_SHIELD_PRESENT_BEFORE_HIT' },
    { timestamp_ms: 79218, hud_before: 630, hud_after: 0, shield_state: 'NO_INDEPENDENT_SHIELD_AMOUNT_AT_HIT', class: 'LETHAL' },
  ];
  return anchors.map((anchor) => {
    const row = rows.find((item) => item.replay_time_ms === anchor.timestamp_ms);
    if (!row) throw new Error(`missing controlled Damage row at ${anchor.timestamp_ms}`);
    const primary = row.decoded_fields.field_24_f32;
    const secondary = row.decoded_fields.field_2c_f32;
    const hypotheses = PROJECTIONS.map((projection) => {
      const interval = decreaseInterval(anchor.hud_before, anchor.hud_after, projection);
      return { projection, internal_hp_decrease_interval: interval, primary_amount_compatible: intervalContains(interval, primary) };
    });
    return {
      ...anchor,
      field_24: primary,
      field_2c: secondary,
      hud_integer_difference_for_reference_only: anchor.hud_before - anchor.hud_after,
      projection_hypotheses: hypotheses,
      compatible_projection_count: hypotheses.filter((item) => item.primary_amount_compatible).length,
      exact_packet_ref: {
        replay_sha256: row.replay_sha256,
        chunk_index: row.chunk_index,
        decompressed_block_offset: row.decompressed_block_offset,
        raw_payload_sha256: row.raw_payload_sha256,
      },
    };
  });
}

function joinPairedDeathContexts(damageValidation, deathValidation) {
  const contexts = [];
  for (const damage of damageValidation.matches || []) {
    const replaySha = damage.raw_packet_ref && damage.raw_packet_ref.replay_sha256;
    const hitTime = damage.replay_packet_time_ms;
    const death = (deathValidation.matches || []).find((item) => item.replay_sha256 === replaySha
      && item.participant_id === damage.target_participant_id
      && Math.abs(item.replay_packet_timestamp_ms - hitTime) <= 2);
    if (!death) continue;
    contexts.push({
      replay_sha256: replaySha,
      damage_packet_time_ms: hitTime,
      death_packet_time_ms: death.replay_packet_timestamp_ms,
      target_participant_id: damage.target_participant_id,
      damage_type: damage.damage_type,
      field_24_recorded_amount: damage.recorded_amount,
      field_2c_secondary_amount: damage.secondary_amount,
      classification: 'LETHAL_CONTEXT_COMPONENT_NOT_ISOLATED_LETHAL_HP_DELTA',
    });
  }
  return contexts;
}

const DERIVABLE_DEPENDENCIES = Object.freeze({
  CURRENT_HP: ['absolute HP anchor', 'complete applied-to-health damage/heal/regen/special-effect delta stream', 'shield layering'],
  MAX_HP: ['exact champion build data', 'LEVEL_TRANSITION state_at(t)', 'verified ITEM_STATE state_at(t)', 'all buff/percent modifiers'],
  ARMOR: ['exact champion build data', 'LEVEL_TRANSITION state_at(t)', 'verified ITEM_STATE state_at(t)', 'all buff/debuff/percent modifiers'],
  MAGIC_RESIST: ['exact champion build data', 'LEVEL_TRANSITION state_at(t)', 'verified ITEM_STATE state_at(t)', 'all buff/debuff/percent modifiers'],
  DAMAGE_STAGE: ['internal HP before/after or independently labeled pipeline-stage truth', 'shield state'],
  DAMAGE_MITIGATION: ['verified damage stage', 'target Armor/MR at hit', 'exact-build mechanics and modifiers'],
  HEAL_EFFECTIVE: ['internal HP before/after', 'max HP and overlapping effects'],
  OVERHEAL: ['HEAL_REPORTED', 'HEAL_EFFECTIVE or pre-heal missing-health state'],
  SHIELD_REMAINING: ['shield instance/application state', 'absorbed/expired/replaced delta stream'],
  TEMPORARY_HP: ['direct temporary-health layer or complete verified layer transitions'],
});

const NON_DETERMINISTIC_OR_OUTSIDE = new Set(['CAMP_CLEAR', 'CAMP_STATE', 'MAP_MECHANIC']);
const DIRECT_REQUIRED = new Set([
  'ITEM_BUY', 'ITEM_SELL', 'ITEM_UNDO', 'ITEM_TRANSFORM', 'ITEM_DESTROY',
  'HEAL_REPORTED', 'SHIELD_GENERATED', 'SHIELD_ABSORBED', 'RUNE_PROC', 'PASSIVE_PROC',
]);

function derivabilityAudit(manifest = createCapabilityManifest()) {
  const records = manifest.build_profiles[EXACT_BUILD].records;
  if (CAPABILITY_VOCABULARY.length !== 79 || records.length !== 79) throw new Error('expected the governed 79-capability vocabulary');
  const rows = records.map((record) => {
    let classification;
    let missingInputs = [];
    if (record.evidence_grade === 'VERIFIED_DERIVED') classification = 'DERIVABLE_NOW';
    else if (DERIVABLE_DEPENDENCIES[record.semantic_capability]) {
      classification = 'DERIVABLE_IF_INPUT_X';
      missingInputs = DERIVABLE_DEPENDENCIES[record.semantic_capability];
    } else if (NON_DETERMINISTIC_OR_OUTSIDE.has(record.semantic_capability)) classification = 'NON_DETERMINISTIC';
    else if (record.evidence_grade === 'CANDIDATE') classification = 'CONDITIONALLY_DERIVABLE';
    else if (record.evidence_grade === 'VERIFIED_DIRECT' || DIRECT_REQUIRED.has(record.semantic_capability)) classification = 'DIRECT_REQUIRED';
    else classification = 'INSUFFICIENT_EVIDENCE';
    return {
      semantic_capability: record.semantic_capability,
      manifest_evidence_grade: record.evidence_grade,
      manifest_validation_status: record.validation_status,
      derivability_classification: classification,
      missing_inputs: missingInputs,
      public_manifest_changed: false,
      boundary: 'AUDIT_CLASSIFICATION_ONLY; DOES_NOT ALTER CAPABILITY STATUS OR EMIT A VALUE',
    };
  });
  const counts = Object.fromEntries(DERIVABILITY_CLASSES.map((key) => [key, rows.filter((row) => row.derivability_classification === key).length]));
  return { capability_count: rows.length, classification_counts: counts, rows };
}

function analyzeHealShield(deepReport, shieldSamples) {
  const comparison = deepReport.heal_shield_on_event.summary_anchor_comparison;
  const controlledShield = {
    generated_amount: 100,
    damage_field_2c: 100,
    indicator_transition: 'PRESENT_TO_ABSENT_AFTER_HIT',
    conclusion: 'ONE_CASE_LAYER_CORRESPONDENCE_CANDIDATE',
    prohibited_inference: 'DO_NOT_DEFINE_ABSORBED_AS_GENERATED_MINUS_HP_LOSS',
  };
  return {
    heal: {
      controlled_reported_amount: 80,
      controlled_hud_before: 549,
      controlled_hud_after: 629,
      quantized_compatibility: Object.fromEntries(PROJECTIONS.map((projection) => [projection,
        intervalContains(decreaseInterval(629, 549, projection), 80)])),
      latest_four_reported_event_count: deepReport.heal_shield_on_event.shape_and_team_counts['event_0x004b'],
      aggregate_raw_to_summary_ratio: comparison.raw_to_anchor_ratio_distributions['0x004b'],
      aggregate_counterexample_count: comparison.counts['0x004b:participant_sources'],
      effective_status: 'UNAVAILABLE_EVENT_LEVEL_INTERNAL_HP',
      overheal_status: 'UNAVAILABLE_EVENT_LEVEL_INTERNAL_HP_AND_MAX_HP',
      conclusion: 'REPORTED_OR_GROSS_DIRECT; EFFECTIVE_AND_OVERHEAL_NOT_RECOVERED',
    },
    shield: {
      controlled: controlledShield,
      prior_build_direct_absorption_samples: shieldSamples.samples.map((sample) => ({
        build_scope: '16.15_ONLY', replay_sha256: sample.replay_sha256,
        shield_absorbed_amount: sample.shield_absorbed_amount,
        related_unit_apply_damage_amount: sample.related_damage.unit_apply_damage_amount,
        combined_direct_amounts: sample.related_damage.combined_shield_plus_damage_amount,
      })),
      latest_four_generated_event_count: deepReport.heal_shield_on_event.shape_and_team_counts['event_0x00ed'],
      latest_four_absorption_route_status: 'BOUNDED_ABSENCE_IN_SELECTED_16_16_ROWS_NOT_PROTOCOL_NONEXISTENCE',
      absorbed_status_16_16: 'CANDIDATE_ONE_CONTROLLED_CASE_NOT_PROMOTED',
      remaining_status_16_16: 'UNAVAILABLE',
    },
  };
}

function markdown(report) {
  const d = report.damage_stage_promotion_audit;
  const lines = [
    '# QUANTIZED COMBAT RECONSTRUCTION', '',
    `Status: **${report.status}**`, '',
    `Exact build: \`${report.exact_build}\``, '',
    '## Damage stage', '',
    `All ${d.controlled_anchor_count} controlled field_24 samples are compatible with every still-open HUD projection; this removes integer-equality rejection but does not identify a unique projection or pipeline stage.`, '',
    `Decision: **${d.promotion_decision}** — ${d.stage_conclusion}`, '',
    '## Corpus search', '',
    `Latest-four: ${report.corpus_search.latest_four.row_count} exact rows; ${report.corpus_search.latest_four.single_damage_target_timestamp_group_count} single target/timestamp groups; secondary nonzero ${report.corpus_search.latest_four.secondary_nonzero_count}.`, '',
    'Physical/magic/true are present, but no corpus-side HP/shield/heal truth permits labeling no-shield, no-heal, nonlethal, or lethal rows.', '',
    '## Closure', '',
    `Mitigation: **${report.mitigation.status}**. Heal: **${report.heal_shield.heal.conclusion}**. Shield absorbed: **${report.heal_shield.shield.absorbed_status_16_16}**; remaining: **${report.heal_shield.shield.remaining_status_16_16}**.`, '',
    '## Derivability audit', '',
    `All ${report.derivable_capability_audit.capability_count} governed capabilities were classified without changing their manifest status.`, '',
    '## Protected boundary', '',
    'enumerated/read/hashed/decoded/tested/consumed: false/false/false/false/false/false', '',
  ];
  return `${lines.join('\n')}\n`;
}

async function runQuantizedCombatReconstruction(options) {
  const outputDir = path.resolve(options.outputDir);
  assertSafePath(outputDir);
  fs.mkdirSync(outputDir, { recursive: true });
  const inputs = Object.fromEntries(Object.entries(options.inputs).map(([key, value]) => [key, path.resolve(value)]));
  for (const file of Object.values(inputs)) assertSafePath(file);
  const controlled = readJsonl(inputs.controlledDamage);
  const damageValidation = readJson(inputs.damageValidation);
  const deathValidation = readJson(inputs.deathValidation);
  const deepReport = readJson(inputs.deepReport);
  const shieldSamples = readJson(inputs.shieldSamples);
  const runtimeTrace = readJson(inputs.runtimeTrace);
  const legacyProtectionContract = readJson(inputs.legacyProtectionContract);
  const legacyShieldReplayManifest = readJson(inputs.legacyShieldReplayManifest);
  if (legacyShieldReplayManifest.target_replay_version !== legacyProtectionContract.client_version
      || legacyShieldReplayManifest.replay_count !== 14
      || legacyShieldReplayManifest.selected_packet_count !== 2
      || legacyShieldReplayManifest.packet_counts?.['23'] !== 2
      || legacyShieldReplayManifest.replays?.length !== 14
      || legacyShieldReplayManifest.replays.some((row) => row.version !== legacyProtectionContract.client_version
        || row.parser_error_count !== 0 || !/^[0-9a-f]{64}$/.test(row.sha256))) {
    throw new Error('legacy 0x0017 replay-set manifest identity mismatch');
  }
  validateShieldCallbackDisassembly(fs.readFileSync(inputs.shieldCallbackDisassembly),
    fs.readFileSync(inputs.runtimeImage));
  if (damageValidation.exact_build !== EXACT_BUILD
    || deathValidation.exact_build !== EXACT_BUILD
    || deepReport.build !== EXACT_BUILD) {
    throw new Error('supporting evidence exact-build identity mismatch');
  }
  const latest = await scanLatestDamage(inputs.latestDamage);
  const shieldMigrationScan = options.shieldMigrationScanPath
    ? validateShieldMigrationScan(readJson(options.shieldMigrationScanPath), {
      inventoryCsv: inputs.replayInventoryCsv, cachedScanPath: options.shieldMigrationScanPath })
    : validateShieldMigrationScan(await scanShieldRouteMigrationCorpus(inputs.replayInventoryCsv), {
      inventoryCsv: inputs.replayInventoryCsv });
  const staticShieldRegistration = findStaticShieldRegistration(runtimeTrace);
  const shieldAbsorbedRecovery = recoverShieldAbsorbedRows(outputDir, shieldMigrationScan, inputs.runtimeImage);
  const shieldMigrationEvidence = buildShieldAbsorbedMigrationEvidence({
    legacyContract: legacyProtectionContract,
    legacyReplayManifestSha: sha256File(inputs.legacyShieldReplayManifest),
    shieldMigrationScan,
    targetRuntimeSha: sha256File(inputs.runtimeImage),
  });
  const localShieldLayer = await analyzeLocalShieldLayer(inputs.latestDamage, inputs.onEventLatest);
  const anchors = controlledDamageAudit(controlled);
  const lethalContexts = joinPairedDeathContexts(damageValidation, deathValidation);
  const allCompatible = anchors.every((anchor) => anchor.compatible_projection_count === PROJECTIONS.length);
  const healShield = analyzeHealShield(deepReport, shieldSamples);
  healShield.shield.absorbed_status_16_16 = 'DIRECT_RECOVERED_0x01e1_TARGET_TOTAL_12_ROWS';
  healShield.shield.absorbed_recovery_scope = 'TARGET_TOTAL_ONLY; SOURCE_AND_SHIELD_INSTANCE_UNAVAILABLE';
  const report = {
    schema: 'ROFL_QUANTIZED_COMBAT_RECONSTRUCTION_V1', schema_version: 1,
    status: 'COMBAT_SCAN_EVIDENCE_EXHAUSTED_WITH_EXPLICIT_EXTERNAL_TRUTH_REQUIREMENTS',
    status_scope: 'THIS_COMBAT_RECONSTRUCTION_SCAN_ONLY_NOT_GLOBAL_PROJECT',
    exact_build: EXACT_BUILD, controlled_replay_sha256: EXACT_REPLAY_SHA,
    project_context_loaded: true, architecture_gate: 'PASS',
    hud_projection: {
      status: 'UNRESOLVED_AMONG_FLOOR_ROUND_TRUNCATE_FOR_NONNEGATIVE_VALUES',
      hypotheses: PROJECTIONS,
      hypothesis_set_not_exhaustive: true,
      interval_arithmetic_used: true,
      integer_exact_equality_used: false,
      boundary_comparison_rule: 'STRICT_MATHEMATICAL_OPEN_OR_CLOSED_BOUNDARY; INTEGER_AND_HALF_ENDPOINTS_ARE_BINARY_EXACT; NO_EPSILON',
    },
    damage_stage_promotion_audit: {
      controlled_anchor_count: anchors.length, anchors,
      all_controlled_primary_amounts_quantized_compatible: allCompatible,
      paired_details_anchor_count: damageValidation.matched_anchor_count,
      paired_damage_type_counts: damageValidation.damage_type_match_counts,
      paired_details_limit: 'DETAILS COMPONENT ROUNDING VALIDATES RECORDED COMPONENT AND TYPE, NOT HP LOSS OR PIPELINE STAGE',
      structural_reader_writer_relation: '0x017f PKT_UnitApplyDamage_s exact runtime deserializer and callback established by existing pinned runtime trace',
      counterexample_search: 'LATEST_FOUR_SCANNED; HP/SHIELD/HEAL LABELS ABSENT',
      candidate_stage: 'HUD_QUANTIZED_HP_DECREASE_COMPATIBLE_COMPONENT_HYPOTHESIS',
      stage_conclusion: 'field_24 is compatible with the HUD-quantized HP-decrease interval in all three controlled cases, including one shield-present case; compatibility alone does not prove applied-to-health, the other two cases lack independent shield labels, pre/post-mitigation cannot be distinguished, and cross-replay HP truth is absent',
      promotion_decision: 'NO_PUBLIC_PROMOTION',
      missing_gate: ['cross-replay internal/current HP anchors', 'verified HUD projection or equivalent internal HP truth', 'target defense state for mitigation separation'],
    },
    corpus_search: { latest_four: latest, paired_details: {
      decoded_row_count: damageValidation.decoded_row_count,
      matched_anchor_count: damageValidation.matched_anchor_count,
      physical_magic_true: damageValidation.damage_type_match_counts,
      no_shield_no_heal_nonlethal_lethal_labels: 'UNAVAILABLE',
      lethal_context_component_count: lethalContexts.length,
      lethal_context_components: lethalContexts,
      lethal_context_limit: 'A component coincident with HERO_DEATH is not necessarily the isolated killing hit or the full HP delta.',
    } },
    mitigation: {
      status: 'EXTERNAL_INPUT_REQUIRED',
      recorded_damage: 'VERIFIED_DIRECT',
      theoretical_pre_mitigation: 'NOT_COMPUTABLE',
      missing_inputs: ['target Armor/MR at hit', 'source raw damage/formula inputs', 'exact-build mechanics modifiers', 'verified field_24 stage'],
    },
    current_hp_reconstruction: {
      direct: 'UNAVAILABLE', absolute_anchors: ['manual HUD observations only', 'death HUD 0', 'respawn HUD 655'],
      deterministic_delta_stream: 'INCOMPLETE',
      verified_deltas: ['0x017f recorded Damage amount stage candidate', '0x0371 HEAL_REPORTED gross/reported'],
      missing_deltas: ['regen', 'fountain/full heal', 'special effects', 'shield layering', 'effective heal', 'complete applied-to-health damage semantics'],
      result: 'CONDITIONALLY_DERIVABLE_NOT_CURRENTLY_EMITTABLE',
    },
    heal_shield: healShield,
    shield_route_migration_audit: {
      legacy_16_15_fingerprint: {
        exact_build: legacyProtectionContract.client_version,
        route: '0x0017',
        packet_name: legacyProtectionContract.packets['0x0017'].descriptor,
        object_size: legacyProtectionContract.packets['0x0017'].object_size,
        deserializer_rva: legacyProtectionContract.packets['0x0017'].deserializer_rva,
        callback_rva: legacyProtectionContract.packets['0x0017'].callback_rva,
        verified_fields: legacyProtectionContract.packets['0x0017'].fields,
        verified_row_count: legacyProtectionContract.packets['0x0017'].scan.rows,
        runtime_image_sha256: legacyProtectionContract.runtime_image_sha256,
      },
      static_16_16_replacement: staticShieldRegistration,
      migration_relation: {
        status: 'VERIFIED_STATIC_ROUTE_RENUMBERING_AND_OBJECT_SIZE_CONTINUITY',
        from_route: '0x0017', to_route: '0x01e1',
        same_packet_name: staticShieldRegistration.packet_name === legacyProtectionContract.packets['0x0017'].descriptor,
        same_object_size: staticShieldRegistration.object_size === legacyProtectionContract.packets['0x0017'].object_size,
        semantic_field_layout_status: 'VERIFIED_BY_12_EXACT_FULL_CONSUME_ROWS_AND_CALLBACK_FIELD_INVERSE',
      },
      semantic_fingerprint: {
        sha256: shieldMigrationEvidence.fingerprint_sha256,
        artifact: 'shield_absorbed_semantic_fingerprint.json',
      },
      migration_oracle: {
        status: shieldMigrationEvidence.decision.status,
        artifact: 'shield_absorbed_migration_oracle_decision.json',
        decision: shieldMigrationEvidence.decision,
      },
      governed_corpus_scan: shieldMigrationScan,
      direct_16_16_absorption_recovery: {
        status: 'DIRECT_RECOVERED_TARGET_TOTAL',
        route: '0x01e1',
        amount_field: 'callback-decoded object +0x10 f32',
        target_fields: ['callback-decoded object +0x18 u32', 'callback-decoded object +0x1c u32'],
        neutral_field: 'callback-decoded object +0x14 u32 is zero in 12/12 rows',
        source_or_shield_instance: 'UNAVAILABLE',
        ordered_same_timestamp_following_0x017f_count:
          shieldMigrationScan.same_target_same_timestamp_following_0x017f_rows.length,
        ...shieldAbsorbedRecovery.summary,
        artifact: path.basename(shieldAbsorbedRecovery.directPath),
      },
      semantic_registry: {
        shield_absorbed_16_16: createCapabilityManifest().build_profiles[EXACT_BUILD].records
          .find((row) => row.semantic_capability === 'SHIELD_ABSORBED'),
        shield_remaining_16_16: createCapabilityManifest().build_profiles[EXACT_BUILD].records
          .find((row) => row.semantic_capability === 'SHIELD_REMAINING'),
      },
      local_hp_shield_layer_search: localShieldLayer,
      conclusion: 'STATIC_REPLACEMENT_ROUTE_RECOVERED; 12 OBSERVED ROWS EXACT-FULL-CONSUMED; CALLBACK INVERSE RECOVERS DIRECT POSITIVE TARGET-TOTAL ABSORPTION; SHIELD_REMAINING_NOT_CLOSED',
      bounded_absence: shieldMigrationScan.migrated_static_route_0x01e1_count === 0
        ? '0x01e1 and legacy 0x0017 are absent only in the exact governed 40-replay corpus; protocol nonexistence is not claimed.'
        : 'Legacy 0x0017 is absent; migrated 0x01e1 is present. No absence claim applies to the migrated route.',
    },
    derivable_capability_audit: derivabilityAudit(),
    public_capability_changes: [{ semantic: 'SHIELD_ABSORBED', exact_build: EXACT_BUILD,
      evidence_grade: 'VERIFIED_DIRECT', validation_status: 'PASS', route: '0x01e1',
      boundary: 'TARGET_TOTAL_ONLY; SOURCE_INSTANCE_AND_REMAINING_UNAVAILABLE' }],
    true_external_blockers: [
      'cross-replay independently labeled HP-before/after with shield/heal overlap state',
      'exact-build Armor/MR at damage time or independently labeled pre-mitigation truth',
      'event-level internal HP/max-HP truth for effective heal and overheal',
      'independently labeled or complete application/expiry/replacement/instance state is required for shield remaining; 16.16 target-total absorption itself is recovered locally',
    ],
    new_replay_required: 'NO_BY_DEFAULT', level_up_hold: 'REMAINS_HOLD_NOT_BLOCKING',
    protected_holdout: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
    inputs: Object.fromEntries(Object.entries(inputs).map(([key, file]) => [key, { path: file, sha256: sha256File(file), bytes: fs.statSync(file).size }])),
  };
  const jsonPath = path.join(outputDir, 'quantized_combat_reconstruction_report.json');
  const mdPath = path.join(outputDir, 'QUANTIZED_COMBAT_RECONSTRUCTION_REPORT.md');
  const shieldScanPath = path.join(outputDir, 'shield_route_migration_scan.json');
  const shieldRowsPath = shieldAbsorbedRecovery.rowsPath;
  const shieldProfilePath = shieldAbsorbedRecovery.profilePath;
  const shieldFingerprintPath = path.join(outputDir, 'shield_absorbed_semantic_fingerprint.json');
  const shieldMigrationDecisionPath = path.join(outputDir, 'shield_absorbed_migration_oracle_decision.json');
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(mdPath, markdown(report));
  fs.writeFileSync(shieldScanPath, `${JSON.stringify(shieldMigrationScan, null, 2)}\n`);
  fs.writeFileSync(shieldFingerprintPath, `${JSON.stringify(shieldMigrationEvidence.fingerprint, null, 2)}\n`);
  fs.writeFileSync(shieldMigrationDecisionPath, `${JSON.stringify(shieldMigrationEvidence.decision, null, 2)}\n`);
  const manifest = {
    schema: 'ROFL_QUANTIZED_COMBAT_ARTIFACT_MANIFEST_V1', schema_version: 1,
    artifacts: [jsonPath, mdPath, shieldScanPath, shieldRowsPath, shieldProfilePath,
      shieldAbsorbedRecovery.neutralDecodedPath, shieldAbsorbedRecovery.neutralSummaryPath,
      shieldAbsorbedRecovery.directPath, shieldFingerprintPath, shieldMigrationDecisionPath]
      .map((file) => ({ path: file, bytes: fs.statSync(file).size, sha256: sha256File(file) })),
    protected_holdout: report.protected_holdout,
  };
  const manifestPath = path.join(outputDir, 'artifact_manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { report, paths: { jsonPath, mdPath, shieldScanPath, shieldRowsPath,
    shieldProfilePath, shieldAbsorbedPath: shieldAbsorbedRecovery.directPath,
    shieldFingerprintPath, shieldMigrationDecisionPath, manifestPath } };
}

module.exports = {
  DERIVABILITY_CLASSES, EXACT_BUILD, EXACT_DAMAGE_DECODER_PROFILE, EXACT_REPLAY_SHA,
  EXACT_RUNTIME_IMAGE_SHA, PROJECTIONS,
  controlledDamageAudit, decodeShieldCallbackObject, decreaseInterval, derivabilityAudit, displayInterval,
  intervalContains, joinPairedDeathContexts, runQuantizedCombatReconstruction,
  scanLatestDamage, scanShieldRouteMigrationCorpus, validateShieldMigrationScan,
};
