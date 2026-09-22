#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function rows(file) {
  return fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function packageManifest(root) {
  const manifestPath = path.join(root, 'package_manifest.json');
  return fs.existsSync(manifestPath) ? {
    path: manifestPath,
    value: JSON.parse(fs.readFileSync(manifestPath, 'utf8')),
  } : null;
}

function validateLitePackage(root, manifestInfo) {
  const manifest = manifestInfo.value;
  assert(manifest.package === 'v2-complete-independent-review-lite', 'unexpected lite package manifest');
  assert(manifest.verification_mode === 'LITE_PACKAGE_EVIDENCE_ONLY', 'lite package verification mode missing');
  assert(Array.isArray(manifest.deliberately_excluded) && manifest.deliberately_excluded.length > 0,
    'lite package exclusions missing');
  const files = manifest.files ?? {};
  const fileResults = Object.entries(files).map(([relative, expected]) => {
    assert(!path.isAbsolute(relative) && !relative.split(/[\\/]/).includes('..'), `unsafe manifest path: ${relative}`);
    const file = path.resolve(root, relative);
    assert(file.startsWith(`${root}${path.sep}`), `manifest file escapes package root: ${relative}`);
    const actual = fs.existsSync(file) ? { size: fs.statSync(file).size, sha256: sha256(file) } : null;
    return {
      relative,
      pass: actual?.size === expected.size && actual?.sha256 === expected.sha256,
    };
  });
  assert(fileResults.length === manifest.file_count, 'lite package manifest file count mismatch');
  assert(fileResults.every((result) => result.pass), 'lite package payload hash mismatch');

  const summaryPath = path.join(root, 'artifacts/v2_ward_spawn/current_full_decode/summary.json');
  const validationPath = path.join(root, 'artifacts/v2_ward_spawn/current_full_decode/validation.json');
  const packetManifestPath = path.join(root, 'artifacts/v2_ward_spawn/current_full_decode/packet_0353.jsonl.manifest.json');
  const samplePath = path.join(root, 'samples/ward_spawns_first_100.jsonl');
  const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
  const validation = JSON.parse(fs.readFileSync(validationPath, 'utf8'));
  const packets = JSON.parse(fs.readFileSync(packetManifestPath, 'utf8'));
  const sample = rows(samplePath);
  assert(summary.status === 'PASS' && summary.counts?.input_packets === 17406
    && summary.counts?.cast_spawn_matches === 464 && summary.counts?.unmatched_casts === 0,
  'pinned ward summary does not preserve V2 semantics');
  assert(validation.status === 'PASS' && validation.validated_match_count === 464
    && validation.validated_lifecycle_count === 637, 'pinned ward validation does not preserve V2 semantics');
  assert(packets.packet_ids?.length === 1 && packets.packet_ids[0] === 851
    && packets.selected_packet_count === 17406 && packets.replays?.length === 10,
  'pinned selected-packet manifest is invalid');
  assert(sample.length === 100 && sample.every((row) => row.raw_packet_ref?.packet_id === 851
    && row.raw_packet_ref?.raw_payload_sha256 && Number.isFinite(row.position?.x)
    && Number.isFinite(row.position?.y)), 'bounded ward sample lacks direct packet provenance');
  return {
    status: 'PASS',
    verification_mode: 'LITE_PACKAGE_EVIDENCE_ONLY',
    raw_redecode_performed: false,
    excluded_raw_artifacts: manifest.deliberately_excluded,
    manifest: path.relative(root, manifestInfo.path).replaceAll('\\', '/'),
    verified_payload_count: fileResults.length,
    bounded_ward_sample_count: sample.length,
    pinned_counts: { input_packets: 17406, cast_spawn_matches: 464, lifecycle_matches: 637 },
  };
}

function main() {
  const root = path.resolve(__dirname, '..');
  const litePackage = packageManifest(root);
  if (litePackage) {
    const report = validateLitePackage(root, litePackage);
    const output = path.join(root, 'artifacts/v2_ward_spawn/current_full_decode/lite_package_validation.json');
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, `${JSON.stringify({ ...report, output }, null, 2)}\n`);
    process.stdout.write(`${JSON.stringify({ ...report, output }, null, 2)}\n`);
    return;
  }
  const summaryPath = path.resolve(process.argv[2] || 'artifacts/v2_ward_spawn/current_full_decode/summary.json');
  const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
  const packets = rows(summary.input_artifacts.selected_packets);
  const wards = rows(summary.output_artifacts.ward_spawns);
  const matches = rows(summary.output_artifacts.cast_spawn_matches);
  const lifecycle = rows(summary.output_artifacts.ward_lifecycle);
  assert(sha256(summary.input_artifacts.runtime_image) === summary.input_artifacts.runtime_image_sha256, 'runtime image hash mismatch');
  assert(sha256(summary.input_artifacts.selected_packets) === summary.input_artifacts.selected_packets_sha256, 'packet input hash mismatch');
  assert(sha256(summary.input_artifacts.selected_packets_manifest) === summary.input_artifacts.selected_packets_manifest_sha256, 'packet manifest hash mismatch');
  for (const [file, digest] of Object.entries(summary.input_artifacts.cast_artifact_sha256)) {
    assert(sha256(file) === digest, `CastSpell artifact hash mismatch: ${file}`);
  }
  for (const [name, file] of Object.entries(summary.output_artifacts)) {
    assert(fs.existsSync(file), `missing output ${name}`);
    assert(sha256(file) === summary.output_sha256[name], `output hash mismatch: ${name}`);
  }
  assert(packets.length === summary.counts.input_packets, 'input packet count mismatch');
  assert(packets.every((row) => row.packet_id === 851 && row.raw_payload_sha256), 'invalid selected packet provenance');
  assert(wards.length === summary.counts.ward_spawns, 'ward count mismatch');
  assert(matches.length === summary.counts.cast_spawn_matches, 'match count mismatch');
  assert(lifecycle.length === summary.counts.lifecycle_matches, 'lifecycle count mismatch');
  assert(lifecycle.every((row) => row.duration_ms >= 0 && row.match_rule
    && row.spawn_raw_packet_ref && row.remove_raw_packet_ref), 'invalid lifecycle evidence');
  assert(summary.counts.trinket_casts === 464, `expected 464 casts, got ${summary.counts.trinket_casts}`);
  assert(matches.length >= 100, `expected >=100 matches, got ${matches.length}`);
  assert(summary.coordinate_independence.includes('object write trace'), 'coordinate independence statement missing');
  assert(wards.every((row) => row.raw_packet_ref.packet_id === 851
    && row.raw_packet_ref.raw_payload_sha256
    && Number.isFinite(row.position.x) && Number.isFinite(row.position.y)
    && row.write_evidence.position_x.selection === 'last_size_4_write'
    && row.write_evidence.owner_network_id.selection === 'first_size_4_write'
    && row.write_evidence.entity_network_id.selection === 'first_size_4_write'), 'invalid ward direct fields/provenance');
  assert(matches.every((row) => row.cast_raw_packet_ref && row.spawn_raw_packet_ref
    && row.owner_network_id && Number.isFinite(row.coordinate_error_start_like)
    && Number.isFinite(row.coordinate_error_end_like)), 'invalid match provenance/statistics');
  const report = {
    status: 'PASS', summary: summaryPath, validated_packet_count: packets.length,
    validated_ward_count: wards.length, validated_match_count: matches.length,
    validated_lifecycle_count: lifecycle.length,
    timestamp_delta_ms: summary.timestamp_delta_ms,
    coordinate_error_start_like: summary.coordinate_euclidean_error_start_like_target_position,
    coordinate_error_end_like: summary.coordinate_euclidean_error_end_like_target_position_end,
    proxy_decision: summary.proxy_decision,
  };
  const output = path.join(path.dirname(summaryPath), 'validation.json');
  fs.writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({ ...report, output }, null, 2)}\n`);
}

try { main(); } catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
}
