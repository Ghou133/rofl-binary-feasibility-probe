'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function read(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function compact(document, sourcePath, limit = 25) {
  return {
    replay_path: document.replay_path,
    replay_sha256: document.replay_sha256,
    replay_version: document.replay_version,
    source_path: sourcePath,
    source_sha256: sha256(sourcePath),
    cast_count: document.cast_count,
    eligible_count: document.eligible_count,
    nearby_count: document.nearby_count,
    candidate_count: document.candidate_count,
    walk: document.walk,
    top_shapes: document.candidates.slice(0, limit).map((candidate) => ({
      packet_id: candidate.packet_id,
      packet_type: candidate.packet_type,
      payload_length: candidate.payload_length,
      count: candidate.count,
      distinct_raw_params: Object.keys(candidate.params ?? {}).length,
      sample_count: candidate.samples?.length ?? 0,
    })),
  };
}

function main(argv = process.argv.slice(2)) {
  const developmentPath = path.resolve(argv[0] ?? 'artifacts/v2_research/ward_entity_params_11154791609_fixed.json');
  const holdoutPath = path.resolve(argv[1] ?? 'artifacts/v2_research/ward_entity_params_holdout_fixed.json');
  const outputPath = path.resolve(argv[2] ?? 'artifacts/v2_research/ward_entity_params_summary.json');
  const development = read(developmentPath);
  const holdout = read(holdoutPath);
  const developmentShapes = new Set(development.candidates.map(
    (candidate) => `${candidate.packet_id}:${candidate.payload_length}`,
  ));
  const holdoutShapes = new Set(holdout.candidates.map(
    (candidate) => `${candidate.packet_id}:${candidate.payload_length}`,
  ));
  const overlap = [...developmentShapes].filter((shape) => holdoutShapes.has(shape)).sort();
  const output = {
    schema_version: 2,
    status: 'WARD_ENTITY_NOT_VERIFIED',
    conclusion: 'Nearby packet shape repetition did not establish a Ward entity spawn decoder; known UnitApplyDamage and CastSpell families remain separate from Ward identity.',
    development: compact(development, developmentPath),
    holdout: compact(holdout, holdoutPath),
    shape_comparison: {
      development_shape_count: developmentShapes.size,
      holdout_shape_count: holdoutShapes.size,
      overlap_count: overlap.length,
      development_only_count: developmentShapes.size - overlap.length,
      holdout_only_count: holdoutShapes.size - overlap.length,
      overlap_sample: overlap.slice(0, 100),
    },
    interpretation: {
      packet_id_650: 'VERIFIED_UNIT_APPLY_DAMAGE_NOT_WARD_ENTITY',
      packet_id_1113: 'VERIFIED_CASTSPELL_NOT_WARD_ENTITY_SPAWN',
      remaining_shapes: 'RAW_ONLY_UNAVAILABLE',
      actual_spawn_position: 'UNAVAILABLE',
      lifecycle: 'UNAVAILABLE',
    },
  };
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ output_path: outputPath, overlap_count: overlap.length }, null, 2)}\n`);
  return output;
}

if (require.main === module) main();
module.exports = { compact, main };
