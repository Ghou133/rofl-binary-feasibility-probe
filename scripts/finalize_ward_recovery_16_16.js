#!/usr/bin/env node

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'artifacts', '16_16_ward_semantic_recovery_v1');
const SUMMARY = path.join(OUTPUT, 'runtime', 'ward_validation_summary.json');

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function filesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return filesUnder(absolute);
    return [absolute];
  });
}

function markdown(summary) {
  const counts = summary.counts;
  const owner = summary.owner_mapping;
  const lifecycle = summary.lifecycle;
  return `# 16.16 Ward semantic recovery V1

## A. STATUS

\`${summary.task_status}\`

## B. ROUTE

- Exact Replay build: \`${summary.game_version}\`.
- Raw route: \`0x049a\`; it is a broad entity-spawn family, not one Ward per packet.
- Factory/constructor/vtable/deserializer: \`0x00ed97b0\` / \`0x00eabb20\` / \`0x01b14570\` / \`0x01025d50\`.
- Rejected old candidate: \`0x00fc7770\`.
- Runtime image SHA-256: \`${summary.runtime_image_sha256}\`.
- Validation: ${summary.packet_manifest.replay_count} replays, ${counts.valid_input_rows.toLocaleString()} packets, ${counts.fully_consumed.toLocaleString()}/${counts.valid_input_rows.toLocaleString()} full-consume, ${counts.infrastructure_failures} infrastructure failures.

## C. SPAWN

- \`WARD_SPAWN_READY=YES\`.
- Spawn time: direct Replay block timestamp.
- Position: direct object writes \`+0x10/+0x14/+0x18\` (x/height/y); all confirmed points finite and map-range; ${summary.position_validation.unique_xy_count.toLocaleString()} unique x/y pairs.
- CastSpell target position was not used.

## D. OWNER

- Owner entity: direct \`+0x1c\` write.
- Participant: exact-build network-ID formula, derived.
- Team: exact Replay-tail participant mapping, derived.
- Coverage: ${owner.coverage_count.toLocaleString()}/${counts.player_active_ward_confirmed.toLocaleString()} (${(owner.coverage_rate * 100).toFixed(2)}%).
- Conflicts: ${owner.conflict_count}.
- Independent end-stat check: ${owner.tail_ward_placed_exact_match_count}/${owner.participant_rows} participant-game rows equal \`WARD_PLACED\` exactly; the remaining rows differ by at most ${owner.tail_ward_placed_absolute_error.max}.

## E. TYPE

Direct-name-derived confirmed player types:

${Object.entries(summary.ward_type_counts).map(([name, count]) => `- ${name}: ${count.toLocaleString()}`).join('\n')}

## F. SPECIAL VISION

- Confirmed player wards: ${counts.player_active_ward_confirmed.toLocaleString()}.
- Special/map vision: ${counts.special_or_map_vision.toLocaleString()}.
- Uncertain player-Ward entities: ${counts.uncertain_ward_entities.toLocaleString()}.
- Player, special, map-mechanic and unknown rows remain separate public classes; none are silently discarded.

## G. LIFECYCLE

- Direct corpse signals: ${lifecycle.direct_end_events.toLocaleString()}.
- Conservative \`OBSERVED_END\` matches: ${lifecycle.observed_end_matches.toLocaleString()}.
- Estimated ends: ${lifecycle.estimated_end_rows}.
- End reason: \`${lifecycle.end_reason}\`.
- Release status: \`${lifecycle.release_status}\`; \`VISION_LIFECYCLE_READY=NO\`.

## H. VERSION SAFETY

- 16.16 is exact-build bound to the route, RVAs, runtime image SHA and Replay manifests above.
- Build resolution never falls back to a neighbouring version.
- The frozen 16.15 Ward profile and regression corpus are unchanged.

## I. REGRESSION

See \`regression_results.md\` for the executed test matrix and exact results.

## J. RELEASE

- \`VISION_SPAWN_READY=YES\`.
- \`VISION_LIFECYCLE_READY=NO\`.
- \`VISION_DOWNSTREAM_READY=YES\` for spawn-based early Vision Timeline consumption.

## K. NEXT

\`RETURN_TO_LOL_INFERENCE_LAB_FOR_VISION_TIMELINE\`.

Do not infer Vision Habit, strategic location clusters or gank recommendations in this project.
`;
}

function main() {
  const summary = JSON.parse(fs.readFileSync(SUMMARY, 'utf8'));
  if (summary.status !== 'PASS' || summary.release.VISION_SPAWN_READY !== true) {
    throw new Error('Ward corpus release gates have not passed');
  }
  fs.writeFileSync(path.join(OUTPUT, 'ward_semantic_summary.md'), markdown(summary));
  const manifestPath = path.join(OUTPUT, 'release_manifest.json');
  const files = filesUnder(OUTPUT)
    .filter((filePath) => filePath !== manifestPath)
    .sort()
    .map((filePath) => ({
      path: path.relative(ROOT, filePath).replaceAll('\\', '/'),
      size: fs.statSync(filePath).size,
      sha256: sha256File(filePath),
    }));
  const manifest = {
    schema_version: 1,
    release_id: '16_16_WARD_SEMANTIC_RECOVERY_V1',
    status: summary.task_status,
    game_version: summary.game_version,
    runtime_image_sha256: summary.runtime_image_sha256,
    build_profile: summary.profile.id,
    packet_id: summary.profile.client_opcode,
    release: summary.release,
    evidence_summary: {
      replay_count: summary.packet_manifest.replay_count,
      packet_rows: summary.counts.valid_input_rows,
      fully_consumed_rows: summary.counts.fully_consumed,
      confirmed_player_wards: summary.counts.player_active_ward_confirmed,
      observed_end_matches: summary.counts.observed_lifecycle_ends,
      owner_conflicts: summary.owner_mapping.conflict_count,
    },
    files,
    note: 'Manifest excludes itself; rerun scripts/finalize_ward_recovery_16_16.js after any artifact change.',
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify({
    status: manifest.status,
    manifest: manifestPath,
    file_count: files.length,
  }, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, markdown };
