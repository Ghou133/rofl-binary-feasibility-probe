'use strict';

const path = require('node:path');

function cell(value) {
  return String(value ?? 'UNAVAILABLE').replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 'UNAVAILABLE';
}

function rawAnchorChainStatus(summary) {
  const validation = summary.real_replay_validation || {};
  const rawVerified = (summary.replay_files_tested?.length ?? 0) > 0
    && summary.packet_count > 0 && validation.block_framing_errors === 0;
  const semanticVerified = rawVerified
    && validation.semantic_events_verified === true
    && validation.all_replays_completed_without_errors === true
    && ['RESEARCH_READY_COMPLETE', 'RESEARCH_READY_V2_COMPLETE'].includes(summary.status);
  return {
    raw_packet: rawVerified ? 'VERIFIED' : 'NOT_VALIDATED',
    decoded_event: semanticVerified ? 'VERIFIED_DIRECT' : 'NOT_VALIDATED',
    entity_attribution: semanticVerified ? 'VERIFIED_DERIVED' : 'NOT_VALIDATED',
    final_semantic_output: semanticVerified ? 'VERIFIED_DERIVED' : 'NOT_VALIDATED',
  };
}

function renderAcceptanceReport(summary, results, artifactRoot, testCommand) {
  const lines = [
    '# ROFL Analyzer Acceptance Report', '',
    `- Status: **${cell(summary.status)}**`,
    `- Parsed Replay files: ${count(summary.replay_files_tested?.length)}`,
    `- Replay versions: ${cell(summary.replay_versions?.join(', ') || 'none')}`,
    `- Total parsed blocks: ${count(summary.packet_count)}`,
    `- Block framing errors: ${count(summary.real_replay_validation?.block_framing_errors)}`,
    `- Tests: ${summary.tests_total == null ? 'NOT RUN' : `${count(summary.tests_passed)}/${count(summary.tests_total)} passed; ${count(summary.tests_failed)} failed; ${count(summary.test_summary?.skipped)} skipped`}`,
    `- Upstream data unchanged: ${summary.upstream_unchanged === true ? 'YES' : summary.upstream_unchanged === false ? 'NO' : 'NOT CHECKED'}`,
    '', '## Execution scope', '',
    'Capability rows below come from successfully executed per-Replay decoders, not from a static feature list. They do not override the overall validation status.', '',
  ];
  const shown = new Set();
  let executed = 0;
  for (const result of results) {
    if (!result.ok) {
      lines.push(`- Input failed: ${cell(result.error?.code)} — ${cell(result.error?.message)}`);
      continue;
    }
    const analysis = result.analysis;
    lines.push(`- Build ${cell(analysis.replay_version)}: ${cell(analysis.decoder?.status)}`);
    if (analysis.decoder?.status !== 'RESEARCH_READY_COMPLETE'
        || !Array.isArray(analysis.block_errors) || analysis.block_errors.length !== 0) {
      lines.push('  Semantic fields are NOT VALIDATED for this input; empty event arrays are not evidence of zero events.');
      if (analysis.decoder?.note) lines.push(`  ${cell(analysis.decoder.note)}`);
      continue;
    }
    executed += 1;
    const capabilities = Array.isArray(analysis.capabilities) ? analysis.capabilities : [];
    const key = JSON.stringify([analysis.replay_version, capabilities]);
    if (shown.has(key)) continue;
    shown.add(key);
    lines.push('', '| Capability | Decoder-declared status | Scope / evidence |', '| --- | --- | --- |');
    for (const row of capabilities) {
      lines.push(`| ${cell(row.capability)} | ${cell(row.status)} | ${cell(row.evidence ?? row.version ?? '')} |`);
    }
    if (capabilities.length === 0) lines.push('| Capability metadata | UNAVAILABLE | No list returned by the decoder |');
    lines.push('');
  }
  if (executed === 0) lines.push('No successful semantic execution is attested by this run.');
  lines.push('', '## Interpretation limits', '',
    'Direct, derived, partial, candidate and unavailable fields retain their decoder-declared scope. Target-total shield absorption is not source or shield-instance attribution; reported healing is not effective healing or overheal.',
    'A supported capability that was not executed is not verified by this report. No counts here establish semantic completeness.',
    '', '## Independent review', '',
    `- Per-Replay artifacts: ${cell(path.resolve(artifactRoot, 'replays'))}`,
    `- Full Node regression command: \`${cell(testCommand)}\` (some tests need private exact-build inputs).`,
    '- Recompute Replay/payload hashes and inspect raw_packet_ref before relying on a semantic field.',
    '- Match Details remain validation-only; they do not enter the decoder.',
    '', 'The report itself is not evidence. Use reviewer_manifest.json to reproduce the recorded run.', '',
  );
  return lines.join('\n');
}

module.exports = { rawAnchorChainStatus, renderAcceptanceReport };
