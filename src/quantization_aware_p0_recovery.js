'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile } = require('./rofl');
const {
  EXPECTED_BUILD,
  EXPECTED_REPLAY_SHA,
  P0_SEMANTICS,
  DEFAULT_SCALES,
  loadGroundTruthOracle,
  buildOracleTransitions,
  scanReplayCandidates,
  scoreCandidate,
  summarizeForSemantic,
} = require('./oracle_guided_p0_recovery');

const FLAT_STEP = Object.freeze({ MAX_HP: 150, ARMOR: 15, MAGIC_RESIST: 20 });
const DISPLAY_FUNCTIONS = Object.freeze(['FLOOR', 'ROUND_HALF_AWAY_FROM_ZERO', 'TRUNCATE_TOWARD_ZERO']);
const EXPECTED_PARTIAL_COUNTS = Object.freeze({ MAX_HP: 18, ARMOR: 105, MAGIC_RESIST: 23, CURRENT_HP: 15 });

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function representationDeltaTolerance(representation, scale, rawBefore, rawAfter) {
  const absScale = Math.abs(scale);
  const internalBefore = rawBefore * scale;
  const internalAfter = rawAfter * scale;
  const multiplicationBudget = (Math.abs(internalBefore) + Math.abs(internalAfter)) * Number.EPSILON * 4;
  if (/^f32/.test(representation)) {
    const beforeUlp = Math.max(Math.abs(rawBefore), 2 ** -126) * 2 ** -23;
    const afterUlp = Math.max(Math.abs(rawAfter), 2 ** -126) * 2 ** -23;
    return (beforeUlp + afterUlp) * absScale + multiplicationBudget + Number.EPSILON;
  }
  if (/^f64/.test(representation)) {
    const beforeUlp = Math.max(Math.abs(rawBefore), Number.MIN_VALUE) * 2 ** -52;
    const afterUlp = Math.max(Math.abs(rawAfter), Number.MIN_VALUE) * 2 ** -52;
    return (beforeUlp + afterUlp) * absScale + multiplicationBudget + Number.EPSILON;
  }
  return (Math.abs(internalBefore) + Math.abs(internalAfter) + Math.abs(internalAfter - internalBefore))
    * Number.EPSILON * 8 + Number.EPSILON;
}

function floatDeltaTolerance(representation, expectedDelta) {
  return representationDeltaTolerance(representation, 1, 0, expectedDelta);
}

function displayInterval(displayValue, displayFunction) {
  if (displayFunction === 'FLOOR') return { lower: displayValue, upper: displayValue + 1, lower_inclusive: true, upper_inclusive: false };
  if (displayFunction === 'ROUND_HALF_AWAY_FROM_ZERO') {
    return { lower: displayValue - 0.5, upper: displayValue + 0.5, lower_inclusive: true, upper_inclusive: false };
  }
  if (displayFunction === 'TRUNCATE_TOWARD_ZERO') {
    return displayValue >= 0
      ? { lower: displayValue, upper: displayValue + 1, lower_inclusive: true, upper_inclusive: false }
      : { lower: displayValue - 1, upper: displayValue, lower_inclusive: false, upper_inclusive: true };
  }
  throw new Error(`unknown display function: ${displayFunction}`);
}

function deltaInterval(beforeDisplay, afterDisplay, displayFunction) {
  const before = displayInterval(beforeDisplay, displayFunction);
  const after = displayInterval(afterDisplay, displayFunction);
  return {
    lower: after.lower - before.upper,
    upper: after.upper - before.lower,
    lower_inclusive: after.lower_inclusive && before.upper_inclusive,
    upper_inclusive: after.upper_inclusive && before.lower_inclusive,
  };
}

function intervalContains(interval, value, tolerance = 0) {
  const lower = interval.lower_inclusive
    ? value >= interval.lower - tolerance
    : value > interval.lower && value >= interval.lower - tolerance;
  const upper = interval.upper_inclusive
    ? value <= interval.upper + tolerance
    : value < interval.upper && value <= interval.upper + tolerance;
  return lower && upper;
}

function fractionalResidue(value) {
  return value - Math.floor(value);
}

function responseAudit(candidate, response) {
  const representation = candidate.view;
  const rawBefore = candidate.scale === 0 ? null : response.candidate_before / candidate.scale;
  const rawAfter = candidate.scale === 0 ? null : response.candidate_after / candidate.scale;
  const tolerance = representationDeltaTolerance(representation, candidate.scale, rawBefore, rawAfter);
  const hypotheses = DISPLAY_FUNCTIONS.map((displayFunction) => {
    const internalDeltaInterval = deltaInterval(response.oracle_before, response.oracle_after, displayFunction);
    return {
      display_function: displayFunction,
      internal_delta_interval: internalDeltaInterval,
      candidate_delta_compatible: intervalContains(internalDeltaInterval, response.candidate_delta, tolerance),
    };
  });
  return {
    transition_id: response.transition_id,
    semantic: response.semantic,
    raw_before: rawBefore,
    raw_after: rawAfter,
    internal_before: response.candidate_before,
    internal_after: response.candidate_after,
    observed_HUD_before: response.oracle_before,
    observed_HUD_after: response.oracle_after,
    internal_delta: response.candidate_delta,
    HUD_delta: response.oracle_delta,
    binary_representation_error: response.candidate_delta - response.oracle_delta,
    representation_delta_tolerance: tolerance,
    tolerance_inputs: { representation, scale: candidate.scale, raw_before: rawBefore, raw_after: rawAfter },
    strict_flat_delta_match: Math.abs(response.candidate_delta - response.oracle_delta) <= tolerance,
    direction_match: response.oracle_delta === 0
      ? Math.abs(response.candidate_delta) <= tolerance
      : Math.sign(response.candidate_delta) === Math.sign(response.oracle_delta),
    fractional_residue_before: fractionalResidue(response.candidate_before),
    fractional_residue_after: fractionalResidue(response.candidate_after),
    fractional_residue_preserved: Math.abs(fractionalResidue(response.candidate_before) - fractionalResidue(response.candidate_after)) <= tolerance,
    quantized_HUD_hypotheses: hypotheses,
    any_quantized_HUD_hypothesis_compatible: hypotheses.some((item) => item.candidate_delta_compatible),
    old_absolute_snapshot_match: response.absolute_snapshot_match,
  };
}

function auditCandidate(semantic, candidate, allTransitions) {
  const targetTransitions = allTransitions.filter((row) => row.semantic === semantic && row.delta !== 0);
  const targetIds = new Set(targetTransitions.map((row) => row.id));
  const auditedResponses = candidate.responses.map((response) => responseAudit(candidate, response));
  const target = auditedResponses.filter((row) => row.semantic === semantic && row.HUD_delta !== 0);
  const crossStat = auditedResponses.filter((row) => row.semantic !== semantic && row.HUD_delta !== 0);
  const coveredIds = new Set(target.map((row) => row.transition_id));
  const strictMatches = target.filter((row) => row.strict_flat_delta_match);
  const quantizedMatches = target.filter((row) => row.any_quantized_HUD_hypothesis_compatible);
  const directions = target.filter((row) => row.direction_match);
  const residuePreserved = target.filter((row) => row.fractional_residue_preserved);
  const crossStatResponses = crossStat.filter((row) => Math.abs(row.internal_delta) > row.representation_delta_tolerance);
  const experimentFor = (transitionId) => {
    if (/RUBY/.test(transitionId)) return 'RUBY';
    if (/CLOTH/.test(transitionId)) return 'CLOTH';
    if (/-MR-/.test(transitionId)) return 'MANTLE';
    return 'OTHER';
  };
  const negativeControlMatrix = Object.fromEntries(['RUBY', 'CLOTH', 'MANTLE'].map((experiment) => {
    const rows = auditedResponses.filter((row) => experimentFor(row.transition_id) === experiment);
    return [experiment, {
      observed_pair_count: rows.length,
      response_count: rows.filter((row) => Math.abs(row.internal_delta) > row.representation_delta_tolerance).length,
      strict_corresponding_step_count: rows.filter((row) => row.strict_flat_delta_match).length,
      responses: rows.map((row) => ({ transition_id: row.transition_id, internal_delta: row.internal_delta, HUD_delta: row.HUD_delta })),
    }];
  }));
  const paths = {
    BUY_UNDO: target.filter((row) => /BUY-UNDO/.test(row.transition_id)),
    BUY_SELL: target.filter((row) => /BUY-SELL/.test(row.transition_id)),
  };
  const ownExperiment = { MAX_HP: 'RUBY', ARMOR: 'CLOTH', MAGIC_RESIST: 'MANTLE' }[semantic] || null;
  const requiredNegativeExperiments = ownExperiment
    ? ['RUBY', 'CLOTH', 'MANTLE'].filter((name) => name !== ownExperiment)
    : [];
  const negativeControlStrategy = semantic === 'CURRENT_HP'
    ? 'UNAVAILABLE_NO_CURRENT_HP_OBSERVATIONS_AT_ITEM_TRANSITION_ANCHORS'
    : 'OTHER_TWO_FLAT_STAT_ITEMS_MUST_HAVE_OBSERVED_PAIRS_AND_NO_RESPONSE';
  const missingNegativeExperiments = requiredNegativeExperiments.filter((name) => negativeControlMatrix[name].observed_pair_count === 0);
  const respondingNegativeExperiments = requiredNegativeExperiments.filter((name) => negativeControlMatrix[name].response_count > 0);
  const itemNegativeControlPass = semantic !== 'CURRENT_HP'
    && missingNegativeExperiments.length === 0 && respondingNegativeExperiments.length === 0;
  let failureGate = 'PROMOTION_ELIGIBLE';
  let failureReason = null;
  if (coveredIds.size !== targetIds.size) {
    failureGate = 'REPEATED_STEP_COVERAGE';
    failureReason = `observed ${coveredIds.size}/${targetIds.size} required BUY/UNDO + BUY/SELL transitions`;
  } else if (strictMatches.length !== target.length) {
    failureGate = 'STRICT_FLAT_DELTA';
    failureReason = `only ${strictMatches.length}/${target.length} deltas equal the flat-stat step within the uniform representation tolerance`;
  } else if (directions.length !== target.length) {
    failureGate = 'DIRECTIONALITY';
    failureReason = 'BUY/UNDO/BUY/SELL direction does not match the controlled transition';
  } else if (!paths.BUY_UNDO.length || !paths.BUY_SELL.length) {
    failureGate = 'INDEPENDENT_REVERSAL_PATHS';
    failureReason = 'both BUY→UNDO and BUY→SELL paths are required';
  } else if (residuePreserved.length !== target.length) {
    failureGate = 'FRACTIONAL_RESIDUE_PRESERVATION';
    failureReason = 'fractional residue is not preserved across a pure flat-stat step';
  } else if (!itemNegativeControlPass) {
    failureGate = 'CROSS_STAT_NEGATIVE_CONTROL';
    failureReason = semantic === 'CURRENT_HP'
      ? negativeControlStrategy
      : `missing item controls=${missingNegativeExperiments.join(',') || 'none'}; responding item controls=${respondingNegativeExperiments.join(',') || 'none'}`;
  }
  return {
    semantic,
    route: candidate.route,
    component: `${candidate.source}/${candidate.binding_scope}`,
    field: `${candidate.view}@${candidate.offset}`,
    representation: { view: candidate.view, scale: candidate.scale, stream: candidate.stream },
    failure_gate: failureGate,
    failure_reason: failureReason,
    old_gate_inputs: {
      target_delta_match_count: candidate.target_delta_match_count,
      target_observed_pair_count: candidate.target_observed_pair_count,
      old_absolute_snapshot_match_was_gate: false,
    },
    target_transition_count: targetTransitions.length,
    target_covered_count: coveredIds.size,
    strict_delta_match_count: strictMatches.length,
    quantized_compatible_count: quantizedMatches.length,
    direction_match_count: directions.length,
    fractional_residue_preserved_count: residuePreserved.length,
    cross_stat_response_count: crossStatResponses.length,
    cross_stat_negative_control_matrix: negativeControlMatrix,
    cross_stat_negative_control_policy: {
      strategy: negativeControlStrategy,
      own_experiment_excluded: ownExperiment,
      required_negative_experiments: requiredNegativeExperiments,
      missing_negative_experiments: missingNegativeExperiments,
      responding_negative_experiments: respondingNegativeExperiments,
      pass: itemNegativeControlPass,
    },
    promoted: failureGate === 'PROMOTION_ELIGIBLE',
    responses: auditedResponses,
  };
}

function reconstructPriorPartials(scan, transitions, semantic) {
  const partials = [];
  for (const [key, observations] of scan.observations) {
    let best = null;
    for (const scale of DEFAULT_SCALES) {
      const summary = summarizeForSemantic(scoreCandidate(key, observations, transitions, scale, 3000), semantic, transitions);
      const score = summary.target_delta_match_count * 100 + summary.target_observed_pair_count * 5
        - summary.cross_stat_response_count * 20 - (summary.mean_absolute_difference_of_differences || 0);
      if (!best || score > best._score) best = { ...summary, _score: score };
    }
    if (best.target_delta_match_count > 0) {
      const { _score, ...candidate } = best;
      partials.push(candidate);
    }
  }
  return partials;
}

function buildQuantizedOracleInterpretation(oracle, oraclePath) {
  return {
    schema_version: 'GROUND_TRUTH_ORACLE_DERIVED_INTERPRETATION_V1',
    source_oracle: { path: oraclePath, sha256: sha256File(oraclePath), immutable_record_count: oracle.records.length },
    interpretation_only: true,
    raw_observation_mutated: false,
    hypotheses_are_non_exhaustive: true,
    records: oracle.records.map((record) => ({
      source_record_id: record.case_id,
      semantic: record.semantic,
      timestamp_ms: record.timestamp,
      observation_type: 'HUD_QUANTIZED_SCALAR',
      observation_semantics: 'HUD_QUANTIZED',
      display_value: record.observed_value,
      display_function: 'UNVERIFIED_MULTIPLE_HYPOTHESES',
      internal_lower_bound: null,
      internal_upper_bound: null,
      certainty: 'MANUAL_DISPLAY_OBSERVATION_VERIFIED; DISPLAY_PROJECTION_UNVERIFIED',
      hypotheses: DISPLAY_FUNCTIONS.map((name) => ({ name, interval: displayInterval(record.observed_value, name) })),
    })),
  };
}

function renderMarkdown(report) {
  const lines = [
    '# Quantization-aware P0 rejection-gate audit', '',
    `- Exact build: \`${report.exact_build}\``,
    `- Replay SHA-256: \`${report.replay_sha256}\``,
    `- Immutable manual records: ${report.oracle.immutable_record_count}`,
    `- HUD display function: ${report.quantized_hud_model.display_function_status}`, '',
    '| semantic | old partial | reconstructed | >=1 quantized-compatible | all-required quantized survivor | repeated strict | negative-control survivors | promoted |',
    '|---|---:|---:|---:|---:|---:|---:|---:|',
  ];
  for (const semantic of P0_SEMANTICS) {
    const row = report.p0_candidate_counts[semantic];
    lines.push(`| ${semantic} | ${row.before_quantization_aware_audit} | ${row.reconstructed_partial_count} | ${row.at_least_one_quantized_compatible} | ${row.all_required_transitions_quantized_compatible} | ${row.after_repeated_directional_gate} | ${row.after_negative_controls} | ${row.promoted} |`);
  }
  lines.push('', `Question 1: ${report.question_1_old_exact_equality_rejection.answer}`, report.question_1_old_exact_equality_rejection.reason, '',
    'The source oracle was not changed. The additive interpretation stores floor, round-half-away-from-zero, and truncation intervals until a runtime HUD formatter is verified.');
  return `${lines.join('\n')}\n`;
}

function renderEvidence(report, invocation) {
  const rows = [
    '# Quantization-aware P0 execution evidence', '',
    `Invocation: \`${invocation}\``, '',
    '| success criterion | exact scenario | binary observable | captured artifact |',
    '|---|---|---|---|',
    `| Complete prior rejection audit | Reconstruct prior 18/105/23/15 partial identities under the pinned build/replay | reconstructed counts equal prior funnel counts; each candidate has a failure gate and raw/internal/HUD deltas | quantization_aware_p0_recovery_report.json |`,
    `| Quantized HUD interpretation | Interpret all 50 immutable manual HUD observations under floor/round/truncate hypotheses | source SHA remains ${report.oracle.sha256}; 50 additive HUD_QUANTIZED_SCALAR records | hud_quantized_oracle_interpretation.json |`,
    `| Delta-first repeated controls | BUY→UNDO and BUY→SELL for Ruby/Cloth/Mantle | repeated-direction survivor counts and explicit cross-stat matrix per candidate | quantization_aware_p0_recovery_report.json |`,
    `| Protected holdout boundary | Run controlled replay audit only | enumerated/read/hashed/decoded/tested/consumed are all false | quantization_aware_p0_recovery_report.json |`,
    '', 'Binary result: PASS means the audit completed and artifacts were written; it does not mean a P0 field was promoted.', '',
  ];
  return `${rows.join('\n')}\n`;
}

function writeManifest(outputDir, outputPaths) {
  const manifestPath = path.join(outputDir, 'artifact_manifest.json');
  const manifest = {
    schema_version: 'QUANTIZATION_AWARE_P0_ARTIFACT_MANIFEST_V1',
    outputs: outputPaths.map((filePath) => ({ path: path.basename(filePath), byte_size: fs.statSync(filePath).size, sha256: sha256File(filePath) })),
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifestPath;
}

function runQuantizationAwareP0Recovery(options = {}) {
  const root = path.resolve(options.repository_root || path.join(__dirname, '..'));
  const priorReportPath = path.resolve(options.prior_report_path || path.join(root, '.omo', 'evidence', 'oracle_guided_p0_recovery_core', 'oracle_guided_p0_recovery_report.json'));
  const oraclePath = path.resolve(options.oracle_path || path.join(root, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'p0_anchor_scan', 'manual_ground_truth_import_v1', 'manual_ground_truth_oracle.json'));
  if (!options.replay_path) throw new Error('replay_path is required for this controlled audit');
  const replayPath = path.resolve(options.replay_path);
  const outputDir = path.resolve(options.output_directory || path.join(root, '.omo', 'evidence', 'quantization_aware_p0_recovery'));
  const prior = JSON.parse(fs.readFileSync(priorReportPath, 'utf8'));
  if (prior.exact_build !== EXPECTED_BUILD || prior.replay_sha256 !== EXPECTED_REPLAY_SHA) throw new Error('prior report build/SHA mismatch');
  const oracle = loadGroundTruthOracle({ oracle_path: oraclePath });
  const oracleHashBefore = sha256File(oraclePath);
  if (sha256File(replayPath) !== EXPECTED_REPLAY_SHA) throw new Error('controlled replay SHA mismatch');
  const replay = parseReplayFile(replayPath);
  if (replay.header.version !== EXPECTED_BUILD) throw new Error('controlled replay exact build mismatch');
  const transitions = buildOracleTransitions(oracle.records);

  // This reconstructs the prior partial set under the exact prior scoring rules. The
  // quantization-aware audit below is restricted to those partial identities.
  const scan = scanReplayCandidates(replay, transitions, { windowMs: 3000 });
  const audits = {};
  const counts = {};
  for (const semantic of P0_SEMANTICS) {
    const expected = prior.p0[semantic].funnel.partial_signature_count;
    if (expected !== EXPECTED_PARTIAL_COUNTS[semantic]) throw new Error(`unexpected prior ${semantic} partial count: ${expected}`);
    const partials = reconstructPriorPartials(scan, transitions, semantic);
    if (partials.length !== expected) throw new Error(`reconstructed ${semantic} list has ${partials.length}, expected ${expected}`);
    audits[semantic] = partials.map((candidate) => auditCandidate(semantic, candidate, transitions));
    const atLeastOneQuantizedCompatible = audits[semantic].filter((candidate) => candidate.quantized_compatible_count > 0);
    const allRequiredQuantizedCompatible = audits[semantic].filter((candidate) => candidate.target_covered_count === candidate.target_transition_count
      && candidate.quantized_compatible_count === candidate.target_transition_count);
    const repeated = audits[semantic].filter((candidate) => candidate.target_covered_count === candidate.target_transition_count
      && candidate.strict_delta_match_count === candidate.target_transition_count && candidate.direction_match_count === candidate.target_transition_count);
    const afterNegative = repeated.filter((candidate) => candidate.cross_stat_negative_control_policy.pass
      && candidate.fractional_residue_preserved_count === candidate.target_transition_count);
    counts[semantic] = {
      before_quantization_aware_audit: expected,
      reconstructed_partial_count: partials.length,
      at_least_one_quantized_compatible: atLeastOneQuantizedCompatible.length,
      all_required_transitions_quantized_compatible: allRequiredQuantizedCompatible.length,
      after_quantization_aware_audit: allRequiredQuantizedCompatible.length,
      after_repeated_directional_gate: repeated.length,
      after_negative_controls: afterNegative.length,
      promoted: audits[semantic].filter((candidate) => candidate.promoted).length,
    };
  }
  if (sha256File(oraclePath) !== oracleHashBefore) throw new Error('manual oracle changed during interpretation');
  const interpretation = buildQuantizedOracleInterpretation(oracle, oraclePath);
  const report = {
    schema_version: 'QUANTIZATION_AWARE_P0_RECOVERY_V1',
    exact_build: EXPECTED_BUILD,
    replay_sha256: EXPECTED_REPLAY_SHA,
    prior_report: { path: priorReportPath, sha256: sha256File(priorReportPath) },
    method: {
      starting_population: 'PRIOR_PARTIAL_AND_FAILED_GATE_CANDIDATES_ONLY',
      full_blind_rescan_as_new_candidate_pool: false,
      reconstruction_note: 'Replay bytes were parsed once solely to reconstruct all 18/105/23/15 prior partial identities omitted by the prior top-20 report.',
      tolerance_rule: 'Per response: raw before/after magnitude and representation ULP, declared scale, plus a conservative JS multiplication/subtraction rounding budget; never tuned by candidate or expected HUD delta.',
    },
    oracle: { path: oraclePath, sha256: oracleHashBefore, immutable_record_count: oracle.records.length, raw_observation_mutated: false },
    quantized_hud_model: {
      observation_type: 'HUD_QUANTIZED_SCALAR',
      display_function_status: 'UNVERIFIED_MULTIPLE_HYPOTHESES',
      hypotheses: DISPLAY_FUNCTIONS,
      hypotheses_are_non_exhaustive: true,
      no_projection_preselected: true,
    },
    question_1_old_exact_equality_rejection: {
      answer: 'NO',
      reason: 'The prior scorer recorded absolute_snapshot_match but survivor gates used target delta coverage, repeated step response, and cross-stat controls. Every reconstructed partial failed before promotion without absolute HUD/internal equality being consulted.',
      prior_absolute_snapshot_field_was_gate: false,
    },
    p0_candidate_counts: counts,
    rejection_gate_audit: audits,
    level_up: { status: 'HOLD', global_blocker: false, requested: false },
    protected_holdout_access: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
  };
  fs.mkdirSync(outputDir, { recursive: true });
  const reportPath = path.join(outputDir, 'quantization_aware_p0_recovery_report.json');
  const markdownPath = path.join(outputDir, 'quantization_aware_p0_recovery_report.md');
  const interpretationPath = path.join(outputDir, 'hud_quantized_oracle_interpretation.json');
  const evidencePath = path.join(outputDir, 'EVIDENCE.md');
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(markdownPath, renderMarkdown(report));
  fs.writeFileSync(interpretationPath, `${JSON.stringify(interpretation, null, 2)}\n`);
  fs.writeFileSync(evidencePath, renderEvidence(report, 'node scripts/run_quantization_aware_p0_recovery.js --output-dir .omo/evidence/quantization_aware_p0_recovery'));
  const manifestPath = writeManifest(outputDir, [reportPath, markdownPath, interpretationPath, evidencePath]);
  return { status: 'PASS', output_directory: outputDir, report_path: reportPath, markdown_path: markdownPath, interpretation_path: interpretationPath, evidence_path: evidencePath, artifact_manifest: manifestPath, report };
}

module.exports = {
  DISPLAY_FUNCTIONS,
  EXPECTED_PARTIAL_COUNTS,
  floatDeltaTolerance,
  representationDeltaTolerance,
  displayInterval,
  deltaInterval,
  intervalContains,
  fractionalResidue,
  responseAudit,
  auditCandidate,
  reconstructPriorPartials,
  buildQuantizedOracleInterpretation,
  renderEvidence,
  runQuantizationAwareP0Recovery,
};
