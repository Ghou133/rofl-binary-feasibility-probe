'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const ROUTES = Object.freeze(['0x004a', '0x0092', '0x00b9', '0x0199', '0x02d4', '0x0405', '0x0474']);
const DECISIONS = new Set(['PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE']);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function rejectProtectedPath(value) {
  const resolved = path.resolve(value);
  invariant(!resolved.toLowerCase().includes('holdout'), `protected Holdout path is forbidden: ${resolved}`);
  return resolved;
}

function sha256File(value) {
  return crypto.createHash('sha256').update(fs.readFileSync(rejectProtectedPath(value))).digest('hex');
}

function validateDecision(decision, packet) {
  invariant(decision.packet_discriminator === packet, `${packet} decision route mismatch`);
  invariant(DECISIONS.has(decision.decision), `${packet} invalid decision`);
  invariant(decision.evidence_exhausted === true, `${packet} local evidence is not exhausted`);
  if (packet === '0x0405') {
    invariant(decision.decision === 'PROMOTE', '0x0405 exact callback identity must be promoted');
    invariant(decision.structural_claim_only === false, '0x0405 exact identity was hidden');
    invariant(typeof decision.semantic_claim === 'string'
      && decision.semantic_claim.includes('PKT_S2C_SetItemGroupData_Broadcast_s'),
    '0x0405 exact semantic identity is missing');
  } else {
    invariant(decision.structural_claim_only === true, `${packet} must remain structural-only`);
    invariant(decision.semantic_claim === null, `${packet} semantic claim must remain null`);
  }
  invariant(Array.isArray(decision.next_required_evidence) && decision.next_required_evidence.length > 0,
    `${packet} next evidence is missing`);
  for (const item of decision.next_required_evidence) {
    const lowered = item.toLowerCase();
    invariant(['controlled', 'live-heap', 'live plaintext', 'new exact-build'].some((token) => lowered.includes(token)),
      `${packet} still lists a locally executable next step: ${item}`);
  }
  for (const key of ['factory_case_rva_hex', 'constructor_rva_hex', 'vtable_rva_hex', 'deserializer_rva_hex']) {
    invariant(/^0x[0-9a-f]{8}$/.test(decision[key]), `${packet} invalid ${key}`);
  }
}

function validateExhaustionReport(report) {
  invariant(report?.schema === 'HIGH_FREQUENCY_LEFTOVER_EXHAUSTION_V2', 'wrong exhaustion schema');
  invariant(report.schema_version === 2, 'wrong exhaustion schema version');
  invariant(report.exact_build === EXACT_BUILD, 'wrong exact build');
  invariant(report.exact_build_only === true, 'report is not exact-build-only');
  invariant(report.nearest_build_fallback === 'FORBIDDEN', 'nearest-build fallback must be forbidden');
  invariant(report.architecture_gate === 'PASS', 'architecture gate did not pass');
  invariant(report.status === 'LOCAL_EVIDENCE_EXHAUSTED', 'unexpected exhaustion status');
  invariant(JSON.stringify(report.scope) === JSON.stringify(ROUTES), 'route scope drifted');
  invariant(report.inputs?.image?.sha256 === RUNTIME_SHA256, 'runtime image hash drifted');

  const holdout = report.protected_holdout;
  invariant(holdout && Object.values(holdout).every((value) => value === false), 'protected Holdout was touched');
  invariant(report.validations?.all_pass === true, 'report validations did not pass');
  invariant(Object.entries(report.validations)
    .filter(([key]) => key !== 'all_pass')
    .every(([, value]) => value === true), 'a report validation is false');

  invariant(Array.isArray(report.route_decisions) && report.route_decisions.length === ROUTES.length,
    'route decision count mismatch');
  const decisionIndex = new Map(report.route_decisions.map((row) => [row.packet_discriminator, row]));
  for (const packet of ROUTES) {
    invariant(decisionIndex.has(packet), `${packet} decision missing`);
    validateDecision(decisionIndex.get(packet), packet);
    invariant(report.static_recovery?.routes?.[packet], `${packet} static recovery missing`);
    invariant(report.profiles?.[packet]?.sha256, `${packet} exact profile missing`);
    invariant(report.decodes?.[packet], `${packet} decode summary missing`);
    invariant(report.input_conservation?.[packet], `${packet} conservation summary missing`);
  }
  invariant(report.decodes['0x02d4'].all_three_observed_length_branches_consumed === true,
    '0x02d4 length branches are incomplete');
  invariant(report.decodes['0x02d4'].both_observed_high_bit_families_consumed === true,
    '0x02d4 high-bit families are incomplete');
  invariant(new Set(report.decodes['0x02d4'].observed_branch_matrix
    .map((row) => row.payload_length)).size === 3, '0x02d4 branch matrix is incomplete');
  invariant(report.decodes['0x0474'].full_inventory_weight_conserved === true,
    '0x0474 full inventory was not conserved');
  invariant(report.decodes['0x0199'].full_inventory_input_conserved === true,
    '0x0199 full inventory input was not conserved');
  invariant(report.decodes['0x0199'].all_unique_payloads_classified === true,
    '0x0199 has an unclassified payload branch');
  invariant(report.decodes['0x0199'].all_blocked_payloads_have_verified_prefix === true,
    '0x0199 blocked payload prefix coverage is incomplete');
  invariant(report.decodes['0x00b9'].all_containers_empty === true,
    '0x00b9 is not an empty-container control prefix');
  invariant(report.static_recovery.pair_0092_00b9.shared_deserializer_direct_call_targets.length >= 3,
    '0x0092/0x00b9 shared container path is missing');
  return report;
}

function verifyHashManifest(manifest) {
  invariant(manifest?.schema === 'HIGHFREQ_LEFTOVER_EXHAUSTION_HASHES_V2', 'wrong hash manifest schema');
  invariant(manifest.exact_build === EXACT_BUILD, 'hash manifest build mismatch');
  invariant(Array.isArray(manifest.files) && manifest.files.length === 9, 'hash manifest file count mismatch');
  const holdout = manifest.protected_holdout;
  invariant(holdout && Object.values(holdout).every((value) => value === false), 'hash manifest touched Holdout');
  for (const row of manifest.files) {
    invariant(sha256File(row.path) === row.sha256, `artifact hash mismatch: ${row.path}`);
    invariant(fs.statSync(rejectProtectedPath(row.path)).size === row.size, `artifact size mismatch: ${row.path}`);
  }
  return true;
}

function decisionSummary(report) {
  validateExhaustionReport(report);
  return Object.fromEntries(report.route_decisions.map((row) => [row.packet_discriminator, {
    decision: row.decision,
    hypothesis: row.hypothesis,
    evidence_exhausted: row.evidence_exhausted,
    receive_identity_status: row.receive_identity_status,
  }]));
}

module.exports = {
  DECISIONS,
  EXACT_BUILD,
  ROUTES,
  RUNTIME_SHA256,
  decisionSummary,
  rejectProtectedPath,
  sha256File,
  validateExhaustionReport,
  verifyHashManifest,
};
