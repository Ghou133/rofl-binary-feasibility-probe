'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  ALLOWED_DECISIONS,
  ALLOWED_DOMAINS,
  ALLOWED_STATUSES,
  DEFAULT_SAFE_SOURCE_SPECS,
  EXACT_BUILD,
  HASH_MANIFEST_SCHEMA,
  LEDGER_SCHEMA,
  SATURATION_CLOSURE_EXTRACTOR,
  SATURATION_CLOSURE_SCHEMA,
  assertSafePath,
  buildDecisionLedger,
  buildHashManifest,
  decisionIdentity,
  decisionIdentityMaterial,
  decisionKey,
  jsonBytes,
  loadSafeSources,
  requiresOnlyExternalEvidence,
  sha256,
  validateDecisionLedger,
} = require('../src/deep_recovery_decision_ledger');
const {
  buildDeepRecoveryPriority,
  buildRouteQueue,
  loadDeepRecoveryInputs,
} = require('../src/semantic_research_priority');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'decision_ledger',
);

function buildCurrent() {
  return buildDecisionLedger({ sources: loadSafeSources(ROOT) });
}

function syntheticSource({
  id,
  document,
  extractor = 'direct',
  precedence = 10,
  artifact = `synthetic/${id}.json`,
}) {
  const bytes = jsonBytes(document);
  return {
    id,
    artifact,
    extractor,
    precedence,
    bytes,
    byte_count: bytes.length,
    sha256: sha256(bytes),
    document,
  };
}

function buildSyntheticClosureFixture({
  supersededIds = null,
  pinSha = null,
  flag = true,
  supersedesNull = false,
  duplicateCapabilityHistory = false,
  omitOneSupersededId = false,
  mutatePreclosure = null,
} = {}) {
  const baseDocument = {
    schema: 'SYNTHETIC_DECISION_SOURCE_V1',
    exact_build: EXACT_BUILD,
    nearest_build_fallback: 'FORBIDDEN',
    route_decisions: [{
      packet_id: 0x0100,
      decision: 'KEEP_CANDIDATE',
      evidence_exhausted: false,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: ['decode the bounded route payload'],
      next_required_evidence: ['Decode the bounded route payload.'],
    }],
    capability_decisions: [{
      semantic_capability: 'ABILITY_POWER',
      decision: 'KEEP_CANDIDATE',
      evidence_exhausted: false,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: ['trace live scalar updates'],
      next_required_evidence: ['Trace the local exact-build live scalar update.'],
    }],
    domain_decisions: [{
      domain: 'state',
      decision: 'KEEP_CANDIDATE',
      evidence_exhausted: false,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: ['trace the state carrier'],
      next_required_evidence: ['Trace the local exact-build state carrier.'],
    }],
  };
  if (duplicateCapabilityHistory) {
    baseDocument.capability_decisions.push({
      ...baseDocument.capability_decisions[0],
      decision: 'REJECT',
    });
  }
  const base = syntheticSource({ id: 'synthetic_base', document: baseDocument });
  let preclosureDocument = buildDecisionLedger({ sources: [base] });
  if (mutatePreclosure) preclosureDocument = mutatePreclosure(structuredClone(preclosureDocument));
  const preclosureBytes = jsonBytes(preclosureDocument);
  const preclosure = {
    artifact: 'synthetic/preclosure_decision_ledger.json',
    bytes: preclosureBytes,
    byte_count: preclosureBytes.length,
    sha256: sha256(preclosureBytes),
    document: preclosureDocument,
  };
  const previousCapability = preclosureDocument.capability_decisions
    .find((row) => row.semantic_capability === 'ABILITY_POWER');
  const previousDomain = preclosureDocument.domain_decisions
    .find((row) => row.domain === 'state');
  const makeClosureDecision = (kind, key, row, previous) => {
    const fullIds = supersededIds ?? previous.decision_history
      .filter((history) => history.effective)
      .map((history) => history.decision_id);
    const ids = omitOneSupersededId && fullIds.length > 1
      ? fullIds.slice(0, -1)
      : fullIds;
    const decision = {
      ...row,
      actual_reverse_engineering_executed: true,
      evidence_exhausted: true,
      actionable_hypotheses: [],
      next_required_evidence: ['A new governed external exact-build oracle is required.'],
      supersedes_previous_decision: flag,
      supersedes: supersedesNull ? null : {
        preclosure_ledger_sha256: pinSha ?? preclosure.sha256,
        decision_kind: kind,
        decision_key: key,
        superseded_decision_ids: ids,
      },
    };
    decision.decision_id = decisionIdentity(kind, key, decision);
    return decision;
  };
  const closureDocument = {
    schema: SATURATION_CLOSURE_SCHEMA,
    schema_version: 1,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    preclosure_inputs: {
      research_queue: {
        path: 'synthetic/semantic_research_queue.json',
        sha256: 'd'.repeat(64),
        byte_count: 1,
        schema: 'SEMANTIC_RESEARCH_QUEUE_V2',
        schema_version: 2,
      },
      decision_ledger: {
        path: preclosure.artifact,
        sha256: pinSha ?? preclosure.sha256,
        byte_count: preclosure.byte_count,
        schema: LEDGER_SCHEMA,
        schema_version: 1,
      },
    },
    route_decisions: [],
    capability_decisions: [makeClosureDecision('capability', 'ABILITY_POWER', {
      semantic_capability: 'ABILITY_POWER',
      domain: 'state',
      decision: 'KEEP_CANDIDATE',
    }, previousCapability)],
    domain_decisions: [makeClosureDecision('domain', 'state', {
      domain: 'state',
      decision: 'KEEP_CANDIDATE',
    }, previousDomain)],
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
  const closure = syntheticSource({
    id: 'semantic_capability_domain_saturation_closure',
    document: closureDocument,
    extractor: SATURATION_CLOSURE_EXTRACTOR,
    precedence: 100,
    artifact: 'synthetic/semantic_capability_domain_closure.json',
  });
  closure.preclosure_ledger = preclosure;
  return { base, closure, preclosure };
}

test('decision ledger schema is exact-build-only and every normalized record is complete', () => {
  const ledger = buildCurrent();
  assert.equal(validateDecisionLedger(ledger), true);
  assert.equal(ledger.schema, LEDGER_SCHEMA);
  assert.equal(ledger.exact_build, EXACT_BUILD);
  assert.equal(ledger.exact_build_only, true);
  assert.equal(ledger.nearest_build_fallback, 'FORBIDDEN');
  assert.ok(ledger.route_decisions.length >= 55);
  assert.ok(ledger.capability_decisions.length >= 48);
  assert.ok(ledger.domain_decisions.length >= 10);

  for (const collection of [
    ledger.route_decisions,
    ledger.capability_decisions,
    ledger.domain_decisions,
  ]) {
    for (const row of collection) {
      assert.ok(ALLOWED_DECISIONS.includes(row.decision));
      assert.ok(ALLOWED_STATUSES.includes(row.status));
      assert.equal(typeof row.evidence_exhausted, 'boolean');
      assert.equal(typeof row.actual_reverse_engineering_executed, 'boolean');
      assert.ok(Array.isArray(row.actionable_hypotheses));
      assert.ok(Array.isArray(row.next_required_evidence));
      assert.match(row.provenance.sha256, /^[0-9a-f]{64}$/);
      assert.ok(row.provenance.artifact.length > 0);
      assert.ok(Array.isArray(row.decision_history));
      assert.ok(row.decision_history.length > 0);
    }
  }
});

test('current-resource exhaustion distinguishes external gates from executable local work', () => {
  assert.equal(requiresOnlyExternalEvidence([
    'Controlled safe exact-build replay with one isolated modifier toggle.',
    'Independent ground truth oracle for the plaintext field role.',
  ]), true);
  assert.equal(requiresOnlyExternalEvidence([
    'Recover the exact nested vector decoder from the local runtime image.',
  ]), false);
  assert.equal(requiresOnlyExternalEvidence([
    'Controlled replay plus decode the bounded raw field profile.',
  ]), false);
  assert.equal(requiresOnlyExternalEvidence([]), false);
});

test('route ids are numeric and unique; capability and domain keys use queue vocabulary', () => {
  const ledger = buildCurrent();
  const routeIds = ledger.route_decisions.map((row) => row.packet_id);
  assert.equal(routeIds.every(Number.isInteger), true);
  assert.equal(new Set(routeIds).size, routeIds.length);
  assert.deepEqual(routeIds, [...routeIds].sort((left, right) => left - right));

  const capabilities = ledger.capability_decisions.map((row) => row.semantic_capability);
  assert.equal(new Set(capabilities).size, capabilities.length);
  assert.ok(capabilities.includes('HERO_DEATH_TIMER'));
  assert.ok(capabilities.includes('BUFF'));
  assert.ok(capabilities.includes('CAST_SPELL'));
  assert.ok(capabilities.includes('ITEM_STATE'));
  assert.ok(capabilities.includes('SUPPORT_QUEST_ITEM_STAGE'));
  assert.ok(capabilities.includes('EXACT_BUILD_ROUTE_0X0473_OUTER_VECTOR_COUNT_DECODER'));
  assert.ok(capabilities.includes('FACE_DIRECTION_VECTOR'));
  assert.ok(capabilities.includes('ABILITY_COOLDOWN_BROADCAST'));
  assert.ok(capabilities.includes('BASIC_ATTACK_POSITION_MINION'));

  const domains = ledger.domain_decisions.map((row) => row.domain);
  assert.equal(new Set(domains).size, domains.length);
  assert.equal(domains.every((domain) => ALLOWED_DOMAINS.includes(domain)), true);
  assert.ok(domains.includes('minion'));

  for (const packetId of [0x04ce, 0x0441, 0x0278, 0x046e, 0x00fc, 0x011a, 0x0433]) {
    const row = ledger.route_decisions.find((decision) => decision.packet_id === packetId);
    assert.equal(row.evidence_exhausted, true);
    assert.equal(row.provenance.source_id, 'residual_p7_wave_saturation_audit');
  }
  for (const packetId of [0x0137, 0x04b3]) {
    const row = ledger.route_decisions.find((decision) => decision.packet_id === packetId);
    assert.equal(row.decision, 'REPURPOSE');
    assert.equal(row.evidence_exhausted, true);
    assert.equal(row.provenance.source_id, 'item_family_saturation_audit');
  }
});

test('explicit safe input allowlist hashes every declared source and no protected path', () => {
  const sources = loadSafeSources(ROOT);
  assert.equal(sources.length, DEFAULT_SAFE_SOURCE_SPECS.length);
  for (const source of sources) {
    assert.equal(source.artifact.toLowerCase().includes('holdout'), false);
    const bytes = fs.readFileSync(path.join(ROOT, source.artifact));
    assert.equal(source.sha256, sha256(bytes));
    assert.equal(source.byte_count, bytes.length);
  }
  assert.throws(
    () => assertSafePath(path.join(ROOT, 'protected-holdout-fixture.json')),
    /protected evidence path is forbidden/,
  );
});

test('safe source loading retains the exact allowlisted preclosure snapshot for closure validation', (t) => {
  const fixture = buildSyntheticClosureFixture();
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-ledger-closure-'));
  t.after(() => {
    assert.equal(path.resolve(temporaryRoot).startsWith(path.resolve(os.tmpdir())), true);
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  });
  const syntheticDirectory = path.join(temporaryRoot, 'synthetic');
  fs.mkdirSync(syntheticDirectory, { recursive: true });
  fs.writeFileSync(path.join(temporaryRoot, fixture.closure.artifact), fixture.closure.bytes);
  fs.writeFileSync(path.join(temporaryRoot, fixture.preclosure.artifact), fixture.preclosure.bytes);
  const spec = {
    id: fixture.closure.id,
    artifact: fixture.closure.artifact,
    extractor: SATURATION_CLOSURE_EXTRACTOR,
    precedence: 100,
    preclosure_ledger_artifact: fixture.preclosure.artifact,
  };
  const [loaded] = loadSafeSources(temporaryRoot, [spec]);
  assert.equal(loaded.preclosure_ledger.sha256, fixture.preclosure.sha256);
  assert.deepEqual(loaded.preclosure_ledger.bytes, fixture.preclosure.bytes);
  const ledger = buildDecisionLedger({ sources: [fixture.base, loaded] });
  assert.equal(validateDecisionLedger(ledger), true);

  assert.throws(() => loadSafeSources(temporaryRoot, [{
    ...spec,
    preclosure_ledger_artifact: undefined,
  }]), /preclosure_ledger_artifact is required/);
});

test('specific audits supersede sampled baselines while retaining decision history and negative evidence', () => {
  const ledger = buildCurrent();
  const pairPrelude = ledger.route_decisions.find((row) => row.packet_id === 0x01c2);
  const pairEnvelope = ledger.route_decisions.find((row) => row.packet_id === 0x0473);
  const marker = ledger.route_decisions.find((row) => row.packet_id === 0x00b9);
  assert.equal(pairPrelude.decision, 'REPURPOSE');
  assert.equal(pairPrelude.evidence_exhausted, true);
  assert.equal(pairEnvelope.decision, 'REPURPOSE');
  assert.equal(pairEnvelope.evidence_exhausted, true);
  assert.equal(marker.decision, 'REPURPOSE');
  assert.ok(pairPrelude.decision_history.some((row) => row.decision === 'KEEP_CANDIDATE'));
  assert.ok(pairPrelude.negative_evidence.some((row) => row.includes('DIRECT_CURRENT_HP_SCALAR')));

  const neutralOverride = ledger.route_decisions.find((row) => row.packet_id === 0x00dd);
  assert.equal(neutralOverride.decision, 'KEEP_CANDIDATE');
  assert.ok(neutralOverride.decision_history.some((row) => row.decision === 'PROMOTE'));

  const wallCache = ledger.route_decisions.find((row) => row.packet_id === 0x0298);
  assert.equal(wallCache.decision, 'REPURPOSE');
  assert.equal(wallCache.evidence_exhausted, true);
  assert.ok(wallCache.negative_evidence.some((row) => row.includes('keyframe-only cache data')));
});

test('normalized ledger is directly accepted as semantic priority route decision evidence', () => {
  const ledger = buildCurrent();
  const rows = buildRouteQueue([{
    packet_id: 0x01c2,
    packet_discriminator: '0x01c2',
    observed: { count: 73852, source_provenance: [] },
    status: { baseline_status: 'UNKNOWN' },
    domain: { primary_domain: 'entity' },
  }], [ledger]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].current_decision, 'REPURPOSE');
  assert.equal(rows[0].evidence_exhausted, true);
  assert.equal(rows[0].actionable, false);
});

test('final rebuilt ledger alone converges priority and the semantic saturation gate', () => {
  const ledger = buildCurrent();
  const inputs = loadDeepRecoveryInputs({ root: ROOT });
  const result = buildDeepRecoveryPriority({
    ...inputs,
    decisionDocuments: [ledger],
  });
  assert.equal(result.queue.summary.actionable_route_count, 0);
  assert.equal(result.queue.summary.actionable_capability_count, 0);
  assert.equal(result.saturation.saturated, true);
  assert.equal(result.saturation.status, 'SEMANTIC_RECOVERY_SATURATED');
  assert.equal(result.saturation.domains.every((row) =>
    row.actual_reverse_engineering_executed
      && row.evidence_exhausted
      && row.actionable_hypotheses.length === 0), true);
});

test('priority rejects tampered selected facts and multiple/non-final ledgers', () => {
  const inputs = loadDeepRecoveryInputs({ root: ROOT });
  const ledger = buildCurrent();
  const tampered = structuredClone(ledger);
  tampered.domain_decisions.find((row) => row.domain === 'state')
    .actual_reverse_engineering_executed = false;
  assert.throws(() => buildDeepRecoveryPriority({
    ...inputs,
    decisionDocuments: [tampered],
  }), /selected fields must come directly from its effective decision/);
  assert.throws(() => buildDeepRecoveryPriority({
    ...inputs,
    decisionDocuments: [ledger, ledger],
  }), /at most one validated final decision ledger/);
  const notFinal = structuredClone(ledger);
  notFinal.input_sources = notFinal.input_sources.filter((row) =>
    row.extractor !== SATURATION_CLOSURE_EXTRACTOR);
  assert.throws(() => buildDeepRecoveryPriority({
    ...inputs,
    decisionDocuments: [notFinal],
  }), /history provenance is not pinned|not final/);
});

test('coordinated top-level, effective-history, and superseded_by id tampering fails content identity', () => {
  const tampered = structuredClone(buildCurrent());
  const capability = tampered.capability_decisions.find((row) =>
    row.semantic_capability === 'ABILITY_POWER');
  const effective = capability.decision_history.find((row) => row.effective);
  capability.decision = 'REJECT';
  capability.status = 'REJECTED_CURRENT_EVIDENCE';
  effective.decision = 'REJECT';
  effective.status = 'REJECTED_CURRENT_EVIDENCE';
  effective.decision_identity_material = decisionIdentityMaterial(
    'capability', 'ABILITY_POWER', effective,
  );
  const replacementId = sha256(Buffer.from(JSON.stringify(
    effective.decision_identity_material,
  ), 'utf8'));
  capability.decision_id = replacementId;
  effective.decision_id = replacementId;
  for (const history of capability.decision_history.filter((row) => !row.effective)) {
    history.superseded_by.decision_id = replacementId;
  }
  assert.throws(() => validateDecisionLedger(tampered),
    /normalized history is not bound to its source decision identity/);
});

test('priority CLI loader pins the final ledger bytes to its sibling manifest', (t) => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-priority-ledger-pin-'));
  t.after(() => fs.rmSync(temporaryRoot, { recursive: true, force: true }));
  const ledger = buildCurrent();
  const bytes = jsonBytes(ledger);
  fs.writeFileSync(path.join(temporaryRoot, 'decision_ledger.json'), bytes);
  const manifest = buildHashManifest(ledger, bytes);
  manifest.files[0].sha256 = '0'.repeat(64);
  fs.writeFileSync(path.join(temporaryRoot, 'artifact_manifest.json'), jsonBytes(manifest));
  assert.throws(() => loadDeepRecoveryInputs({
    root: ROOT,
    decisionPaths: [path.join(temporaryRoot, 'decision_ledger.json')],
  }), /not pinned by the sibling hash manifest/);
});

test('ledger protected evidence boundary is exact, not truthy-by-omission', () => {
  const ledger = buildCurrent();
  const missing = structuredClone(ledger);
  delete missing.protected_evidence_boundary.jungle_objective_fixture_consumed;
  assert.throws(() => validateDecisionLedger(missing), /exactly six explicit false keys/);
  const extra = structuredClone(ledger);
  extra.protected_evidence_boundary.extra = false;
  assert.throws(() => validateDecisionLedger(extra), /exactly six explicit false keys/);
});

test('decision identities are stable and include the normalized kind/key boundary', () => {
  const left = decisionIdentity('capability', 'ABILITY_POWER', {
    decision: 'KEEP_CANDIDATE',
    evidence_exhausted: true,
    next_required_evidence: ['external oracle'],
  });
  const right = decisionIdentity('capability', 'ABILITY_POWER', {
    next_required_evidence: ['external oracle'],
    evidence_exhausted: true,
    decision: 'KEEP_CANDIDATE',
    decision_id: 'ignored-derived-field',
  });
  assert.equal(left, right);
  assert.match(left, /^[0-9a-f]{64}$/);
  assert.notEqual(left, decisionIdentity('domain', 'state', {
    decision: 'KEEP_CANDIDATE',
    evidence_exhausted: true,
    next_required_evidence: ['external oracle'],
  }));
  assert.equal(decisionKey('route', 0x0100), 'route:0x0100');
});

test('hash-bound closure supersedes the exact prior chains while preserving marked history', () => {
  const { base, closure, preclosure } = buildSyntheticClosureFixture();
  const ledger = buildDecisionLedger({ sources: [base, closure] });
  assert.equal(validateDecisionLedger(ledger), true);
  const capability = ledger.capability_decisions
    .find((row) => row.semantic_capability === 'ABILITY_POWER');
  const domain = ledger.domain_decisions.find((row) => row.domain === 'state');
  for (const decision of [capability, domain]) {
    assert.equal(decision.evidence_exhausted, true);
    assert.deepEqual(decision.actionable_hypotheses, []);
    assert.equal(decision.provenance.source_id, closure.id);
    assert.equal(decision.superseded_decision_count, 1);
    assert.equal(decision.decision_history.length, 2);
    const old = decision.decision_history.find((row) => row.provenance.source_id === base.id);
    const replacement = decision.decision_history
      .find((row) => row.provenance.source_id === closure.id);
    assert.equal(old.effective, false);
    assert.equal(old.superseded_by.decision_id, replacement.decision_id);
    assert.equal(old.superseded_by.preclosure_ledger_sha256, preclosure.sha256);
    assert.equal(replacement.effective, true);
    assert.equal(replacement.supersession_validated, true);
  }

  const queueRows = buildRouteQueue([{
    packet_id: 0x0100,
    packet_discriminator: '0x0100',
    observed: { count: 50000, source_provenance: [] },
    status: { baseline_status: 'UNKNOWN' },
    domain: { primary_domain: 'state' },
  }], [ledger]);
  assert.equal(queueRows.length, 1);
  assert.equal(queueRows[0].current_decision, 'KEEP_CANDIDATE');
  assert.equal(queueRows[0].evidence_exhausted, false);
  assert.equal(queueRows[0].actionable, true);

  const tampered = structuredClone(ledger);
  const tamperedOld = tampered.capability_decisions
    .find((row) => row.semantic_capability === 'ABILITY_POWER')
    .decision_history.find((row) => row.effective === false);
  tamperedOld.superseded_by.preclosure_ledger_sha256 = 'e'.repeat(64);
  assert.throws(() => validateDecisionLedger(tampered),
    /superseded history preclosure sha256 mismatch/);
});

test('closure supersession fails closed on stale hashes, foreign ids, and incomplete id sets', () => {
  {
    const { base, closure } = buildSyntheticClosureFixture({ pinSha: 'a'.repeat(64) });
    assert.throws(() => buildDecisionLedger({ sources: [base, closure] }),
      /preclosure ledger sha256 mismatch/);
  }
  {
    const { base, closure } = buildSyntheticClosureFixture({
      supersededIds: ['b'.repeat(64)],
    });
    assert.throws(() => buildDecisionLedger({ sources: [base, closure] }),
      /must exactly match the pinned effective decision chain/);
  }
  {
    const { base, closure } = buildSyntheticClosureFixture({
      duplicateCapabilityHistory: true,
      omitOneSupersededId: true,
    });
    assert.throws(() => buildDecisionLedger({ sources: [base, closure] }),
      /must exactly match the pinned effective decision chain/);
  }
  {
    const { base, closure } = buildSyntheticClosureFixture();
    base.document.capability_decisions[0].decision = 'REJECT';
    assert.throws(() => buildDecisionLedger({ sources: [base, closure] }),
      /source document does not match retained bytes/);
  }
});

test('closure cannot declare supersession without the exact old key or through circular provenance', () => {
  {
    const { base, closure } = buildSyntheticClosureFixture({ flag: false, supersedesNull: true });
    assert.throws(() => buildDecisionLedger({ sources: [base, closure] }),
      /must explicitly supersede its preclosure decision chain/);
  }
  {
    const { base, closure } = buildSyntheticClosureFixture({
      mutatePreclosure: (ledger) => {
        ledger.input_sources.push({
          source_id: 'semantic_capability_domain_saturation_closure',
          artifact: 'synthetic/semantic_capability_domain_closure.json',
          sha256: 'c'.repeat(64),
          byte_count: 1,
          source_schema: SATURATION_CLOSURE_SCHEMA,
          extractor: SATURATION_CLOSURE_EXTRACTOR,
          route_decision_instance_count: 0,
          capability_decision_instance_count: 0,
          domain_decision_instance_count: 0,
        });
        ledger.summary.input_source_count += 1;
        return ledger;
      },
    });
    assert.throws(() => buildDecisionLedger({ sources: [base, closure] }),
      /circular closure input provenance/);
  }
});

test('checked-in ledger and hash manifest are deterministic and input-attested', () => {
  const ledger = buildCurrent();
  const checkedLedgerBytes = fs.readFileSync(path.join(OUTPUT, 'decision_ledger.json'));
  const checkedLedger = JSON.parse(checkedLedgerBytes.toString('utf8'));
  assert.deepEqual(checkedLedger, ledger);
  assert.deepEqual(jsonBytes(ledger), checkedLedgerBytes);

  const expectedManifest = buildHashManifest(ledger, checkedLedgerBytes);
  const checkedManifest = JSON.parse(fs.readFileSync(
    path.join(OUTPUT, 'artifact_manifest.json'),
    'utf8',
  ));
  assert.equal(checkedManifest.schema, HASH_MANIFEST_SCHEMA);
  assert.deepEqual(checkedManifest, expectedManifest);
  assert.equal(checkedManifest.files[0].sha256, sha256(checkedLedgerBytes));
  assert.deepEqual(
    checkedManifest.inputs.map((row) => row.sha256),
    ledger.input_sources.map((row) => row.sha256),
  );
});
