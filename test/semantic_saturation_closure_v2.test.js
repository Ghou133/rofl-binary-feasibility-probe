'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { decisionIdentity } = require('../src/deep_recovery_decision_ledger');
const {
  CAPABILITY_DOMAINS,
  DEFAULT_SOURCE_SPECS,
  EXACT_BUILD,
  HIGH_VALUE_DOMAINS,
  buildCapabilityDomainClosure,
  capabilityRuleMap,
  loadSources,
  safeResolvedPath,
  sha256,
} = require('../src/semantic_saturation_closure_v2');
const { main } = require('../scripts/build_semantic_saturation_closure_v2');

function cleanHoldout() {
  return { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false };
}

function closedRow(extra = {}) {
  return {
    decision: 'KEEP_CANDIDATE',
    actual_reverse_engineering_executed: true,
    evidence_exhausted: true,
    actionable_hypotheses: [],
    next_required_evidence: ['controlled external evidence'],
    ...extra,
  };
}

function ledgerHistory(kind, key) {
  const history = {
    decision: 'KEEP_CANDIDATE',
    status: 'CANDIDATE',
    evidence_exhausted: false,
    source_evidence_exhausted: false,
    exhaustion_basis: 'LOCAL_ACTION_REMAINS',
    next_required_evidence: ['local action'],
    actual_reverse_engineering_executed: true,
    actionable_hypotheses: ['local action'],
    provenance: {
      artifact: 'safe/source.json',
      sha256: '1'.repeat(64),
      source_id: 'safe_source',
      source_schema: 'SAFE_SOURCE_V1',
    },
    negative_evidence: [],
    source_context: {},
    precedence: 1,
    effective: true,
  };
  history.decision_id = decisionIdentity(kind, key, history);
  return history;
}

function ledgerDocument() {
  return {
    schema: 'ROFL_DEEP_RECOVERY_DECISION_LEDGER_V1',
    schema_version: 1,
    generated_at: '2026-08-20',
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    input_sources: [],
    route_decisions: [],
    capability_decisions: [{
      semantic_capability: 'ITEM_STATE',
      decision_key: 'capability:ITEM_STATE',
      decision_history: [ledgerHistory('capability', 'ITEM_STATE')],
    }],
    domain_decisions: [{
      domain: 'item',
      decision_key: 'domain:item',
      decision_history: [ledgerHistory('domain', 'item')],
    }],
    summary: {},
    protected_evidence_boundary: {
      jungle_objective_fixture_enumerated: false,
      jungle_objective_fixture_read: false,
      jungle_objective_fixture_hashed: false,
      jungle_objective_fixture_decoded: false,
      jungle_objective_fixture_tested: false,
      jungle_objective_fixture_consumed: false,
    },
  };
}

function sourceDocument(id, ledger) {
  const machine = closedRow({ packet_id: 1, semantic_capability: 'SAFE', domain: 'safe' });
  const base = { exact_build: EXACT_BUILD, exact_build_only: true, nearest_build_fallback: 'FORBIDDEN' };
  if (id === 'decision_ledger') return ledger;
  if (id === 'hero_state') return {
    ...base,
    schema: 'ROFL_FULL_SEMANTIC_DEEP_RECOVERY_HERO_STATE_DAMAGE_DEFENSE_V2',
    schema_version: 2,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    status: 'SATURATED_NO_PERSISTENT_STATE_PROMOTION',
    route_decisions: Array.from({ length: 18 }, () => ({ evidence_exhausted: true })),
    exhausted_search_space: ['bounded route inventory'],
  };
  if (id === 'buff_spell') return {
    ...base,
    schema: 'ROFL_FULL_SEMANTIC_DEEP_RECOVERY_V2_BUFF_SPELL_PROMOTION_MATRIX_V1',
    schema_version: 1,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    status: 'SATURATED_WITH_RESEARCH_ONLY_PROMOTIONS_AND_BOUNDED_UNKNOWNS',
    promotions: Array.from({ length: 5 }, () => ({})),
    rejections: [{}],
    exhausted_or_bounded_absence: [{}],
  };
  if (id === 'entity_item') return {
    schema: 'ENTITY_ITEM_DEEP_RECOVERY_V2',
    build: EXACT_BUILD,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    route_decisions: Array.from({ length: 10 }, () => ({})),
    domain_decisions: [{
      domain: 'generic_entity_semantics',
      decision: 'REJECT',
      evidence_exhausted: true,
      scope: 'NO_GENERIC_CREATE_OR_OWNER_TEAM_CLASS_EVENT',
    }],
  };
  if (id === 'hero_stats') return {
    ...base,
    schema: 'ROFL_16_16_HERO_STATS_SCOREBOARD_VALIDATION_V1',
    schema_version: 1,
    status: 'PASS',
    decoded_packet_count: 1,
    matched_count: 1,
    unmatched_packet_count: 0,
    fields: {},
    comparison_rows: [{}],
  };
  if (id === 'ward') return {
    schema_version: 1,
    game_version: EXACT_BUILD,
    task_status: '16_16_WARD_SEMANTIC_RECOVERY_V1_COMPLETE',
    status: 'PASS',
    runtime_image_sha256_verified: true,
    full_consume_rate: 1,
    acceptance_gates: { exact_route_nonempty_full_consume: true },
  };
  if (id === 'gameplay_tail') return {
    ...base,
    schema: 'GAMEPLAY_ROUTE_TAIL_SATURATION_AUDIT_V2',
    schema_version: 2,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    saturation: { current_local_evidence_saturated: true },
    decisions: { route_decisions: [machine], domain_decisions: [machine] },
  };
  const schema = {
    named_gameplay: 'ROFL_NAMED_GAMEPLAY_WAVE_DECISIONS_V1',
    residual_p7: 'RESIDUAL_P7_WAVE_MACHINE_DECISIONS_V2',
    item_family: 'ITEM_FAMILY_SATURATION_DECISIONS_V2',
  }[id];
  return {
    ...base,
    schema,
    schema_version: 1,
    route_decisions: [machine],
    capability_decisions: [machine],
    domain_decisions: [machine],
  };
}

function exactQueue({ activeRoute = false } = {}) {
  const capabilityQueue = [...capabilityRuleMap()].map(([semanticCapability, rule]) => ({
    semantic_capability: semanticCapability,
    domain: rule.expectedDomain,
    actionable: true,
    validation_status: 'UNAVAILABLE',
    evidence_grade: 'UNAVAILABLE',
  }));
  const routeQueue = [{
    packet_id: 1,
    packet_discriminator: '0x0001',
    research_domain: 'state',
    actionable: activeRoute,
  }];
  return {
    schema: 'SEMANTIC_RESEARCH_QUEUE_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    protected_holdout: cleanHoldout(),
    route_queue: routeQueue,
    capability_queue: capabilityQueue,
    summary: {
      route_row_count: routeQueue.length,
      actionable_route_count: activeRoute ? 1 : 0,
      capability_row_count: capabilityQueue.length,
      actionable_capability_count: capabilityQueue.length,
    },
  };
}

function writeJson(root, relativePath, document) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`);
}

function fixture({ activeRoute = false, mutateSource = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-closure-v2-'));
  const ledgerSeed = ledgerDocument();
  for (const [id, relativePath] of DEFAULT_SOURCE_SPECS) {
    const document = sourceDocument(id, ledgerSeed);
    if (mutateSource?.id === id) mutateSource.mutate(document);
    writeJson(root, relativePath, document);
  }
  const queue = exactQueue({ activeRoute });
  writeJson(root, 'queue.json', queue);
  const sources = loadSources(root);
  const ledger = sources.decision_ledger.document;
  const queueBytes = Buffer.from(`${JSON.stringify(queue, null, 2)}\n`);
  const ledgerBytes = sources.decision_ledger.bytes;
  const queueInput = {
    path: 'queue.json', sha256: sha256(queueBytes), byte_count: queueBytes.length,
    schema: queue.schema, schema_version: queue.schema_version,
    bytes: queueBytes, document: queue,
  };
  const ledgerInput = {
    path: DEFAULT_SOURCE_SPECS[0][1], sha256: sha256(ledgerBytes), byte_count: ledgerBytes.length,
    schema: ledger.schema, schema_version: ledger.schema_version,
    bytes: ledgerBytes, document: ledger,
  };
  return {
    root, queue, ledger, sources, queueInput, ledgerInput,
    close() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

function buildFromFixture(value) {
  return buildCapabilityDomainClosure({
    queue: value.queue,
    ledger: value.ledger,
    sources: value.sources,
    queueInput: value.queueInput,
    ledgerInput: value.ledgerInput,
  });
}

test('closure contract is exactly 49 unique capabilities with pinned domains', () => {
  assert.equal(capabilityRuleMap().size, 49);
  assert.equal(Object.keys(CAPABILITY_DOMAINS).length, 49);
  assert.equal(CAPABILITY_DOMAINS.ATTACK_DAMAGE, 'combat');
  assert.equal(CAPABILITY_DOMAINS.OBJECTIVE, 'objective');
});

test('closure derives decisions from validated sources and bounds domain promotions', () => {
  const value = fixture();
  try {
    const document = buildFromFixture(value);
    assert.equal(document.capability_decisions.length, 49);
    assert.equal(document.domain_decisions.length, HIGH_VALUE_DOMAINS.length);
    assert.ok(document.capability_decisions.every((row) => row.actual_reverse_engineering_executed));
    assert.ok(document.capability_decisions.every((row) => row.evidence_exhausted));
    assert.ok(document.domain_decisions.every((row) => row.actionable_hypotheses.length === 0));
    assert.equal(document.capability_decisions.find((row) => row.semantic_capability === 'ITEM_STATE').decision, 'PROMOTE');
    assert.equal(document.domain_decisions.find((row) => row.domain === 'item').decision, 'KEEP_CANDIDATE');
    assert.equal(document.domain_decisions.find((row) => row.domain === 'economy').decision, 'KEEP_CANDIDATE');
    assert.equal(document.domain_decisions.find((row) => row.domain === 'vision').decision, 'KEEP_CANDIDATE');
    assert.equal(document.domain_decisions.find((row) => row.domain === 'map').decision, 'REJECT');
    const itemState = document.capability_decisions.find((row) => row.semantic_capability === 'ITEM_STATE');
    assert.equal(itemState.supersedes_previous_decision, true);
    assert.equal(itemState.supersedes.superseded_decision_ids.length, 1);
    assert.equal(document.claim_boundary.forbidden_status, 'FULLY_PARSED');
  } finally {
    value.close();
  }
});

test('queue gate rejects missing arrays, non-boolean actionability, partial/duplicate sets and wrong domains', () => {
  const cases = [
    [(queue) => { delete queue.route_queue; }, /route_queue/],
    [(queue) => { queue.route_queue[0].actionable = 'false'; }, /must be boolean/],
    [(queue) => { queue.capability_queue.pop(); queue.summary.capability_row_count -= 1; queue.summary.actionable_capability_count -= 1; }, /exactly 49/],
    [(queue) => { queue.capability_queue[1].semantic_capability = queue.capability_queue[0].semantic_capability; }, /unique/],
    [(queue) => { queue.capability_queue.find((row) => row.semantic_capability === 'CURRENT_MANA').domain = 'madeup'; }, /expected domain/],
    [(queue) => { queue.summary.actionable_route_count = 1; }, /summary actionable route count mismatch/],
  ];
  for (const [mutate, pattern] of cases) {
    const value = fixture();
    try {
      mutate(value.queue);
      assert.throws(() => buildFromFixture(value), pattern);
    } finally {
      value.close();
    }
  }
});

test('closure refuses active routes and aliased prior closure provenance', () => {
  const active = fixture({ activeRoute: true });
  try {
    assert.throws(() => buildFromFixture(active), /route exhaustion/);
  } finally {
    active.close();
  }

  const cycled = fixture();
  try {
    cycled.ledger.input_sources.push({
      source_id: 'innocent_alias',
      source_schema: 'ROFL_SEMANTIC_CAPABILITY_DOMAIN_CLOSURE_V2',
      artifact: 'safe/renamed.json',
      sha256: '2'.repeat(64),
    });
    assert.throws(() => buildFromFixture(cycled), /aliased closure provenance/);
  } finally {
    cycled.close();
  }
});

test('source loader rejects negative machine attestations instead of assigning constants', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-closure-source-v2-'));
  try {
    const ledger = ledgerDocument();
    for (const [id, relativePath] of DEFAULT_SOURCE_SPECS) {
      const document = sourceDocument(id, ledger);
      if (id === 'residual_p7') document.route_decisions[0].actual_reverse_engineering_executed = false;
      writeJson(root, relativePath, document);
    }
    assert.throws(() => loadSources(root), /explicitly denies actual reverse engineering/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('top-level source summaries cannot override false or actionable machine rows', () => {
  const cases = [
    [(row) => { row.actual_reverse_engineering_executed = false; }, /explicitly denies actual/],
    [(row) => { row.evidence_exhausted = false; }, /explicitly denies evidence exhaustion/],
    [(row) => { row.actionable_hypotheses = ['still executable']; }, /retains actionable hypotheses/],
  ];
  for (const [mutate, pattern] of cases) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-closure-machine-negative-'));
    try {
      const ledger = ledgerDocument();
      for (const [id, relativePath] of DEFAULT_SOURCE_SPECS) {
        const document = sourceDocument(id, ledger);
        if (id === 'residual_p7') mutate(document.route_decisions[0]);
        writeJson(root, relativePath, document);
      }
      assert.throws(() => loadSources(root), pattern);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});

test('resolved root, input and output Holdout paths fail before protected I/O', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-closure-path-v2-'));
  try {
    assert.throws(() => safeResolvedPath(root, 'Synthetic-Holdout/missing.json', {
      label: 'synthetic protected input', mustExist: true,
    }), /protected Holdout path/);
    assert.equal(fs.existsSync(path.join(root, 'Synthetic-Holdout')), false);
    assert.throws(() => safeResolvedPath(`${root}-Holdout`, 'safe.json', {
      label: 'synthetic protected root', mustExist: false,
    }), /protected Holdout path/);
    assert.throws(() => safeResolvedPath(root, 'Synthetic-Holdout-output', {
      label: 'synthetic protected output', mustExist: false,
    }), /protected Holdout path/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('missing descendants are checked through the nearest existing canonical alias', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-closure-alias-v2-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const syntheticProtected = path.join(root, 'Synthetic-Holdout-target');
  const alias = path.join(root, 'safe-alias');
  fs.mkdirSync(syntheticProtected);
  fs.symlinkSync(syntheticProtected, alias, process.platform === 'win32' ? 'junction' : 'dir');
  assert.throws(() => safeResolvedPath(root, 'safe-alias/missing/deep/output.json', {
    label: 'synthetic aliased missing output', mustExist: false,
  }), /canonical .*protected Holdout path/);
  assert.equal(fs.existsSync(path.join(alias, 'missing')), false);
});

test('queue and ledger boundaries require exactly six explicit false keys', () => {
  {
    const value = fixture();
    try {
      value.queue.protected_holdout.extra = false;
      assert.throws(() => buildFromFixture(value), /explicitly clean/);
    } finally {
      value.close();
    }
  }
  {
    const value = fixture();
    try {
      delete value.ledger.protected_evidence_boundary.jungle_objective_fixture_consumed;
      assert.throws(() => buildFromFixture(value), /boundary must be clean/);
    } finally {
      value.close();
    }
  }
});

test('CLI performs no output write when route exhaustion fails', () => {
  const value = fixture({ activeRoute: true });
  const output = 'safe-output';
  try {
    assert.throws(() => main([
      '--root', value.root,
      '--queue', 'queue.json',
      '--ledger', DEFAULT_SOURCE_SPECS[0][1],
      '--output-dir', output,
    ]), /route exhaustion/);
    assert.equal(fs.existsSync(path.join(value.root, output)), false);
  } finally {
    value.close();
  }
});

test('source bytes and queue provenance remain hash-bound', () => {
  const value = fixture();
  try {
    value.queueInput.sha256 = crypto.randomBytes(32).toString('hex');
    assert.throws(() => buildFromFixture(value), /queue bytes do not match pinned SHA-256/);
    value.queueInput.sha256 = sha256(value.queueInput.bytes);
    value.sources.decision_ledger.sha256 = crypto.randomBytes(32).toString('hex');
    assert.throws(() => buildFromFixture(value), /source bytes do not match pinned provenance/);
  } finally {
    value.close();
  }
});
