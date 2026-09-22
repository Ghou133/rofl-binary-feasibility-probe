'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  assembleBaseline,
  assertManifestMember,
  buildDerivableCapabilityAudit,
  researchQuestions,
  statsAt,
  validateNodeTestLog,
  verifyArtifactManifest,
} = require('../src/stat_combat_semantic_layer');

const EXACT_BUILD = '16.16.805.0442';

function fixtureDocuments() {
  const capabilityRows = require('../src/capability_manifest').CAPABILITY_VOCABULARY.map((name) => ({
    semantic_capability: name,
    derivability_classification: 'INSUFFICIENT_EVIDENCE',
    missing_inputs: [],
  }));
  return {
    registry: {
      exact_build: EXACT_BUILD,
      corpus_scope: {
        accepted_unique_packet_count: 10,
        count_scope_reconciliation: { upstream_runtime_report_count: 9 },
      },
      verified_static_mappings: [{
        selector: 11, lane: 0, semantic: 'MANA_REGEN', display_format: '%0.f',
        localization_token: '@ManaRegen@', evidence_grade: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
      }],
      selectors: [{
        selector: 194, observed_in_local_042f_corpus: true, observed_output_record_count: 10,
        lane_relationships: {}, selector_semantic_status: 'UNKNOWN_NOT_PROMOTED',
      }],
    },
    selectorRuntime: {
      reader: { lookup_rva_hex: '0x00995c40' },
      caller_enumeration: { wrapper: [], storage_accessor: [{}, {}, {}, {}], selector_lane_lookup: Array(9).fill({}) },
      selector_enum_table_search: { status: 'PARTIAL_NO_FULL_ENUM_OR_SELECTOR_TO_STAT_TABLE_RECOVERED' },
      mana_regen_neighborhood: {
        status: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
        control_flow_and_value_flow_proof: { status: 'VERIFIED' },
      },
    },
    modifierReport: { adjustment_observations: { record_count: 714 } },
    dependencyGraph: {
      status: 'NO_PROMOTED_EDGES', promoted_edges: [],
      temporal_observations: {
        bracketed_by_strict_before_after_count: 660, zero_lane_delta_count: 660,
      },
    },
    derivedReport: {
      engine_status: 'READY_FAIL_CLOSED',
      publication_boundary: {
        max_hp: 'CONDITIONAL_ON_EXACT_BUILD_COMPLETE_INPUTS',
        armor: 'CONDITIONAL_ON_EXACT_BUILD_COMPLETE_INPUTS',
        magic_resist: 'CONDITIONAL_ON_EXACT_BUILD_COMPLETE_INPUTS',
      },
      algorithm_conformance: { pass: true },
      combat_computability_audit: {
        current_hp: { status: 'NOT_COMPUTABLE', missing_inputs: ['regen'] },
        shield_remaining: { status: 'NOT_COMPUTABLE', missing_inputs: ['instance'] },
        retained_direct_semantics: {
          damage_recorded_amount: true, heal_reported: true,
          shield_generated: true, shield_absorbed_target_total: true,
        },
      },
    },
    mechanics: {
      status: 'EVIDENCE_EXHAUSTED', decision: 'NO_EXACT_BUILD_DERIVED_P0_STAT_PERMISSION',
      components: {}, patch_family_negative_control: { accepted_as_exact_build_mechanics: false },
    },
    exceptionRegistry: { exception_count: 1, exceptions: [{ exception_id: 'MISSING' }] },
    inventoryReport: {
      schema: 'ROFL_INVENTORY_STATE_AT_AUDIT_V1', exact_build: EXACT_BUILD,
      published_event_audit: { ITEM_STATE_SET: { direct_rows_observed: 53 } },
      rune_input_availability: [
        { capability: 'RUNE_STATE', published_status: 'UNAVAILABLE' },
        { capability: 'RUNE_PROC', published_status: 'UNAVAILABLE' },
      ],
    },
    combatDataflowReport: {
      exact_build: EXACT_BUILD, status: 'EVIDENCE_EXHAUSTED',
      promotion_decisions: {
        DAMAGE_STAGE: { reason: 'unresolved damage consumer edge' },
        CURRENT_HP: { reason: 'no absolute health accessor' },
        HEAL_EFFECTIVE: { reason: 'no health clamp edge' },
        OVERHEAL: { reason: 'no requested/effective split' },
        SHIELD_REMAINING: { reason: 'no remaining-balance edge' },
        SHIELD_INSTANCE: { reason: 'no instance identity' },
      },
    },
    combatReport: {
      derivable_capability_audit: { rows: capabilityRows },
      combat_closure: {
        damage_stage_promotion_audit: { stage_conclusion: 'ambiguous' },
        mitigation: { missing_inputs: ['defense'] },
      },
      migration_integration: {},
      runtime_dynamic_access: { status: 'RUNTIME_DYNAMIC_ACCESS_BLOCKED' },
    },
  };
}

test('integration conserves A-Z, Q1-Q8, 79 capabilities and fail-closed P0 status', () => {
  const report = assembleBaseline(fixtureDocuments());
  assert.equal(report.status, 'EVIDENCE_EXHAUSTED');
  assert.deepEqual(Object.keys(report.final_report_A_to_Z), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''));
  assert.deepEqual(Object.keys(report.research_questions), Array.from({ length: 8 }, (_, index) => `Q${index + 1}`));
  assert.equal(report.derivable_capability_audit_v2.capability_count, 79);
  assert.equal(Object.values(report.derivable_capability_audit_v2.classification_counts)
    .reduce((sum, count) => sum + count, 0), 79);
  assert.equal(report.hero_stat_state_api.public_value_emission_now, false);
  assert.equal(report.stat_selector_summary.verified_mapping_count, 1);
  assert.equal(report.stat_modifier_summary.promoted_dependency_edge_count, 0);
});

test('research answers explicitly distinguish conditional derivation and unavailable HP state', () => {
  const questions = researchQuestions();
  assert.match(questions.Q1, /ONE/);
  assert.match(questions.Q2, /CONDITIONAL/);
  assert.match(questions.Q4, /NO UNIQUE STAGE/);
  assert.match(questions.Q8, /UNAVAILABLE/);
  assert.match(questions.Q8, /not publishable as HP_DELTA_ONLY/);
});

test('79-capability audit gives P0 fields precise current prerequisites', () => {
  const audit = buildDerivableCapabilityAudit(fixtureDocuments().combatReport);
  for (const capability of ['MAX_HP', 'ARMOR', 'MAGIC_RESIST']) {
    const row = audit.rows.find((entry) => entry.semantic_capability === capability);
    assert.equal(row.derivability_state_v2,
      'DERIVABLE_IF_EXACT_BUILD_MECHANICS_AND_COMPLETE_STATE');
    assert.ok(row.missing_inputs.length >= 5);
  }
});

test('statsAt is a real fail-closed API and preserves per-field missing inputs', () => {
  const state = statsAt({ participant_id: 1, champion: 'Kayn' }, 120000, {});
  assert.equal(state.schema, 'HERO_STAT_STATE_V1');
  assert.equal(state.exact_build, EXACT_BUILD);
  assert.equal(state.max_hp, null);
  assert.equal(state.armor, null);
  assert.equal(state.magic_resist, null);
  assert.ok(state.fields.max_hp.missing_inputs.includes('champion_identity.covers_game_time'));
  assert.equal(state.fields.max_hp.publication_eligible, false);
});

test('stable semantic API exports camelCase and canonical snake_case stat/inventory queries', () => {
  const api = require('../src/semantic_api');
  assert.equal(api.stats_at, api.statsAt);
  assert.equal(api.inventory_state_at, api.inventoryStateAt);
  const state = api.stats_at('Kayn', 120000);
  assert.equal(state.max_hp, null);
  const inventory = api.inventoryStateIndex([]);
  assert.equal(api.inventory_state_at(inventory, 1, 0).status, 'UNKNOWN');
});

test('manifest verifier rejects a same-size artifact with the wrong content hash', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'stat-combat-manifest-'));
  try {
    const artifact = path.join(temp, 'artifact.json');
    const manifest = path.join(temp, 'manifest.json');
    fs.writeFileSync(artifact, '{}\n');
    fs.writeFileSync(manifest, `${JSON.stringify({
      schema: 'FIXTURE',
      artifacts: [{
        path: 'artifact.json', bytes: 3,
        sha256: crypto.createHash('sha256').update('[]\n').digest('hex'),
      }],
    })}\n`);
    assert.throws(() => verifyArtifactManifest(manifest), /SHA mismatch/);
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('a valid manifest cannot attest a substituted same-build document', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'stat-combat-substitution-'));
  try {
    const attestedPath = path.join(temp, 'attested.json');
    const substitutePath = path.join(temp, 'substitute.json');
    const manifestPath = path.join(temp, 'manifest.json');
    const attested = Buffer.from('{"exact_build":"16.16.805.0442","value":"A"}\n');
    const substitute = Buffer.from('{"exact_build":"16.16.805.0442","value":"B"}\n');
    fs.writeFileSync(attestedPath, attested);
    fs.writeFileSync(substitutePath, substitute);
    fs.writeFileSync(manifestPath, `${JSON.stringify({
      schema: 'FIXTURE',
      artifacts: [{
        path: 'attested.json', bytes: attested.length,
        sha256: crypto.createHash('sha256').update(attested).digest('hex'),
      }],
    })}\n`);
    const verification = verifyArtifactManifest(manifestPath);
    const substituteBinding = {
      file: substitutePath,
      bytes: substitute.length,
      sha256: crypto.createHash('sha256').update(substitute).digest('hex'),
    };
    assert.throws(
      () => assertManifestMember(manifestPath, verification, substituteBinding, 'substitute'),
      /not a member/,
    );
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
});

test('test-log attestation requires a conserved positive pass with zero failures', () => {
  const passing = { text: 'ℹ tests 10\nℹ pass 10\nℹ fail 0\nℹ cancelled 0\nℹ skipped 0\n' };
  assert.deepEqual(validateNodeTestLog(passing, 'fixture'), {
    tests: 10, pass: 10, fail: 0, cancelled: 0, skipped: 0,
  });
  assert.throws(() => validateNodeTestLog({
    text: 'ℹ tests 10\nℹ pass 9\nℹ fail 1\nℹ cancelled 0\nℹ skipped 0\n',
  }, 'fixture'), /failures/);
});
