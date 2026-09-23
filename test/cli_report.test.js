'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { rawAnchorChainStatus, renderAcceptanceReport } = require('../src/cli_report');

function summary(overrides = {}) {
  return {
    status: 'RESEARCH_READY_COMPLETE', replay_files_tested: [{ sha256: 'synthetic' }],
    replay_versions: ['16.15.801.3452'], packet_count: 1,
    tests_total: null, upstream_unchanged: true,
    real_replay_validation: {
      block_framing_errors: 0, semantic_events_verified: true,
      all_replays_completed_without_errors: true,
    }, ...overrides,
  };
}

function result(version = '16.15.801.3452', status = 'RESEARCH_READY_COMPLETE') {
  return { ok: true, analysis: {
    replay_version: version, block_errors: [], decoder: { status },
    capabilities: [
      { capability: 'shield absorbed', status: 'VERIFIED_DIRECT_TARGET_TOTAL' },
      { capability: 'shield absorbed source attribution', status: 'UNAVAILABLE' },
      { capability: 'shield instance attribution', status: 'UNAVAILABLE' },
    ],
  } };
}

function report(value, results) {
  return renderAcceptanceReport(value, results, 'unit-output', 'npm run test:all');
}

test('report uses executed capability data instead of the old shield-absorption disclaimer', () => {
  const text = report(summary(), [result()]);
  assert.match(text, /shield absorbed \| VERIFIED_DIRECT_TARGET_TOTAL/);
  assert.match(text, /shield absorbed source attribution \| UNAVAILABLE/);
  assert.doesNotMatch(text, /Shield remaining\/absorbed\/unused/);
});

test('unsupported and raw-only results never publish their static capability list as executed', () => {
  for (const status of ['UNSUPPORTED_REPLAY_VERSION', 'UNVERIFIED', 'UNAVAILABLE']) {
    const text = report(summary({ status }), [result('16.16.805.0442', status)]);
    assert.match(text, /Semantic fields are NOT VALIDATED/);
    assert.match(text, /No successful semantic execution/);
    assert.doesNotMatch(text, /VERIFIED_DIRECT_TARGET_TOTAL/);
  }
});

test('missing input and failed input do not produce a verified-semantics section', () => {
  assert.match(report(summary({ replay_files_tested: [] }), []), /No successful semantic execution/);
  const text = report(summary({ status: 'VALIDATION_FAILED' }), [
    { ok: false, error: { code: 'MISSING_DECODER_IMAGE', message: 'external input missing' } },
  ]);
  assert.match(text, /MISSING_DECODER_IMAGE/);
  assert.match(text, /No successful semantic execution/);
});

test('partial and unavailable field statuses are not promoted', () => {
  const row = result();
  row.analysis.capabilities = [{ capability: 'shield', status: 'PARTIAL' }];
  const text = report(summary(), [row]);
  assert.match(text, /shield \| PARTIAL/);
  assert.doesNotMatch(text, /shield \| VERIFIED/);
});

test('framing errors suppress semantic attestation for the affected input', () => {
  const row = result();
  row.analysis.block_errors = [{ code: 'BOUNDS_ERROR' }];
  const text = report(summary({ status: 'VALIDATION_FAILED' }), [row]);
  assert.match(text, /NOT VALIDATED/);
  assert.doesNotMatch(text, /VERIFIED_DIRECT_TARGET_TOTAL/);
});

test('mixed builds are reported separately without borrowing capability status', () => {
  const text = report(summary({ status: 'UNSUPPORTED_REPLAY_VERSION' }), [
    result(), result('16.16.805.0442', 'UNSUPPORTED_REPLAY_VERSION'),
  ]);
  assert.match(text, /Build 16\.15\.801\.3452: RESEARCH_READY_COMPLETE/);
  assert.match(text, /Build 16\.16\.805\.0442: UNSUPPORTED_REPLAY_VERSION/);
  assert.equal((text.match(/shield absorbed \| VERIFIED_DIRECT_TARGET_TOTAL/g) || []).length, 1);
});

test('repeated identical capabilities are not duplicated for every replay', () => {
  const text = report(summary(), [result(), result()]);
  assert.equal((text.match(/\| Capability \|/g) || []).length, 1);
});

test('test failures and skips remain visible independently of successful decoding', () => {
  const text = report(summary({
    status: 'VALIDATION_FAILED', tests_total: 3, tests_passed: 1, tests_failed: 1,
    test_summary: { skipped: 1 },
  }), [result()]);
  assert.match(text, /VALIDATION_FAILED/);
  assert.match(text, /1\/3 passed; 1 failed; 1 skipped/);
});

test('empty or failed runs cannot claim a verified raw-to-semantic anchor chain', () => {
  for (const value of [{}, summary({ replay_files_tested: [] }), summary({ packet_count: 0 })]) {
    assert.deepEqual(Object.values(rawAnchorChainStatus(value)), Array(4).fill('NOT_VALIDATED'));
  }
  const failed = rawAnchorChainStatus(summary({ status: 'VALIDATION_FAILED' }));
  assert.equal(failed.decoded_event, 'NOT_VALIDATED');
  assert.equal(failed.final_semantic_output, 'NOT_VALIDATED');
});

test('successful complete runs retain the existing aggregate chain grades', () => {
  assert.deepEqual(rawAnchorChainStatus(summary()), {
    raw_packet: 'VERIFIED', decoded_event: 'VERIFIED_DIRECT',
    entity_attribution: 'VERIFIED_DERIVED', final_semantic_output: 'VERIFIED_DERIVED',
  });
});
