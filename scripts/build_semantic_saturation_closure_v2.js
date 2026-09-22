#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  DEFAULT_SOURCE_SPECS,
  EXACT_BUILD,
  buildCapabilityDomainClosure,
  loadSources,
  readSafeJsonBytes,
  safeResolvedPath,
  sha256,
} = require('../src/semantic_saturation_closure_v2');
const {
  DEFAULT_SAFE_SOURCE_SPECS: DECISION_SOURCE_SPECS,
  SATURATION_CLOSURE_EXTRACTOR,
  buildDecisionLedger,
  jsonBytes,
  loadSafeSources,
} = require('../src/deep_recovery_decision_ledger');

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    queue: 'artifacts/full_semantic_deep_recovery_v2/saturation_closure/preclosure_semantic_research_queue_16_16.json',
    ledger: 'artifacts/full_semantic_deep_recovery_v2/saturation_closure/preclosure_decision_ledger_16_16.json',
    outputDirectory: 'artifacts/full_semantic_deep_recovery_v2/saturation_closure',
    rebuildPreclosureLedger: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    const value = () => {
      if (!argv[index + 1] || argv[index + 1].startsWith('--')) {
        throw new Error(`${option} requires a value`);
      }
      index += 1;
      return argv[index];
    };
    if (option === '--root') options.root = path.resolve(value());
    else if (option === '--queue') options.queue = value();
    else if (option === '--ledger') options.ledger = value();
    else if (option === '--output-dir') options.outputDirectory = value();
    else if (option === '--rebuild-preclosure-ledger') options.rebuildPreclosureLedger = true;
    else throw new Error(`unknown option ${option}`);
  }
  return options;
}

function safeJson(root, relativePath) {
  return readSafeJsonBytes(root, relativePath, 'JSON source').document;
}

function markdown(document) {
  const decisions = Object.groupBy(
    document.capability_decisions,
    (row) => row.domain,
  );
  const lines = [
    '# Semantic Saturation Capability/Domain Closure V2',
    '',
    `- Exact build: \`${document.exact_build}\``,
    `- Actionable routes before closure: ${document.preconditions.actionable_route_count}`,
    `- Capability gaps closed to an external-only boundary: ${document.capability_decisions.length}`,
    `- High-value domains closed: ${document.domain_decisions.length}`,
    '- This is an evidence-exhaustion decision, not a claim that the Replay is fully parsed.',
    '',
  ];
  for (const domain of document.domain_decisions.map((row) => row.domain)) {
    lines.push(`## ${domain}`, '');
    for (const row of decisions[domain] ?? []) {
      lines.push(`- \`${row.semantic_capability}\`: **${row.decision}** — ${row.current_local_conclusion}`);
    }
    if (!(decisions[domain] ?? []).length) lines.push('- No unresolved manifest capability row remained.');
    lines.push('');
  }
  lines.push(
    '## Protected Holdout boundary',
    '',
    '- enumerate/read/hash/decode/test/consume are all `false`.',
    '',
    '## Claim boundary',
    '',
    '- Allowed after the independent final gate passes: `SEMANTIC_RECOVERY_SATURATED`.',
    '- Forbidden: `FULLY_PARSED`.',
    '',
  );
  return `${lines.join('\n')}\n`;
}

function writeOutputs({
  root,
  outputDirectory,
  document,
  preclosureLedgerBytes,
  preclosureQueueBytes,
}) {
  if (!Buffer.isBuffer(preclosureLedgerBytes) || !Buffer.isBuffer(preclosureQueueBytes)) {
    throw new Error('preclosure queue and ledger bytes are required');
  }
  if (document?.exact_build !== EXACT_BUILD
    || document?.preclosure_inputs?.decision_ledger?.sha256 !== sha256(preclosureLedgerBytes)
    || document?.preclosure_inputs?.research_queue?.sha256 !== sha256(preclosureQueueBytes)) {
    throw new Error('output document does not match pinned preclosure bytes');
  }
  const boundaryKeys = ['enumerated', 'read', 'hashed', 'decoded', 'tested', 'consumed'];
  if (!document.protected_holdout
    || Object.keys(document.protected_holdout).length !== boundaryKeys.length
    || !boundaryKeys.every((key) => Object.prototype.hasOwnProperty.call(
      document.protected_holdout, key,
    ) && document.protected_holdout[key] === false)) {
    throw new Error('output Holdout boundary must be explicitly clean');
  }

  const resolvedOutput = safeResolvedPath(root, outputDirectory, {
    label: 'closure output directory',
    mustExist: false,
  });
  const jsonPath = path.join(resolvedOutput.absolutePath, 'semantic_capability_domain_closure_16_16.json');
  const markdownPath = path.join(resolvedOutput.absolutePath, 'semantic_capability_domain_closure_16_16.md');
  const preclosureLedgerPath = path.join(resolvedOutput.absolutePath, 'preclosure_decision_ledger_16_16.json');
  const preclosureQueuePath = path.join(resolvedOutput.absolutePath, 'preclosure_semantic_research_queue_16_16.json');
  const hashPath = path.join(resolvedOutput.absolutePath, 'semantic_capability_domain_closure_hashes_16_16.json');
  for (const [label, target] of [
    ['closure JSON', jsonPath],
    ['closure Markdown', markdownPath],
    ['preclosure ledger snapshot', preclosureLedgerPath],
    ['preclosure queue snapshot', preclosureQueuePath],
    ['closure hash manifest', hashPath],
  ]) {
    safeResolvedPath(root, target, { label, mustExist: false });
  }

  const jsonBytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
  const markdownBytes = Buffer.from(markdown(document));
  const manifest = {
    schema: 'ROFL_SEMANTIC_CAPABILITY_DOMAIN_CLOSURE_HASH_MANIFEST_V2',
    exact_build: document.exact_build,
    files: [
      { path: path.basename(jsonPath), sha256: sha256(jsonBytes), byte_count: jsonBytes.length },
      { path: path.basename(markdownPath), sha256: sha256(markdownBytes), byte_count: markdownBytes.length },
      { path: path.basename(preclosureLedgerPath), sha256: sha256(preclosureLedgerBytes), byte_count: preclosureLedgerBytes.length },
      { path: path.basename(preclosureQueuePath), sha256: sha256(preclosureQueueBytes), byte_count: preclosureQueueBytes.length },
    ],
    protected_holdout: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  const outputs = [
    [jsonPath, jsonBytes],
    [markdownPath, markdownBytes],
    [preclosureLedgerPath, preclosureLedgerBytes],
    [preclosureQueuePath, preclosureQueueBytes],
    [hashPath, manifestBytes],
  ];

  const prepared = outputs.map(([target, bytes], index) => {
    const temporaryPath = `${target}.tmp-${process.pid}-${index}`;
    safeResolvedPath(root, temporaryPath, {
      label: `temporary closure output ${index + 1}`,
      mustExist: false,
    });
    return [target, bytes, temporaryPath];
  });
  fs.mkdirSync(resolvedOutput.absolutePath, { recursive: true });
  const temporary = prepared.map(([target, bytes, temporaryPath]) => {
    fs.writeFileSync(temporaryPath, bytes, { flag: 'wx' });
    return [temporaryPath, target];
  });
  try {
    for (const [temporaryPath, target] of temporary) {
      try {
        fs.renameSync(temporaryPath, target);
      } catch (error) {
        if (!['EEXIST', 'EPERM'].includes(error.code)) throw error;
        fs.copyFileSync(temporaryPath, target);
        fs.unlinkSync(temporaryPath);
      }
    }
  } finally {
    for (const [temporaryPath] of temporary) {
      if (fs.existsSync(temporaryPath)) fs.unlinkSync(temporaryPath);
    }
  }
  return {
    jsonPath,
    markdownPath,
    preclosureLedgerPath,
    preclosureQueuePath,
    hashPath,
    manifest,
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const root = path.resolve(options.root);
  const queuePath = safeResolvedPath(root, options.queue, { label: 'research queue', mustExist: true });
  const ledgerPath = safeResolvedPath(root, options.ledger, { label: 'decision ledger', mustExist: true });
  const outputPath = safeResolvedPath(root, options.outputDirectory, {
    label: 'closure output directory',
    mustExist: false,
  });
  const preclosureLedgerPath = path.join(outputPath.absolutePath, 'preclosure_decision_ledger_16_16.json');
  const preclosureQueuePath = path.join(outputPath.absolutePath, 'preclosure_semantic_research_queue_16_16.json');
  const preclosureRelative = path.relative(root, preclosureLedgerPath).replaceAll('\\', '/');
  const preclosureQueueRelative = path.relative(root, preclosureQueuePath).replaceAll('\\', '/');
  safeResolvedPath(root, preclosureLedgerPath, { label: 'preclosure ledger snapshot', mustExist: false });
  safeResolvedPath(root, preclosureQueuePath, { label: 'preclosure queue snapshot', mustExist: false });

  // Each critical input is read exactly once. Validation and closure construction finish
  // before the first mkdir/copy/write, so a failed gate leaves no partial output.
  const queueLoaded = readSafeJsonBytes(root, queuePath.relativePath, 'research queue');
  let ledgerLoaded;
  if (options.rebuildPreclosureLedger) {
    const baseSpecs = DECISION_SOURCE_SPECS.filter((spec) =>
      spec.extractor !== SATURATION_CLOSURE_EXTRACTOR);
    const document = buildDecisionLedger({ sources: loadSafeSources(root, baseSpecs) });
    const bytes = jsonBytes(document);
    ledgerLoaded = {
      bytes,
      document,
      path: ledgerPath.relativePath,
      sha256: sha256(bytes),
      byte_count: bytes.length,
    };
  } else {
    ledgerLoaded = readSafeJsonBytes(root, ledgerPath.relativePath, 'decision ledger');
  }
  const sourceSpecs = DEFAULT_SOURCE_SPECS.map(([id, sourcePath]) =>
    id === 'decision_ledger' ? [id, preclosureRelative] : [id, sourcePath]);
  const sources = loadSources(root, sourceSpecs, {
    preloaded: {
      decision_ledger: { ...ledgerLoaded, path: preclosureRelative },
    },
  });
  const queueInput = {
    path: preclosureQueueRelative,
    sha256: queueLoaded.sha256,
    byte_count: queueLoaded.byte_count,
    schema: queueLoaded.document.schema,
    schema_version: queueLoaded.document.schema_version,
    bytes: queueLoaded.bytes,
    document: queueLoaded.document,
  };
  const ledgerInput = {
    path: preclosureRelative,
    sha256: ledgerLoaded.sha256,
    byte_count: ledgerLoaded.byte_count,
    schema: ledgerLoaded.document.schema,
    schema_version: ledgerLoaded.document.schema_version,
    bytes: ledgerLoaded.bytes,
    document: sources.decision_ledger.document,
  };
  const document = buildCapabilityDomainClosure({
    queue: queueLoaded.document,
    ledger: sources.decision_ledger.document,
    sources,
    queueInput,
    ledgerInput,
  });
  const written = writeOutputs({
    root,
    outputDirectory: outputPath.relativePath,
    document,
    preclosureLedgerBytes: ledgerLoaded.bytes,
    preclosureQueueBytes: queueLoaded.bytes,
  });
  const summary = {
    status: 'PASS',
    exact_build: document.exact_build,
    actionable_route_count_before_closure: document.preconditions.actionable_route_count,
    capability_decision_count: document.capability_decisions.length,
    domain_decision_count: document.domain_decisions.length,
    closure_sha256: written.manifest.files[0].sha256,
    output: written.jsonPath,
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, markdown, parseArgs, safeJson, writeOutputs };
