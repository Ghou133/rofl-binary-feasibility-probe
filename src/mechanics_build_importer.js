'use strict';

// This module deliberately accepts only caller-supplied source descriptors.  It
// does not discover game installations, enumerate directories, or fetch data.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const COMPONENTS = Object.freeze(['champion', 'item', 'rune', 'buff', 'formula']);
const ACCEPTED_IDENTITY = new Set(['VERIFIED_EXACT_BUILD_IDENTITY', 'VERIFIED_DIRECT']);
const ACCEPTED_EQUIVALENCE = new Set(['VERIFIED_CONTENT_EQUIVALENCE', 'VERIFIED_EQUIVALENT']);
const COMPONENT_SEMANTIC_CONTRACTS = Object.freeze({
  champion: Object.freeze({
    scope: 'CHAMPION_BASE_AND_GROWTH',
    required_fields: Object.freeze(['id', 'base_stats', 'growth_stats']),
  }),
  item: Object.freeze({
    scope: 'ITEM_STAT_CONTRIBUTIONS',
    required_fields: Object.freeze(['id', 'always_active_stats', 'conditional_effects']),
  }),
  rune: Object.freeze({
    scope: 'RUNE_STAT_CONTRIBUTIONS',
    required_fields: Object.freeze(['id', 'persistent_effects', 'conditional_effects']),
  }),
  buff: Object.freeze({
    scope: 'BUFF_STAT_MODIFIERS',
    required_fields: Object.freeze(['id', 'stat_modifiers']),
  }),
  formula: Object.freeze({
    scope: 'FORMULA_DEFINITIONS_AND_INPUTS',
    required_fields: Object.freeze(['id', 'expression', 'inputs']),
  }),
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertNoHoldoutPath(candidate, label) {
  const segments = path.resolve(String(candidate)).split(/[\\/]+/u);
  invariant(!segments.some((segment) => /holdout/iu.test(segment)),
    `${label} resolves through a restricted Holdout path`);
}

function canonicalizeExistingSafePath(candidate, label = 'input') {
  const absolute = path.resolve(String(candidate));
  assertNoHoldoutPath(absolute, label);
  const canonical = fs.realpathSync.native(absolute);
  assertNoHoldoutPath(canonical, label);
  return canonical;
}

function canonicalizeProspectiveSafePath(candidate, label = 'output') {
  const absolute = path.resolve(String(candidate));
  assertNoHoldoutPath(absolute, label);
  let ancestor = absolute;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    invariant(parent !== ancestor, `${label} has no existing ancestor`);
    ancestor = parent;
  }
  const canonicalAncestor = fs.realpathSync.native(ancestor);
  assertNoHoldoutPath(canonicalAncestor, label);
  const projected = path.resolve(canonicalAncestor, path.relative(ancestor, absolute));
  assertNoHoldoutPath(projected, label);
  return projected;
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  const canonical = canonicalizeExistingSafePath(filePath, 'hash input');
  return sha256Buffer(fs.readFileSync(canonical));
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stableValue(value));
}

function recordId(row) {
  for (const field of ['id', 'key', 'name', 'identifier']) {
    if (row && Object.prototype.hasOwnProperty.call(row, field) && row[field] !== null) {
      return `${field}:${String(row[field])}`;
    }
  }
  return `content:${sha256Buffer(canonicalJson(row))}`;
}

function normalizedRows(component, document) {
  const plural = `${component}s`;
  const candidates = Array.isArray(document) ? document : [
    document?.[plural], document?.[component], document?.records, document?.entries,
  ];
  const rows = candidates.find(Array.isArray);
  invariant(Array.isArray(rows), `${component} source has no explicit record array`);
  return rows.map((row) => {
    invariant(row && typeof row === 'object' && !Array.isArray(row), `${component} record must be an object`);
    return stableValue(row);
  }).sort((left, right) => recordId(left).localeCompare(recordId(right))
    || canonicalJson(left).localeCompare(canonicalJson(right)));
}

function valueAtPath(value, dottedPath) {
  return dottedPath.split('.').reduce((current, key) => current?.[key], value);
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isIdentifier(value) {
  return (typeof value === 'string' && value.length > 0) || Number.isSafeInteger(value);
}

const COMPONENT_FIELD_VALIDATORS = Object.freeze({
  champion: Object.freeze({ id: isIdentifier, base_stats: isRecord, growth_stats: isRecord }),
  item: Object.freeze({ id: isIdentifier, always_active_stats: isRecord, conditional_effects: Array.isArray }),
  rune: Object.freeze({ id: isIdentifier, persistent_effects: Array.isArray, conditional_effects: Array.isArray }),
  buff: Object.freeze({ id: isIdentifier, stat_modifiers: Array.isArray }),
  formula: Object.freeze({ id: isIdentifier, expression: (value) => typeof value === 'string' && value.length > 0, inputs: Array.isArray }),
});

function semanticScopeGate(descriptor, component) {
  const contract = COMPONENT_SEMANTIC_CONTRACTS[component];
  const scope = descriptor.semantic_scope;
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) return false;
  if (scope.schema !== 'ROFL_COMPONENT_SEMANTIC_SCOPE_V1'
    || scope.component !== component
    || scope.scope !== contract.scope
    || scope.coverage_status !== 'COMPLETE_EXACT_BUILD_COMPONENT_COVERAGE'
    || scope.validation_status !== 'VERIFIED_COMPONENT_SEMANTICS'
    || scope.evidence_grade !== 'VERIFIED_DIRECT'
    || !/^[a-f0-9]{64}$/iu.test(scope.validation_evidence_sha256 || '')) return false;
  return Array.isArray(scope.validated_fields)
    && contract.required_fields.every((field) => scope.validated_fields.includes(field));
}

function componentFieldsGate(component, rows) {
  const contract = COMPONENT_SEMANTIC_CONTRACTS[component];
  const validators = COMPONENT_FIELD_VALIDATORS[component];
  return rows.length > 0 && rows.every((row) => contract.required_fields.every((field) => {
    const value = valueAtPath(row, field);
    return validators[field](value);
  }));
}

function hasExactBuildIdentity(descriptor, requestedBuild) {
  const identity = descriptor.exact_build_identity || {};
  return identity.build === requestedBuild && ACCEPTED_IDENTITY.has(identity.status);
}

function hasExactContentEquivalence(descriptor, requestedBuild) {
  const equivalence = descriptor.content_equivalence || {};
  return equivalence.target_build === requestedBuild && ACCEPTED_EQUIVALENCE.has(equivalence.status);
}

function descriptorSummary(descriptor, canonical, actualHash, requestedBuild) {
  const identityVerified = hasExactBuildIdentity(descriptor, requestedBuild);
  const equivalenceVerified = hasExactContentEquivalence(descriptor, requestedBuild);
  const patchFamily = descriptor.patch_family === true
    || /^PATCH_FAMILY_/u.test(descriptor.binding_status || '')
    || /^PATCH_FAMILY_/u.test(descriptor.content_equivalence?.status || '');
  const exactBuildAccepted = !patchFamily
    && descriptor.declared_build === requestedBuild
    && (identityVerified || equivalenceVerified);
  return stableValue({
    descriptor_id: descriptor.id,
    component: descriptor.component,
    source: descriptor.source,
    declared_version: descriptor.declared_version,
    declared_build: descriptor.declared_build,
    bytes: fs.statSync(canonical).size,
    sha256: actualHash,
    expected_sha256: descriptor.expected_sha256,
    exact_build_identity: descriptor.exact_build_identity || null,
    content_equivalence: descriptor.content_equivalence || null,
    evidence_grade: descriptor.evidence_grade,
    semantic_scope: descriptor.semantic_scope || null,
    patch_family_negative_control: patchFamily,
    identity_or_equivalence_gate: exactBuildAccepted ? 'PASS' : 'FAIL',
    semantic_scope_gate: semanticScopeGate(descriptor, descriptor.component) ? 'PASS' : 'FAIL',
    component_field_gate: 'NOT_EVALUATED',
    status: exactBuildAccepted ? 'EXACT_BUILD_ACCEPTED_PENDING_SEMANTIC_SCOPE'
      : patchFamily ? 'PATCH_FAMILY_REFERENCE_REJECTED'
        : 'EXACT_BUILD_IDENTITY_OR_EQUIVALENCE_REJECTED',
  });
}

function validateDescriptor(descriptor, index, requestedBuild) {
  invariant(descriptor && typeof descriptor === 'object' && !Array.isArray(descriptor),
    `source descriptor ${index} must be an object`);
  for (const field of ['id', 'component', 'path', 'expected_sha256', 'source', 'declared_version',
    'declared_build', 'evidence_grade']) {
    invariant(typeof descriptor[field] === 'string' && descriptor[field].length > 0,
      `source descriptor ${index} missing ${field}`);
  }
  invariant(COMPONENTS.includes(descriptor.component), `source descriptor ${index} has unsupported component`);
  invariant(/^[a-f0-9]{64}$/iu.test(descriptor.expected_sha256),
    `source descriptor ${index} expected_sha256 must be SHA-256`);
  invariant(descriptor.declared_build === requestedBuild || descriptor.patch_family === true
    || /^PATCH_FAMILY_/u.test(descriptor.binding_status || ''),
  `source descriptor ${index} build must be exact or explicitly patch-family reference`);
}

function importMechanicsBuild({ requestedBuild = EXACT_BUILD, sources = [] } = {}) {
  invariant(requestedBuild === EXACT_BUILD, 'exact-build request mismatch');
  invariant(Array.isArray(sources), 'sources must be an explicit descriptor array');
  const seen = new Set();
  const inventory = [];
  const accepted = new Map();
  for (const [index, descriptor] of sources.entries()) {
    validateDescriptor(descriptor, index, requestedBuild);
    invariant(!seen.has(descriptor.id), `duplicate source descriptor id ${descriptor.id}`);
    seen.add(descriptor.id);
    const canonical = canonicalizeExistingSafePath(descriptor.path, `source descriptor ${descriptor.id}`);
    invariant(fs.statSync(canonical).isFile(), `source descriptor ${descriptor.id} is not a file`);
    const actualHash = sha256File(canonical);
    invariant(actualHash === descriptor.expected_sha256.toLowerCase(),
      `source descriptor ${descriptor.id} hash mismatch`);
    const summary = descriptorSummary(descriptor, canonical, actualHash, requestedBuild);
    inventory.push(summary);
    if (summary.identity_or_equivalence_gate === 'PASS'
      && summary.semantic_scope_gate === 'PASS') {
      let rows;
      try {
        rows = normalizedRows(descriptor.component, JSON.parse(fs.readFileSync(canonical, 'utf8')));
      } catch (error) {
        summary.status = 'EXACT_BUILD_SEMANTIC_SOURCE_UNREADABLE';
        summary.component_field_gate = 'FAIL';
        continue;
      }
      if (!componentFieldsGate(descriptor.component, rows)) {
        summary.status = 'EXACT_BUILD_COMPONENT_FIELDS_REJECTED';
        summary.component_field_gate = 'FAIL';
        continue;
      }
      invariant(!accepted.has(descriptor.component),
        `multiple exact-build sources for component ${descriptor.component}`);
      summary.component_field_gate = 'PASS';
      summary.status = 'ACCEPTED_FOR_EXACT_BUILD_NORMALIZATION';
      accepted.set(descriptor.component, { descriptor, rows, summary });
    } else if (summary.identity_or_equivalence_gate === 'PASS') {
      summary.status = 'EXACT_BUILD_SEMANTIC_SCOPE_REJECTED';
    }
  }
  inventory.sort((left, right) => left.descriptor_id.localeCompare(right.descriptor_id));
  const components = {};
  const missingInputs = [];
  for (const component of COMPONENTS) {
    const entry = accepted.get(component);
    if (!entry) {
      const rejected = inventory.filter((row) => row.component === component).map((row) => row.descriptor_id);
      components[component] = {
        status: rejected.length ? 'UNAVAILABLE_EXACT_BUILD_GATE_FAILED' : 'MISSING_REQUIRED_INPUT',
        source_descriptor_ids: rejected,
        rows: [],
      };
      missingInputs.push(component);
      continue;
    }
    components[component] = {
      status: 'VERIFIED_EXACT_BUILD_NORMALIZED',
      source_descriptor_ids: [entry.descriptor.id],
      semantic_scope: entry.summary.semantic_scope,
      rows: entry.rows,
    };
  }
  const result = stableValue({
    schema: 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1',
    exact_build: requestedBuild,
    status: missingInputs.length === 0 ? 'READY' : 'FAIL_CLOSED_MISSING_OR_REJECTED_INPUTS',
    consumer_permission: missingInputs.length === 0,
    missing_inputs: missingInputs,
    source_inventory: inventory,
    components,
  });
  return result;
}

function componentRows(document, component) {
  invariant(document && document.schema === 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1',
    'mechanics manifest schema mismatch');
  const value = document.components?.[component]?.rows;
  return Array.isArray(value) ? value : [];
}

function diffMechanicsBuilds(previous, current) {
  invariant(previous && current, 'previous and current mechanics manifests are required');
  const components = {};
  for (const component of COMPONENTS) {
    const toMap = (rows) => new Map(rows.map((row) => [recordId(row), row]));
    const before = toMap(componentRows(previous, component));
    const after = toMap(componentRows(current, component));
    const ids = [...new Set([...before.keys(), ...after.keys()])].sort();
    const added = [];
    const removed = [];
    const changed = [];
    for (const id of ids) {
      if (!before.has(id)) added.push({ id, after_sha256: sha256Buffer(canonicalJson(after.get(id))) });
      else if (!after.has(id)) removed.push({ id, before_sha256: sha256Buffer(canonicalJson(before.get(id))) });
      else if (canonicalJson(before.get(id)) !== canonicalJson(after.get(id))) {
        changed.push({ id, before_sha256: sha256Buffer(canonicalJson(before.get(id))),
          after_sha256: sha256Buffer(canonicalJson(after.get(id))) });
      }
    }
    components[component] = { added, removed, changed };
  }
  return stableValue({
    schema: 'ROFL_EXACT_BUILD_MECHANICS_BUILD_DIFF_V1',
    previous_build: previous.exact_build,
    current_build: current.exact_build,
    components,
  });
}

function writeJsonSafe(filePath, value, label) {
  const canonical = canonicalizeProspectiveSafePath(filePath, label);
  fs.writeFileSync(canonical, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return canonicalizeExistingSafePath(canonical, label);
}

function writeMechanicsBuildArtifacts({ outputDir, previousManifest = null, ...options } = {}) {
  invariant(outputDir, 'outputDir is required');
  const target = canonicalizeProspectiveSafePath(outputDir, 'output directory');
  fs.mkdirSync(target, { recursive: true });
  const output = canonicalizeExistingSafePath(target, 'output directory');
  const mechanics = importMechanicsBuild(options);
  const files = {
    mechanics: writeJsonSafe(path.join(output, 'exact_build_mechanics_manifest.json'), mechanics,
      'mechanics manifest output'),
  };
  const artifacts = [{
    name: 'exact_build_mechanics_manifest', path: path.basename(files.mechanics),
    bytes: fs.statSync(files.mechanics).size, sha256: sha256File(files.mechanics),
  }];
  let diff = null;
  if (previousManifest) {
    diff = diffMechanicsBuilds(previousManifest, mechanics);
    files.diff = writeJsonSafe(path.join(output, 'mechanics_build_diff.json'), diff, 'build diff output');
    artifacts.push({ name: 'mechanics_build_diff', path: path.basename(files.diff),
      bytes: fs.statSync(files.diff).size, sha256: sha256File(files.diff) });
  }
  artifacts.sort((left, right) => left.name.localeCompare(right.name));
  const closure = stableValue({
    schema: 'ROFL_EXACT_BUILD_MECHANICS_ARTIFACT_CLOSURE_V1',
    exact_build: mechanics.exact_build,
    source_hashes: mechanics.source_inventory.map((row) => ({ descriptor_id: row.descriptor_id, sha256: row.sha256 })),
    artifact_hashes: artifacts,
  });
  files.closure = writeJsonSafe(path.join(output, 'artifact_closure.json'), closure, 'artifact closure output');
  const closureArtifact = { name: 'artifact_closure', path: path.basename(files.closure),
    bytes: fs.statSync(files.closure).size, sha256: sha256File(files.closure) };
  return { mechanics, diff, closure, artifacts: [...artifacts, closureArtifact], paths: files };
}

module.exports = {
  COMPONENTS,
  COMPONENT_SEMANTIC_CONTRACTS,
  EXACT_BUILD,
  assertNoHoldoutPath,
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  diffMechanicsBuilds,
  importMechanicsBuild,
  sha256File,
  writeMechanicsBuildArtifacts,
};
