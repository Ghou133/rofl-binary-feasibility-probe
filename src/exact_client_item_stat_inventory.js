'use strict';

// Exact-client item descriptions are a presentation surface.  This module
// inventories only the literal <stats> block and deliberately never turns it
// into mechanics inputs.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const PRESENTATION_STATUS = 'PRESENTATION_ONLY';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertNoHoldoutPath(candidate, label = 'path') {
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

function normalizeText(value) {
  return String(value || '')
    .replace(/<[^>]*>/gu, ' ')
    .replace(/&nbsp;/giu, ' ')
    .replace(/&amp;/giu, '&')
    .replace(/\s+/gu, ' ')
    .trim();
}

function extractTagContents(text, tag) {
  const expression = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'giu');
  const contents = [];
  let match;
  while ((match = expression.exec(text)) !== null) contents.push(match[1]);
  return contents;
}

function parseDisplayedNumber(raw) {
  const normalized = normalizeText(raw).replace(/,/gu, '');
  const match = /^([+-]?\d+(?:\.\d+)?)(%)?$/u.exec(normalized);
  if (!match) return null;
  const value = Number(match[1]);
  if (!Number.isFinite(value)) return null;
  return { value, display_unit: match[2] ? 'percent' : 'flat', raw_value: normalizeText(raw) };
}

function recognizedField(label, displayUnit) {
  const normalized = normalizeText(label).toLocaleLowerCase('en-US');
  const flatOrPercent = (flat, percent) => (displayUnit === 'percent' ? percent : flat);
  switch (normalized) {
    case 'health': return displayUnit === 'flat' ? 'health' : null;
    case 'armor': return displayUnit === 'flat' ? 'armor' : null;
    case 'magic resist': return displayUnit === 'flat' ? 'magic_resist' : null;
    case 'attack damage': return displayUnit === 'flat' ? 'attack_damage' : null;
    case 'attack speed': return displayUnit === 'percent' ? 'attack_speed_percent' : null;
    case 'ability power': return displayUnit === 'flat' ? 'ability_power' : null;
    case 'armor penetration': return flatOrPercent('armor_penetration_flat', 'armor_penetration_percent');
    case 'magic penetration': return flatOrPercent('magic_penetration_flat', 'magic_penetration_percent');
    case 'base health regen': return displayUnit === 'percent' ? 'health_regen_percent' : null;
    default: return null;
  }
}

function parseStatsBlock(statsBlock) {
  const clauses = [];
  const expression = /<attention>([\s\S]*?)<\/attention>([\s\S]*?)(?=<attention>|$)/giu;
  let match;
  while ((match = expression.exec(statsBlock)) !== null) {
    const number = parseDisplayedNumber(match[1]);
    const label = normalizeText(match[2]);
    const raw = match[0];
    if (!number || !label) {
      clauses.push({ raw, parsed: null });
      continue;
    }
    const field = recognizedField(label, number.display_unit);
    clauses.push({
      raw,
      parsed: field ? { field, label, ...number } : null,
    });
  }
  const recognized_displayed_fields = clauses.filter((clause) => clause.parsed).map((clause) => clause.parsed);
  const unparsed_stats_text = clauses.filter((clause) => !clause.parsed).map((clause) => normalizeText(clause.raw))
    .filter(Boolean);
  if (clauses.length === 0 && normalizeText(statsBlock)) unparsed_stats_text.push(normalizeText(statsBlock));
  return { recognized_displayed_fields, unparsed_stats_text };
}

function presentationBody(description, statsBlocks) {
  let body = String(description || '');
  for (const block of statsBlocks) body = body.replace(`<stats>${block}</stats>`, '');
  return body;
}

function inventoryItem(item) {
  invariant(item && typeof item === 'object' && !Array.isArray(item), 'item row must be an object');
  invariant(Number.isSafeInteger(item.id) || (typeof item.id === 'string' && item.id.length > 0),
    'item row requires an id');
  const description = typeof item.description === 'string' ? item.description : '';
  const statsBlocks = extractTagContents(description, 'stats');
  const parsedBlocks = statsBlocks.map(parseStatsBlock);
  const recognized_displayed_fields = parsedBlocks.flatMap((block) => block.recognized_displayed_fields);
  const unparsed_stats_text = parsedBlocks.flatMap((block) => block.unparsed_stats_text);
  const body = presentationBody(description, statsBlocks);
  return stableValue({
    id: item.id,
    name: typeof item.name === 'string' ? item.name : '',
    presentation_status: PRESENTATION_STATUS,
    mechanics_consumer_eligible: false,
    stats_blocks_raw: statsBlocks,
    recognized_displayed_fields,
    unparsed_stats_text,
    passive_labels_raw: extractTagContents(body, 'passive'),
    conditional_or_passive_body_raw: body,
  });
}

function validateBinding(binding) {
  invariant(binding && typeof binding === 'object' && !Array.isArray(binding), 'exact build binding is required');
  invariant(binding.exact_build === EXACT_BUILD, 'exact build binding mismatch');
  invariant(binding.status === 'VERIFIED_EXACT_BUILD_IDENTITY',
    'exact build binding is not directly verified');
  return stableValue(binding);
}

function buildExactClientItemStatInventory({ itemsPath, expectedSha256, exactBuildBinding } = {}) {
  invariant(typeof itemsPath === 'string' && itemsPath.length > 0, 'itemsPath is required');
  invariant(typeof expectedSha256 === 'string' && /^[a-f0-9]{64}$/iu.test(expectedSha256),
    'expectedSha256 must be SHA-256');
  const binding = validateBinding(exactBuildBinding);
  const canonicalItems = canonicalizeExistingSafePath(itemsPath, 'items input');
  invariant(fs.statSync(canonicalItems).isFile(), 'items input is not a file');
  const actualSha256 = sha256File(canonicalItems);
  invariant(actualSha256 === expectedSha256.toLowerCase(), 'items input hash mismatch');
  const document = JSON.parse(fs.readFileSync(canonicalItems, 'utf8'));
  invariant(Array.isArray(document), 'items input must be an array');
  const items = document.map(inventoryItem).sort((left, right) => String(left.id).localeCompare(String(right.id))
    || left.name.localeCompare(right.name));
  const recognized_field_counts = {};
  let unparsedStatClauseCount = 0;
  for (const item of items) {
    for (const field of item.recognized_displayed_fields) {
      recognized_field_counts[field.field] = (recognized_field_counts[field.field] || 0) + 1;
    }
    unparsedStatClauseCount += item.unparsed_stats_text.length;
  }
  return stableValue({
    schema: 'ROFL_EXACT_CLIENT_ITEM_PRESENTATION_INVENTORY_V1',
    exact_build: EXACT_BUILD,
    exact_build_binding: binding,
    status: PRESENTATION_STATUS,
    mechanics_consumer_eligible: false,
    semantic_boundary: [
      'Literal client presentation text only.',
      'No conditional value, stacking, formula, ordering, or runtime semantic is inferred.',
      'This inventory cannot authorize mechanics consumers.',
    ],
    source: {
      path: canonicalItems,
      bytes: fs.statSync(canonicalItems).size,
      sha256: actualSha256,
      expected_sha256: expectedSha256.toLowerCase(),
    },
    summary: {
      item_count: items.length,
      recognized_displayed_field_count: Object.values(recognized_field_counts).reduce((total, count) => total + count, 0),
      recognized_field_counts,
      unparsed_stats_text_count: unparsedStatClauseCount,
    },
    items,
  });
}

function writeJsonSafe(filePath, value, label) {
  const canonical = canonicalizeProspectiveSafePath(filePath, label);
  fs.writeFileSync(canonical, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return canonicalizeExistingSafePath(canonical, label);
}

function writeExactClientItemStatInventoryArtifacts({ outputDir, ...options } = {}) {
  invariant(typeof outputDir === 'string' && outputDir.length > 0, 'outputDir is required');
  const target = canonicalizeProspectiveSafePath(outputDir, 'output directory');
  fs.mkdirSync(target, { recursive: true });
  const output = canonicalizeExistingSafePath(target, 'output directory');
  const inventory = buildExactClientItemStatInventory(options);
  const inventoryPath = writeJsonSafe(path.join(output, 'exact_client_item_stat_inventory.json'), inventory,
    'item presentation inventory output');
  const artifact = {
    name: 'exact_client_item_stat_inventory', path: path.basename(inventoryPath),
    bytes: fs.statSync(inventoryPath).size, sha256: sha256File(inventoryPath),
  };
  const closure = stableValue({
    schema: 'ROFL_EXACT_CLIENT_ITEM_PRESENTATION_ARTIFACT_CLOSURE_V1',
    exact_build: inventory.exact_build,
    status: PRESENTATION_STATUS,
    mechanics_consumer_eligible: false,
    source_sha256: inventory.source.sha256,
    artifacts: [artifact],
  });
  const closurePath = writeJsonSafe(path.join(output, 'artifact_closure.json'), closure,
    'item presentation inventory closure output');
  return { inventory, closure, paths: { inventory: inventoryPath, closure: closurePath }, artifacts: [artifact] };
}

module.exports = {
  EXACT_BUILD,
  PRESENTATION_STATUS,
  assertNoHoldoutPath,
  buildExactClientItemStatInventory,
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  inventoryItem,
  parseStatsBlock,
  sha256File,
  writeExactClientItemStatInventoryArtifacts,
};
