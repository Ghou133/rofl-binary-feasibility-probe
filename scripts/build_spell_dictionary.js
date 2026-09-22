#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_VERSION = '16.15';
const DEFAULT_EVENTS = path.join('artifacts', 'runtime_probe', 'packet_1113_decoded_all.jsonl');
const DEFAULT_INVENTORY_ROOT = path.join('artifacts', 'replays');
const DEFAULT_OUTPUT = path.join('artifacts', 'runtime_probe', 'spell_dictionary_16.15.json');

const GENERIC_SCRIPTS = [
  ['Recall', 'RECALL'],
  ['TrinketTotemLvl1', 'ITEM'],
  ['TrinketTotemLvl2', 'ITEM'],
  ['TrinketSweeperLvl3', 'ITEM'],
  ['SummonerBarrier', null],
  ['SummonerBoost', null],
  ['SummonerDot', null],
  ['SummonerExhaust', null],
  ['SummonerFlash', null],
  ['SummonerHaste', null],
  ['SummonerHeal', null],
  ['SummonerSmite', null],
  ['SummonerTeleport', null],
];

function parseArgs(argv) {
  const options = {
    version: DEFAULT_VERSION,
    events: DEFAULT_EVENTS,
    inventoryRoot: DEFAULT_INVENTORY_ROOT,
    output: DEFAULT_OUTPUT,
    allChampions: false,
  };
  const args = [...argv];
  while (args.length > 0) {
    const token = args.shift();
    if (token === '--all-champions') {
      options.allChampions = true;
      continue;
    }
    const value = args.shift();
    if (!value) throw new Error(`missing value for ${token}`);
    if (token === '--version') options.version = value;
    else if (token === '--events') options.events = value;
    else if (token === '--inventory-root') options.inventoryRoot = value;
    else if (token === '--output') options.output = value;
    else throw new Error(`unknown option: ${token}`);
  }
  return options;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function elfHashLower(value) {
  let hash = 0;
  for (const byte of Buffer.from(value.toLowerCase(), 'utf8')) {
    hash = ((hash << 4) + byte) >>> 0;
    const high = hash & 0xf0000000;
    if (high !== 0) {
      hash ^= high >>> 24;
      hash &= ~high;
    }
  }
  return hash >>> 0;
}

function hex32(value) {
  return `0x${(value >>> 0).toString(16).padStart(8, '0')}`;
}

function normalizedIconName(iconPath) {
  if (typeof iconPath !== 'string') return null;
  return path.posix.basename(iconPath).replace(/\.[^.]+$/, '').toLowerCase();
}

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': 'rofl-binary-feasibility-probe' },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${url}`);
  const raw = await response.text();
  return { data: JSON.parse(raw), raw, sha256: sha256(raw) };
}

function replayLabels(eventsPath) {
  const labels = new Set();
  for (const line of fs.readFileSync(eventsPath, 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    labels.add(JSON.parse(line).replay_label);
  }
  return [...labels].sort();
}

function rosterNames(labels, inventoryRoot) {
  const names = new Set();
  const inventories = [];
  for (const label of labels) {
    const inventoryPath = path.join(inventoryRoot, label, 'rofl_inventory.json');
    const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));
    const champions = inventory.metadata.players.map((player) => player.champion);
    champions.forEach((champion) => names.add(champion));
    inventories.push({
      replay_label: label,
      replay_sha256: inventory.sha256,
      champions,
    });
  }
  return { names, inventories };
}

function slotByRootIcon(gameData) {
  const result = new Map();
  for (const spell of gameData.spells || []) {
    const icon = normalizedIconName(spell.abilityIconPath);
    if (!icon) continue;
    result.set(icon, {
      slot: String(spell.spellKey).toUpperCase(),
      display_name: spell.name,
    });
  }
  return result;
}

function inferAbilitySlot(abilityPath, ability, binData, icons) {
  const label = `${ability.mName || ''} ${abilityPath}`;
  if (/passive|tailwindself|pability/i.test(label)) {
    return { slot: 'P', display_name: null };
  }
  const root = binData[ability.mRootSpell];
  const rootIcons = root?.mSpell?.mImgIconName || [];
  for (const iconPath of rootIcons) {
    const match = icons.get(normalizedIconName(iconPath));
    if (match) return match;
  }
  const explicit = /([qwer])ability(?:\b|\/|$)/i.exec(label);
  if (explicit) return { slot: explicit[1].toUpperCase(), display_name: null };
  return { slot: null, display_name: null };
}

function scriptsForChampion(champion, binData, gameData) {
  const icons = slotByRootIcon(gameData);
  const childMetadata = new Map();
  const abilities = [];
  for (const [abilityPath, ability] of Object.entries(binData)) {
    if (ability?.__type !== 'AbilityObject') continue;
    const inferred = inferAbilitySlot(abilityPath, ability, binData, icons);
    const children = new Set([ability.mRootSpell, ...(ability.mChildSpells || [])]);
    for (const childPath of children) {
      if (!childPath) continue;
      childMetadata.set(childPath, {
        ability_path: abilityPath,
        ability_name: ability.mName || null,
        root_path: ability.mRootSpell || null,
        phase: childPath === ability.mRootSpell ? 'PRIMARY' : 'INTERNAL_CHILD',
        ...inferred,
      });
    }
    abilities.push({
      ability_path: abilityPath,
      ability_name: ability.mName || null,
      root_path: ability.mRootSpell || null,
      child_paths: [...children].filter(Boolean),
      ...inferred,
    });
  }

  const scripts = [];
  for (const [objectPath, object] of Object.entries(binData)) {
    if (object?.__type !== 'SpellObject' || typeof object.mScriptName !== 'string') continue;
    const association = childMetadata.get(objectPath) || {};
    scripts.push({
      spell_key: elfHashLower(object.mScriptName),
      spell_key_hex: hex32(elfHashLower(object.mScriptName)),
      script_name: object.mScriptName,
      object_path: objectPath,
      champion_id: champion.id,
      champion_name: champion.name,
      champion_alias: champion.alias,
      spell_slot: association.slot ?? null,
      display_name: association.display_name ?? null,
      phase: association.phase ?? 'ENGINE_CAST',
      ability_name: association.ability_name ?? null,
      ability_path: association.ability_path ?? null,
      root_path: association.root_path ?? null,
      source: 'COMMUNITYDRAGON_16_15_BIN',
    });
  }
  scripts.sort((left, right) => left.spell_key - right.spell_key
    || left.script_name.localeCompare(right.script_name));
  abilities.sort((left, right) => (left.slot || '').localeCompare(right.slot || '')
    || left.ability_path.localeCompare(right.ability_path));
  return { scripts, abilities };
}

function addByHash(index, script) {
  const key = script.spell_key_hex;
  if (!index[key]) index[key] = [];
  index[key].push(script);
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const labels = replayLabels(options.events);
  const roster = rosterNames(labels, options.inventoryRoot);
  const root = `https://raw.communitydragon.org/${options.version}`;
  const championListUrl = `${root}/plugins/rcp-be-lol-game-data/global/default/v1/champion-summary.json`;
  const championList = await fetchJson(championListUrl);
  const champions = championList.data.filter((champion) => champion.id > 0 && (
    options.allChampions
    || roster.names.has(champion.name)
    || roster.names.has(champion.alias)
  ));
  const unresolved = [...roster.names].filter((name) => !champions.some(
    (champion) => champion.name === name || champion.alias === name,
  ));
  if (unresolved.length > 0) throw new Error(`unresolved champion names: ${unresolved.join(', ')}`);

  const outputChampions = [];
  const scripts = [];
  const upstream = [{ url: championListUrl, sha256: championList.sha256 }];
  for (const champion of champions.sort((left, right) => left.id - right.id)) {
    const alias = champion.alias.toLowerCase();
    const binUrl = `${root}/game/data/characters/${alias}/${alias}.bin.json`;
    const gameDataUrl = `${root}/plugins/rcp-be-lol-game-data/global/default/v1/champions/${champion.id}.json`;
    const [bin, gameData] = await Promise.all([fetchJson(binUrl), fetchJson(gameDataUrl)]);
    const recovered = scriptsForChampion(champion, bin.data, gameData.data);
    scripts.push(...recovered.scripts);
    outputChampions.push({
      id: champion.id,
      name: champion.name,
      alias: champion.alias,
      bin_url: binUrl,
      bin_sha256: bin.sha256,
      game_data_url: gameDataUrl,
      game_data_sha256: gameData.sha256,
      abilities: recovered.abilities,
      script_count: recovered.scripts.length,
    });
    upstream.push(
      { url: binUrl, sha256: bin.sha256 },
      { url: gameDataUrl, sha256: gameData.sha256 },
    );
  }

  for (const [scriptName, slot] of GENERIC_SCRIPTS) {
    scripts.push({
      spell_key: elfHashLower(scriptName),
      spell_key_hex: hex32(elfHashLower(scriptName)),
      script_name: scriptName,
      object_path: null,
      champion_id: null,
      champion_name: null,
      champion_alias: null,
      spell_slot: slot,
      display_name: null,
      phase: 'PRIMARY',
      ability_name: null,
      ability_path: null,
      root_path: null,
      source: 'PUBLIC_SCRIPT_NAME_ELF_HASH',
    });
  }

  const byHash = {};
  scripts.forEach((script) => addByHash(byHash, script));
  for (const entries of Object.values(byHash)) {
    entries.sort((left, right) => (left.champion_id ?? -1) - (right.champion_id ?? -1)
      || left.script_name.localeCompare(right.script_name));
  }
  const output = {
    schema_version: 1,
    patch: options.version,
    method: 'ELFHash(lowercase(mScriptName)) over pinned CommunityDragon BIN data',
    details_or_oracle_input: false,
    events_path: path.normalize(options.events),
    replay_inventories: roster.inventories,
    upstream,
    champion_count: outputChampions.length,
    script_count: scripts.length,
    unique_spell_key_count: Object.keys(byHash).length,
    champions: outputChampions,
    by_hash: byHash,
  };
  const outputPath = path.resolve(options.output);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`);
  console.log(JSON.stringify({
    output: outputPath,
    champion_count: output.champion_count,
    script_count: output.script_count,
    unique_spell_key_count: output.unique_spell_key_count,
  }, null, 2));
}

main().catch((error) => {
  console.error(`${error.name}: ${error.message}`);
  process.exitCode = 1;
});

module.exports = { elfHashLower, scriptsForChampion };
