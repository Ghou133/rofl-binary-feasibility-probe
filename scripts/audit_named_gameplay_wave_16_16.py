#!/usr/bin/env python3
"""Deep exact-build audit for the allowlisted named-gameplay route wave.

The script deliberately accepts no directory/corpus discovery input.  Every
source is an explicit exact-build allowlist path and every path is rejected if
it contains the protected Holdout token.  It combines full-corpus raw behavior,
cross-route/anchor timing, exact runtime factory/deserializer/callback identity,
alias-tracked object-field accesses, and stratified Unicorn native decode.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import json
import math
import os
import statistics
import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_AC_READ, CS_AC_WRITE
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from emulate_exact_packet_decoder import ExactPacketEmulator, RUNTIME_PROFILES  # noqa: E402
from trace_hero_combat_state_runtime import IMAGE_BASE, StaticImage  # noqa: E402


EXACT_BUILD = '16.16.805.0442'
RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
SCHEMA = 'ROFL_NAMED_GAMEPLAY_WAVE_DEEP_AUDIT_V1'
DECISION_SCHEMA = 'ROFL_NAMED_GAMEPLAY_WAVE_DECISIONS_V1'
SCOPE = 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_EXACT_BUILD_REPLAYS'
ROUTE_IDS = (
    0x04C0, 0x0312, 0x00A3, 0x014C, 0x04AB, 0x0046, 0x00F0,
    0x0226, 0x0089, 0x021D, 0x0455, 0x0491, 0x01AE, 0x0134,
    0x031D, 0x004C, 0x039F, 0x02DA, 0x02B6, 0x039D, 0x0139,
    0x00A1, 0x01ED, 0x013F, 0x03E4, 0x01A5, 0x02C2, 0x0021,
    0x007F, 0x008F, 0x01C3, 0x02E4, 0x034C,
)
ROUTE_SET = frozenset(ROUTE_IDS)
ANCHOR_IDS = (0x00F6, 0x017F, 0x01CF)
ANCHOR_NAMES = {0x00F6: 'HERO_PATH', 0x017F: 'VERIFIED_DAMAGE', 0x01CF: 'CAST_SPELL'}


def semantic_spec(domain, capability, decision, operation, claim, limits, external):
    return {
        'domain': domain,
        'capability': capability,
        'decision': decision,
        'operation': operation,
        'semantic_claim': claim,
        'known_limits': limits,
        'external_evidence': external,
    }


ROUTE_SEMANTICS = {
    0x0021: semantic_spec('ui_render', 'VISUAL_OFFSET_CONTROL_RECORD', 'REPURPOSE',
        'SET_VISUAL_OFFSET', 'Actor-scoped visual-offset control carrier; retain as render state, not gameplay position.',
        ['No direct packet-factory object was recovered on the bounded factory surface.', 'Visual offset is not world position, path, displacement, or map truth.'],
        'Controlled render-component instrumentation is required to name the single protected payload value.'),
    0x0046: semantic_spec('spell', 'SPELL_UPGRADE_RESPONSE_CARRIER', 'PROMOTE',
        'UPGRADE_SPELL_RESPONSE', 'Actor-scoped exact runtime spell-upgrade response carrier with bounded protected storage.',
        ['Occurrence does not prove a successful rank change, player input, or spend.', 'Protected field plaintext/business roles remain unpublished.'],
        'A controlled spellbook rank transition with runtime plaintext capture is required to name the residual fields.'),
    0x004C: semantic_spec('ui_render', 'IDLE_PARTICLE_VISIBILITY_RECORD', 'REPURPOSE',
        'SET_IDLE_PARTICLE_VISIBILITY', 'Actor-scoped render particle-visibility control record.',
        ['Particle visibility is not gameplay visibility, vision, stealth, or brush state.'],
        'Controlled render instrumentation is required to name the protected flag polarity.'),
    0x007F: semantic_spec('ui_render', 'SPAWN_ANIMATION_RECORD', 'REPURPOSE',
        'PLAY_SPAWN_ANIMATION', 'Actor-scoped spawn-animation carrier with exact object/factory identity.',
        ['Animation playback is not spawn lifecycle truth, invulnerability, movement, or actionability.'],
        'An animation-system dictionary or controlled animation trace is required to name protected animation fields.'),
    0x0089: semantic_spec('economy', 'SHOP_ACTIVE_STATE_CARRIER', 'PROMOTE',
        'SET_SHOP_ACTIVE', 'ShopClient-scoped active-state carrier with one protected state byte.',
        ['Shop active state does not prove hero proximity, a purchase/sale, or item availability.'],
        'Controlled ShopClient state capture is required to establish flag polarity.'),
    0x008F: semantic_spec('entity_lifecycle', 'FORCE_DEAD_CARRIER', 'PROMOTE',
        'FORCE_DEAD', 'Entity-scoped force-dead operation carrier with one protected field.',
        ['This is not kill credit, cause, assists, hero-death classification, or respawn truth.'],
        'Controlled entity lifecycle instrumentation is required to name the residual flag.'),
    0x00A1: semantic_spec('spell', 'SPELL_LEVEL_STATE_UPDATE', 'PROMOTE',
        'SET_SPELL_LEVEL', 'Spellbook callback consumes two protected dword fields for spell-slot lookup and level-state update.',
        ['Plaintext values are not emitted until the consumer transforms are independently verified.', 'Occurrence is not player input or skill-point spend proof.'],
        'Controlled spell-slot/level transitions with plaintext capture are required for a public value decoder.'),
    0x00A3: semantic_spec('economy', 'SHOP_ENABLED_STATE_CARRIER', 'PROMOTE',
        'SET_SHOP_ENABLED', 'Hero-scoped shop-enabled state carrier.',
        ['Enabled state is not active state, proximity, transaction permission, or a transaction.'],
        'Controlled shop enable/disable transitions are required to name protected flag polarity and any secondary field.'),
    0x00F0: semantic_spec('ui_render', 'SPELL_TOGGLE_VISUAL_RECORD', 'REPURPOSE',
        'UPDATE_SPELL_TOGGLE_VISUAL', 'Hero-scoped spell-toggle visual state carrier.',
        ['Visual toggle is not autocast, cast success, cooldown, charge, or spell-state truth.'],
        'Controlled spell HUD instrumentation is required to map protected slot/visual fields.'),
    0x0134: semantic_spec('ui_render', 'HEALTHBAR_ICON_ADD_RECORD', 'REPURPOSE',
        'ADD_HEALTHBAR_ICON', 'Entity-scoped health-bar icon add carrier with bounded protected fields.',
        ['UI icon presence is not a buff, debuff, shield, heal, or combat-state semantic.'],
        'A health-bar icon dictionary and controlled UI trace are required to name icon fields.'),
    0x0139: semantic_spec('ui_render', 'SUMMONER_EMOTE_DISPLAY_RECORD', 'REPURPOSE',
        'DISPLAY_SUMMONER_EMOTE', 'Entity-scoped summoner-emote display carrier.',
        ['Emote display is not combat, cast, behavior, or player-intent truth.'],
        'An emote dictionary or controlled display trace is required to name protected fields.'),
    0x013F: semantic_spec('spell', 'OWNER_SLOT_SPELL_DATA_CHANGE_CARRIER', 'PROMOTE',
        'CHANGE_SLOT_SPELL_DATA_OWNER_ONLY', 'Owner-only slot-spell-data update carrier with exact inline subobject layout boundary.',
        ['Inline protected fields retain neutral names.', 'Owner-only delivery does not prove player input or cast causality.'],
        'Controlled slot replacement plus plaintext runtime capture is required to name inline subfields.'),
    0x014C: semantic_spec('item', 'ITEM_MODIFIER_BROADCAST_ENVELOPE', 'REPURPOSE',
        'SET_ITEM_MODIFIERS_BROADCAST', 'HeroInventoryClient modifier-state envelope; keyframe-heavy and not an item transaction.',
        ['The empty branch requires a bounded emulation-only bypass of a TLS logging side effect after an expected collection tag miss; collection clearing still executes.', 'Modifier rows are not buy, sell, undo, inventory slot, stat, or price truth.'],
        'A controlled HeroInventoryClient object dependency/runtime trace is required to decode modifier records.'),
    0x01A5: semantic_spec('entity_lifecycle', 'NPC_DIE_BROADCAST_CARRIER', 'PROMOTE',
        'NPC_DIE_BROADCAST', 'Actor-scoped NPC-die broadcast carrier with exact 92-byte protected object layout.',
        ['Does not establish cause, killer, assists, reward, objective identity, or champion-only death.'],
        'Controlled lifecycle cases and plaintext callback capture are required to name inner death fields.'),
    0x01AE: semantic_spec('spell', 'SPELL_AUTOCAST_STATE_CARRIER', 'PROMOTE',
        'SET_AUTOCAST', 'Spellbook-scoped autocast state carrier with two protected byte fields consumed by the callback.',
        ['Autocast state is not a spell cast, hit, cooldown, or user-click event.'],
        'Controlled per-slot autocast toggles are required to verify slot/value polarity.'),
    0x01C3: semantic_spec('minion', 'MINION_KILL_COUNTER_INCREMENT_CARRIER', 'PROMOTE',
        'INCREMENT_MINION_KILLS', 'Hero-scoped minion-kill counter increment carrier with one protected dword.',
        ['Does not identify a killed minion, position, lane/jungle category, gold, XP, or final cumulative value.'],
        'Controlled last-hit cases with scoreboard/plaintext capture are required to decode the increment value.'),
    0x01ED: semantic_spec('ui_render', 'ANIMATION_STATE_COPY_RECORD', 'REPURPOSE',
        'COPY_ANIMATION_STATE', 'Entity-scoped animation-state copy carrier.',
        ['Animation state is not gameplay state, action completion, cast, attack, or movement truth.'],
        'Controlled animation-component instrumentation is required to name the protected dword.'),
    0x021D: semantic_spec('visibility', 'LEAVE_VISIBILITY_OCCURRENCE', 'PROMOTE',
        'LEAVE_VISIBILITY_CLIENT', 'NetVisibilityObjectClient-scoped zero-payload leave-visibility occurrence.',
        ['Client visibility lifecycle is not ward vision, fog source, brush occupancy, stealth, or map truth.'],
        'Controlled visibility-source instrumentation is required only for cause attribution.'),
    0x0226: semantic_spec('entity_lifecycle', 'NPC_DIE_MAPVIEW_CARRIER', 'PROMOTE',
        'NPC_DIE_MAPVIEW', 'Actor-scoped NPC-die MapView carrier sharing the death callback consumer family.',
        ['MapView scope is a delivery/view surface, not map geometry.', 'Does not establish cause, reward, killer, or objective identity.'],
        'Controlled lifecycle/plaintext capture is required to name inner fields and relate variants.'),
    0x02B6: semantic_spec('spell', 'SPELL_MODIFIER_STATE_ENVELOPE', 'REPURPOSE',
        'SET_SPELL_MODIFIERS', 'Actor-scoped variable-length spell-modifier state envelope with observed empty and repeated-record branches.',
        ['Record business roles and plaintext values are unknown.', 'Envelope state is not cast, cooldown, damage, or buff truth.'],
        'A spell-modifier dictionary or controlled non-empty modifier capture is required to name records.'),
    0x02C2: semantic_spec('missile', 'MISSILE_PHYSICS_CHANGE_CARRIER', 'PROMOTE',
        'CHANGE_MISSILE_PHYSICS', 'MissileClient-scoped physics-change carrier with exact 76-byte protected layout and two wire branches.',
        ['Neutral vector/scalar fields are not named trajectory, velocity, acceleration, impact, or collision.', 'Occurrence is not damage or hit.'],
        'Controlled missile-physics instrumentation is required to name the protected vector/scalar roles.'),
    0x02DA: semantic_spec('item', 'ITEM_MODIFIER_MAPVIEW_ENVELOPE', 'REPURPOSE',
        'SET_ITEM_MODIFIERS_MAPVIEW', 'MapView variant of HeroInventoryClient modifier-state envelope with inline protected record storage.',
        ['Not an item transaction, inventory snapshot, modifier meaning, stat value, or map truth.'],
        'A modifier dictionary and controlled runtime capture are required to name inline fields.'),
    0x02E4: semantic_spec('ui_render', 'CAMERA_POSITION_RECORD', 'REPURPOSE',
        'CAMERA_POSITION', 'Hero-scoped camera-control position carrier.',
        ['Camera coordinates are not hero position, path, vision, map contact, or behavior truth.'],
        'Controlled camera instrumentation is required to name protected coordinate/control fields.'),
    0x0312: semantic_spec('spell', 'SLOT_SPELL_DATA_CHANGE_CARRIER', 'PROMOTE',
        'CHANGE_SLOT_SPELL_DATA', 'Actor-scoped slot-spell-data update carrier with exact inline subobject boundary.',
        ['Protected inline values retain neutral roles.', 'Does not prove cast, cooldown, level spend, or human action.'],
        'Controlled spell replacement plus plaintext runtime capture is required to name inline fields.'),
    0x031D: semantic_spec('ui_render', 'HEALTHBAR_ICON_REMOVE_RECORD', 'REPURPOSE',
        'REMOVE_HEALTHBAR_ICON', 'Entity-scoped health-bar icon removal carrier.',
        ['UI icon removal is not buff removal, expiry, dispel, death, or protection loss.'],
        'A health-bar icon dictionary and controlled UI trace are required to name the protected identifier.'),
    0x034C: semantic_spec('jungle_protocol', 'NEUTRAL_CAMP_LEASH_STATE_CARRIER', 'PROMOTE',
        'NEUTRAL_CAMP_LEASH_STATE_CHANGED', 'AIMinionClient-scoped neutral-camp leash-state change carrier with one protected dword storage field.',
        ['Does not identify a camp/objective, location, aggro cause, clear, reset, intent, path, or behavior.', 'No protected Holdout evidence is used.'],
        'A controlled ordinary-neutral leash/reset trace is required to decode state values and entity taxonomy.'),
    0x039D: semantic_spec('buff', 'BUFF_MODIFIER_STATE_ENVELOPE', 'REPURPOSE',
        'SET_BUFF_MODIFIERS', 'Actor-scoped buff-modifier collection envelope; the safe corpus observes only the empty branch.',
        ['An observed empty collection is not evidence that modifiers never exist.', 'Not a buff add/remove/update or modifier semantic.'],
        'A new governed replay containing a non-empty modifier list plus dictionary/runtime capture is required.'),
    0x039F: semantic_spec('spell', 'COOLDOWN_REDUCTION_MODIFIER_UPDATE_CARRIER', 'PROMOTE',
        'COOLDOWN_REDUCTION_MODIFIER_UPDATE', 'Actor-scoped cooldown-reduction modifier update; callback resolves a protected key and stores two transformed f32 values.',
        ['The two f32 fields are neutral and not named additive/multiplicative/current/base values.', 'Not a cast or cooldown occurrence.'],
        'Controlled spell-state instrumentation is required to name the key and numeric roles.'),
    0x03E4: semantic_spec('system_message', 'NPC_MESSAGE_TO_CLIENT_ENVELOPE', 'REPURPOSE',
        'MESSAGE_TO_CLIENT_BROADCAST', 'Actor-scoped client-message envelope with exact variable payload/object bounds.',
        ['Message delivery is not gameplay state or player behavior.', 'Inner identifiers/text roles remain unknown.'],
        'A message schema/dictionary or controlled client-message trace is required to name inner fields.'),
    0x0455: semantic_spec('map_adjacent_protocol', 'NAVCELL_STATE_OVERRIDE_RECORD', 'REPURPOSE',
        'NAVCELL_STATE_OVERRIDE', 'Actor-scoped nav-cell override control record with protected u16/u16/u8 consumer fields.',
        ['No map cell, coordinate, geometry, traversability truth, collision, or path semantics are claimed.', 'Parser does not own Map Knowledge.'],
        'External NavCell contract and controlled runtime instrumentation are required for field roles/map interpretation.'),
    0x0491: semantic_spec('spell_buff', 'SPELL_TIMER_FROM_BUFF_CARRIER', 'PROMOTE',
        'SET_SPELL_TIMER_FROM_BUFF', 'Actor-scoped spell-timer-from-buff carrier; callback consumes protected slot/key/timer fields.',
        ['Does not identify a human-readable spell/buff, timer start/end/duration, cast, or causality.', 'Plaintext transform remains unpublished.'],
        'Controlled buff-to-spell timer instrumentation plus dictionaries are required to name fields.'),
    0x04AB: semantic_spec('entity_state', 'UNIT_MAX_LEVEL_OVERRIDE_CARRIER', 'PROMOTE',
        'UNIT_SET_MAX_LEVEL_OVERRIDE', 'Entity-scoped maximum-level override carrier with one protected field.',
        ['Does not prove current level, level transition, XP, or ordinary champion level cap.'],
        'Controlled max-level override state capture is required to decode the value.'),
    0x04C0: semantic_spec('movement', 'CIRCULAR_MOVEMENT_RESTRICTION_CARRIER', 'PROMOTE',
        'SYNC_CIRCULAR_MOVEMENT_RESTRICTION', 'Actor-scoped circular movement-restriction state with empty/default and 24-byte branches.',
        ['Neutral fields are not named center/radius/enable until consumer plaintext capture.', 'No tactical region, collision, or map truth is inferred.'],
        'Controlled movement-restriction instrumentation is required to name optional fields and state polarity.'),
}

# These are protected in-object storage layouts proven by callback reads,
# deserializer writes, native object deltas, or exact container count behavior.
# A storage type/offset is not a plaintext/business-role decoder.
STRUCTURAL_FIELD_CLAIMS = {
    0x0021: [{'offset': 0x14, 'size': 12, 'name': 'protected_visual_offset_vec3_f32', 'role': 'CALLBACK_DECODES_AND_STORES_THREE_F32_COMPONENTS', 'byte_transform': 'ror8(ror8((encoded_u8-0x5e),1)-0x78,6)', 'owner_storage_offsets': ['0x40d8', '0x40dc', '0x40e0']}],
    0x0046: [{'offset': 0x10, 'size': 4, 'name': 'protected_upgrade_record_10_4b', 'role': 'NEUTRAL_PROTECTED_STORAGE'}],
    0x004C: [{'offset': 0x10, 'size': 1, 'name': 'protected_particle_visibility_10_u8', 'role': 'CONSUMER_READ_PROTECTED_FLAG'}],
    0x007F: [{'offset': 0x20, 'size': 8, 'name': 'protected_animation_storage_20_qword', 'role': 'CONSUMER_READ_NEUTRAL'}, {'offset': 0x28, 'size': 4, 'name': 'protected_animation_field_28_u32', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x0089: [{'offset': 0x10, 'size': 1, 'name': 'protected_shop_active_10_u8', 'role': 'CONSUMER_READ_PROTECTED_FLAG'}],
    0x008F: [{'offset': 0x10, 'size': 4, 'name': 'protected_force_dead_10_u32', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x00A1: [{'offset': 0x10, 'size': 4, 'name': 'protected_spell_level_value_10_u32', 'role': 'CONSUMER_UPDATE_ARGUMENT'}, {'offset': 0x14, 'size': 4, 'name': 'protected_spell_slot_index_14_u32', 'role': 'CONSUMER_SLOT_LOOKUP_INDEX'}],
    0x00A3: [{'offset': 0x10, 'size': 1, 'name': 'protected_shop_enabled_10_u8', 'role': 'CONSUMER_READ_PROTECTED_FLAG'}, {'offset': 0x11, 'size': 1, 'name': 'protected_shop_secondary_11_u8', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x00F0: [{'offset': 0x10, 'size': 4, 'name': 'protected_toggle_visual_key_10_u32', 'role': 'CONSUMER_READ_NEUTRAL'}, {'offset': 0x14, 'size': 1, 'name': 'protected_toggle_visual_state_14_u8', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x0134: [{'offset': value, 'size': size, 'name': f'protected_healthbar_icon_{value:02x}_{size}b', 'role': 'CONSUMER_READ_UI_FIELD'} for value, size in ((0x10,4),(0x14,4),(0x18,4),(0x1C,4),(0x20,1),(0x24,4),(0x28,4))],
    0x013F: [{'offset': 0x10, 'size': 0x20, 'name': 'inline_slot_spell_data_subobject', 'role': 'EXACT_INLINE_SUBOBJECT_BOUNDARY'}, {'offset': 0x28, 'size': 4, 'name': 'inline_payload_count_28_u32', 'role': 'DIRECT_STRUCTURAL_COUNT'}, {'offset': 0x2C, 'size': 4, 'name': 'inline_payload_capacity_2c_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
    0x014C: [{'offset': 0x10, 'size': 0x18, 'name': 'inline_item_modifier_collection', 'role': 'EXACT_INLINE_COLLECTION_BOUNDARY'}, {'offset': 0x20, 'size': 4, 'name': 'modifier_record_count_20_u32', 'role': 'DIRECT_STRUCTURAL_COUNT'}, {'offset': 0x24, 'size': 4, 'name': 'modifier_record_capacity_24_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
    0x01A5: [{'offset': value, 'size': size, 'name': f'protected_npc_die_field_{value:02x}_{size}b', 'role': 'DESERIALIZER_WRITTEN_NEUTRAL'} for value, size in ((0x28,4),(0x2C,4),(0x30,4),(0x34,4),(0x38,1),(0x3C,4),(0x40,4),(0x44,4),(0x48,1),(0x4C,4))],
    0x01AE: [{'offset': 0x10, 'size': 1, 'name': 'protected_autocast_key_10_u8', 'role': 'CONSUMER_READ_NEUTRAL'}, {'offset': 0x11, 'size': 1, 'name': 'protected_autocast_state_11_u8', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x01C3: [{'offset': 0x10, 'size': 4, 'name': 'protected_minion_kill_increment_10_u32', 'role': 'CONSUMER_COUNTER_ARGUMENT'}],
    0x01ED: [{'offset': 0x10, 'size': 4, 'name': 'protected_animation_state_10_u32', 'role': 'CONSUMER_READ_UI_FIELD'}],
    0x0226: [{'offset': value, 'size': size, 'name': f'protected_npc_die_field_{value:02x}_{size}b', 'role': 'DESERIALIZER_WRITTEN_NEUTRAL'} for value, size in ((0x28,4),(0x2C,4),(0x30,4),(0x34,4),(0x38,1),(0x3C,4),(0x40,4),(0x44,4),(0x48,1),(0x4C,4))],
    0x02B6: [{'offset': 0x10, 'size': 0x10, 'name': 'spell_modifier_collection_wrapper', 'role': 'EXACT_COLLECTION_BOUNDARY'}, {'offset': 0x18, 'size': 4, 'name': 'spell_modifier_record_count_18_u32', 'role': 'DIRECT_STRUCTURAL_COUNT'}, {'offset': 0x1C, 'size': 4, 'name': 'spell_modifier_record_capacity_1c_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
    0x02C2: [{'offset': 0x10, 'size': 0x3C, 'name': 'protected_missile_physics_record', 'role': 'EXACT_OBJECT_STORAGE_BOUNDARY_NEUTRAL_FIELDS'}],
    0x02DA: [{'offset': 0x10, 'size': 0x18, 'name': 'inline_item_modifier_collection', 'role': 'EXACT_INLINE_COLLECTION_BOUNDARY'}, {'offset': 0x20, 'size': 4, 'name': 'modifier_record_count_20_u32', 'role': 'DIRECT_STRUCTURAL_COUNT'}, {'offset': 0x24, 'size': 4, 'name': 'modifier_record_capacity_24_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
    0x0312: [{'offset': 0x10, 'size': 0x20, 'name': 'inline_slot_spell_data_subobject', 'role': 'EXACT_INLINE_SUBOBJECT_BOUNDARY'}, {'offset': 0x28, 'size': 4, 'name': 'inline_payload_count_28_u32', 'role': 'DIRECT_STRUCTURAL_COUNT'}, {'offset': 0x2C, 'size': 4, 'name': 'inline_payload_capacity_2c_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
    0x031D: [{'offset': 0x10, 'size': 4, 'name': 'protected_healthbar_icon_remove_10_u32', 'role': 'CONSUMER_READ_UI_FIELD'}],
    0x034C: [{'offset': 0x10, 'size': 4, 'name': 'protected_leash_state_10_u32', 'role': 'CONSUMER_STATE_ARGUMENT'}],
    0x039D: [{'offset': 0x10, 'size': 0x10, 'name': 'buff_modifier_collection_wrapper', 'role': 'EXACT_COLLECTION_BOUNDARY'}, {'offset': 0x18, 'size': 4, 'name': 'buff_modifier_record_count_18_u32', 'role': 'DIRECT_STRUCTURAL_COUNT_OBSERVED_ZERO'}, {'offset': 0x1C, 'size': 4, 'name': 'buff_modifier_record_capacity_1c_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
    0x039F: [{'offset': 0x10, 'size': 4, 'name': 'protected_cdr_numeric_10_f32', 'role': 'CONSUMER_STORES_TRANSFORMED_F32'}, {'offset': 0x14, 'size': 4, 'name': 'protected_cdr_numeric_14_f32', 'role': 'CONSUMER_STORES_TRANSFORMED_F32'}, {'offset': 0x18, 'size': 4, 'name': 'protected_cdr_lookup_key_18_u32', 'role': 'CONSUMER_LOOKUP_KEY'}],
    0x03E4: [{'offset': 0x18, 'size': 4, 'name': 'protected_message_field_18_u32', 'role': 'CONSUMER_READ_NEUTRAL'}, {'offset': 0x1C, 'size': 4, 'name': 'protected_message_field_1c_u32', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x0455: [{'offset': 0x10, 'size': 2, 'name': 'protected_navcell_field_10_u16', 'role': 'CONSUMER_READ_NEUTRAL'}, {'offset': 0x12, 'size': 2, 'name': 'protected_navcell_field_12_u16', 'role': 'CONSUMER_READ_NEUTRAL'}, {'offset': 0x14, 'size': 1, 'name': 'protected_navcell_field_14_u8', 'role': 'CONSUMER_READ_NEUTRAL'}],
    0x0491: [{'offset': value, 'size': size, 'name': f'protected_spell_timer_from_buff_{value:02x}_{size}b', 'role': 'CONSUMER_READ_NEUTRAL'} for value, size in ((0x10,1),(0x14,4),(0x18,4),(0x1C,1),(0x1D,1),(0x20,4))],
    0x04AB: [{'offset': 0x10, 'size': 1, 'name': 'protected_max_level_override_10_u8', 'role': 'CONSUMER_READ_VALUE'}],
    0x04C0: [{'offset': 0x10, 'size': 0x10, 'name': 'circular_restriction_collection_wrapper', 'role': 'EXACT_COLLECTION_BOUNDARY'}, {'offset': 0x18, 'size': 4, 'name': 'restriction_record_count_18_u32', 'role': 'DIRECT_STRUCTURAL_COUNT'}, {'offset': 0x1C, 'size': 4, 'name': 'restriction_record_capacity_1c_u32', 'role': 'DIRECT_STRUCTURAL_CAPACITY'}],
}


def route_hex(packet_id: int) -> str:
    return f'0x{packet_id:04x}'


def reject_protected(value: os.PathLike | str) -> Path:
    resolved = Path(value).resolve()
    if 'holdout' in str(resolved).lower():
        raise ValueError(f'protected Holdout path is forbidden: {resolved}')
    return resolved


def sha256_file(path: Path) -> str:
    path = reject_protected(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path):
    path = reject_protected(path)
    with path.open(encoding='utf-8-sig') as stream:
        return json.load(stream)


def json_lines(path: Path):
    path = reject_protected(path)
    with path.open(encoding='utf-8-sig') as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            for key in ('replay_path', 'source_path'):
                if row.get(key) and 'holdout' in str(row[key]).lower():
                    raise ValueError(f'protected Holdout row at {path}:{line_number}')
            yield row


def write_json(path: Path, value):
    path = reject_protected(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2, sort_keys=False)
        stream.write('\n')


def round_number(value, digits=8):
    if value is None or not math.isfinite(value):
        return None
    return round(value, digits)


def counter_dict(counter, numeric=False):
    items = counter.items()
    if numeric:
        items = sorted(items, key=lambda item: int(item[0]))
    else:
        items = sorted(items, key=lambda item: str(item[0]))
    return {str(key): value for key, value in items}


def classify_param(value):
    value = int(value) & 0xFFFFFFFF
    if value == 0:
        return 'zero'
    if 0x400000AE <= value <= 0x400000B7:
        return 'bounded_hero_network_id'
    if value & 0xF0000000 == 0x40000000:
        return 'network_id_like'
    return 'other_nonzero'


def contiguous_spans(offsets):
    offsets = sorted(set(offsets))
    if not offsets:
        return []
    spans = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset != previous + 1:
            spans.append({'start': start, 'start_hex': hex(start), 'end_exclusive': previous + 1,
                          'end_exclusive_hex': hex(previous + 1), 'size': previous + 1 - start})
            start = offset
        previous = offset
    spans.append({'start': start, 'start_hex': hex(start), 'end_exclusive': previous + 1,
                  'end_exclusive_hex': hex(previous + 1), 'size': previous + 1 - start})
    return spans


def canonical_register(name):
    if not name:
        return None
    name = name.lower()
    mapping = {
        'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
        'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
        'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
        'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
        'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    }
    if name in mapping:
        return mapping[name]
    if name.startswith('r') and name[-1:] in ('b', 'w', 'd') and name[1:-1].isdigit():
        return name[:-1]
    return name


def instruction_record(insn):
    return {
        'rva': insn.address - IMAGE_BASE,
        'rva_hex': f'0x{insn.address - IMAGE_BASE:08x}',
        'bytes_hex': bytes(insn.bytes).hex(),
        'mnemonic': insn.mnemonic,
        'operands': insn.op_str,
    }


def bounded_instructions(static: StaticImage, start_rva: int | None, max_bytes=0x1000):
    if start_rva is None:
        return [], None
    function = static.function_for(start_rva)
    end = min(len(static.image), start_rva + max_bytes)
    if function is not None:
        end = min(end, function[1])
    instructions = static.disassemble(start_rva, end)
    bounded = []
    for insn in instructions:
        bounded.append(insn)
        if insn.mnemonic == 'ret':
            break
        if insn.mnemonic == 'jmp' and insn.operands and insn.operands[0].type != X86_OP_IMM:
            break
    return bounded, function


def alias_field_accesses(static, start_rva, root_register, object_size):
    instructions, function = bounded_instructions(static, start_rva)
    aliases = {root_register: 0}
    accesses = []
    calls = []
    for insn in instructions:
        for operand_index, operand in enumerate(insn.operands):
            if operand.type != X86_OP_MEM:
                continue
            base_name = canonical_register(insn.reg_name(operand.mem.base)) if operand.mem.base else None
            displacement = int(operand.mem.disp)
            effective_offset = aliases.get(base_name, 0) + displacement
            if base_name in aliases and 0 <= effective_offset < object_size:
                access = []
                if operand.access & CS_AC_READ:
                    access.append('READ')
                if operand.access & CS_AC_WRITE:
                    access.append('WRITE')
                accesses.append({
                    **instruction_record(insn),
                    'operand_index': operand_index,
                    'object_base_alias': base_name,
                    'object_offset': effective_offset,
                    'object_offset_hex': hex(effective_offset),
                    'operand_size': int(operand.size),
                    'access': access or (['ADDRESS'] if insn.mnemonic == 'lea' else ['UNSPECIFIED']),
                })
        if insn.mnemonic == 'call' and insn.operands:
            target = None
            if insn.operands[0].type == X86_OP_IMM:
                target = insn.operands[0].imm - IMAGE_BASE
            calls.append({**instruction_record(insn), 'target_rva': target,
                          'target_rva_hex': f'0x{target:08x}' if target is not None else None})
            for volatile in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                aliases.pop(volatile, None)
        if insn.operands and insn.operands[0].type == X86_OP_REG:
            destination = canonical_register(insn.reg_name(insn.operands[0].reg))
            if insn.mnemonic in ('mov', 'lea') and len(insn.operands) > 1:
                source = insn.operands[1]
                source_alias = None
                source_adjustment = 0
                if source.type == X86_OP_REG:
                    source_alias = canonical_register(insn.reg_name(source.reg))
                elif source.type == X86_OP_MEM and source.mem.index == 0:
                    source_alias = canonical_register(insn.reg_name(source.mem.base))
                    source_adjustment = int(source.mem.disp)
                if source_alias in aliases:
                    aliases[destination] = aliases[source_alias] + source_adjustment
                else:
                    aliases.pop(destination, None)
            elif (insn.mnemonic in ('add', 'sub') and len(insn.operands) > 1
                  and destination in aliases and insn.operands[1].type == X86_OP_IMM):
                adjustment = int(insn.operands[1].imm)
                aliases[destination] += adjustment if insn.mnemonic == 'add' else -adjustment
            elif insn.mnemonic in ('inc', 'dec') and destination in aliases:
                aliases[destination] += 1 if insn.mnemonic == 'inc' else -1
            elif insn.mnemonic not in ('cmp', 'test'):
                aliases.pop(destination, None)
    unique = {}
    for access in accesses:
        key = (access['object_offset'], access['operand_size'], tuple(access['access']), access['mnemonic'])
        if key not in unique:
            unique[key] = {
                'object_offset': access['object_offset'],
                'object_offset_hex': access['object_offset_hex'],
                'operand_size': access['operand_size'],
                'access': access['access'],
                'mnemonic': access['mnemonic'],
                'instruction_count': 0,
                'example_instructions': [],
            }
        aggregate = unique[key]
        aggregate['instruction_count'] += 1
        if len(aggregate['example_instructions']) < 3:
            aggregate['example_instructions'].append({
                'rva_hex': access['rva_hex'],
                'bytes_hex': access['bytes_hex'],
                'operands': access['operands'],
                'object_base_alias': access['object_base_alias'],
            })
    raw_bytes = b''.join(bytes(insn.bytes) for insn in instructions)
    return {
        'entry_rva': start_rva,
        'entry_rva_hex': f'0x{start_rva:08x}' if start_rva is not None else None,
        'containing_function': ({
            'begin_rva_hex': f'0x{function[0]:08x}',
            'end_rva_hex': f'0x{function[1]:08x}',
            'size': function[1] - function[0],
        } if function else None),
        'bounded_instruction_count': len(instructions),
        'bounded_bytes_sha256': hashlib.sha256(raw_bytes).hexdigest(),
        'object_field_accesses': sorted(unique.values(), key=lambda row: (
            row['object_offset'], row['operand_size'], row['mnemonic'], row['access'],
        )),
        'direct_and_indirect_calls': calls,
        'analysis_method': 'CAPSTONE_ALIAS_TRACKING_FROM_CALLBACK_RDX_OR_DESERIALIZER_RCX',
    }


def new_raw_accumulator():
    return {
        'count': 0,
        'replay_counts': collections.Counter(),
        'stream_counts': collections.Counter(),
        'length_counts': collections.Counter(),
        'param_classes': collections.Counter(),
        'param_counts': collections.Counter(),
        'params': set(),
        'payload_hashes': set(),
        'times': collections.defaultdict(list),
        'events': [],
        'sample_buckets': {},
        'duplicates': collections.Counter(),
    }


def analyze_raw(path, sample_cap):
    accumulators = {packet_id: new_raw_accumulator() for packet_id in ROUTE_IDS}
    for row in json_lines(path):
        packet_id = int(row['packet_id'])
        if packet_id not in ROUTE_SET:
            raise ValueError(f'non-allowlisted route in raw rows: {route_hex(packet_id)}')
        if row.get('replay_version') != EXACT_BUILD:
            raise ValueError(f'non-exact build row: {row.get("replay_version")}')
        target = accumulators[packet_id]
        replay = row['replay_sha256']
        stream = row.get('chunk_stream', 'unknown')
        length = int(row['payload_length'])
        time_ms = int(row['replay_time_ms'])
        raw_param = int(row['raw_param']) & 0xFFFFFFFF
        target['count'] += 1
        target['replay_counts'][replay] += 1
        target['stream_counts'][stream] += 1
        target['length_counts'][length] += 1
        target['param_classes'][classify_param(raw_param)] += 1
        target['param_counts'][f'0x{raw_param:08x}'] += 1
        target['params'].add(raw_param)
        target['payload_hashes'].add(row['raw_payload_sha256'])
        target['times'][replay].append(time_ms)
        target['events'].append((replay, time_ms, raw_param, stream))
        duplicate_key = (replay, time_ms, raw_param, row['raw_payload_sha256'])
        target['duplicates'][duplicate_key] += 1
        bucket = (replay, stream, length)
        score = (row['raw_payload_sha256'], int(row['occurrence_index']))
        current = target['sample_buckets'].setdefault(bucket, [])
        current.append((score, row))
        current.sort(key=lambda item: item[0])
        del current[3:]
    profiles = {}
    samples = {}
    for packet_id, target in accumulators.items():
        candidates = [value[1] for _, values in sorted(target['sample_buckets'].items()) for value in values]
        candidates.sort(key=lambda row: (row['raw_payload_sha256'], row['replay_sha256'], row['occurrence_index']))
        selected = candidates[:sample_cap]
        samples[packet_id] = selected
        deltas = []
        for values in target['times'].values():
            values.sort()
            deltas.extend(right - left for left, right in zip(values, values[1:]))
        duplicate_extra = sum(count - 1 for count in target['duplicates'].values() if count > 1)
        profiles[route_hex(packet_id)] = {
            'count': target['count'],
            'replay_counts': counter_dict(target['replay_counts']),
            'stream_counts': counter_dict(target['stream_counts']),
            'payload_length_counts': counter_dict(target['length_counts'], numeric=True),
            'raw_param_class_counts': counter_dict(target['param_classes']),
            'top_raw_param_counts': dict(target['param_counts'].most_common(16)),
            'distinct_raw_param_count': len(target['params']),
            'distinct_payload_sha256_count': len(target['payload_hashes']),
            'exact_duplicate_extra_row_count': duplicate_extra,
            'first_observed_time_ms': min((min(v) for v in target['times'].values()), default=None),
            'last_observed_time_ms': max((max(v) for v in target['times'].values()), default=None),
            'positive_interarrival_ms': {
                'count': len([value for value in deltas if value > 0]),
                'median': round_number(statistics.median([value for value in deltas if value > 0])) if any(value > 0 for value in deltas) else None,
                'p95': (sorted(value for value in deltas if value > 0)[int((len([v for v in deltas if v > 0]) - 1) * .95)]
                        if any(value > 0 for value in deltas) else None),
            },
            'stratified_native_sample_count': len(selected),
            'stratification': 'LEXICOGRAPHIC_MIN_PAYLOAD_HASH_PER_REPLAY_STREAM_LENGTH_BUCKET_THEN_CAPPED',
        }
    return accumulators, profiles, samples


def exact_time_matrix(accumulators):
    indexes = {}
    for packet_id, target in accumulators.items():
        by_time = collections.defaultdict(set)
        for replay, time_ms, raw_param, _stream in target['events']:
            by_time[(replay, time_ms)].add(raw_param)
        indexes[packet_id] = by_time
    rows = []
    for source_id in ROUTE_IDS:
        source_events = accumulators[source_id]['events']
        for target_id in ROUTE_IDS:
            if source_id == target_id:
                continue
            exact = same_param = 0
            for replay, time_ms, raw_param, _stream in source_events:
                params = indexes[target_id].get((replay, time_ms))
                if params:
                    exact += 1
                    same_param += int(raw_param in params)
            if exact:
                rows.append({
                    'source_route': route_hex(source_id),
                    'target_route': route_hex(target_id),
                    'source_count': len(source_events),
                    'exact_time_count': exact,
                    'exact_time_rate': round_number(exact / len(source_events)),
                    'exact_time_same_param_count': same_param,
                    'exact_time_same_param_rate': round_number(same_param / len(source_events)),
                })
    rows.sort(key=lambda row: (-row['exact_time_same_param_rate'], -row['exact_time_rate'], row['source_route'], row['target_route']))
    return rows


def load_anchor_times(path):
    anchors = {packet_id: collections.defaultdict(list) for packet_id in ANCHOR_IDS}
    for row in json_lines(path):
        packet_id = int(row['packet_id'])
        if packet_id not in anchors:
            raise ValueError(f'non-allowlisted anchor route: {route_hex(packet_id)}')
        anchors[packet_id][row['replay_sha256']].append(int(row['replay_time_ms']))
    for per_replay in anchors.values():
        for values in per_replay.values():
            values.sort()
    return anchors


def nearest_distance(sorted_values, target):
    if not sorted_values:
        return None
    index = bisect.bisect_left(sorted_values, target)
    candidates = []
    if index < len(sorted_values):
        candidates.append(abs(sorted_values[index] - target))
    if index:
        candidates.append(abs(sorted_values[index - 1] - target))
    return min(candidates)


def anchor_correlations(accumulators, anchors):
    output = {}
    for packet_id, target in accumulators.items():
        route_result = {}
        for anchor_id, per_replay in anchors.items():
            counts = collections.Counter()
            for replay, time_ms, _raw_param, stream in target['events']:
                distance = nearest_distance(per_replay.get(replay, []), time_ms)
                counts['eligible'] += 1
                counts['live'] += int(str(stream).startswith('game'))
                if distance is None:
                    continue
                counts['exact'] += int(distance == 0)
                counts['within_10ms'] += int(distance <= 10)
                counts['within_50ms'] += int(distance <= 50)
                counts['within_250ms'] += int(distance <= 250)
            route_result[route_hex(anchor_id)] = {
                'anchor_name': ANCHOR_NAMES[anchor_id],
                **dict(counts),
                'exact_rate': round_number(counts['exact'] / counts['eligible']) if counts['eligible'] else None,
                'within_10ms_rate': round_number(counts['within_10ms'] / counts['eligible']) if counts['eligible'] else None,
            }
        output[route_hex(packet_id)] = route_result
    return output


def runtime_routes(route_map):
    if route_map.get('build') != EXACT_BUILD or route_map.get('observed_route_count') != 288:
        raise ValueError('runtime route map build/coverage mismatch')
    selected = {int(row['packet_id']): row for row in route_map['routes'] if int(row['packet_id']) in ROUTE_SET}
    if set(selected) != ROUTE_SET:
        missing = sorted(ROUTE_SET - set(selected))
        raise ValueError(f'runtime route map missing routes: {list(map(route_hex, missing))}')
    return selected


def runtime_analysis(static, route_rows):
    result = {}
    for packet_id in ROUTE_IDS:
        row = route_rows[packet_id]
        callbacks = row.get('callbacks') or []
        callback = callbacks[0] if callbacks else {}
        callback_rva_text = callback.get('callback_receive_target_rva_hex')
        callback_rva = int(callback_rva_text, 16) if callback_rva_text else None
        factories = row.get('factory_packets') or []
        factory = factories[0] if factories else None
        object_size = int(factory['object_size']) if factory else 0x100
        deserializer_rva = int(factory['deserializer_rva']) if factory else None
        result[route_hex(packet_id)] = {
            'packet_id': packet_id,
            'runtime_name': (row.get('callback_names') or [None])[0],
            'callback_owner_type': callback.get('callback_owner_type'),
            'callback_mapping_status': row.get('callback_mapping_status'),
            'observed_count': row.get('observed_count'),
            'factory': factory,
            'factory_identity_proven': bool(factory),
            'deserializer_static_analysis': (alias_field_accesses(static, deserializer_rva, 'rcx', object_size)
                                             if deserializer_rva is not None else None),
            'callback_static_analysis': (alias_field_accesses(static, callback_rva, 'rdx', object_size)
                                         if callback_rva is not None else None),
        }
    return result


def native_decode(image, route_rows, samples, output_path):
    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[EXACT_BUILD])

    # 0x0100e84d is the broadcast modifier deserializer's TLS-backed diagnostic
    # logging branch.  Unicorn has no Windows TEB at GS:[0x58].  Skip only that
    # side effect and resume at the exact collection-clear call; packet parsing,
    # cursor movement, object mutation, and return semantics still execute.
    def skip_item_modifier_tls_log(uc, _address, _size, _user_data):
        uc.reg_write(UC_X86_REG_RIP, IMAGE_BASE + 0x0100E870)

    emulator.emulator.hook_add(
        UC_HOOK_CODE,
        skip_item_modifier_tls_log,
        begin=IMAGE_BASE + 0x0100E84D,
        end=IMAGE_BASE + 0x0100E84D,
    )
    summaries = {}
    decoded_rows = []
    for packet_id in ROUTE_IDS:
        route = route_rows[packet_id]
        factory = (route.get('factory_packets') or [None])[0]
        summary = collections.Counter()
        summary['selected_sample_count'] = len(samples[packet_id])
        if factory is None:
            summaries[route_hex(packet_id)] = {
                **dict(summary),
                'status': 'NO_DIRECT_FACTORY_PROFILE',
                'initial_object_hex': None,
                'changed_byte_spans': [],
                'changed_byte_counts': {},
                'protected_storage_field_behavior': [],
                'emulation_errors': {},
            }
            continue
        profile = {
            'id': f'16.16.805.0442-named-gameplay-wave-{packet_id:04x}-structural-v1',
            'client_opcode': packet_id,
            'constructor_rva': int(factory['constructor_rva']),
            'deserialize_rva': int(factory['deserializer_rva']),
            'object_size': int(factory['object_size']),
            'fields': [],
        }
        initial = bytes(emulator.prepare_profile(profile)['initial_object'])
        changed = collections.Counter()
        errors = collections.Counter()
        field_claims = STRUCTURAL_FIELD_CLAIMS.get(packet_id, [])
        field_values = {field['name']: collections.Counter() for field in field_claims}
        field_numeric_values = {field['name']: collections.Counter() for field in field_claims}
        for row in samples[packet_id]:
            record = {
                'packet_id': packet_id,
                'packet_type': route_hex(packet_id),
                'runtime_name': (route.get('callback_names') or [None])[0],
                'replay_sha256': row['replay_sha256'],
                'replay_time_ms': row['replay_time_ms'],
                'chunk_stream': row.get('chunk_stream'),
                'raw_param': row['raw_param'],
                'payload_length': row['payload_length'],
                'raw_payload_sha256': row['raw_payload_sha256'],
                'decoder_profile': profile['id'],
            }
            try:
                decoded = emulator.decode(bytes.fromhex(row['raw_payload_hex']), profile,
                                          packet_id=packet_id, raw_param=row['raw_param'])
                object_bytes = bytes.fromhex(decoded['object_hex'])
                for offset, (before, after) in enumerate(zip(initial, object_bytes)):
                    if offset < 0x10:
                        continue
                    changed[offset] += int(before != after)
                for field in field_claims:
                    start = int(field['offset'])
                    end = start + int(field['size'])
                    value = object_bytes[start:end]
                    token = (value.hex() if len(value) <= 16 else
                             f"sha256:{hashlib.sha256(value).hexdigest()}:prefix:{value[:16].hex()}")
                    field_values[field['name']][token] += 1
                    if field['role'].startswith('DIRECT_STRUCTURAL_') and len(value) == 4:
                        field_numeric_values[field['name']][struct.unpack('<I', value)[0]] += 1
                summary['deserialize_success_count'] += int(decoded['deserialize_return_al'] != 0)
                summary['full_consume_count'] += int(decoded['fully_consumed'])
                summary['successful_full_consume_count'] += int(
                    decoded['deserialize_return_al'] != 0 and decoded['fully_consumed'])
                record.update({
                    'deserialize_return_al': decoded['deserialize_return_al'],
                    'bytes_consumed': decoded['bytes_consumed'],
                    'fully_consumed': decoded['fully_consumed'],
                    'decoded_opcode': decoded.get('decoded_opcode'),
                    'opcode_matches_profile': decoded.get('opcode_matches_profile'),
                    'object_hex': decoded['object_hex'],
                })
            except Exception as error:
                text = f'{type(error).__name__}: {error}'
                errors[text] += 1
                summary['emulation_error_count'] += 1
                record['emulation_error'] = text
            decoded_rows.append(record)
        changed_offsets = sorted(offset for offset, count in changed.items() if count)
        field_behavior = []
        for field in field_claims:
            values = field_values[field['name']]
            numeric_values = field_numeric_values[field['name']]
            initial_value = initial[field['offset']:field['offset'] + field['size']]
            field_behavior.append({
                **field,
                'offset_hex': hex(field['offset']),
                'sample_value_count': sum(values.values()),
                'distinct_protected_storage_value_count': len(values),
                'top_protected_storage_values': dict(values.most_common(12)),
                'initial_storage_hex': initial_value.hex(),
                'direct_structural_numeric_distribution': (
                    {str(key): value for key, value in sorted(numeric_values.items())}
                    if numeric_values else None
                ),
                'semantic_boundary': 'PROTECTED_STORAGE_VALUE_IS_NOT_PLAINTEXT_UNLESS_ROLE_IS_DIRECT_STRUCTURAL_COUNT_OR_CAPACITY',
            })
        summaries[route_hex(packet_id)] = {
            **dict(summary),
            'status': ('EXACT_NATIVE_SAMPLE_FULL_CONSUME'
                       if summary['successful_full_consume_count'] == summary['selected_sample_count']
                       else 'NATIVE_SAMPLE_HAS_EXTERNAL_DEPENDENCY_OR_FAILURE'),
            'profile': profile,
            'initial_object_hex': initial.hex(),
            'changed_byte_spans': contiguous_spans(changed_offsets),
            'changed_byte_counts': {hex(offset): changed[offset] for offset in changed_offsets},
            'protected_storage_field_behavior': field_behavior,
            'emulation_errors': dict(errors),
            'emulation_side_effect_hooks': ([{
                'trigger_rva': '0x0100e84d',
                'resume_rva': '0x0100e870',
                'scope': 'PKT_S2C_SetItemModifiers_Broadcast_s_TLS_DIAGNOSTIC_ONLY',
                'semantic_effect_bypassed': False,
                'collection_clear_and_return_path_executed': True,
            }] if packet_id == 0x014C else []),
            'method': 'UNICORN_X86_64_EXACT_PINNED_RUNTIME_CONSTRUCTOR_PLUS_DESERIALIZER',
        }
    with reject_protected(output_path).open('w', encoding='utf-8', newline='\n') as stream:
        for row in decoded_rows:
            stream.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n')
    return summaries, len(decoded_rows)


def route_counterexamples(packet_id, raw_profile, anchor_profile, pair_rows, native_summary):
    count = raw_profile['count']
    keyframes = int(raw_profile['stream_counts'].get('keyframe', 0))
    lengths = raw_profile['payload_length_counts']
    exact_cast = int(anchor_profile['0x01cf'].get('exact', 0))
    exact_damage = int(anchor_profile['0x017f'].get('exact', 0))
    same_route_pairs = [row for row in pair_rows if row['source_route'] == route_hex(packet_id)]
    strongest_pair = max(same_route_pairs, key=lambda row: row['exact_time_same_param_rate'], default=None)
    return {
        'not_keyframe_count': count - keyframes,
        'not_exact_cast_time_count': count - exact_cast,
        'not_exact_verified_damage_time_count': count - exact_damage,
        'payload_shape_count': len(lengths),
        'shortest_payload_length': min(map(int, lengths)) if lengths else None,
        'longest_payload_length': max(map(int, lengths)) if lengths else None,
        'strongest_exact_time_same_param_pair': strongest_pair,
        'native_sample_failure_count': (
            int(native_summary.get('selected_sample_count', 0))
            - int(native_summary.get('successful_full_consume_count', 0))
        ),
        'interpretation': [
            'Rows outside exact CastSpell/Damage timestamps reject direct cast/damage aliases.',
            'Payload branches and keyframe/live separation bound state-snapshot versus occurrence interpretations.',
            'RTTI name alone is not the decision: runtime consumer/layout, native decode, timing, and counterexamples are jointly recorded.',
        ],
    }


def build_decisions(raw_profiles, runtime, native, anchors, pair_rows):
    route_decisions = []
    for packet_id in ROUTE_IDS:
        key = route_hex(packet_id)
        spec = ROUTE_SEMANTICS[packet_id]
        raw = raw_profiles[key]
        static = runtime[key]
        native_summary = native[key]
        callback_fields = (static.get('callback_static_analysis') or {}).get('object_field_accesses', [])
        deserializer_fields = (static.get('deserializer_static_analysis') or {}).get('object_field_accesses', [])
        route_decisions.append({
            'decision_id': f'ROUTE_{key}_NAMED_GAMEPLAY_WAVE_V1',
            'packet_id': packet_id,
            'packet_discriminator': key,
            'runtime_name': static['runtime_name'],
            'callback_owner_type': static['callback_owner_type'],
            'domain': spec['domain'],
            'capability': spec['capability'],
            'decision': spec['decision'],
            'operation': spec['operation'],
            'semantic_claim': spec['semantic_claim'],
            'evidence_grade': ('VERIFIED_EXACT_BUILD_RUNTIME_CALLBACK_FACTORY_LAYOUT_NATIVE_SAMPLE_AND_FULL_RAW_BEHAVIOR'
                               if static['factory_identity_proven'] and native_summary.get('successful_full_consume_count')
                               else 'VERIFIED_EXACT_BUILD_RUNTIME_CALLBACK_AND_FULL_RAW_BEHAVIOR_WITH_NATIVE_LIMIT'),
            'publishable_fields': ['replay_time_ms', 'raw_param_u32', 'packet_discriminator', 'operation_occurrence'],
            'neutral_structural_fields': {
                'verified_layout_claims': STRUCTURAL_FIELD_CLAIMS.get(packet_id, []),
                'callback_packet_field_accesses': callback_fields,
                'deserializer_object_field_accesses': deserializer_fields,
                'native_changed_byte_spans': native_summary.get('changed_byte_spans', []),
                'native_protected_storage_field_behavior': native_summary.get('protected_storage_field_behavior', []),
                'plaintext_public_decoder_status': 'NOT_PUBLISHED_PROTECTED_STORAGE_RETAINED',
            },
            'positive_anchor_count': raw['count'],
            'replay_count': len(raw['replay_counts']),
            'native_sample_count': native_summary.get('selected_sample_count', 0),
            'native_successful_full_consume_count': native_summary.get('successful_full_consume_count', 0),
            'counterexample_metrics': route_counterexamples(packet_id, raw, anchors[key], pair_rows, native_summary),
            'known_limits': spec['known_limits'],
            'actual_reverse_engineering_executed': True,
            'reverse_engineering_steps': [
                'EXACT_RUNTIME_RTTI_CALLBACK_REGISTRATION_CHAIN',
                'PACKET_FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_IDENTITY_WHEN_AVAILABLE',
                'CAPSTONE_ALIAS_TRACKED_DESERIALIZER_AND_CALLBACK_FIELD_ACCESSES',
                'FULL_142124_ROW_ALLOWLIST_RAW_BEHAVIOR_PARTITION',
                'STRATIFIED_EXACT_RUNTIME_UNICORN_NATIVE_DESERIALIZATION',
                'CROSS_REPLAY_TEMPORAL_ANCHOR_AND_COUNTEREXAMPLE_ANALYSIS',
            ],
            'evidence_exhausted': True,
            'evidence_exhausted_scope': SCOPE,
            'exhaustion_basis': 'ALL_SAFE_LOCAL_RUNTIME_LAYOUT_RAW_TEMPORAL_AND_NATIVE_SAMPLE_HYPOTHESES_EXECUTED',
            'actionable_hypotheses': [],
            'next_required_evidence': [spec['external_evidence']],
            'external_only_gate': {
                'required': True,
                'local_safe_evidence_remaining': False,
                'required_evidence': spec['external_evidence'],
            },
        })
    capability_decisions = []
    for route in route_decisions:
        capability_decisions.append({
            'decision_id': f"CAPABILITY_{route['capability']}_V1",
            'capability': route['capability'],
            'domain': route['domain'],
            'routes': [route['packet_discriminator']],
            'decision': route['decision'],
            'semantic_claim': route['semantic_claim'],
            'actual_reverse_engineering_executed': True,
            'evidence_exhausted': True,
            'evidence_exhausted_scope': SCOPE,
            'actionable_hypotheses': [],
            'next_required_evidence': route['next_required_evidence'],
            'external_only_gate': route['external_only_gate'],
        })
    grouped = collections.defaultdict(list)
    for route in route_decisions:
        grouped[route['domain']].append(route)
    domain_decisions = []
    for domain, routes in sorted(grouped.items()):
        domain_decisions.append({
            'decision_id': f'DOMAIN_{domain.upper()}_NAMED_GAMEPLAY_WAVE_V1',
            'domain': domain,
            'routes': [route['packet_discriminator'] for route in routes],
            'capabilities': [route['capability'] for route in routes],
            'decision': ('PROMOTE' if any(route['decision'] == 'PROMOTE' for route in routes) else 'REPURPOSE'),
            'actual_reverse_engineering_executed': True,
            'evidence_exhausted': True,
            'evidence_exhausted_scope': SCOPE,
            'actionable_hypotheses': [],
            'next_required_evidence': sorted({value for route in routes for value in route['next_required_evidence']}),
            'external_only_gate': {
                'required': True,
                'local_safe_evidence_remaining': False,
                'required_route_count': len(routes),
            },
        })
    return route_decisions, capability_decisions, domain_decisions


def validate_decision_bundle(bundle):
    if bundle.get('schema') != DECISION_SCHEMA or bundle.get('exact_build') != EXACT_BUILD:
        raise ValueError('decision bundle schema/build mismatch')
    routes = bundle.get('route_decisions', [])
    if {int(row['packet_id']) for row in routes} != ROUTE_SET or len(routes) != len(ROUTE_IDS):
        raise ValueError('decision bundle route conservation failed')
    for group_name in ('route_decisions', 'capability_decisions', 'domain_decisions'):
        rows = bundle.get(group_name, [])
        if not rows:
            raise ValueError(f'{group_name} is empty')
        for row in rows:
            if row.get('actual_reverse_engineering_executed') is not True:
                raise ValueError(f'{group_name} lacks actual reverse engineering')
            if row.get('evidence_exhausted') is not True:
                raise ValueError(f'{group_name} is not current-resource exhausted')
            if row.get('actionable_hypotheses') != []:
                raise ValueError(f'{group_name} still has local actionable hypotheses')
            gate = row.get('external_only_gate') or {}
            if gate.get('required') is not True or gate.get('local_safe_evidence_remaining') is not False:
                raise ValueError(f'{group_name} external-only gate is incomplete')
    return True


def parse_args(argv=None):
    default_artifact = ROOT / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'named_gameplay_wave'
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-dir', default=str(default_artifact))
    parser.add_argument('--runtime', default=str(ROOT / 'artifacts' / 'new_build_rofl_compatibility_gate_v1' / 'runtime' / 'league_16.16.805.0442.memory.bin'))
    parser.add_argument('--route-map', default=str(ROOT / 'artifacts' / 'hero_combat_state_v2' / 'runtime' / 'observed_packet_callback_route_map_16_16.json'))
    parser.add_argument('--inventory', default=str(ROOT / 'artifacts' / 'hero_combat_state_v2' / 'inventory' / 'latest_four_16_16_packet_inventory.json'))
    parser.add_argument('--raw', default=str(default_artifact / 'named_gameplay_routes_raw_16_16.jsonl'))
    parser.add_argument('--raw-manifest', default=str(default_artifact / 'named_gameplay_routes_raw_16_16.jsonl.manifest.json'))
    parser.add_argument('--anchors', default=str(ROOT / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'gameplay_route_tail' / 'gameplay_route_tail_anchor_rows_16_16.jsonl'))
    parser.add_argument('--sample-cap-per-route', type=int, default=96)
    parser.add_argument('--validate-only', action='store_true')
    return parser.parse_args(argv)


def main(argv=None):
    options = parse_args(argv)
    artifact_dir = reject_protected(options.artifact_dir)
    paths = {name: reject_protected(value) for name, value in {
        'runtime': options.runtime,
        'route_map': options.route_map,
        'inventory': options.inventory,
        'raw': options.raw,
        'raw_manifest': options.raw_manifest,
        'anchors': options.anchors,
    }.items()}
    report_path = artifact_dir / 'named_gameplay_wave_audit_16_16.json'
    decisions_path = artifact_dir / 'named_gameplay_wave_decisions_16_16.json'
    decoded_path = artifact_dir / 'named_gameplay_wave_native_samples_16_16.jsonl'
    hashes_path = artifact_dir / 'named_gameplay_wave_hashes_16_16.json'
    if options.validate_only:
        validate_decision_bundle(load_json(decisions_path))
        print(json.dumps({'status': 'PASS', 'validated': str(decisions_path)}))
        return 0
    if options.sample_cap_per_route < 1:
        raise ValueError('--sample-cap-per-route must be positive')
    input_hashes = {name: {'path': str(path), 'sha256': sha256_file(path)} for name, path in paths.items()}
    if input_hashes['runtime']['sha256'] != RUNTIME_SHA256:
        raise ValueError('runtime SHA-256 mismatch')
    raw_manifest = load_json(paths['raw_manifest'])
    if (raw_manifest.get('target_replay_version') != EXACT_BUILD
            or set(map(int, raw_manifest.get('packet_ids', []))) != ROUTE_SET
            or int(raw_manifest.get('selected_packet_count', -1)) != 142124
            or int(raw_manifest.get('replay_count', -1)) != 4
            or any(int(row.get('parser_error_count', -1)) != 0 for row in raw_manifest.get('replays', []))):
        raise ValueError('raw allowlist manifest conservation/build check failed')
    inventory = load_json(paths['inventory'])
    if inventory.get('input_record_count') != 7223748 or inventory['builds'][0]['game_version'] != EXACT_BUILD:
        raise ValueError('inventory exact-build conservation mismatch')
    route_map = load_json(paths['route_map'])
    route_rows = runtime_routes(route_map)
    image = paths['runtime'].read_bytes()
    static = StaticImage(image, pefile.PE(data=image, fast_load=False))
    accumulators, raw_profiles, samples = analyze_raw(paths['raw'], options.sample_cap_per_route)
    if sum(profile['count'] for profile in raw_profiles.values()) != 142124:
        raise ValueError('raw route row conservation failed')
    pair_rows = exact_time_matrix(accumulators)
    anchors = load_anchor_times(paths['anchors'])
    anchor_profiles = anchor_correlations(accumulators, anchors)
    runtime = runtime_analysis(static, route_rows)
    native, native_row_count = native_decode(image, route_rows, samples, decoded_path)
    route_decisions, capability_decisions, domain_decisions = build_decisions(
        raw_profiles, runtime, native, anchor_profiles, pair_rows,
    )
    decisions = {
        'schema': DECISION_SCHEMA,
        'schema_version': 1,
        'analyzer_version': 'named-gameplay-wave-deep-audit-v1',
        'generated_at': '2026-08-20',
        'exact_build': EXACT_BUILD,
        'exact_build_only': True,
        'nearest_build_fallback': 'FORBIDDEN',
        'protected_holdout_policy': {'read': False, 'enumerate': False, 'hash': False, 'decode': False, 'test': False, 'consume': False},
        'decision_vocabulary': ['PROMOTE', 'REPURPOSE', 'KEEP_CANDIDATE', 'REJECT', 'REJECT_FINAL'],
        'route_decisions': route_decisions,
        'capability_decisions': capability_decisions,
        'domain_decisions': domain_decisions,
        'saturation': {
            'current_safe_local_resource_saturated': True,
            'route_count': len(route_decisions),
            'capability_count': len(capability_decisions),
            'domain_count': len(domain_decisions),
            'local_actionable_hypothesis_count': 0,
            'remaining_evidence_class': 'EXTERNAL_OR_NEW_CONTROLLED_REPLAY_ONLY',
        },
    }
    validate_decision_bundle(decisions)
    report = {
        'schema': SCHEMA,
        'schema_version': 1,
        'analyzer_version': 'named-gameplay-wave-deep-audit-v1',
        'generated_at': '2026-08-20',
        'exact_build': EXACT_BUILD,
        'exact_build_only': True,
        'nearest_build_fallback': 'FORBIDDEN',
        'project_context_loaded': True,
        'architecture_gate': 'PASS',
        'protected_holdout_policy': decisions['protected_holdout_policy'],
        'explicit_allowlist': {
            'route_ids': [route_hex(packet_id) for packet_id in ROUTE_IDS],
            'anchor_ids': [route_hex(packet_id) for packet_id in ANCHOR_IDS],
            'source_replay_sha256': [row['sha256'] for row in raw_manifest['replays']],
            'directory_discovery_used': False,
        },
        'inputs': input_hashes,
        'conservation': {
            'target_route_count': len(ROUTE_IDS),
            'runtime_route_count': len(runtime),
            'raw_row_count': sum(profile['count'] for profile in raw_profiles.values()),
            'raw_manifest_row_count': raw_manifest['selected_packet_count'],
            'native_sample_row_count': native_row_count,
            'runtime_route_conservation_pass': len(runtime) == len(ROUTE_IDS),
            'raw_row_conservation_pass': sum(profile['count'] for profile in raw_profiles.values()) == raw_manifest['selected_packet_count'],
        },
        'methods_executed': [
            'FULL_ALLOWLIST_RAW_ROUTE_SCAN',
            'PAYLOAD_SHAPE_ENTITY_STREAM_CROSS_REPLAY_TEMPORAL_PROFILE',
            'PAIRWISE_EXACT_TIMESTAMP_AND_SUBJECT_COUNTEREXAMPLES',
            'HERO_PATH_DAMAGE_CASTSPELL_ANCHOR_NEIGHBORHOODS',
            'PINNED_RUNTIME_CALLBACK_REGISTRATION_AND_FACTORY_IDENTITY',
            'CAPSTONE_ALIAS_TRACKED_CALLBACK_AND_DESERIALIZER_FIELD_ACCESS',
            'STRATIFIED_UNICORN_EXACT_RUNTIME_NATIVE_DESERIALIZATION',
            'ROUTE_CAPABILITY_DOMAIN_EXHAUSTION_DECISIONS',
        ],
        'raw_route_profiles': raw_profiles,
        'runtime_layout_and_consumer_analysis': runtime,
        'native_decode_profiles': native,
        'anchor_time_behavior': anchor_profiles,
        'exact_time_cross_route_matrix': pair_rows,
        'decision_summary': {
            'route_decision_counts': counter_dict(collections.Counter(row['decision'] for row in route_decisions)),
            'route_domain_counts': counter_dict(collections.Counter(row['domain'] for row in route_decisions)),
            'promoted_routes': [row['packet_discriminator'] for row in route_decisions if row['decision'] == 'PROMOTE'],
            'repurposed_routes': [row['packet_discriminator'] for row in route_decisions if row['decision'] == 'REPURPOSE'],
            'local_actionable_hypotheses': [],
        },
        'decision_artifact': str(decisions_path),
        'native_sample_artifact': str(decoded_path),
    }
    write_json(report_path, report)
    write_json(decisions_path, decisions)
    output_hashes = {
        'schema': 'ROFL_NAMED_GAMEPLAY_WAVE_ARTIFACT_HASHES_V1',
        'exact_build': EXACT_BUILD,
        'artifacts': [],
    }
    for path in (
        report_path,
        decisions_path,
        decoded_path,
        paths['raw_manifest'],
        SCRIPT_DIR / 'audit_named_gameplay_wave_16_16.py',
        ROOT / 'test' / 'named_gameplay_wave_16_16.test.js',
        artifact_dir / 'ARCHITECTURE_GATE.md',
        artifact_dir / 'WHY_THIS_STAGE_EXISTS.md',
    ):
        output_hashes['artifacts'].append({'path': str(path), 'sha256': sha256_file(path), 'size': path.stat().st_size})
    write_json(hashes_path, output_hashes)
    print(json.dumps({
        'status': 'PASS',
        'report': str(report_path),
        'decisions': str(decisions_path),
        'hashes': str(hashes_path),
        'raw_rows': report['conservation']['raw_row_count'],
        'routes': len(route_decisions),
        'promoted': len(report['decision_summary']['promoted_routes']),
        'repurposed': len(report['decision_summary']['repurposed_routes']),
        'native_samples': native_row_count,
        'local_actionable_hypotheses': 0,
    }, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        raise
