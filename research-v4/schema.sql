-- Additive Protection Telemetry V4.  This schema intentionally does not alter V3.
CREATE TABLE IF NOT EXISTS protection_v4_profiles (
    replay_sha256 VARCHAR PRIMARY KEY, game_id VARCHAR, patch VARCHAR,
    profile_status VARCHAR NOT NULL, decoder_profile VARCHAR,
    decoded_row_count BIGINT NOT NULL DEFAULT 0, protection_row_count BIGINT NOT NULL DEFAULT 0,
    details_json JSON, created_at TIMESTAMP DEFAULT current_timestamp,
    v4_schema_version INTEGER NOT NULL DEFAULT 2,
    on_event_decoder_status VARCHAR,
    shield_damage_decoder_status VARCHAR,
    decoder_profiles_json JSON
);

-- Packet source columns are repeated deliberately: each row is independently auditable.
CREATE TABLE IF NOT EXISTS health_state_events (
    fact_id VARCHAR PRIMARY KEY, replay_sha256 VARCHAR NOT NULL, game_id VARCHAR, replay_time_ms BIGINT,
    event_id INTEGER, source_network_id BIGINT, target_network_id BIGINT, observed_amount DOUBLE,
    health_before DOUBLE, health_after DOUBLE, temporary_hp_before DOUBLE, temporary_hp_after DOUBLE,
    raw_amount DOUBLE, effective_amount DOUBLE, overheal_amount DOUBLE,
    chunk_index BIGINT, chunk_id BIGINT, chunk_stream VARCHAR, chunk_file_offset BIGINT,
    compressed_body_offset BIGINT, decompressed_block_offset BIGINT, decompressed_payload_offset BIGINT,
    global_occurrence_index BIGINT, raw_occurrence_index BIGINT, packet_occurrence_index BIGINT,
    raw_param BIGINT, raw_param_hex VARCHAR, raw_payload_length BIGINT, raw_payload_sha256 VARCHAR,
    raw_payload_hex VARCHAR, params_length BIGINT, params_sha256 VARCHAR, params_hex VARCHAR,
    raw_provenance_json JSON
);
CREATE TABLE IF NOT EXISTS shield_state_events AS SELECT * FROM health_state_events WHERE FALSE;
CREATE TABLE IF NOT EXISTS heal_events AS SELECT * FROM health_state_events WHERE FALSE;
CREATE TABLE IF NOT EXISTS temporary_hp_events AS SELECT * FROM health_state_events WHERE FALSE;

CREATE TABLE IF NOT EXISTS protection_events (
    fact_id VARCHAR PRIMARY KEY, replay_sha256 VARCHAR NOT NULL, game_id VARCHAR, replay_time_ms BIGINT,
    protection_kind VARCHAR NOT NULL, source_network_id BIGINT, target_network_id BIGINT,
    observed_amount DOUBLE, raw_amount DOUBLE, effective_amount DOUBLE, overheal_amount DOUBLE,
    canonical BOOLEAN NOT NULL, heal_group_size BIGINT, canonical_first_raw_occurrence BIGINT,
    paired_source_route_fact_id VARCHAR,
    chunk_index BIGINT, chunk_id BIGINT, chunk_stream VARCHAR, chunk_file_offset BIGINT,
    compressed_body_offset BIGINT, decompressed_block_offset BIGINT, decompressed_payload_offset BIGINT,
    global_occurrence_index BIGINT, raw_occurrence_index BIGINT, packet_occurrence_index BIGINT,
    raw_param BIGINT, raw_param_hex VARCHAR, raw_payload_length BIGINT, raw_payload_sha256 VARCHAR,
    raw_payload_hex VARCHAR, params_length BIGINT, params_sha256 VARCHAR, params_hex VARCHAR,
    raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS protection_state_transitions (
    fact_id VARCHAR PRIMARY KEY, replay_sha256 VARCHAR NOT NULL, game_id VARCHAR, replay_time_ms BIGINT,
    transition_kind VARCHAR NOT NULL, source_network_id BIGINT, target_network_id BIGINT,
    observed_amount DOUBLE, remaining_amount DOUBLE, absorbed_amount DOUBLE, unused_amount DOUBLE,
    raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS protection_spell_inventory (
    fact_id VARCHAR PRIMARY KEY, replay_sha256 VARCHAR NOT NULL, game_id VARCHAR,
    source_network_id BIGINT, source_participant_id INTEGER, champion VARCHAR,
    spell_identifier VARCHAR, spell_slot VARCHAR, protection_cast_kind VARCHAR,
    replay_time_ms BIGINT, raw_provenance_json JSON,
    cast_count BIGINT, target_count BIGINT, buff_candidate_count BIGINT,
    damage_window_count BIGINT, first_cast_ms BIGINT, last_cast_ms BIGINT
);

CREATE TABLE IF NOT EXISTS adc_death_protection (
    fact_id VARCHAR PRIMARY KEY, replay_sha256 VARCHAR NOT NULL, game_id VARCHAR,
    adc_death_id VARCHAR NOT NULL, replay_time_ms BIGINT, protection_kind VARCHAR NOT NULL,
    source_network_id BIGINT, source_participant_id INTEGER, target_network_id BIGINT,
    observed_amount DOUBLE, direct_heal_lower DOUBLE, direct_heal_upper DOUBLE,
    raw_amount DOUBLE, effective_amount DOUBLE, overheal_amount DOUBLE,
    source_is_external_ally BOOLEAN, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS adc_survival_features_v4 (
    fact_id VARCHAR PRIMARY KEY, replay_sha256 VARCHAR NOT NULL, game_id VARCHAR,
    adc_death_id VARCHAR NOT NULL, combat_start_ms BIGINT, death_time_ms BIGINT,
    external_ally_shield_generated DOUBLE, external_ally_direct_heal_lower DOUBLE,
    external_ally_direct_heal_upper DOUBLE, direct_heal_exact BOOLEAN,
    incoming_damage_event_count BIGINT, incoming_damage_amount DOUBLE,
    incoming_damage_type_json JSON, incoming_basic_attack_count BIGINT, incoming_spell_damage_count BIGINT,
    shield_remaining DOUBLE, shield_absorbed DOUBLE, shield_unused DOUBLE,
    health_before DOUBLE, health_after DOUBLE, temporary_hp_before DOUBLE, temporary_hp_after DOUBLE,
    raw_provenance_json JSON
);

CREATE INDEX IF NOT EXISTS idx_v4_protection_time ON protection_events(replay_sha256, replay_time_ms, raw_occurrence_index);
CREATE INDEX IF NOT EXISTS idx_v4_adc_protection ON adc_death_protection(adc_death_id, replay_time_ms);
