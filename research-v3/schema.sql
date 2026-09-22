CREATE TABLE IF NOT EXISTS ingest_runs (
    run_id VARCHAR PRIMARY KEY, started_at TIMESTAMP, finished_at TIMESTAMP,
    status VARCHAR NOT NULL, manifest_path VARCHAR, artifact_root VARCHAR,
    replay_count INTEGER DEFAULT 0, inserted_rows BIGINT DEFAULT 0,
    details_json JSON
);

CREATE TABLE IF NOT EXISTS ingest_rejections (
    rejection_id VARCHAR PRIMARY KEY, run_id VARCHAR, game_id VARCHAR,
    replay_sha256 VARCHAR, patch VARCHAR, reason VARCHAR NOT NULL,
    raw_provenance_json JSON, created_at TIMESTAMP DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS replays (
    game_id VARCHAR NOT NULL, replay_sha256 VARCHAR PRIMARY KEY, patch VARCHAR NOT NULL,
    replay_label VARCHAR, sample_role VARCHAR, replay_path VARCHAR, duration_ms BIGINT,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR,
    raw_provenance_json JSON, ingested_at TIMESTAMP DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS participants (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    participant_id INTEGER, network_id BIGINT, champion VARCHAR, team_id INTEGER,
    team VARCHAR, role VARCHAR, win BOOLEAN, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS death_events (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, source_network_id BIGINT, target_network_id BIGINT,
    source_participant_id INTEGER, target_participant_id INTEGER,
    source_champion VARCHAR, target_champion VARCHAR, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS damage_events (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, source_network_id BIGINT, target_network_id BIGINT,
    source_participant_id INTEGER, target_participant_id INTEGER,
    source_champion VARCHAR, target_champion VARCHAR, amount DOUBLE,
    damage_type VARCHAR, spell VARCHAR, spell_slot VARCHAR, is_basic_attack BOOLEAN,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS spell_events (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, source_network_id BIGINT, target_network_id BIGINT,
    source_participant_id INTEGER, target_participant_id INTEGER,
    source_champion VARCHAR, target_champion VARCHAR, spell_identifier VARCHAR,
    spell_slot VARCHAR, spell_key BIGINT, target_count INTEGER,
    position_x DOUBLE, position_y DOUBLE, position_z DOUBLE,
    target_x DOUBLE, target_y DOUBLE, target_z DOUBLE,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS buff_events (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, source_network_id BIGINT, target_network_id BIGINT,
    source_participant_id INTEGER, target_participant_id INTEGER,
    buff_operation VARCHAR, buff_slot INTEGER, buff_name_hash BIGINT, buff_type INTEGER,
    stack_count INTEGER, duration_seconds DOUBLE, lifecycle_id VARCHAR,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_spawns (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, owner_network_id BIGINT, entity_network_id BIGINT,
    owner_participant_id INTEGER, owner_team_id INTEGER, ward_type VARCHAR,
    generic_name VARCHAR, entity_name VARCHAR, position_x DOUBLE, position_y DOUBLE,
    position_height DOUBLE, owner_mapping_confidence VARCHAR, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_lifecycles (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    ward_network_id BIGINT, spawn_time_ms BIGINT, remove_time_ms BIGINT,
    duration_ms BIGINT, removal_reason VARCHAR, match_rule VARCHAR,
    coordinate_error DOUBLE, decoder_profile VARCHAR, confidence VARCHAR,
    status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS hero_paths (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, entity_id BIGINT, speed DOUBLE, waypoints_json JSON,
    raw_packet_occurrence_index BIGINT, record_index INTEGER, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS hero_positions_1s (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    replay_time_ms BIGINT, entity_id BIGINT, position_x DOUBLE, position_z DOUBLE,
    source_path_timestamp_ms BIGINT, source_age_ms BIGINT,
    interpolation_method VARCHAR, position_status VARCHAR, raw_packet_ref JSON,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS adc_deaths (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    adc VARCHAR, adc_participant_id INTEGER, support VARCHAR, support_participant_id INTEGER,
    death_time_ms BIGINT, combat_start_ms BIGINT, combat_duration_ms BIGINT, killer VARCHAR,
    nearby_enemy_count INTEGER, nearby_ally_count INTEGER, support_distance DOUBLE,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS adc_death_damage (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    adc_death_id VARCHAR, attacker_participant_id INTEGER, attacker_champion VARCHAR,
    attacker_network_id BIGINT, hit_count INTEGER, damage_amount DOUBLE,
    first_hit_time_ms BIGINT, last_hit_time_ms BIGINT, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS adc_death_support_actions (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    adc_death_id VARCHAR, action_kind VARCHAR, replay_time_ms BIGINT,
    spell_identifier VARCHAR, spell_slot VARCHAR, source_network_id BIGINT,
    target_network_id BIGINT, decoder_profile VARCHAR, confidence VARCHAR,
    status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS adc_death_position_context (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    adc_death_id VARCHAR, replay_time_ms BIGINT, entity_id BIGINT,
    position_x DOUBLE, position_z DOUBLE, context_kind VARCHAR, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_position_context (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    ward_network_id BIGINT, replay_time_ms BIGINT, owner_participant_id INTEGER,
    owner_x DOUBLE, owner_z DOUBLE, nearest_enemy_distance DOUBLE,
    enemy_jungler_distance DOUBLE, nearby_enemy_count INTEGER, nearby_ally_count INTEGER,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_research_events (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    timestamp_ms BIGINT, minute DOUBLE, event_kind VARCHAR, ward_network_id BIGINT,
    ward_type VARCHAR, owner_participant INTEGER, owner_champion VARCHAR,
    owner_role VARCHAR, owner_team INTEGER, actual_x DOUBLE, actual_y DOUBLE,
    height DOUBLE, spawn_position_status VARCHAR, remove_time_ms BIGINT,
    lifetime_ms BIGINT, lifecycle_status VARCHAR, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS map_regions (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    region_id VARCHAR, region_name VARCHAR, geometry_json JSON, decoder_profile VARCHAR,
    confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_heatmap_cells (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    cell_x INTEGER, cell_z INTEGER, cell_size DOUBLE, ward_count BIGINT,
    decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_hotspots (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    hotspot_id VARCHAR, center_x DOUBLE, center_z DOUBLE, ward_count BIGINT,
    radius DOUBLE, decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR,
    raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS adc_death_features (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    adc_death_id VARCHAR, feature_name VARCHAR, numeric_value DOUBLE,
    text_value VARCHAR, decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR,
    raw_provenance_json JSON
);

CREATE TABLE IF NOT EXISTS ward_death_context (
    fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
    adc_death_id VARCHAR, ward_network_id BIGINT, distance DOUBLE,
    time_delta_ms BIGINT, relation VARCHAR, decoder_profile VARCHAR, confidence VARCHAR,
    status VARCHAR, raw_provenance_json JSON
);

CREATE INDEX IF NOT EXISTS idx_death_game_time ON death_events(game_id, replay_time_ms);
CREATE INDEX IF NOT EXISTS idx_damage_game_time ON damage_events(game_id, replay_time_ms);
CREATE INDEX IF NOT EXISTS idx_spell_game_time ON spell_events(game_id, replay_time_ms);
CREATE INDEX IF NOT EXISTS idx_ward_game_time ON ward_spawns(game_id, replay_time_ms);
CREATE INDEX IF NOT EXISTS idx_position_game_entity_time ON hero_positions_1s(game_id, entity_id, replay_time_ms);
