# V3 WardSpawn research API

`ward_analysis.py` is a pure Python, DuckDB-compatible analysis layer over the
canonical `ward_research_events` table. Its expected columns are:

`game_id`, `replay_sha256`, `timestamp_ms`, `minute`, `ward_network_id`,
`ward_type`, `owner_participant`, `owner_champion`, `owner_role`, `owner_team`,
`actual_x`, `actual_y`, `height`, `spawn_position_status`, `remove_time_ms`,
`lifetime_ms`, `lifecycle_status`, `map_region`, and
`owner_mapping_confidence`.

## Coordinate contract

Every spatial helper uses only canonical `actual_x` and `actual_y`, which are
the planar axes recovered from the direct WardSpawn object writes. If either
field is missing, or `spawn_position_status` explicitly says it is not direct,
the row is omitted from grids and hotspots. CastSpell target fields are not
read as a fallback. Region labels are additive and raw coordinates are copied
unchanged.

## Module API

```python
from ward_analysis import analyze_ward_rows, query_ward_rows, write_query_output

analysis = analyze_ward_rows(
    rows,
    {"viewer_team": 100, "perspective": "enemy", "min_minute": 10, "max_minute": 20},
    cell_size=1000,
    hotspot_radius_cells=1,
)
rows = query_ward_rows(connection, "ward_research_events", {"ward_type": "CONTROL_WARD"})
write_query_output(rows, "out/controls.parquet")
```

`filter_ward_rows` supports absolute `team` (100/200/blue/red), relative
`team` or `perspective` (`ally`/`enemy`, requiring `viewer_team`), `role`,
`champion`, `ward_type`, and inclusive `min_minute`/`max_minute` bounds.
`build_filter_sql` exposes the same parameterized predicate for core-owned
DuckDB queries. `export_duckdb_query` combines query and CSV/Parquet export.

`build_grid_heatmap` bins direct WardSpawn positions into configurable square
cells. `cluster_hotspots` deterministically joins occupied cells using a
Chebyshev cell radius and reports a weighted center, count, percentage, ward
type, minute/time, role, and team distributions.

## Editable map labels

`map_regions.v1.json` contains the default `summoners-rift-conservative-v1`
polygons. They are versioned, approximate labels for broad areas only; they do
not recalibrate, normalize, or otherwise modify the raw WardSpawn coordinates.
Points on polygon boundaries are assigned inclusively. When polygons overlap,
the lowest numeric `priority`, then region id, wins. Use `load_region_map` or
pass an edited compatible mapping to `assign_regions`/`analyze_ward_rows`.

## DuckDB export

CSV uses Python's standard library. Parquet uses a temporary DuckDB table and
`COPY ... FORMAT PARQUET`; no pandas dependency is required.
