"""Pure WardSpawn research helpers for the V3 DuckDB surface.

Spatial facts come only from ``actual_x`` and ``actual_y`` on the canonical
``ward_research_events`` schema.  In particular, this module never reads
CastSpell target coordinate fields as a fallback.
"""

from __future__ import annotations

import copy
import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

WARD_RESEARCH_SCHEMA_VERSION = 1
CANONICAL_TABLE = "ward_research_events"
DIRECT_POSITION_STATUSES = frozenset({
    "VERIFIED_DIRECT", "VERIFIED_DIRECT_OBJECT_WRITE_TRACE", "ENTITY_SPAWN_DIRECT",
})
DEFAULT_REGION_MAP_PATH = Path(__file__).with_name("map_regions.v1.json")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
WARD_TYPE_ALIASES = {
    "yellow": "YELLOW_OR_SIGHT_WARD",
    "sight": "YELLOW_OR_SIGHT_WARD",
    "yellow_or_sight": "YELLOW_OR_SIGHT_WARD",
    "yellow_or_sight_ward": "YELLOW_OR_SIGHT_WARD",
    "control": "CONTROL_WARD",
    "control_ward": "CONTROL_WARD",
    "farsight": "FARSIGHT_WARD",
    "farsight_ward": "FARSIGHT_WARD",
    "other": "OTHER_WARD",
    "other_ward": "OTHER_WARD",
}


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _normal_token(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def _list(value: Any) -> list[Any] | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [item for item in value if item is not None and item != ""]
    return [value]


def _team(value: Any) -> int | None:
    if isinstance(value, str):
        value = {"blue": 100, "red": 200, "team_blue": 100, "team_red": 200}.get(value.strip().lower(), value)
    number = _finite(value)
    return int(number) if number in (100, 200) else None


def _normal_values(value: Any, normalizer) -> tuple[Any, ...] | None:
    items = _list(value)
    if not items:
        return None
    normalized = tuple(dict.fromkeys(item for item in (normalizer(value) for value in items) if item is not None))
    return normalized or None


def normalize_filters(filters: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Normalize V3 filters without changing source rows.

    ``team`` accepts 100/200/blue/red. ``perspective`` accepts ally/enemy and
    requires ``viewer_team``. Minute bounds are inclusive.
    """
    source = dict(filters or {})
    viewer_team = _team(source.get("viewer_team", source.get("viewerTeam")))
    raw_team = _list(source.get("team", source.get("owner_team")))
    team_values: list[int] = []
    relative: list[str] = []
    for item in raw_team or []:
        token = _normal_token(item)
        if token in {"ally", "enemy"}:
            relative.append(token)
        else:
            parsed = _team(item)
            if parsed is None:
                raise ValueError("team must contain 100, 200, blue, red, ally, or enemy")
            team_values.append(parsed)
    perspective = _normal_values(source.get("perspective"), _normal_token)
    if perspective is not None:
        invalid = set(perspective) - {"ally", "enemy", "unknown"}
        if invalid:
            raise ValueError("perspective must contain ally, enemy, or unknown")
    perspective = tuple(dict.fromkeys((perspective or ()) + tuple(relative))) or None
    if perspective and any(value in {"ally", "enemy"} for value in perspective) and viewer_team is None:
        raise ValueError("viewer_team is required for ally/enemy perspective filtering")

    def bounds(prefix: str) -> tuple[float | None, float | None]:
        value = source.get(prefix, source.get(f"{prefix}_range"))
        low = source.get(f"min_{prefix}", source.get(f"from_{prefix}"))
        high = source.get(f"max_{prefix}", source.get(f"to_{prefix}"))
        if value is not None:
            parts = value if isinstance(value, (list, tuple)) else str(value).replace("..", ",").split(",")
            if low is None and parts:
                low = parts[0]
            if high is None and len(parts) > 1:
                high = parts[1]
        low_number, high_number = _finite(low), _finite(high)
        if low_number is not None and high_number is not None and low_number > high_number:
            raise ValueError(f"minimum {prefix} must not exceed maximum {prefix}")
        return low_number, high_number

    min_minute, max_minute = bounds("minute")
    return {
        "team": tuple(dict.fromkeys(team_values)) or None,
        "perspective": perspective,
        "viewer_team": viewer_team,
        "role": _normal_values(source.get("role", source.get("owner_role")), _normal_token),
        "champion": _normal_values(source.get("champion", source.get("owner_champion")), _normal_token),
        "ward_type": _normal_values(
            source.get("ward_type", source.get("wardType")),
            lambda value: WARD_TYPE_ALIASES.get(
                _normal_token(value) or "", (_normal_token(value) or "").upper()
            ) or None,
        ),
        "enemy_jungler": _normal_values(
            source.get("enemy_jungler", source.get("enemy_jungler_champion")),
            _normal_token,
        ),
        "min_minute": min_minute,
        "max_minute": max_minute,
    }


def row_minute(row: Mapping[str, Any]) -> float | None:
    minute = _finite(row.get("minute"))
    if minute is not None:
        return minute
    timestamp = _finite(row.get("timestamp_ms"))
    return timestamp / 60000.0 if timestamp is not None else None


def row_perspective(row: Mapping[str, Any], viewer_team: int | None) -> str:
    team = _team(row.get("owner_team"))
    if team is None or viewer_team is None:
        return "unknown"
    return "ally" if team == viewer_team else "enemy"


def matches_filters(row: Mapping[str, Any], filters: Mapping[str, Any] | None = None) -> bool:
    normalized = normalize_filters(filters) if filters is None or "min_minute" not in filters else dict(filters)
    team = _team(row.get("owner_team"))
    if normalized["team"] and team not in normalized["team"]:
        return False
    perspective = row_perspective(row, normalized["viewer_team"])
    if normalized["perspective"] and perspective not in normalized["perspective"]:
        return False
    if normalized["role"] and _normal_token(row.get("owner_role")) not in normalized["role"]:
        return False
    if normalized["champion"] and _normal_token(row.get("owner_champion")) not in normalized["champion"]:
        return False
    if normalized["enemy_jungler"] and _normal_token(row.get("enemy_jungler_champion")) not in normalized["enemy_jungler"]:
        return False
    ward_type = (_normal_token(row.get("ward_type")) or "").upper()
    if normalized["ward_type"] and ward_type not in normalized["ward_type"]:
        return False
    minute = row_minute(row)
    if normalized["min_minute"] is not None and (minute is None or minute < normalized["min_minute"]):
        return False
    if normalized["max_minute"] is not None and (minute is None or minute > normalized["max_minute"]):
        return False
    return True


def filter_ward_rows(rows: Iterable[Mapping[str, Any]], filters: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return copied, filtered canonical rows; raw coordinate fields are untouched."""
    normalized = normalize_filters(filters)
    return [copy.deepcopy(dict(row)) for row in rows if matches_filters(row, normalized)]


def wardspawn_coordinates(row: Mapping[str, Any]) -> tuple[float, float] | None:
    """Return direct planar WardSpawn coordinates, or ``None``.

    Only the canonical direct fields ``actual_x`` and ``actual_y`` are read.
    A CastSpell coordinate such as ``cast_target_x`` is deliberately ignored.
    """
    x, y = _finite(row.get("actual_x")), _finite(row.get("actual_y"))
    if x is None or y is None:
        return None
    status = _normal_token(row.get("spawn_position_status"))
    if status is not None and status.upper() not in DIRECT_POSITION_STATUSES:
        return None
    return x, y


def load_region_map(path: str | Path | None = None) -> dict[str, Any]:
    """Load a versioned, editable approximate region definition."""
    region_map = json.loads(Path(path or DEFAULT_REGION_MAP_PATH).read_text(encoding="utf-8"))
    if region_map.get("schema_version") != 1 or not isinstance(region_map.get("regions"), list):
        raise ValueError("unsupported map-region document")
    return region_map


def _on_segment(x: float, y: float, a: Sequence[float], b: Sequence[float]) -> bool:
    ax, ay, bx, by = float(a[0]), float(a[1]), float(b[0]), float(b[1])
    cross = (x - ax) * (by - ay) - (y - ay) * (bx - ax)
    return abs(cross) <= 1e-9 and min(ax, bx) - 1e-9 <= x <= max(ax, bx) + 1e-9 and min(ay, by) - 1e-9 <= y <= max(ay, by) + 1e-9


def point_in_polygon(x: float, y: float, polygon: Sequence[Sequence[float]]) -> bool:
    """Inclusive ray-casting point-in-polygon test; polygon boundaries count in."""
    if len(polygon) < 3:
        raise ValueError("polygon requires at least three points")
    inside = False
    previous = polygon[-1]
    for current in polygon:
        if _on_segment(x, y, previous, current):
            return True
        xi, yi, xj, yj = float(current[0]), float(current[1]), float(previous[0]), float(previous[1])
        if (yi > y) != (yj > y):
            crossing_x = (xj - xi) * (y - yi) / (yj - yi) + xi
            if x < crossing_x:
                inside = not inside
        previous = current
    return inside


def assign_map_region(row: Mapping[str, Any], region_map: Mapping[str, Any] | None = None) -> str | None:
    coords = wardspawn_coordinates(row)
    if coords is None:
        return None
    x, y = coords
    regions = sorted((region_map or load_region_map()).get("regions", []), key=lambda item: (item.get("priority", 999), item.get("id", "")))
    for region in regions:
        bounds = region.get("bounds", {})
        if bounds and not (bounds.get("x_min", -math.inf) <= x <= bounds.get("x_max", math.inf) and bounds.get("y_min", -math.inf) <= y <= bounds.get("y_max", math.inf)):
            continue
        if point_in_polygon(x, y, region["polygon"]):
            return region["id"]
    return None


def assign_regions(rows: Iterable[Mapping[str, Any]], region_map: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Add ``map_region`` as a derived label without replacing raw coordinates."""
    region_map = region_map or load_region_map()
    result = []
    for source in rows:
        row = copy.deepcopy(dict(source))
        row["map_region"] = assign_map_region(row, region_map)
        result.append(row)
    return result


def build_grid_heatmap(rows: Iterable[Mapping[str, Any]], cell_size: float = 1000) -> list[dict[str, Any]]:
    if not isinstance(cell_size, (int, float)) or not math.isfinite(cell_size) or cell_size <= 0:
        raise ValueError("cell_size must be a positive finite number")
    cells: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
    for row in rows:
        coords = wardspawn_coordinates(row)
        if coords is None:
            continue
        x, y = coords
        key = (math.floor(x / cell_size), math.floor(y / cell_size))
        cells.setdefault(key, []).append(row)
    total = sum(len(cell_rows) for cell_rows in cells.values())
    return [
        {"cell_x": x_index * cell_size, "cell_y": y_index * cell_size, "cell_size": cell_size,
         "cell_x_index": x_index, "cell_y_index": y_index, "count": len(cell_rows),
         "percentage": (len(cell_rows) * 100.0 / total) if total else 0.0}
        for (x_index, y_index), cell_rows in sorted(cells.items())
    ]


def _distribution(rows: Iterable[Mapping[str, Any]], field: str, normalizer=lambda value: value) -> dict[str, int]:
    counts = Counter()
    for row in rows:
        value = normalizer(row.get(field))
        counts[str(value) if value is not None and value != "" else "unknown"] += 1
    return dict(sorted(counts.items()))


def cluster_hotspots(rows: Iterable[Mapping[str, Any]], cell_size: float = 1000, radius_cells: int = 1) -> list[dict[str, Any]]:
    """Partition occupied cells around deterministic local-density peaks.

    A peak is scored by the WardSpawn count in its Chebyshev ``radius_cells``
    neighbourhood.  Non-maximum suppression keeps peaks at least two local
    radius apart, then every occupied cell is assigned exactly once to its
    nearest retained peak.  Unlike connected components, this fixed-radius
    partition cannot merge a long chain of occupied cells into one hotspot.
    """
    if not isinstance(cell_size, (int, float)) or not math.isfinite(cell_size) or cell_size <= 0:
        raise ValueError("cell_size must be a positive finite number")
    if not isinstance(radius_cells, int) or radius_cells < 1:
        raise ValueError("radius_cells must be a positive integer")
    coordinate_rows = [row for row in rows if wardspawn_coordinates(row) is not None]
    buckets: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
    for row in coordinate_rows:
        x, y = wardspawn_coordinates(row)  # type: ignore[misc]
        buckets.setdefault((math.floor(x / cell_size), math.floor(y / cell_size)), []).append(row)
    cells = sorted(buckets)

    def chebyshev_distance(left: tuple[int, int], right: tuple[int, int]) -> int:
        return max(abs(left[0] - right[0]), abs(left[1] - right[1]))

    local_density = {
        cell: sum(
            len(buckets.get((cell[0] + offset_x, cell[1] + offset_y), ()))
            for offset_x in range(-radius_cells, radius_cells + 1)
            for offset_y in range(-radius_cells, radius_cells + 1)
        )
        for cell in cells
    }
    suppression_radius = radius_cells
    peaks: list[tuple[int, int]] = []
    for candidate in sorted(cells, key=lambda cell: (-local_density[cell], cell[0], cell[1])):
        if all(chebyshev_distance(candidate, peak) > suppression_radius for peak in peaks):
            peaks.append(candidate)

    clusters = {peak: [] for peak in peaks}
    for cell in cells:
        peak = min(
            peaks,
            key=lambda candidate: (
                chebyshev_distance(cell, candidate), -local_density[candidate], candidate[0], candidate[1],
            ),
        )
        clusters[peak].append(cell)
    total = len(coordinate_rows)
    results = []
    for index, peak in enumerate(sorted(clusters), 1):
        component = clusters[peak]
        cluster_rows = [row for cell in component for row in buckets[cell]]
        points = [wardspawn_coordinates(row) for row in cluster_rows]
        minute_distribution = _minute_distribution(cluster_rows)
        results.append({
            "hotspot_id": f"hotspot-{index:03d}", "cell_size": cell_size, "radius_cells": radius_cells,
            "cells": [{"cell_x_index": x, "cell_y_index": y} for x, y in component],
            "count": len(cluster_rows), "percentage": len(cluster_rows) * 100.0 / total if total else 0.0,
            "center": {"x": sum(point[0] for point in points if point) / len(points), "y": sum(point[1] for point in points if point) / len(points)},
            "ward_type_distribution": _distribution(cluster_rows, "ward_type", lambda value: (_normal_token(value) or "").upper() or None),
            "minute_distribution": minute_distribution,
            "time_distribution": minute_distribution.copy(),
            "role_distribution": _distribution(cluster_rows, "owner_role", _normal_token),
            "team_distribution": _distribution(cluster_rows, "owner_team", _team),
        })
    return results


def _minute_distribution(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter("unknown" if row_minute(row) is None else str(int(math.floor(row_minute(row) or 0))) for row in rows)
    return dict(sorted(counts.items(), key=lambda item: (item[0] == "unknown", int(item[0]) if item[0] != "unknown" else 0)))


def analyze_ward_rows(rows: Iterable[Mapping[str, Any]], filters: Mapping[str, Any] | None = None, *, cell_size: float = 1000, hotspot_radius_cells: int = 1, region_map: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Filter canonical rows, assign approximate regions, then derive grid/hotspots."""
    source_rows = list(rows)
    selected = filter_ward_rows(source_rows, filters)
    annotated = assign_regions(selected, region_map)
    coordinate_rows = [row for row in annotated if wardspawn_coordinates(row) is not None]
    return {
        "schema_version": WARD_RESEARCH_SCHEMA_VERSION,
        "status": "WARDSPAWN_RESEARCH_READY",
        "input_row_count": len(source_rows),
        "row_count": len(annotated), "spatial_row_count": len(coordinate_rows),
        "filters": normalize_filters(filters), "coordinate_policy": "ACTUAL_WARDSPAWN_X_Y_ONLY_NO_CASTSPELL_SUBSTITUTION",
        "map_regions": {"region_set": (region_map or load_region_map()).get("region_set"), "status": (region_map or load_region_map()).get("status")},
        "rows": annotated, "grid": build_grid_heatmap(annotated, cell_size),
        "hotspots": cluster_hotspots(annotated, cell_size, hotspot_radius_cells),
    }


def build_filter_sql(filters: Mapping[str, Any] | None = None) -> tuple[str, list[Any]]:
    """Return parameterized DuckDB WHERE SQL for ``ward_research_events``."""
    values = normalize_filters(filters)
    clauses: list[str] = []
    parameters: list[Any] = []
    def in_clause(column: str, items: tuple[Any, ...] | None) -> None:
        if items:
            clauses.append(f"{column} IN ({', '.join('?' for _ in items)})")
            parameters.extend(items)
    in_clause("owner_team", values["team"])
    if values["perspective"]:
        relative = values["perspective"]
        perspective_sql = []
        if "ally" in relative:
            perspective_sql.append("owner_team = ?"); parameters.append(values["viewer_team"])
        if "enemy" in relative:
            perspective_sql.append("owner_team <> ?"); parameters.append(values["viewer_team"])
        if "unknown" in relative:
            perspective_sql.append("owner_team IS NULL")
        clauses.append("(" + " OR ".join(perspective_sql) + ")")
    in_clause("lower(owner_role)", values["role"])
    in_clause("lower(owner_champion)", values["champion"])
    in_clause("lower(enemy_jungler_champion)", values["enemy_jungler"])
    in_clause("upper(ward_type)", values["ward_type"])
    if values["min_minute"] is not None:
        clauses.append("minute >= ?"); parameters.append(values["min_minute"])
    if values["max_minute"] is not None:
        clauses.append("minute <= ?"); parameters.append(values["max_minute"])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", parameters


def _quoted_source(source: str) -> str:
    parts = source.split(".")
    if not parts or not all(_SAFE_IDENTIFIER.fullmatch(part) for part in parts):
        raise ValueError("source must be a simple DuckDB table or view identifier")
    return ".".join(f'"{part}"' for part in parts)


def query_ward_rows(connection: Any, source: str = CANONICAL_TABLE, filters: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run the canonical filter query via a DuckDB-compatible connection."""
    where_sql, parameters = build_filter_sql(filters)
    cursor = connection.execute(f"SELECT * FROM {_quoted_source(source)}{where_sql}", parameters)
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, result)) for result in cursor.fetchall()]


def _columns(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    return list(dict.fromkeys(key for row in rows for key in row.keys()))


def write_query_output(rows: Iterable[Mapping[str, Any]], output_path: str | Path, output_format: str | None = None) -> Path:
    """Write filtered rows as CSV or Parquet; Parquet uses DuckDB only, not pandas."""
    materialized = [dict(row) for row in rows]
    destination = Path(output_path)
    output_format = (output_format or destination.suffix.lstrip(".")).lower()
    if output_format not in {"csv", "parquet"}:
        raise ValueError("output_format must be csv or parquet")
    destination.parent.mkdir(parents=True, exist_ok=True)
    columns = _columns(materialized)
    if output_format == "csv":
        with destination.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in materialized:
                writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})
        return destination
    try:
        import duckdb  # type: ignore
    except ImportError as error:
        raise RuntimeError("Parquet output requires the duckdb Python package") from error
    if not columns:
        connection = duckdb.connect()
        connection.execute("CREATE TEMP TABLE _ward_export (empty VARCHAR)")
    else:
        def sql_type(values: list[Any]) -> str:
            values = [value for value in values if value is not None]
            if values and all(isinstance(value, bool) for value in values): return "BOOLEAN"
            if values and all(isinstance(value, int) and not isinstance(value, bool) for value in values): return "BIGINT"
            if values and all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in values): return "DOUBLE"
            return "VARCHAR"
        connection = duckdb.connect()
        definition = ", ".join(f'"{column}" {sql_type([row.get(column) for row in materialized])}' for column in columns)
        connection.execute(f"CREATE TEMP TABLE _ward_export ({definition})")
        placeholders = ", ".join("?" for _ in columns)
        values = [[json.dumps(row.get(column), sort_keys=True) if isinstance(row.get(column), (dict, list)) else row.get(column) for column in columns] for row in materialized]
        if values:
            connection.executemany(f"INSERT INTO _ward_export VALUES ({placeholders})", values)
    safe_path = str(destination.resolve()).replace("'", "''")
    connection.execute(f"COPY _ward_export TO '{safe_path}' (FORMAT PARQUET)")
    connection.close()
    return destination


def export_duckdb_query(connection: Any, output_path: str | Path, source: str = CANONICAL_TABLE, filters: Mapping[str, Any] | None = None, output_format: str | None = None) -> Path:
    """Filter a DuckDB table/view and export the selected rows as CSV or Parquet."""
    return write_query_output(query_ward_rows(connection, source, filters), output_path, output_format)


__all__ = [
    "CANONICAL_TABLE", "WARD_RESEARCH_SCHEMA_VERSION", "DIRECT_POSITION_STATUSES", "normalize_filters", "row_minute", "row_perspective", "matches_filters", "filter_ward_rows", "wardspawn_coordinates", "load_region_map", "point_in_polygon", "assign_map_region", "assign_regions", "build_grid_heatmap", "cluster_hotspots", "analyze_ward_rows", "build_filter_sql", "query_ward_rows", "write_query_output", "export_duckdb_query",
]
