"""Non-programmer CLI for the V3 League Replay research database."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb

try:
    from .batch_ingest import ingest_replay_directory
    from .core import DEFAULT_ARTIFACT_ROOT, DEFAULT_DB, DEFAULT_MANIFEST, ReplayStore
    from .research_layer import (
        export_research_parquet, publish_all, research_status,
        write_first_research_report, write_research_status,
    )
    from .ward_analysis import analyze_ward_rows, query_ward_rows, write_query_output
except ImportError:  # direct: python research-v3/cli.py
    from batch_ingest import ingest_replay_directory
    from core import DEFAULT_ARTIFACT_ROOT, DEFAULT_DB, DEFAULT_MANIFEST, ReplayStore
    from research_layer import (
        export_research_parquet, publish_all, research_status,
        write_first_research_report, write_research_status,
    )
    from ward_analysis import analyze_ward_rows, query_ward_rows, write_query_output


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--db", default=str(DEFAULT_DB), help="DuckDB file path")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create all schema tables")

    ingest_directory = commands.add_parser(
        "ingest", help="discover, de-duplicate, decode and ingest a Replay directory"
    )
    ingest_directory.add_argument("replay_directory")
    ingest_directory.add_argument("--max-position-age-ms", type=int, default=2000)

    ingest = commands.add_parser(
        "ingest-artifacts", help="stream the current decoded artifacts into DuckDB"
    )
    ingest.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ingest.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    ingest.add_argument("--max-position-age-ms", type=int, default=2000)

    publish = commands.add_parser(
        "publish", help="materialize research tables, status, report and Parquet"
    )
    publish.add_argument("--max-position-age-ms", type=int, default=2000)

    status = commands.add_parser("status", help="print the V3 data-quality status")
    status.add_argument("--write", action="store_true", help="also update research_status.json")

    report = commands.add_parser("report", help="generate FIRST_RESEARCH_SANITY_REPORT.md")
    report.add_argument("--output")

    wards = commands.add_parser("wards", help="query actual WardSpawn research rows")
    wards.add_argument("--team")
    wards.add_argument("--perspective-team", dest="viewer_team", type=int)
    wards.add_argument("--perspective", choices=("ally", "enemy", "unknown"))
    wards.add_argument("--role")
    wards.add_argument("--champion")
    wards.add_argument("--enemy-jungler")
    wards.add_argument("--ward-type")
    wards.add_argument("--minute-from", type=float)
    wards.add_argument("--minute-to", type=float)
    wards.add_argument("--max-position-age-ms", type=int)
    wards.add_argument("--cell-size", type=float, default=1000.0)
    wards.add_argument("--hotspot-radius-cells", type=int, default=1)
    wards.add_argument("--output", default="research-v3/output/queries/wards.csv")
    wards.add_argument("--format", choices=("csv", "parquet"))
    wards.add_argument("--analysis-output")

    export = commands.add_parser("export", help="export research tables to Parquet")
    export.add_argument("tables", nargs="*", help="table names; default exports all research tables")
    export.add_argument("--output-dir", default="research-v3/output/parquet")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = ReplayStore(args.db)
    if args.command == "init":
        result = {"db_path": str(store.init()), "status": "INITIALIZED"}
    elif args.command == "ingest":
        result = ingest_replay_directory(
            args.replay_directory, db_path=args.db,
            max_position_age_ms=args.max_position_age_ms,
        )
    elif args.command == "ingest-artifacts":
        base = store.ingest_artifacts(
            args.manifest, args.artifact_root, args.max_position_age_ms
        )
        result = {
            "base_ingest": base,
            "publication": publish_all(
                args.db, max_position_age_ms=args.max_position_age_ms
            ),
        }
    elif args.command == "publish":
        result = publish_all(args.db, max_position_age_ms=args.max_position_age_ms)
    elif args.command == "status":
        result = research_status(args.db)
        if args.write:
            result["status_path"] = str(write_research_status(args.db))
    elif args.command == "report":
        path = (
            write_first_research_report(args.db, args.output)
            if args.output else write_first_research_report(args.db)
        )
        result = {"report": str(path)}
    elif args.command == "wards":
        filters = {
            "team": args.team, "viewer_team": args.viewer_team,
            "perspective": args.perspective, "role": args.role,
            "champion": args.champion, "enemy_jungler": args.enemy_jungler,
            "ward_type": args.ward_type, "min_minute": args.minute_from,
            "max_minute": args.minute_to,
        }
        with duckdb.connect(str(Path(args.db).resolve()), read_only=True) as connection:
            rows = query_ward_rows(connection, filters=filters)
        if args.max_position_age_ms is not None:
            if args.max_position_age_ms < 0:
                raise ValueError("max-position-age-ms must be non-negative")
            position_fields = (
                "owner_position_x", "owner_position_y", "nearest_enemy_distance",
                "enemy_jungler_distance", "allied_adc_position_x",
                "allied_adc_position_y", "allied_support_position_x",
                "allied_support_position_y", "nearby_enemy_count",
                "nearby_ally_count",
            )
            for row in rows:
                age = row.get("owner_position_source_age_ms")
                row["query_max_position_age_ms"] = args.max_position_age_ms
                if age is None or age > args.max_position_age_ms:
                    for field in position_fields:
                        row[field] = None
                    row["owner_position_freshness"] = "STALE_BY_QUERY_THRESHOLD"
        output = write_query_output(rows, args.output, args.format)
        analysis = analyze_ward_rows(
            rows, cell_size=args.cell_size,
            hotspot_radius_cells=args.hotspot_radius_cells,
        )
        analysis_path = Path(
            args.analysis_output or output.with_suffix(".analysis.json")
        ).resolve()
        analysis_path.parent.mkdir(parents=True, exist_ok=True)
        compact_analysis = {key: value for key, value in analysis.items() if key != "rows"}
        analysis_path.write_text(
            json.dumps(compact_analysis, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result = {
            "status": "PASS", "row_count": len(rows), "output": str(output),
            "analysis": str(analysis_path), "grid_cell_count": len(analysis["grid"]),
            "hotspot_count": len(analysis["hotspots"]),
        }
    else:
        exports = (
            store.export(args.tables, args.output_dir) if args.tables
            else export_research_parquet(args.db, args.output_dir)
        )
        result = {"db_path": str(Path(args.db).resolve()), "exports": exports}
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
