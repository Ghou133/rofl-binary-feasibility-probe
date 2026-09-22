"""Measure one Protection V4 backfill without weakening decoder attestation."""
from __future__ import annotations

import argparse
import cProfile
import json
import pstats
import time
from collections import Counter
from pathlib import Path
from typing import Any

import duckdb

import protection_layer as layer


class TimedConnection:
    """DuckDB connection proxy which attributes Python-to-SQL boundary time."""

    def __init__(self, connection: duckdb.DuckDBPyConnection) -> None:
        self.connection = connection
        self.calls: Counter[str] = Counter()
        self.seconds: Counter[str] = Counter()

    @staticmethod
    def _key(method: str, statement: str) -> str:
        normalized = " ".join(statement.split()).upper()
        verb = normalized.split(" ", 1)[0] if normalized else "EMPTY"
        if verb in {"DELETE", "INSERT", "UPDATE", "BEGIN", "COMMIT", "ROLLBACK"}:
            return f"{method}:{verb}"
        if normalized.startswith("SELECT"):
            return f"{method}:SELECT"
        return f"{method}:{verb}"

    def execute(self, statement: str, parameters: Any = None) -> "TimedConnection":
        key = self._key("execute", statement)
        started = time.perf_counter()
        if parameters is None:
            self.connection.execute(statement)
        else:
            self.connection.execute(statement, parameters)
        self.calls[key] += 1
        self.seconds[key] += time.perf_counter() - started
        return self

    def executemany(self, statement: str, parameters: Any) -> "TimedConnection":
        key = self._key("executemany", statement)
        started = time.perf_counter()
        self.connection.executemany(statement, parameters)
        self.calls[key] += 1
        self.seconds[key] += time.perf_counter() - started
        return self

    def __getattr__(self, name: str) -> Any:
        return getattr(self.connection, name)


def _elapsed(fn, *args, **kwargs):
    started = time.perf_counter()
    value = fn(*args, **kwargs)
    return value, time.perf_counter() - started


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(layer.DEFAULT_DB))
    parser.add_argument("--decoded-jsonl", action="append", required=True)
    parser.add_argument("--replay-sha256", required=True)
    args = parser.parse_args()

    # Preserve the caller's path spelling: it is attested provenance persisted
    # in protection_v4_profiles.details_json, so benchmark invocation must not
    # rewrite slash style before comparing semantic fingerprints.
    paths = args.decoded_jsonl
    artifacts, artifact_seconds = _elapsed(layer._load_decoder_artifacts, paths)
    validated, filtering_seconds = _elapsed(
        layer._validated_decoded_inputs, paths, args.replay_sha256, artifacts=artifacts
    )
    with duckdb.connect(args.db) as raw_connection:
        timed_connection = TimedConnection(raw_connection)
        _, schema_seconds = _elapsed(layer.init_v4, timed_connection)
        profiler = cProfile.Profile()
        started = time.perf_counter()
        result = profiler.runcall(
            layer._backfill_decoded,
            timed_connection,
            replay_sha256=args.replay_sha256,
            decoded=validated[0],
            input_paths=paths,
            validated_input=validated,
        )
        backfill_seconds = time.perf_counter() - started
    stats = pstats.Stats(profiler).strip_dirs().sort_stats("cumulative")
    profile_rows = []
    for (filename, line, function), values in list(stats.stats.items()):
        cc, nc, tt, ct, callers = values
        if filename.endswith("protection_layer.py"):
            profile_rows.append({
                "function": f"{function} ({line})", "calls": nc,
                "self_seconds": round(tt, 6), "cumulative_seconds": round(ct, 6),
            })
    profile_rows.sort(key=lambda row: row["cumulative_seconds"], reverse=True)
    print(json.dumps({
        "replay_sha256": args.replay_sha256,
        "result": result,
        "seconds": {
            "artifact_read_parse_and_attestation": round(artifact_seconds, 6),
            "per_replay_filtering": round(filtering_seconds, 6),
            "schema_init": round(schema_seconds, 6),
            "backfill_total": round(backfill_seconds, 6),
        },
        "sql": {
            "calls": dict(timed_connection.calls),
            "seconds": {key: round(value, 6) for key, value in timed_connection.seconds.items()},
        },
        "profile_top": profile_rows[:25],
    }, indent=2))


if __name__ == "__main__":
    main()
