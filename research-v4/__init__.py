"""Additive V4 protection-telemetry DuckDB layer."""

from .protection_layer import (
    DEFAULT_DB,
    backfill_all_protection,
    backfill_protection,
    init_v4,
)

__all__ = [
    "DEFAULT_DB",
    "backfill_all_protection",
    "backfill_protection",
    "init_v4",
]
