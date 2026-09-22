# V3 DuckDB ingest

This directory contains the streaming, idempotent ingest core for the ten-replay research corpus. It uses Python's standard library and `duckdb`. The default database is `research-v3/output/replay_research.duckdb`.

The database and published Parquet files are local working data and are not in the portable handoff package. The current workspace database includes the recognized additive V4 schema, so its full-container hash differs from the frozen V3 publication manifest. `verify_v3.py` now passes it only after classifying the delta as `EXPECTED_ADDITIVE_V4_CONTAINER_CHANGE` and proving that the frozen V3 tables still match the hash-bound Parquet publication. Generate a new atomic manifest before distributing the entire V4-extended container as one publication.

Batch directory ingest additionally requires Node.js on `PATH` to parse replay versions and validate ROFL files. Decoding an unknown, supported replay also requires `artifacts/runtime_probe/league_16.15.801.3452.memory.bin`. The batch command checks these dependencies before it starts the decode stage and names any missing input explicitly.

```powershell
python research-v3/cli.py init
python research-v3/cli.py ingest-artifacts
python research-v3/cli.py status
python research-v3/cli.py export replays ward_spawns hero_positions_1s --output-dir research-v3/output/parquet
python research-v3/cli.py publish
python research-v3/verify_v3.py --db research-v3/output/replay_research.duckdb
```

`ingest-artifacts` reads `artifacts/replay_manifest.json`, per-replay files below `artifacts/final_run/replays`, the full WardSpawn/lifecycle decode, and the hero-path/enriched-position artifacts. JSONL input is decoded one line at a time and inserted in bounded batches. Replays are deduplicated by SHA-256; a second run records an ingest run but inserts no duplicate facts. Patches outside the explicit supported set are retained in `ingest_rejections`, not silently decoded.

Every fact table carries `game_id`, `replay_sha256`, `patch`, decoder/confidence/status fields, and JSON provenance. JSON provenance retains the complete source object, including explicit JSON null values. Ward owners in the hero network-ID range are joined deterministically to metadata participants; owner ID zero remains NULL.

`publish` writes a publication bundle next to the selected database: `research_status.json`, `FIRST_RESEARCH_SANITY_REPORT.md`, `parquet/`, and `publication_manifest.json`. It checkpoints and closes writable database connections before calculating `database_sha256`; the status and report both carry that hash, and the manifest records SHA-256 and byte size for the database, status, report, and every exported Parquet file. `verify_v3.py --db <path>` resolves this sibling bundle by default and rejects stale or altered artifacts. Use `--status`, `--report`, `--parquet-dir`, or `--publication-manifest` only when verifying an explicitly located bundle.

Run tests with:

```powershell
python -m unittest discover -s research-v3/tests -v
```
