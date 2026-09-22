"""Streaming, idempotent DuckDB ingest for the V3 replay research dataset."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = Path(__file__).resolve().parent / "output" / "replay_research.duckdb"
DEFAULT_MANIFEST = PROJECT_ROOT / "artifacts" / "replay_manifest.json"
DEFAULT_ARTIFACT_ROOT = PROJECT_ROOT / "artifacts"
SUPPORTED_PATCHES = {"16.15.801.3452"}
BATCH_SIZE = 10_000


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def stable_id(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def game_id_from_label(label: str | None) -> str | None:
    if not label:
        return None
    return label.rsplit("-", 1)[-1]


def iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield one decoded object at a time; never materialize a JSONL artifact."""
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                yield line_number, json.loads(line)


def _chunks(rows: Iterable[Sequence[Any]], size: int = BATCH_SIZE) -> Iterator[list[Sequence[Any]]]:
    batch: list[Sequence[Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


class ReplayStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = Path(db_path).resolve()

    def connect(self) -> duckdb.DuckDBPyConnection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        return duckdb.connect(str(self.db_path))

    def init(self) -> Path:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with self.connect() as con:
            con.execute(schema)
        return self.db_path

    @staticmethod
    def _insert_batches(con: duckdb.DuckDBPyConnection, sql: str, rows: Iterable[Sequence[Any]]) -> int:
        count = 0
        for batch in _chunks(rows):
            con.executemany(sql, batch)
            count += len(batch)
        return count

    def ingest_artifacts(
        self,
        manifest_path: str | Path = DEFAULT_MANIFEST,
        artifact_root: str | Path = DEFAULT_ARTIFACT_ROOT,
        max_position_age_ms: int = 2000,
    ) -> dict[str, Any]:
        self.init()
        manifest_path = Path(manifest_path).resolve()
        artifact_root = Path(artifact_root).resolve()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        run_id = str(uuid.uuid4())
        started = utcnow()
        counts: dict[str, int] = {}
        accepted: dict[str, dict[str, Any]] = {}
        rejected = 0

        with self.connect() as con:
            con.execute(
                "INSERT INTO ingest_runs VALUES (?, ?, NULL, 'RUNNING', ?, ?, 0, 0, NULL)",
                [run_id, started, str(manifest_path), str(artifact_root)],
            )
            try:
                existing = {r[0] for r in con.execute("SELECT replay_sha256 FROM replays").fetchall()}
                for replay in manifest.get("replays", []):
                    sha = replay.get("replay_sha256")
                    patch = replay.get("patch")
                    game_id = str(replay.get("game_id"))
                    if patch not in SUPPORTED_PATCHES:
                        rejection_id = stable_id(run_id, sha, "UNSUPPORTED_PATCH")
                        con.execute(
                            "INSERT INTO ingest_rejections VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            [rejection_id, run_id, game_id, sha, patch, "UNSUPPORTED_REPLAY_VERSION", compact_json(replay), utcnow()],
                        )
                        rejected += 1
                    elif sha not in existing:
                        accepted[sha] = replay

                if accepted:
                    counts["replays"] = self._ingest_replays(con, accepted, artifact_root)
                    counts["participants"] = self._ingest_participants(con, accepted, artifact_root)
                    for table, filename in (
                        ("death_events", "death_events.jsonl"),
                        ("damage_events", "damage_events.jsonl"),
                        ("spell_events", "spell_events.jsonl"),
                        ("buff_events", "buff_events.jsonl"),
                    ):
                        counts[table] = self._ingest_event_table(con, table, filename, accepted, artifact_root)
                    adc_counts = self._ingest_adc(con, accepted, artifact_root)
                    counts.update(adc_counts)
                    counts["ward_spawns"] = self._ingest_ward_spawns(con, accepted, artifact_root)
                    counts["ward_lifecycles"] = self._ingest_ward_lifecycles(con, accepted, artifact_root)
                    counts["ward_research_events"] = self._materialize_ward_research(con, accepted)
                    counts["hero_paths"] = self._ingest_hero_paths(con, accepted, artifact_root)
                    counts["hero_positions_1s"] = self._ingest_positions(con, accepted, artifact_root)

                # Position-context research is materialized by research_layer.py.  The
                # base ingest deliberately stops after canonical, provenance-rich facts.

                inserted = sum(counts.values())
                status = "COMPLETED_WITH_REJECTIONS" if rejected else "COMPLETED"
                details = {"table_counts": counts, "rejections": rejected, "deduplicated_replays": len(existing)}
                con.execute(
                    "UPDATE ingest_runs SET finished_at=?, status=?, replay_count=?, inserted_rows=?, details_json=? WHERE run_id=?",
                    [utcnow(), status, len(accepted), inserted, compact_json(details), run_id],
                )
                return {"run_id": run_id, "status": status, "db_path": str(self.db_path), **details}
            except Exception as exc:
                con.execute(
                    "UPDATE ingest_runs SET finished_at=?, status='FAILED', details_json=? WHERE run_id=?",
                    [utcnow(), compact_json({"error": f"{type(exc).__name__}: {exc}"}), run_id],
                )
                raise

    @staticmethod
    def _replay_dir(artifact_root: Path, game_id: str) -> Path:
        return artifact_root / "final_run" / "replays" / f"HN1-{game_id}"

    def _ingest_replays(self, con, accepted, artifact_root) -> int:
        inventory = json.loads((artifact_root / "final_run" / "rofl_inventory.json").read_text(encoding="utf-8"))
        by_sha = {item["sha256"]: item for item in inventory}
        rows = []
        for sha, replay in accepted.items():
            inv = by_sha.get(sha, {})
            profile = inv.get("decoder_profile")
            rows.append((str(replay["game_id"]), sha, replay["patch"], f"HN1-{replay['game_id']}", replay.get("sample_role"), replay.get("replay_path"), inv.get("duration"), compact_json(profile) if profile else None, "VERIFIED", replay.get("decoder_status"), compact_json({"manifest": replay, "inventory": inv}), utcnow()))
        con.executemany("INSERT INTO replays VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        return len(rows)

    def _ingest_participants(self, con, accepted, artifact_root) -> int:
        inventory = json.loads((artifact_root / "final_run" / "rofl_inventory.json").read_text(encoding="utf-8"))
        by_sha = {item["sha256"]: item for item in inventory}
        rows = []
        for sha, replay in accepted.items():
            inv = by_sha.get(sha, {})
            for index, player in enumerate(inv.get("metadata", {}).get("players", []), 1):
                participant_id = index
                network_id = 0x400000AD + participant_id
                rows.append((stable_id("participant", sha, participant_id), str(replay["game_id"]), sha, replay["patch"], participant_id, network_id, player.get("champion"), player.get("team_id"), player.get("team"), player.get("role"), player.get("win"), "rofl-metadata-stats-json-v1", player.get("confidence", "VERIFIED"), player.get("role_status"), compact_json(player)))
        return self._insert_batches(con, "INSERT INTO participants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def _ingest_event_table(self, con, table, filename, accepted, artifact_root) -> int:
        specs = {
            "death_events": ("INSERT INTO death_events VALUES (" + ",".join(["?"] * 15) + ")", self._death_row),
            "damage_events": ("INSERT INTO damage_events VALUES (" + ",".join(["?"] * 20) + ")", self._damage_row),
            "spell_events": ("INSERT INTO spell_events VALUES (" + ",".join(["?"] * 25) + ")", self._spell_row),
            "buff_events": ("INSERT INTO buff_events VALUES (" + ",".join(["?"] * 20) + ")", self._buff_row),
        }
        sql, builder = specs[table]

        def rows():
            for sha, replay in accepted.items():
                path = self._replay_dir(artifact_root, str(replay["game_id"])) / filename
                for line_no, obj in iter_jsonl(path):
                    yield builder(obj, replay, sha, line_no)
        return self._insert_batches(con, sql, rows())

    @staticmethod
    def _base(obj, replay, sha, kind, line_no):
        return (stable_id(kind, sha, line_no), str(replay["game_id"]), sha, replay["patch"])

    def _death_row(self, o, r, sha, n):
        return self._base(o, r, sha, "death", n) + (o.get("replay_time_ms"), o.get("source_network_id"), o.get("target_network_id"), o.get("source_participant_id"), o.get("target_participant_id"), o.get("source_champion"), o.get("target_champion"), o.get("decoder_profile"), o.get("confidence"), o.get("semantic_status"), compact_json(o))

    def _damage_row(self, o, r, sha, n):
        return self._base(o, r, sha, "damage", n) + (o.get("replay_time_ms"), o.get("source_network_id"), o.get("target_network_id"), o.get("source_participant_id"), o.get("target_participant_id"), o.get("source_champion"), o.get("target_champion"), o.get("amount"), o.get("damage_type"), o.get("spell"), o.get("spell_slot"), o.get("is_basic_attack"), o.get("decoder_profile"), o.get("confidence"), o.get("semantic_status"), compact_json(o))

    def _spell_row(self, o, r, sha, n):
        pos, target = o.get("position") or [], o.get("target_position") or []
        return self._base(o, r, sha, "spell", n) + (o.get("replay_time_ms"), o.get("source_network_id"), o.get("target_network_id"), o.get("source_participant_id"), o.get("target_participant_id"), o.get("source_champion"), o.get("target_champion"), o.get("spell_identifier"), o.get("spell_slot"), o.get("spell_key"), o.get("target_count"), *(pos + [None] * 3)[:3], *(target + [None] * 3)[:3], o.get("decoder_profile"), o.get("confidence"), o.get("semantic_status"), compact_json(o))

    def _buff_row(self, o, r, sha, n):
        return self._base(o, r, sha, "buff", n) + (o.get("replay_time_ms"), o.get("source_network_id"), o.get("target_network_id"), o.get("source_participant_id"), o.get("target_participant_id"), o.get("buff_operation"), o.get("buff_slot"), o.get("buff_name_hash"), o.get("buff_type"), o.get("stack_count"), o.get("duration_seconds"), o.get("lifecycle_id"), o.get("decoder_profile"), o.get("confidence"), o.get("semantic_status"), compact_json(o))

    def _ingest_adc(self, con, accepted, artifact_root) -> dict[str, int]:
        death_rows, damage_rows, support_rows = [], [], []
        for sha, replay in accepted.items():
            path = self._replay_dir(artifact_root, str(replay["game_id"])) / "adc_deaths.jsonl"
            for line_no, o in iter_jsonl(path):
                death_id = stable_id("adc_death", sha, line_no)
                common = (str(replay["game_id"]), sha, replay["patch"])
                raw_death = o.get("raw_death_event") or {}
                death_rows.append((death_id, *common, o.get("adc"), o.get("adc_participant_id"), o.get("support"), o.get("support_participant_id"), o.get("death_time_ms"), o.get("combat_start_ms"), o.get("combat_duration_ms"), o.get("killer"), o.get("nearby_enemy_count"), o.get("nearby_ally_count"), o.get("support_distance"), raw_death.get("decoder_profile"), raw_death.get("confidence", "VERIFIED_DERIVED"), raw_death.get("semantic_status", "DERIVED"), compact_json(o)))
                for i, a in enumerate(o.get("attackers") or []):
                    damage_rows.append((stable_id(death_id, "attacker", i), *common, death_id, a.get("participant_id"), a.get("champion"), a.get("network_id"), a.get("hit_count"), a.get("damage_amount"), a.get("first_hit_time_ms"), a.get("last_hit_time_ms"), "adc-combat-window-v1", a.get("confidence", "VERIFIED_DERIVED"), "DERIVED", compact_json(a)))
                actions = [("SPELL_CAST", x) for x in (o.get("support_spell_casts") or [])] + [("BUFF", x) for x in (o.get("support_buff_events") or [])]
                for i, (kind, a) in enumerate(actions):
                    support_rows.append((stable_id(death_id, "support", i), *common, death_id, kind, a.get("replay_time_ms"), a.get("spell_identifier"), a.get("spell_slot"), a.get("source_network_id"), a.get("target_network_id"), a.get("decoder_profile", "adc-support-correlation-v1"), a.get("confidence", "VERIFIED_DERIVED"), a.get("semantic_status", "DERIVED"), compact_json(a)))
        return {
            "adc_deaths": self._insert_batches(con, "INSERT INTO adc_deaths VALUES (" + ",".join(["?"] * 19) + ")", death_rows),
            "adc_death_damage": self._insert_batches(con, "INSERT INTO adc_death_damage VALUES (" + ",".join(["?"] * 16) + ")", damage_rows),
            "adc_death_support_actions": self._insert_batches(con, "INSERT INTO adc_death_support_actions VALUES (" + ",".join(["?"] * 15) + ")", support_rows),
        }

    def _ingest_ward_spawns(self, con, accepted, artifact_root) -> int:
        path = artifact_root / "v2_ward_spawn" / "current_full_decode" / "ward_spawns.jsonl"
        def rows():
            for line_no, o in iter_jsonl(path):
                raw = o.get("raw_packet_ref") or {}
                sha = raw.get("replay_sha256")
                if sha not in accepted:
                    continue
                replay = accepted[sha]
                owner_network_id = o.get("owner_network_id")
                if owner_network_id and 0x400000AE <= owner_network_id <= 0x400000B7:
                    participant_id = owner_network_id - 0x400000AD
                    team_id = 100 if participant_id <= 5 else 200
                    owner_confidence = "VERIFIED_DERIVED_NETWORK_ID_JOIN"
                else:
                    participant_id = team_id = None
                    owner_confidence = "UNAVAILABLE"
                pos = o.get("position") or {}
                yield (stable_id("ward_spawn", sha, line_no), str(replay["game_id"]), sha, replay["patch"], o.get("replay_time_ms"), owner_network_id, o.get("entity_network_id"), participant_id, team_id, o.get("ward_type"), o.get("generic_name"), o.get("entity_name"), pos.get("x"), pos.get("y"), pos.get("height"), owner_confidence, o.get("decoder_profile"), "VERIFIED_DIRECT_OBJECT_WRITE_TRACE", "DECODED", compact_json(o))
        return self._insert_batches(con, "INSERT INTO ward_spawns VALUES (" + ",".join(["?"] * 20) + ")", rows())

    def _ingest_ward_lifecycles(self, con, accepted, artifact_root) -> int:
        path = artifact_root / "v2_ward_spawn" / "current_full_decode" / "ward_lifecycle.jsonl"
        def rows():
            for line_no, o in iter_jsonl(path):
                sha = (o.get("spawn_raw_packet_ref") or {}).get("replay_sha256")
                if sha not in accepted:
                    continue
                replay = accepted[sha]
                yield (stable_id("ward_lifecycle", sha, line_no), str(replay["game_id"]), sha, replay["patch"], o.get("ward_network_id"), o.get("spawn_time_ms"), o.get("remove_time_ms"), o.get("duration_ms"), o.get("removal_reason"), o.get("match_rule"), o.get("coordinate_error"), "rofl-16.15.801.3452-ward-lifecycle-v1", "VERIFIED_DERIVED", "MATCHED", compact_json(o))
        return self._insert_batches(con, "INSERT INTO ward_lifecycles VALUES (" + ",".join(["?"] * 15) + ")", rows())

    def _ingest_hero_paths(self, con, accepted, artifact_root) -> int:
        path = artifact_root / "v2_ward_spawn" / "current_path_hero_events_all10.jsonl"
        def rows():
            for line_no, o in iter_jsonl(path):
                sha = o.get("replay_sha256")
                if sha not in accepted:
                    continue
                replay = accepted[sha]
                provenance = {"raw_packet_occurrence_index": o.get("raw_packet_occurrence_index"), "record_index": o.get("record_index"), "source": o}
                yield (stable_id("hero_path", sha, line_no), str(replay["game_id"]), sha, replay["patch"], o.get("timestamp_ms"), o.get("entity_id"), o.get("speed"), compact_json(o.get("candidate_waypoints_xz")), o.get("raw_packet_occurrence_index"), o.get("record_index"), "rofl-16.15.801.3452-path-0x02d1-v1", o.get("coordinate_transform_status"), "DECODED", compact_json(provenance))
        return self._insert_batches(con, "INSERT INTO hero_paths VALUES (" + ",".join(["?"] * 14) + ")", rows())

    def _ingest_positions(self, con, accepted, artifact_root) -> int:
        path = artifact_root / "v2_ward_spawn" / "current_path_hero_positions_1s_all10_enriched.jsonl"
        def rows():
            for line_no, o in iter_jsonl(path):
                sha = o.get("replay_sha256")
                if sha not in accepted:
                    continue
                replay = accepted[sha]
                pos = o.get("position_xz") or []
                source_ts = o.get("source_path_timestamp_ms")
                source_age = o.get("timestamp_ms") - source_ts if isinstance(source_ts, (int, float)) else None
                yield (stable_id("hero_position_1s", sha, line_no), str(replay["game_id"]), sha, replay["patch"], o.get("timestamp_ms"), o.get("entity_id"), (pos + [None, None])[0], (pos + [None, None])[1], source_ts, source_age, o.get("interpolation", "LINEAR_ALONG_DECODED_WAYPOINTS"), "VERIFIED_DERIVED", compact_json(o.get("raw_packet_ref")) if o.get("raw_packet_ref") else None, "rofl-16.15.801.3452-path-position-1s-v1", "VERIFIED_DERIVED", "ENRICHED", compact_json(o))
        return self._insert_batches(con, "INSERT INTO hero_positions_1s VALUES (" + ",".join(["?"] * 17) + ")", rows())

    def _materialize_ward_research(self, con, accepted) -> int:
        if not accepted:
            return 0
        before = con.execute("SELECT count(*) FROM ward_research_events").fetchone()[0]
        con.execute("""
            INSERT OR IGNORE INTO ward_research_events
            SELECT w.fact_id, w.game_id, w.replay_sha256, w.patch, w.replay_time_ms,
                   w.replay_time_ms / 60000.0, 'WARD_SPAWN', w.entity_network_id,
                   w.ward_type, w.owner_participant_id, p.champion, p.role, w.owner_team_id,
                   w.position_x, w.position_y, w.position_height,
                   'VERIFIED_DIRECT_OBJECT_WRITE_TRACE', l.remove_time_ms, l.duration_ms,
                   CASE WHEN l.fact_id IS NULL THEN 'OPEN_OR_UNMATCHED' ELSE 'MATCHED' END,
                   w.decoder_profile, w.confidence, w.status, w.raw_provenance_json
            FROM ward_spawns w
            LEFT JOIN participants p ON p.replay_sha256=w.replay_sha256
                                    AND p.participant_id=w.owner_participant_id
            LEFT JOIN ward_lifecycles l ON l.replay_sha256=w.replay_sha256
                                       AND l.ward_network_id=w.entity_network_id
        """)
        return con.execute("SELECT count(*) FROM ward_research_events").fetchone()[0] - before

    def _derive_position_context(self, con, replay_shas, max_age_ms) -> dict[str, int]:
        """Run conservative, no-lookahead position joins over already-ingested facts."""
        if not replay_shas:
            return {}
        try:
            from position_context import (
                PositionIndex, build_adc_death_position_context,
                build_ward_death_context, build_ward_position_context,
            )
        except ImportError:
            from .position_context import (
                PositionIndex, build_adc_death_position_context,
                build_ward_death_context, build_ward_position_context,
            )
        placeholders = ",".join("?" for _ in replay_shas)
        args = list(replay_shas)
        positions = [
            {"replay_sha256": r[0], "entity_id": r[1], "timestamp_ms": r[2],
             "position_xz": [r[3], r[4]], "source_path_timestamp_ms": r[5]}
            for r in con.execute(
                f"SELECT replay_sha256,entity_id,replay_time_ms,position_x,position_z,source_path_timestamp_ms FROM hero_positions_1s WHERE replay_sha256 IN ({placeholders})",
                args,
            ).fetchall()
        ]
        if not positions:
            return {}
        index = PositionIndex(positions)
        participants = [
            {"game_id": r[0], "replay_sha256": r[1], "patch": r[2], "participant_id": r[3],
             "network_id": r[4], "champion": r[5], "team_id": r[6], "role": r[7]}
            for r in con.execute(
                f"SELECT game_id,replay_sha256,patch,participant_id,network_id,champion,team_id,role FROM participants WHERE replay_sha256 IN ({placeholders})", args
            ).fetchall()
        ]
        wards = [
            {"game_id": r[0], "replay_sha256": r[1], "patch": r[2], "replay_time_ms": r[3],
             "owner_network_id": r[4], "entity_network_id": r[5], "owner_participant_id": r[6],
             "owner_team_id": r[7], "x": r[8], "y": r[9]}
            for r in con.execute(
                f"SELECT game_id,replay_sha256,patch,replay_time_ms,owner_network_id,entity_network_id,owner_participant_id,owner_team_id,position_x,position_y FROM ward_spawns WHERE replay_sha256 IN ({placeholders})", args
            ).fetchall()
        ]
        lifecycles = [
            {"replay_sha256": r[0], "ward_network_id": r[1], "spawn_time_ms": r[2], "remove_time_ms": r[3]}
            for r in con.execute(
                f"SELECT replay_sha256,ward_network_id,spawn_time_ms,remove_time_ms FROM ward_lifecycles WHERE replay_sha256 IN ({placeholders})", args
            ).fetchall()
        ]
        adc_deaths = []
        for r in con.execute(
            f"SELECT fact_id,game_id,replay_sha256,patch,adc_participant_id,death_time_ms,combat_start_ms,raw_provenance_json FROM adc_deaths WHERE replay_sha256 IN ({placeholders})", args
        ).fetchall():
            raw = json.loads(r[7]) if isinstance(r[7], str) else (r[7] or {})
            adc_deaths.append({**raw, "fact_id": r[0], "game_id": r[1], "replay_sha256": r[2], "patch": r[3], "adc_participant_id": r[4], "death_time_ms": r[5], "combat_start_ms": r[6]})

        ward_context = build_ward_position_context(wards, participants, index, max_age_ms)
        wc_rows = []
        replay_meta = {p["replay_sha256"]: p for p in participants}
        for row in ward_context:
            meta = replay_meta[row["replay_sha256"]]
            owner = row.get("owner_position") or {}
            wc_rows.append((stable_id("ward_position_context", row["replay_sha256"], row.get("ward_network_id")), meta["game_id"], row["replay_sha256"], meta["patch"], row.get("ward_network_id"), row.get("timestamp_ms"), row.get("owner_participant_id"), owner.get("x"), owner.get("y"), row.get("nearest_enemy_distance"), row.get("enemy_jungler_distance"), row.get("nearby_enemy_count"), row.get("nearby_ally_count"), "path-position-context-v1", "VERIFIED_DERIVED", row.get("position_status"), compact_json(row)))
        con.executemany("INSERT OR IGNORE INTO ward_position_context VALUES (" + ",".join(["?"] * 17) + ")", wc_rows)

        adc_context, features = build_adc_death_position_context(adc_deaths, participants, index, max_age_ms)
        ac_rows = []
        for row in adc_context:
            pos = row.get("subject_position") or {}
            network_id = 0x400000AD + row["adc_participant_id"] if row.get("adc_participant_id") else None
            ac_rows.append((stable_id("adc_position_context", row["death_context_id"], row["checkpoint"]), row.get("game_id"), row["replay_sha256"], row.get("patch"), row["death_context_id"], row["checkpoint_time_ms"], network_id, pos.get("x"), pos.get("y"), row["checkpoint"], "path-position-context-v1", "VERIFIED_DERIVED", row.get("position_status"), compact_json(row)))
        con.executemany("INSERT OR IGNORE INTO adc_death_position_context VALUES (" + ",".join(["?"] * 14) + ")", ac_rows)
        feature_rows = [(stable_id("adc_feature", r["death_context_id"]), r.get("game_id"), r["replay_sha256"], r.get("patch"), r["death_context_id"], "position_combat_features", r.get("time_to_die_ms"), compact_json(r), "path-position-context-v1", "VERIFIED_DERIVED", r.get("position_context_status"), compact_json(r)) for r in features]
        con.executemany("INSERT OR IGNORE INTO adc_death_features VALUES (" + ",".join(["?"] * 12) + ")", feature_rows)

        ward_death = build_ward_death_context(adc_deaths, participants, index, wards, lifecycles, max_age_ms)
        wd_rows = [(stable_id("ward_death_context", r["death_context_id"], r["lookback_ms"]), r.get("game_id"), r["replay_sha256"], next((d.get("patch") for d in adc_deaths if d["replay_sha256"] == r["replay_sha256"]), None), r["death_context_id"], None, r.get("nearest_allied_ward_distance"), r.get("lookback_ms"), "WARD_COVERAGE", "path-ward-death-context-v1", "VERIFIED_DERIVED", r.get("position_status"), compact_json(r)) for r in ward_death]
        con.executemany("INSERT OR IGNORE INTO ward_death_context VALUES (" + ",".join(["?"] * 13) + ")", wd_rows)
        return {"ward_position_context": len(wc_rows), "adc_death_position_context": len(ac_rows), "adc_death_features": len(feature_rows), "ward_death_context": len(wd_rows)}

    def status(self) -> dict[str, Any]:
        self.init()
        with self.connect() as con:
            tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
            counts = {table: con.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0] for table in tables}
            patches = [r[0] for r in con.execute("SELECT DISTINCT patch FROM replays ORDER BY patch").fetchall()]
        return {"db_path": str(self.db_path), "table_counts": counts, "patches": patches}

    def export(self, tables: Sequence[str], output_dir: str | Path) -> dict[str, str]:
        self.init()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            available = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
            result = {}
            for table in tables:
                if table not in available:
                    raise ValueError(f"unknown table: {table}")
                target = output_dir / f"{table}.parquet"
                escaped = str(target).replace("'", "''")
                con.execute(f'COPY (SELECT * FROM "{table}") TO \'{escaped}\' (FORMAT PARQUET, COMPRESSION ZSTD)')
                result[table] = str(target)
        return result
