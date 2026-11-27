"""O-T01 continuation batching: byte-budget packing, full-tail coverage.

Two real runs recorded packet_overflow chains whose depth cap (3) dropped
642 ranges in one run alone: a pure line-count chunk re-overflows on
long-line content, so the serial chain hit the cap before the tail was
supplied. The corrected mechanism packs the leftover by an ESTIMATED
CHARACTER BUDGET (line widths from the frozen manifest) into batches that
each fit one packet, and every batch is a real queued task — the whole
tail is covered by parallel work and the depth cap stays a loop guard.

Synthetic fixtures only: generated long-line content with example paths.
"""

import json
import tempfile
import shutil
import unittest
from pathlib import Path

from auditkit.app.service import AuditAppService
from auditkit.contracts.errors import InvalidInputError
from auditkit.ledger.db import get_db_connection, init_database

SKILL_DIR = Path(__file__).resolve().parents[2] / "skill"

_LONG_LINE = "x" * 1200


def _long_line_target(root: Path) -> Path:
    """A target whose single file overflows any packet: 300 long lines."""
    target = root / "target"
    target.mkdir(parents=True)
    (target / "big.py").write_text(
        "\n".join(f"VALUE_{i} = '{_LONG_LINE}'" for i in range(300)) + "\n",
        encoding="utf-8",
    )
    return target


def _base_config(target: Path, run_dir: Path, **extra) -> dict:
    cfg = {
        "schema_version": "1.0",
        "target": str(target),
        "run_dir": str(run_dir),
        "report_language": "en",
        "profile": "standard",
        "scope": {"include": ["*.py"], "exclude": []},
        "budgets": [{
            "schema_version": "1.0", "dimension": "tasks", "mode": "enforced",
            "limit": 500, "settled": 0, "reserved": 0, "unit": "tasks",
            "availability": "exact",
        }],
        "safety_acceptance": {
            "allow_unverified_execution": False,
            "allow_unverified_network": False,
            "allow_unverified_write": False,
            "user_approved": True,
        },
    }
    cfg.update(extra)
    return cfg


class TestContinuationBatching(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="cont-batch-"))
        self.app = AuditAppService(SKILL_DIR)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_long_line_file_fully_covered_by_batched_continuations(self):
        """A long-line file that overflows any single packet must have its
        WHOLE tail re-supplied by batched continuation tasks (no depth-cap
        drop), and every batch must fit the estimated character budget."""
        target = _long_line_target(self.temp_dir)
        run_dir = self.temp_dir / "run"
        prep = self.app.prepare(str(target), str(run_dir), _base_config(target, run_dir))
        self.app.activate(prep["run_id"], run_dir)

        # Drive one overflow-producing packet publish through the service:
        # claim the unit and let the packet builder overflow, then let the
        # continuation enqueue path run (real pipeline, not mocks).
        conn = get_db_connection(run_dir / "events.db")
        claim = self.app.next(prep["run_id"], run_dir, batch_size=1)[0]
        self.app.start(run_dir, claim)
        # The submit path publishes the packet, records overflow and
        # enqueues batched continuations before the result lands.
        from auditkit.contracts.errors import InvalidInputError
        try:
            self.app.submit(
                run_dir, claim,
                {"schema_version": "1.0", "task_id": claim["task_id"],
                 "attempt_id": claim["attempt_id"], "kind": "hunt",
                 "coverage": [], "records": [], "overflow": []},
                "digest-cont",
            )
        except InvalidInputError:
            pass  # a packet_overflow result may bounce once; the point is the enqueues

        batches = conn.execute(
            "SELECT count(*) AS c FROM tasks WHERE task_key LIKE 'cont:%'"
        ).fetchone()["c"]
        conn.close()

        # 300 x ~1200-char lines = ~360KB against a ~13.6KB budget: several
        # batches are required to carry the whole tail.
        self.assertGreaterEqual(batches, 5, "tail was not fully batched")

        # Every batch carries ranges inside the file and its unit id is
        # depth-1 (the cap must never fire for a properly budgeted chain).
        conn = get_db_connection(run_dir / "events.db")
        total_lines = 0
        for (spec_json,) in conn.execute(
            "SELECT spec_json FROM tasks WHERE task_key LIKE 'cont:%'"
        ):
            unit = (json.loads(spec_json).get("unit") or {})
            self.assertLessEqual(
                unit.get("unit_id", "").count("cont"), 1,
                "chain deepened -- batching did not fit the budget",
            )
            for rng in unit.get("ranges", []):
                total_lines += rng["line_end"] - rng["line_start"] + 1
        conn.close()
        # The tail is fully re-supplied (line unions may overlap slightly
        # at chunk boundaries; the total must cover the file's 300 lines).
        self.assertGreaterEqual(total_lines, 300)

        # No honest-drop event fired: the cap never engaged.
        conn = get_db_connection(run_dir / "events.db")
        drops = conn.execute(
            "SELECT count(*) AS c FROM events WHERE event_type='packet_overflow' "
            "AND payload_json LIKE '%depth cap%'"
        ).fetchone()["c"]
        conn.close()
        self.assertEqual(drops, 0)

    def test_depth_cap_config_still_guards_the_chain(self):
        """The configurable depth cap stays a loop guard: a continuation
        unit already at the configured depth drops its tail honestly."""
        target = self.temp_dir / "target"
        target.mkdir(parents=True)
        (target / "a.py").write_text("value = 1\n", encoding="utf-8")
        run_dir = self.temp_dir / "run"
        run_dir.mkdir(parents=True)
        init_database(run_dir / "events.db")
        # Operator pins the cap to 1 via run config (fault-injection shape).
        (run_dir / "config.json").write_text(json.dumps({
            "schema_version": "1.0",
            "packet_continuation_max_depth": 1,
        }), encoding="utf-8")
        (run_dir / "snapshot").mkdir()
        (run_dir / "snapshot" / "manifest.json").write_text(json.dumps({
            "schema_version": "1.0", "snapshot_id": "snp-t", "hash_algorithm": "sha256",
            "root_hash": "x", "files": [
                {"path": "a.py", "sha256": "y", "bytes": 10, "line_count": 1},
            ],
            "excluded": [],
        }), encoding="utf-8")

        conn = get_db_connection(run_dir / "events.db")
        conn.execute(
            "INSERT INTO runs (run_id, snapshot_id, state, schema_version, skill_version, "
            "knowledge_version, config_ref, revision, created_at, updated_at) "
            "VALUES ('run-t', 'snp-t', 'active', '1.0', ?, '1.0', 'config.json', 1, "
            "datetime('now'), datetime('now'))",
            (self.app._read_skill_version(),),
        )
        conn.commit()
        claim = {"task_id": "task-orig", "attempt_id": "att-1",
                 "generation": 1, "run_id": "run-t"}
        unit = {"unit_id": "unit-t-cont1", "ranges": [{"path": "a.py", "line_start": 1, "line_end": 5}]}
        self.app._enqueue_packet_continuation(
            conn, run_dir, "run-t", claim, {"unit": unit}, "hunt", unit,
            [{"path": "a.py", "line_start": 1, "line_end": 5}],
        )
        dropped = conn.execute(
            "SELECT count(*) AS c FROM events WHERE event_type='packet_overflow' "
            "AND payload_json LIKE '%depth cap%'"
        ).fetchone()["c"]
        enqueued = conn.execute(
            "SELECT count(*) AS c FROM tasks WHERE task_key LIKE 'cont:%'"
        ).fetchone()["c"]
        conn.close()
        # A depth-2 continuation is past the pinned cap: honest drop, no task.
        self.assertEqual(dropped, 1)
        self.assertEqual(enqueued, 0)

    def test_budget_config_rejects_invalid_values(self):
        """Malformed config values fall back to safe defaults instead of
        crashing the continuation path."""
        run_dir = self.temp_dir / "run2"
        run_dir.mkdir(parents=True)
        (run_dir / "config.json").write_text("{broken json", encoding="utf-8")
        depth, budget = self.app._continuation_config(run_dir)
        self.assertEqual(depth, self.app.PACKET_CONTINUATION_MAX_DEPTH)
        self.assertEqual(budget, self.app.PACKET_CONTINUATION_BUDGET_CHARS)


if __name__ == "__main__":
    unittest.main()
