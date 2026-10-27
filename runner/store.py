import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ACTIVE = ("queued", "running", "cancelling")
TERMINAL = ("completed", "failed", "cancelled", "budget_limited", "interrupted")


class AdmissionError(Exception):
    pass


class Store:
    def __init__(self, data_dir):
        self.directory = Path(data_dir)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "runs.sqlite3"
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, idem TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL,
                    created_at REAL NOT NULL, started_at REAL, finished_at REAL,
                    error TEXT, summary TEXT NOT NULL DEFAULT '{}', cancel INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(owner, idem));
                CREATE UNIQUE INDEX IF NOT EXISTS single_active ON runs ((1))
                    WHERE status IN ('queued','running','cancelling');
                CREATE TABLE IF NOT EXISTS results (run_id TEXT, id TEXT, body TEXT, PRIMARY KEY(run_id,id));
                CREATE TABLE IF NOT EXISTS requests (run_id TEXT, id TEXT, body TEXT, PRIMARY KEY(run_id,id));
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def create(self, owner, idem, fingerprint, body):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM runs WHERE owner=? AND idem=?", (owner, idem)).fetchone()
            if row:
                if row["fingerprint"] != fingerprint:
                    raise AdmissionError("Idempotency key was already used for different settings")
                return self.unpack(row), False
            if db.execute("SELECT id FROM runs WHERE status IN ('queued','running','cancelling')").fetchone():
                raise AdmissionError("Another assessment is active; serial execution only")
            run_id = str(uuid.uuid4())
            db.execute("INSERT INTO runs (id,owner,idem,fingerprint,status,body,created_at) VALUES (?,?,?,?,?,?,?)",
                       (run_id, owner, idem, fingerprint, "queued", json.dumps(body), time.time()))
            directory = self.directory / run_id
            directory.mkdir(mode=0o700)
            return self.unpack(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()), True

    @staticmethod
    def unpack(row):
        if row is None:
            return None
        body = json.loads(row["body"])
        return {**body, "id": row["id"], "status": row["status"],
                "created_at": row["created_at"], "started_at": row["started_at"],
                "finished_at": row["finished_at"], "error": row["error"],
                "summary": json.loads(row["summary"]), "cancel_requested": bool(row["cancel"])}

    def get(self, run_id, owner=None):
        with self.connect() as db:
            if owner is None:  # Worker-only internal access.
                row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
            else:
                row = db.execute("SELECT * FROM runs WHERE id=? AND owner=?", (run_id, owner)).fetchone()
            return self.unpack(row)

    def list(self, owner):
        with self.connect() as db:
            return [self.unpack(r) for r in db.execute("SELECT * FROM runs WHERE owner=? ORDER BY created_at DESC LIMIT 100", (owner,))]

    def update(self, run_id, expected_status=None, **values):
        allowed = {"status", "started_at", "finished_at", "error", "summary", "cancel"}
        if not values.keys() <= allowed:
            raise ValueError("Invalid metadata fields")
        if "summary" in values:
            values["summary"] = json.dumps(values["summary"])
        where = " WHERE id=?"
        params = (*values.values(), run_id)
        if expected_status is not None:
            where += " AND status IN (" + ",".join("?" for _ in expected_status) + ")"
            params += tuple(expected_status)
        with self.connect() as db:
            cursor = db.execute("UPDATE runs SET " + ",".join(k + "=?" for k in values) + where, params)
            return cursor.rowcount == 1

    def request_cancel(self, run_id):
        # Predicate and transition occur in one write, never on a stale read.
        return self.update(run_id, expected_status=ACTIVE, cancel=1, status="cancelling")

    def finalize(self, run_id, status, error, metrics):
        if status not in TERMINAL:
            raise ValueError("Final status must be terminal")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,cancel FROM runs WHERE id=?", (run_id,)).fetchone()
            if row is None or row["status"] not in ACTIVE:
                return False
            metrics = dict(metrics)
            if row["cancel"]:
                status, error = "cancelled", "Cancelled by operator"
                metrics["completion_verified"] = False
            db.execute("UPDATE runs SET status=?,finished_at=?,error=?,summary=? WHERE id=? AND status IN ('queued','running','cancelling')",
                       (status, time.time(), error, json.dumps(metrics), run_id))
            return True

    def put(self, table, run_id, record):
        if table not in ("results", "requests"):
            raise ValueError("Unknown record type")
        with self.connect() as db:
            db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)", (run_id, record["id"], json.dumps(record)))

    def records(self, table, run_id):
        if table not in ("results", "requests"):
            raise ValueError("Unknown record type")
        with self.connect() as db:
            return [json.loads(r[0]) for r in db.execute(f"SELECT body FROM {table} WHERE run_id=? ORDER BY rowid", (run_id,))]

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE runs SET status='interrupted',finished_at=?,error='Runner restarted before verified completion' WHERE status IN ('queued','running','cancelling')", (time.time(),))
