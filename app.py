from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from flask import Flask, jsonify, render_template, request, abort, Response, session
import secrets

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("HUNTWEAVE_DB", DATA_DIR / "huntweave.db"))

app = Flask(__name__)
IS_RENDER = os.environ.get("RENDER", "").lower() == "true"
configured_secret = os.environ.get("HUNTWEAVE_SECRET_KEY")
if IS_RENDER and not configured_secret:
    raise RuntimeError("HUNTWEAVE_SECRET_KEY must be configured on Render.")
app.config["SECRET_KEY"] = configured_secret or "local-development-only-change-for-public-deployment"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_RENDER
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # review notes are deliberately small


@app.after_request
def add_security_headers(response: Response) -> Response:
    """Apply conservative headers for the local educational interface."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    )
    if request.path.startswith("/api/") or request.path == "/health":
        response.headers.setdefault("Cache-Control", "no-store")
    return response

HUNTS = [
    {
        "id": "HW-001", "title": "Repeated authentication failures followed by success",
        "category": "Identity", "level": "Investigate", "technique": "T1110 · Brute Force",
        "hypothesis": "A sequence of failed sign-ins followed by a successful sign-in may indicate credential guessing or a legitimate user recovering access.",
        "look_for": "Multiple failures for the same account followed by a success from the same source within a short window.",
        "limits": "This pattern alone does not prove account compromise. Shared NAT, mistyped passwords, and user behavior can produce similar events.",
        "dataset": "identity"
    },
    {
        "id": "HW-002", "title": "PowerShell launched from an unusual parent process",
        "category": "Endpoint", "level": "Review", "technique": "T1059.001 · PowerShell",
        "hypothesis": "PowerShell launched by an unusual parent process may deserve review, but administrative automation can look similar.",
        "look_for": "PowerShell process events, parent process context, account, host, and command-line indicators.",
        "limits": "A process name or command-line fragment is not sufficient to label activity malicious. Validate parent process and business context.",
        "dataset": "endpoint"
    },
    {
        "id": "HW-003", "title": "New privileged role assignment outside the usual pattern",
        "category": "Identity", "level": "Investigate", "technique": "T1098 · Account Manipulation",
        "hypothesis": "A privileged role assignment outside the expected change window may be unauthorized or may reflect an approved change.",
        "look_for": "Role assignment, actor identity, target account, timestamp, and a matching change record if available.",
        "limits": "The synthetic dataset does not include a real change-management system, so authorization cannot be confirmed from these events alone.",
        "dataset": "privilege"
    }
]

EVENTS = [
    ("E-1001", "2026-10-21T08:02:11Z", "identity", "login_failure", "m.alotaibi", "WS-014", "10.20.4.18", "Invalid password", "low", "Repeated failure; review in sequence."),
    ("E-1002", "2026-10-21T08:03:02Z", "identity", "login_failure", "m.alotaibi", "WS-014", "10.20.4.18", "Invalid password", "low", "Same account and source as E-1001."),
    ("E-1003", "2026-10-21T08:03:49Z", "identity", "login_failure", "m.alotaibi", "WS-014", "10.20.4.18", "Invalid password", "low", "Third failure in under two minutes."),
    ("E-1004", "2026-10-21T08:04:17Z", "identity", "login_success", "m.alotaibi", "WS-014", "10.20.4.18", "Interactive sign-in succeeded", "medium", "Success follows failures; investigate context before concluding."),
    ("E-1005", "2026-10-21T08:20:31Z", "identity", "login_success", "m.alotaibi", "WS-014", "10.20.4.18", "Interactive sign-in succeeded", "low", "Later normal sign-in; not proof of malicious activity."),
    ("E-2001", "2026-10-21T09:14:03Z", "endpoint", "process_start", "svc_deploy", "SRV-DEPLOY-02", "local", "powershell.exe launched by deploy-agent.exe", "medium", "Parent is a known synthetic deployment agent."),
    ("E-2002", "2026-10-21T09:14:05Z", "endpoint", "process_start", "svc_deploy", "SRV-DEPLOY-02", "local", "powershell.exe -File deploy-check.ps1", "low", "Script name and parent context are consistent with deployment."),
    ("E-2003", "2026-10-21T09:14:09Z", "endpoint", "file_write", "svc_deploy", "SRV-DEPLOY-02", "local", "Updated application health-check log", "low", "Expected follow-up in the synthetic scenario."),
    ("E-2004", "2026-10-21T10:42:55Z", "endpoint", "process_start", "j.hassan", "WS-031", "local", "powershell.exe launched by winword.exe", "high", "Unusual parent relationship; requires context, not an automatic verdict."),
    ("E-2005", "2026-10-21T10:43:01Z", "endpoint", "process_start", "j.hassan", "WS-031", "local", "powershell.exe with encoded-command flag", "high", "Potentially suspicious command-line indicator; synthetic evidence only."),
    ("E-3001", "2026-10-21T11:58:22Z", "privilege", "role_assignment", "admin.ops", "IDP-01", "10.20.1.10", "Assigned Privileged Role to a.nasser", "high", "Privileged change outside the sample maintenance window."),
    ("E-3002", "2026-10-21T11:58:24Z", "privilege", "audit_change", "admin.ops", "IDP-01", "10.20.1.10", "Role assignment audit record created", "medium", "Corroborates that a role assignment occurred, not whether it was approved."),
    ("E-3003", "2026-10-21T12:02:17Z", "identity", "login_success", "a.nasser", "WS-006", "10.20.8.44", "Interactive sign-in succeeded", "low", "Contextual event after role assignment; not proof of misuse."),
    ("E-4001", "2026-10-21T12:12:00Z", "identity", "login_failure", "s.ali", "WS-009", "10.20.5.77", "Invalid password", "low", "Single failure; common benign event."),
    ("E-4002", "2026-10-21T12:14:12Z", "endpoint", "process_start", "s.ali", "WS-009", "local", "outlook.exe launched", "low", "Routine process event included as background noise."),
    ("E-4003", "2026-10-21T12:15:18Z", "endpoint", "file_read", "s.ali", "WS-009", "local", "Opened quarterly-planning.docx", "low", "Routine synthetic activity."),
    ("E-4004", "2026-10-21T12:20:00Z", "identity", "login_success", "s.ali", "WS-009", "10.20.5.77", "Interactive sign-in succeeded", "low", "No strong evidence of an attack in this sequence."),
    ("E-4005", "2026-10-21T12:35:41Z", "endpoint", "process_start", "k.amin", "WS-020", "local", "services.exe launched svchost.exe", "low", "Normal-looking process context; baseline is synthetic."),
]


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_session():
    """Commit successful database work and always close the SQLite connection."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create the database schema and seed the synthetic event set once.

    Older HuntWeave releases used one shared hunt_notes row per scenario.
    Preserve that table under a legacy name before creating the per-browser
    workspace schema introduced in the hosted-demo release.
    """
    with db_session() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL,
                event_type TEXT NOT NULL, account TEXT NOT NULL, host TEXT NOT NULL,
                source_ip TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL,
                analyst_hint TEXT NOT NULL
            )
        """)

        notes_info = conn.execute("PRAGMA table_info(hunt_notes)").fetchall()
        if notes_info:
            note_columns = {row["name"] for row in notes_info}
            primary_key = [
                row["name"] for row in sorted(notes_info, key=lambda item: item["pk"])
                if row["pk"]
            ]
            if "visitor_id" not in note_columns or primary_key != ["visitor_id", "hunt_id"]:
                legacy_name = "hunt_notes_legacy"
                suffix = 1
                while conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                    (legacy_name,),
                ).fetchone():
                    suffix += 1
                    legacy_name = f"hunt_notes_legacy_{suffix}"
                conn.execute(f'ALTER TABLE hunt_notes RENAME TO "{legacy_name}"')

        conn.execute("""
            CREATE TABLE IF NOT EXISTS hunt_notes (
                visitor_id TEXT NOT NULL, hunt_id TEXT NOT NULL,
                verdict TEXT NOT NULL DEFAULT 'NOT_REVIEWED',
                notes TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
                PRIMARY KEY (visitor_id, hunt_id)
            )
        """)

        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count == 0:
            conn.executemany(
                "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
                EVENTS,
            )


def ensure_visitor_workspace(visitor_id: str) -> None:
    with db_session() as conn:
        for hunt in HUNTS:
            conn.execute(
                "INSERT OR IGNORE INTO hunt_notes(visitor_id, hunt_id, verdict, notes, updated_at) VALUES(?,?,?,?,?)",
                (visitor_id, hunt["id"], "NOT_REVIEWED", "", datetime.now(timezone.utc).isoformat()),
            )


@app.before_request
def prepare_visitor_workspace() -> None:
    # Static assets and health probes do not need a visitor workspace.
    if request.endpoint == "static" or request.path == "/health":
        return
    if "visitor_id" not in session:
        session["visitor_id"] = secrets.token_urlsafe(24)
    ensure_visitor_workspace(session["visitor_id"])


def hunt_by_id(hunt_id: str) -> dict[str, Any] | None:
    return next((h for h in HUNTS if h["id"] == hunt_id), None)


def related_events(hunt: dict[str, Any], q: str = "", source: str = "all") -> list[dict[str, Any]]:
    with db_session() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY timestamp ASC").fetchall()
    events = [dict(r) for r in rows]
    if hunt["dataset"] == "identity":
        events = [e for e in events if e["source"] == "identity" and e["account"] == "m.alotaibi"]
    elif hunt["dataset"] == "endpoint":
        events = [e for e in events if e["source"] == "endpoint" and e["host"] in ("SRV-DEPLOY-02", "WS-031")]
    else:
        events = [e for e in events if e["source"] in ("privilege", "identity") and (e["account"] in ("admin.ops", "a.nasser"))]
    if source != "all":
        events = [e for e in events if e["source"] == source]
    if q:
        term = q.casefold()
        events = [e for e in events if any(term in str(e[k]).casefold() for k in ("id", "account", "host", "message", "event_type", "source_ip"))]
    return events


@app.get("/")
def index():
    with db_session() as conn:
        notes = {r["hunt_id"]: dict(r) for r in conn.execute("SELECT * FROM hunt_notes WHERE visitor_id=?", (session["visitor_id"],))}
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    hunts = []
    verdict_labels = {
        "NOT_REVIEWED": "Not reviewed",
        "SUPPORTED": "Supported by evidence",
        "NOT_SUPPORTED": "Not supported",
        "INCONCLUSIVE": "Inconclusive",
    }
    for item in HUNTS:
        h = dict(item)
        h["state"] = notes.get(item["id"], {}).get("verdict", "NOT_REVIEWED")
        h["state_label"] = verdict_labels.get(h["state"], "Not reviewed")
        h["notes"] = notes.get(item["id"], {}).get("notes", "")
        h["event_count"] = len(related_events(item))
        hunts.append(h)
    return render_template("index.html", hunts=hunts, event_count=event_count)


@app.get("/api/hunts/<hunt_id>")
def api_hunt(hunt_id: str):
    hunt = hunt_by_id(hunt_id)
    if not hunt:
        abort(404)
    q = request.args.get("q", "")[:100]
    source = request.args.get("source", "all")
    if source not in {"all", "identity", "endpoint", "privilege"}:
        return jsonify({"error": "Invalid source filter"}), 400
    with db_session() as conn:
        note = conn.execute("SELECT * FROM hunt_notes WHERE visitor_id=? AND hunt_id=?", (session["visitor_id"], hunt_id)).fetchone()
    public_hunt = {key: hunt[key] for key in (
        "id", "title", "category", "level", "technique", "hypothesis", "look_for", "limits"
    )}
    public_note = (
        {key: note[key] for key in ("hunt_id", "verdict", "notes", "updated_at")}
        if note else None
    )
    return jsonify({
        "hunt": public_hunt,
        "events": related_events(hunt, q, source),
        "note": public_note,
    })


@app.post("/api/hunts/<hunt_id>/review")
def review_hunt(hunt_id: str):
    if not hunt_by_id(hunt_id):
        abort(404)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Expected a JSON object containing verdict and notes"}), 400
    verdict = payload.get("verdict", "NOT_REVIEWED")
    notes = payload.get("notes", "")
    allowed = {"NOT_REVIEWED", "SUPPORTED", "NOT_SUPPORTED", "INCONCLUSIVE"}
    if not isinstance(verdict, str) or verdict not in allowed:
        return jsonify({"error": "Invalid verdict"}), 400
    if not isinstance(notes, str) or len(notes) > 2000:
        return jsonify({"error": "Notes must be text up to 2000 characters"}), 400
    with db_session() as conn:
        conn.execute("UPDATE hunt_notes SET verdict=?, notes=?, updated_at=? WHERE visitor_id=? AND hunt_id=?",
                     (verdict, notes.strip(), datetime.now(timezone.utc).isoformat(), session["visitor_id"], hunt_id))
    return jsonify({"ok": True, "hunt_id": hunt_id, "verdict": verdict})


@app.post("/api/hunts/<hunt_id>/reset")
def reset_hunt(hunt_id: str):
    """Clear one scenario's saved finding without changing its synthetic events."""
    if not hunt_by_id(hunt_id):
        abort(404)
    with db_session() as conn:
        conn.execute(
            "UPDATE hunt_notes SET verdict=?, notes=?, updated_at=? WHERE visitor_id=? AND hunt_id=?",
            ("NOT_REVIEWED", "", datetime.now(timezone.utc).isoformat(), session["visitor_id"], hunt_id),
        )
    return jsonify({"ok": True, "hunt_id": hunt_id, "verdict": "NOT_REVIEWED", "notes": ""})


@app.get("/api/events")
def api_events():
    q = request.args.get("q", "")[:100].casefold()
    source = request.args.get("source", "all")
    if source not in {"all", "identity", "endpoint", "privilege"}:
        return jsonify({"error": "Invalid source filter"}), 400
    with db_session() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY timestamp ASC")]
    if source != "all":
        rows = [r for r in rows if r["source"] == source]
    if q:
        rows = [r for r in rows if any(q in str(r[k]).casefold() for k in ("id", "account", "host", "message", "event_type", "source_ip"))]
    return jsonify({"events": rows, "count": len(rows)})


@app.get("/api/report/<hunt_id>")
def report(hunt_id: str):
    hunt = hunt_by_id(hunt_id)
    if not hunt:
        abort(404)
    with db_session() as conn:
        row = conn.execute("SELECT * FROM hunt_notes WHERE visitor_id=? AND hunt_id=?", (session["visitor_id"], hunt_id)).fetchone()
    note = dict(row) if row else {"verdict": "NOT_REVIEWED", "notes": ""}
    events = related_events(hunt)
    report_data = {
        "product": "HuntWeave — educational threat hunting lab",
        "synthetic_data_only": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hunt": {k: hunt[k] for k in ("id", "title", "hypothesis", "look_for", "limits", "technique")},
        "verdict": note["verdict"], "analyst_notes": note["notes"],
        "review_updated_at": note.get("updated_at"),
        "evidence_count": len(events),
        "evidence": [{k: e[k] for k in ("id", "timestamp", "source", "event_type", "account", "host", "source_ip", "message", "severity", "analyst_hint")} for e in events]
    }
    return Response(json.dumps(report_data, indent=2, ensure_ascii=False), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename={hunt_id.lower()}-hunt-report.json"})


@app.get("/health")
def health():
    with db_session() as conn:
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return jsonify({
        "status": "ok",
        "mode": "educational-synthetic-data",
        "database": "sqlite",
        "synthetic_event_count": event_count,
    })


# Initialize schema at import time so production WSGI servers (e.g. Gunicorn) are ready.
init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5055")), debug=False)
