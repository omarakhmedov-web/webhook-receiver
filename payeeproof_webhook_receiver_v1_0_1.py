import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request

APP_VERSION = "1.0.1-webhook-receiver"
DB_PATH = os.getenv("DB_PATH", "/tmp/webhook_receiver.db")
MAX_ITEMS = int(os.getenv("MAX_ITEMS", "100"))
REQUIRE_TOKEN = os.getenv("RECEIVER_VIEW_TOKEN", "")
PORT = int(os.getenv("PORT", "10000"))
ACK_TIMEOUT_SEC = float(os.getenv("ACK_TIMEOUT_SEC", "8"))

app = Flask(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_events (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            method TEXT,
            path TEXT,
            query_string TEXT,
            remote_addr TEXT,
            headers_json TEXT,
            body_text TEXT,
            body_json TEXT,
            content_type TEXT,
            delivery_id TEXT,
            signature TEXT,
            timestamp_header TEXT,
            ack_url TEXT,
            ack_delivery_id TEXT,
            ack_result_json TEXT
        )
        """
    )
    conn.commit()
    try:
        cur.execute("ALTER TABLE webhook_events ADD COLUMN ack_url TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE webhook_events ADD COLUMN ack_delivery_id TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE webhook_events ADD COLUMN ack_result_json TEXT")
        conn.commit()
    except Exception:
        pass
    conn.close()


def trim_old_rows():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM webhook_events ORDER BY created_at DESC")
    rows = cur.fetchall()
    if len(rows) > MAX_ITEMS:
        ids_to_delete = [r[0] for r in rows[MAX_ITEMS:]]
        cur.executemany("DELETE FROM webhook_events WHERE id = ?", [(x,) for x in ids_to_delete])
        conn.commit()
    conn.close()


def check_view_access():
    if not REQUIRE_TOKEN:
        return None
    token = request.args.get("token", "") or request.headers.get("X-Receiver-Token", "")
    if token != REQUIRE_TOKEN:
        return jsonify({"ok": False, "error": "FORBIDDEN"}), 403
    return None


def post_ack_if_present(parsed_json):
    if not isinstance(parsed_json, dict):
        return None
    ack = parsed_json.get("ack")
    if not isinstance(ack, dict):
        return None
    ack_url = str(ack.get("url") or "").strip()
    delivery_id = str(ack.get("delivery_id") or "").strip()
    token = str(ack.get("token") or "").strip()
    if not ack_url or not delivery_id or not token:
        return {
            "ok": False,
            "attempted": False,
            "reason": "ACK_FIELDS_MISSING",
            "ack_url": ack_url,
            "delivery_id": delivery_id,
        }

    payload = {
        "delivery_id": delivery_id,
        "ack_token": token,
        "status": "received",
        "detail": "Receiver accepted webhook event.",
        "processor": APP_VERSION,
        "processed_at": utc_now(),
    }
    try:
        resp = requests.post(ack_url, json=payload, timeout=ACK_TIMEOUT_SEC)
        try:
            body = resp.json()
        except Exception:
            body = {"text": (resp.text or "")[:500]}
        return {
            "ok": 200 <= int(resp.status_code) < 300,
            "attempted": True,
            "status_code": int(resp.status_code),
            "body": body,
            "ack_url": ack_url,
            "delivery_id": delivery_id,
        }
    except Exception as exc:
        return {
            "ok": False,
            "attempted": True,
            "error": str(exc),
            "ack_url": ack_url,
            "delivery_id": delivery_id,
        }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "service": "payeeproof-webhook-receiver",
        "version": APP_VERSION,
        "time": utc_now(),
        "db_path": DB_PATH,
    })


@app.route("/hook", methods=["POST", "GET", "PUT", "PATCH"])
def hook():
    raw = request.get_data(cache=True, as_text=True)
    parsed_json = None
    try:
        parsed_json = request.get_json(silent=True)
    except Exception:
        parsed_json = None

    event_id = f"evt_{uuid.uuid4().hex[:20]}"
    headers_dict = {k: v for k, v in request.headers.items()}
    body_json_text = json.dumps(parsed_json, ensure_ascii=False) if parsed_json is not None else None
    delivery_id = request.headers.get("X-PayeeProof-Delivery-ID", "") or request.headers.get("X-PayeeProof-Delivery-Id", "")
    signature = request.headers.get("X-PayeeProof-Signature", "")
    timestamp_header = request.headers.get("X-PayeeProof-Timestamp", "")

    ack = parsed_json.get("ack") if isinstance(parsed_json, dict) else None
    ack_url = str(ack.get("url") or "").strip() if isinstance(ack, dict) else ""
    ack_delivery_id = str(ack.get("delivery_id") or "").strip() if isinstance(ack, dict) else ""
    ack_result = post_ack_if_present(parsed_json)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO webhook_events (
            id, created_at, method, path, query_string, remote_addr,
            headers_json, body_text, body_json, content_type,
            delivery_id, signature, timestamp_header, ack_url, ack_delivery_id, ack_result_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            utc_now(),
            request.method,
            request.path,
            request.query_string.decode("utf-8", errors="ignore"),
            request.remote_addr,
            json.dumps(headers_dict, ensure_ascii=False),
            raw,
            body_json_text,
            request.content_type or "",
            delivery_id,
            signature,
            timestamp_header,
            ack_url,
            ack_delivery_id,
            json.dumps(ack_result, ensure_ascii=False) if ack_result is not None else None,
        ),
    )
    conn.commit()
    conn.close()
    trim_old_rows()

    return jsonify({
        "ok": True,
        "stored": True,
        "event_id": event_id,
        "delivery_id": delivery_id,
        "has_signature": bool(signature),
        "has_ack": bool(ack),
        "ack": ack,
        "ack_result": ack_result,
    })


@app.route("/inbox", methods=["GET"])
def inbox():
    access = check_view_access()
    if access is not None:
        return access

    limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, created_at, method, path, delivery_id, signature, timestamp_header, content_type, ack_url, ack_delivery_id
        FROM webhook_events
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"ok": True, "items": rows, "count": len(rows)})


@app.route("/inbox/<event_id>", methods=["GET"])
def inbox_detail(event_id: str):
    access = check_view_access()
    if access is not None:
        return access

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM webhook_events WHERE id = ?", (event_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "NOT_FOUND"}), 404

    item = dict(row)
    for key in ("headers_json", "body_json", "ack_result_json"):
        if item.get(key):
            try:
                item[key] = json.loads(item[key])
            except Exception:
                pass
    return jsonify({"ok": True, "event": item})


@app.route("/latest", methods=["GET"])
def latest():
    access = check_view_access()
    if access is not None:
        return access

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM webhook_events ORDER BY created_at DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": True, "event": None})
    return inbox_detail(row[0])


@app.route("/", methods=["GET"])
def root():
    sample_hint = "Add ?token=YOUR_TOKEN if RECEIVER_VIEW_TOKEN is set."
    return jsonify({
        "ok": True,
        "service": "payeeproof-webhook-receiver",
        "version": APP_VERSION,
        "routes": {
            "health": "/health",
            "hook": "/hook",
            "inbox": "/inbox",
            "latest": "/latest",
            "detail": "/inbox/<event_id>",
        },
        "note": sample_hint,
    })


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT)
else:
    init_db()
