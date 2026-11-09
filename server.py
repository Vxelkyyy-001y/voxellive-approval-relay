#!/usr/bin/env python3
"""VoxelLive 1.6 approval relay and preset-sharing API.

Deploy this service on a public HTTPS host with persistent storage. Each player's
VoxelLive server still runs locally on that player's own Android device.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
DB_PATH = Path(os.environ.get("VOXELLIVE_DB_PATH", str(Path(__file__).with_name("data") / "voxellive-v16.sqlite3")))
ADMIN_TOKEN = os.environ.get("VOXELLIVE_ADMIN_TOKEN", "").strip()
SESSION_DAYS = 3650
MAX_SHARE_BYTES = 30_000
REQUEST_RATE: dict[str, list[int]] = {}


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=20000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db():
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript('''
        CREATE TABLE IF NOT EXISTS access_requests (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          name_key TEXT NOT NULL,
          client_id TEXT NOT NULL,
          secret_hash TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
          created_at INTEGER NOT NULL,
          decided_at INTEGER
        );
        CREATE UNIQUE INDEX IF NOT EXISTS unique_active_voxellive_name
          ON access_requests(name_key) WHERE status IN ('pending','approved');
        CREATE UNIQUE INDEX IF NOT EXISTS unique_active_voxellive_install
          ON access_requests(client_id) WHERE status IN ('pending','approved');
        CREATE INDEX IF NOT EXISTS access_requests_status_created
          ON access_requests(status, created_at);
        CREATE TABLE IF NOT EXISTS access_sessions (
          token_hash TEXT PRIMARY KEY,
          request_id TEXT NOT NULL REFERENCES access_requests(id),
          expires_at INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS access_sessions_request_id ON access_sessions(request_id);
        CREATE TABLE IF NOT EXISTS shared_presets_v16 (
          code TEXT PRIMARY KEY,
          owner_request_id TEXT NOT NULL REFERENCES access_requests(id),
          preset_json TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          import_count INTEGER NOT NULL DEFAULT 0
        );
        ''')


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clean_name(value) -> tuple[str, str]:
    name = " ".join(str(value or "").split())
    if not 2 <= len(name) <= 32:
        raise ValueError("Nama harus terdiri dari 2–32 karakter.")
    if not re.fullmatch(r"[\w .-]+", name, flags=re.UNICODE):
        raise ValueError("Nama hanya boleh berisi huruf, angka, spasi, titik, garis bawah, atau tanda hubung.")
    return name, name.casefold()


def rate_limited(key: str, limit: int = 5, window: int = 900) -> bool:
    now = int(time.time())
    recent = [stamp for stamp in REQUEST_RATE.get(key, []) if now - stamp < window]
    if len(recent) >= limit:
        REQUEST_RATE[key] = recent
        return True
    recent.append(now)
    REQUEST_RATE[key] = recent
    return False


def validate_preset(raw):
    if not isinstance(raw, dict):
        raise ValueError("Data preset tidak valid.")
    name = str(raw.get("name", "Preset dari teman")).strip()[:40] or "Preset dari teman"
    gifts = raw.get("gifts", [])
    follow = raw.get("follow", {})
    cooldown = raw.get("cooldown_ms", 500)
    if not isinstance(gifts, list) or len(gifts) > 100 or not isinstance(follow, dict):
        raise ValueError("Isi preset tidak valid.")
    safe_gifts = []
    for item in gifts:
        if not isinstance(item, dict):
            continue
        gift_name = str(item.get("name", "")).strip()[:50]
        command = str(item.get("command", "")).strip()[:500]
        if not gift_name or not command or "\n" in command or "\r" in command:
            continue
        if not command.startswith("/"):
            command = "/" + command
        safe_gifts.append({
            "id": str(item.get("id") or uuid.uuid4().hex[:12])[:80],
            "gift_id": str(item.get("gift_id", ""))[:40],
            "name": gift_name,
            "emoji": str(item.get("emoji", "🎁"))[:8] or "🎁",
            "command": command,
            "enabled": bool(item.get("enabled", True)),
        })
    follow_command = str(follow.get("command", "")).strip()[:500]
    if "\n" in follow_command or "\r" in follow_command:
        raise ValueError("Command Follow tidak valid.")
    if follow_command and not follow_command.startswith("/"):
        follow_command = "/" + follow_command
    try:
        cooldown = max(100, min(10_000, int(cooldown)))
    except (TypeError, ValueError):
        cooldown = 500
    result = {
        "name": name,
        "gifts": safe_gifts,
        "follow": {"enabled": bool(follow.get("enabled", False)), "command": follow_command},
        "cooldown_ms": cooldown,
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > MAX_SHARE_BYTES:
        raise ValueError("Preset terlalu besar untuk dibagikan.")
    return result


def bearer(handler) -> str:
    value = handler.headers.get("Authorization", "")
    return value[7:].strip() if value.lower().startswith("bearer ") else ""


def get_access_request(request_id: str, request_secret: str):
    if not request_id or not request_secret:
        return None
    with db() as con:
        row = con.execute("SELECT * FROM access_requests WHERE id=?", (request_id,)).fetchone()
    if not row or not hmac.compare_digest(row["secret_hash"], sha256(request_secret)):
        return None
    return row


def lookup_session(token: str):
    if not token:
        return None
    now = int(time.time())
    with db() as con:
        row = con.execute('''SELECT r.id,r.name,r.status,s.expires_at
          FROM access_sessions s JOIN access_requests r ON r.id=s.request_id
          WHERE s.token_hash=?''', (sha256(token),)).fetchone()
    if not row or row["expires_at"] < now or row["status"] != "approved":
        return None
    return {"id": row["id"], "name": row["name"], "status": row["status"]}


class Handler(BaseHTTPRequestHandler):
    server_version = "VoxelLiveRelay/1.6"

    def log_message(self, fmt, *args):
        # Avoid logging request bodies, request secrets, session tokens, or admin tokens.
        print(f"{self.address_string()} - VoxelLive relay request")

    def send_json(self, code, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Content-Length tidak valid.")
        if size < 0 or size > 50_000:
            raise ValueError("Ukuran request tidak valid atau terlalu besar.")
        obj = json.loads(self.rfile.read(size).decode("utf-8") or "{}")
        if not isinstance(obj, dict):
            raise ValueError("JSON harus berupa object.")
        return obj

    def admin_ok(self) -> bool:
        if not ADMIN_TOKEN or len(ADMIN_TOKEN) < 40 or ADMIN_TOKEN.startswith("REPLACE_"):
            self.send_json(503, {"ok": False, "message": "Admin API belum dikonfigurasi dengan token acak yang kuat. Atur VOXELLIVE_ADMIN_TOKEN di hosting."})
            return False
        supplied = bearer(self)
        if not supplied or not hmac.compare_digest(supplied, ADMIN_TOKEN):
            self.send_json(401, {"ok": False, "message": "Token Admin tidak valid."})
            return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            return self.send_json(200, {"ok": True, "service": "VoxelLive Approval Relay", "version": "1.6.0"})
        if parsed.path == "/api/admin/pending":
            if not self.admin_ok():
                return
            with db() as con:
                rows = con.execute("SELECT id,name,created_at FROM access_requests WHERE status='pending' ORDER BY created_at ASC").fetchall()
            return self.send_json(200, {"ok": True, "requests": [dict(row) for row in rows]})
        return self.send_json(404, {"ok": False, "message": "Endpoint tidak ditemukan."})

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            data = self.read_json()
            if parsed.path == "/api/access/request":
                name, name_key = clean_name(data.get("name"))
                client_id = str(data.get("client_id", "")).strip()
                if not re.fullmatch(r"[A-Fa-f0-9-]{16,80}", client_id):
                    return self.send_json(400, {"ok": False, "message": "ID instalasi tidak valid."})
                if rate_limited(client_id):
                    return self.send_json(429, {"ok": False, "message": "Terlalu banyak permintaan dari perangkat ini. Coba lagi 15 menit."})
                request_id = uuid.uuid4().hex
                request_secret = secrets.token_urlsafe(32)
                now = int(time.time())
                try:
                    with db() as con:
                        con.execute('''INSERT INTO access_requests(id,name,name_key,client_id,secret_hash,status,created_at)
                          VALUES(?,?,?,?,?,'pending',?)''', (request_id, name, name_key, client_id, sha256(request_secret), now))
                except sqlite3.IntegrityError:
                    with db() as con:
                        same_device = con.execute("SELECT name,status FROM access_requests WHERE client_id=? AND status IN ('pending','approved')", (client_id,)).fetchone()
                        same_name = con.execute("SELECT name,status FROM access_requests WHERE name_key=? AND status IN ('pending','approved')", (name_key,)).fetchone()
                    if same_device:
                        message = f"Perangkat ini sudah memiliki permintaan/akses atas nama {same_device['name']}. Selesaikan atau minta Admin mencabut akses tersebut terlebih dahulu."
                    elif same_name:
                        message = "Nama ini sedang menunggu persetujuan atau sudah memiliki akses. Gunakan nama lain."
                    else:
                        message = "Permintaan tidak dapat dibuat. Coba beberapa saat lagi."
                    return self.send_json(409, {"ok": False, "message": message})
                return self.send_json(202, {"ok": True, "status": "pending", "request_id": request_id,
                    "request_secret": request_secret, "message": "Permintaan terkirim. Tunggu Admin menyetujui aksesmu."})

            if parsed.path == "/api/access/status":
                row = get_access_request(str(data.get("request_id", "")), str(data.get("request_secret", "")))
                if not row:
                    return self.send_json(404, {"ok": False, "message": "Permintaan tidak ditemukan atau kunci permintaan tidak valid."})
                message = {
                    "pending": "Permintaanmu masih menunggu persetujuan Admin.",
                    "approved": "Akses diterima! Membuka dashboard...",
                    "rejected": "Akses ditolak oleh Admin. SYSTEM OFF.",
                }[row["status"]]
                return self.send_json(200, {"ok": True, "status": row["status"], "name": row["name"], "message": message})

            if parsed.path == "/api/access/claim":
                row = get_access_request(str(data.get("request_id", "")), str(data.get("request_secret", "")))
                if not row:
                    return self.send_json(404, {"ok": False, "message": "Permintaan tidak ditemukan atau kunci permintaan tidak valid."})
                if row["status"] == "rejected":
                    return self.send_json(403, {"ok": False, "status": "rejected", "message": "Admin menolak akses. SYSTEM OFF."})
                if row["status"] != "approved":
                    return self.send_json(409, {"ok": False, "status": "pending", "message": "Akses belum disetujui Admin."})
                token = secrets.token_urlsafe(40)
                now = int(time.time())
                with db() as con:
                    con.execute("INSERT INTO access_sessions(token_hash,request_id,expires_at,created_at) VALUES(?,?,?,?)",
                        (sha256(token), row["id"], now + SESSION_DAYS * 86400, now))
                return self.send_json(200, {"ok": True, "token": token, "user": {"id": row["id"], "name": row["name"]}})

            if parsed.path == "/api/access/validate":
                user = lookup_session(bearer(self))
                if not user:
                    return self.send_json(401, {"ok": False, "status": "rejected", "message": "Akses tidak aktif atau telah dicabut Admin."})
                return self.send_json(200, {"ok": True, "user": user})

            if parsed.path == "/api/access/logout":
                token = bearer(self)
                if token:
                    with db() as con:
                        con.execute("DELETE FROM access_sessions WHERE token_hash=?", (sha256(token),))
                return self.send_json(200, {"ok": True})

            if parsed.path == "/api/admin/decide":
                if not self.admin_ok():
                    return
                name, name_key = clean_name(data.get("name"))
                action = str(data.get("action", "")).strip().lower()
                if action not in ("approve", "reject"):
                    return self.send_json(400, {"ok": False, "message": "Aksi harus approve atau reject."})
                now = int(time.time())
                decision_result = None
                with db() as con:
                    if action == "approve":
                        rows = con.execute("SELECT id,name FROM access_requests WHERE name_key=? AND status='pending'", (name_key,)).fetchall()
                        if len(rows) == 1:
                            con.execute("UPDATE access_requests SET status='approved',decided_at=? WHERE id=?", (now, rows[0]["id"]))
                            decision_result = {"ok": True, "status": "approved", "name": rows[0]["name"], "message": f"Akses {rows[0]['name']} diterima."}
                    else:
                        rows = con.execute("SELECT id,name,status FROM access_requests WHERE name_key=? AND status IN ('pending','approved')", (name_key,)).fetchall()
                        if len(rows) == 1:
                            con.execute("UPDATE access_requests SET status='rejected',decided_at=? WHERE id=?", (now, rows[0]["id"]))
                            con.execute("DELETE FROM access_sessions WHERE request_id=?", (rows[0]["id"],))
                            decision_result = {"ok": True, "status": "rejected", "name": rows[0]["name"], "message": f"Akses {rows[0]['name']} ditolak/dicabut. Hanya pengguna ini yang terputus."}
                if not decision_result:
                    message = "Permintaan pending dengan nama persis tersebut tidak ditemukan." if action == "approve" else "Pengguna aktif/pending dengan nama persis tersebut tidak ditemukan."
                    return self.send_json(404, {"ok": False, "message": message})
                return self.send_json(200, decision_result)

            if parsed.path == "/api/presets/share":
                user = lookup_session(bearer(self))
                if not user:
                    return self.send_json(401, {"ok": False, "message": "Akses diperlukan."})
                preset = validate_preset(data.get("preset"))
                code = "VXL-" + "-".join("".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(4)) for _ in range(2))
                with db() as con:
                    con.execute("INSERT INTO shared_presets_v16(code,owner_request_id,preset_json,created_at) VALUES(?,?,?,?)",
                        (code, user["id"], json.dumps(preset, ensure_ascii=False), int(time.time())))
                return self.send_json(201, {"ok": True, "code": code, "message": "Kode preset berhasil dibuat dan siap dibagikan."})

            if parsed.path == "/api/presets/import":
                user = lookup_session(bearer(self))
                if not user:
                    return self.send_json(401, {"ok": False, "message": "Akses diperlukan."})
                code = str(data.get("code", "")).strip().upper()
                with db() as con:
                    row = con.execute("SELECT preset_json FROM shared_presets_v16 WHERE code=?", (code,)).fetchone()
                    if row:
                        con.execute("UPDATE shared_presets_v16 SET import_count=import_count+1 WHERE code=?", (code,))
                if not row:
                    return self.send_json(404, {"ok": False, "message": "Kode preset tidak ditemukan."})
                return self.send_json(200, {"ok": True, "preset": json.loads(row["preset_json"]), "message": "Preset berhasil ditemukan."})

            return self.send_json(404, {"ok": False, "message": "Endpoint tidak ditemukan."})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return self.send_json(400, {"ok": False, "message": str(exc)})
        except Exception as exc:
            print(f"VoxelLive relay error: {exc.__class__.__name__}: {exc}")
            return self.send_json(500, {"ok": False, "message": "Terjadi kesalahan server. Coba lagi."})


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"VoxelLive Approval Relay 1.6 listening on {HOST}:{PORT}; database={DB_PATH}")
    if not ADMIN_TOKEN or len(ADMIN_TOKEN) < 40 or ADMIN_TOKEN.startswith("REPLACE_"):
        print("WARNING: VOXELLIVE_ADMIN_TOKEN belum diatur dengan token kuat; command Admin tidak bisa digunakan.")
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
