#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

JSON_HEADERS = {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"}
SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": "default-src 'self'; img-src 'self' https://images.unsplash.com data:; media-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}


class BlogApp:
    def __init__(self, root, db_path, admin_password, session_secret):
        self.root = Path(root).resolve()
        self.db_path = Path(db_path)
        self.admin_password = admin_password
        self.secret = session_secret.encode()
        self.session_ttl = 604800
        self.login_limit = 5
        self.login_window = 300
        self.login_key_limit = 2048
        self.login_attempts = {}
        self.login_lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def connect(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        return db

    def _init_db(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slug TEXT UNIQUE,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                content TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('draft','published')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                published_at TEXT
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(posts)")}
            if "cover" not in columns:
                db.execute("ALTER TABLE posts ADD COLUMN cover TEXT NOT NULL DEFAULT ''")

    def encode(self, obj):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()

    def response(self, status, data=None, headers=None):
        h = dict(SECURITY_HEADERS)
        if data is not None:
            h.update(JSON_HEADERS)
        if headers:
            h.update(headers)
        return status, h, b"" if data is None else self.encode(data)

    def parse_json(self, body):
        try:
            return json.loads((body or b"{}").decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def token(self, now=None):
        issued = int(time.time() if now is None else now)
        payload = base64.urlsafe_b64encode(self.encode({"admin": True, "iat": issued, "exp": issued + self.session_ttl, "nonce": secrets.token_hex(8)})).rstrip(b"=").decode()
        sig = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def authenticated(self, headers):
        cookie = headers.get("cookie", "")
        token = next((p.strip()[8:] for p in cookie.split(";") if p.strip().startswith("session=")), "")
        if "." not in token:
            return False
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()):
            return False
        try:
            decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            claims = json.loads(decoded)
            return claims.get("admin") is True and int(claims.get("exp", 0)) >= int(time.time())
        except (ValueError, TypeError, json.JSONDecodeError):
            return False

    def login_key(self, headers):
        return headers.get("x-peer-address", "unknown")

    def prune_login_attempts(self, now):
        stale = [key for key, values in self.login_attempts.items() if not any(now - stamp < self.login_window for stamp in values)]
        for key in stale:
            self.login_attempts.pop(key, None)
        if len(self.login_attempts) >= self.login_key_limit:
            oldest = min(self.login_attempts, key=lambda key: max(self.login_attempts[key], default=0))
            self.login_attempts.pop(oldest, None)

    def login_blocked(self, key, now=None):
        now = time.time() if now is None else now
        with self.login_lock:
            self.prune_login_attempts(now)
            attempts = [t for t in self.login_attempts.get(key, []) if now - t < self.login_window]
            self.login_attempts[key] = attempts
            return len(attempts) >= self.login_limit

    def record_failed_login(self, key, now=None):
        with self.login_lock:
            now = time.time() if now is None else now
            self.prune_login_attempts(now)
            self.login_attempts.setdefault(key, []).append(now)

    def clear_failed_logins(self, key):
        with self.login_lock:
            self.login_attempts.pop(key, None)

    def serialize(self, row):
        return dict(row)

    def validate_post(self, data):
        if not isinstance(data, dict):
            return None
        title = str(data.get("title", "")).strip()
        category = str(data.get("category", "")).strip()
        content = str(data.get("content", "")).strip()
        status = str(data.get("status", "draft"))
        if not title or not content or len(title) > 120 or len(category) > 40 or len(content) > 200000 or status not in ("draft", "published"):
            return None
        cover = str(data.get("cover", "")).strip()
        if len(cover) > 300 or (cover and not cover.startswith("/assets/")):
            return None
        return title, category, content, status, cover

    def handle_api(self, method, path, body, headers):
        authed = self.authenticated(headers)
        if path == "/api/login" and method == "POST":
            key = self.login_key(headers)
            if self.login_blocked(key):
                return self.response(429, {"authenticated": False, "error": "尝试次数过多，请稍后再试"}, {"retry-after": str(self.login_window)})
            data = self.parse_json(body)
            ok = isinstance(data, dict) and hmac.compare_digest(str(data.get("password", "")), self.admin_password)
            if not ok:
                self.record_failed_login(key)
                return self.response(401, {"authenticated": False, "error": "密码错误"})
            self.clear_failed_logins(key)
            cookie = f"session={self.token()}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800"
            return self.response(200, {"authenticated": True}, {"set-cookie": cookie})
        if path == "/api/logout" and method == "POST":
            return self.response(200, {"authenticated": False}, {"set-cookie": "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"})
        if path == "/api/session" and method == "GET":
            return self.response(200, {"authenticated": authed})
        if path == "/api/posts" and method == "GET":
            with self.connect() as db:
                rows = db.execute("SELECT * FROM posts WHERE status='published' ORDER BY COALESCE(published_at,created_at) DESC,id DESC").fetchall()
            return self.response(200, [self.serialize(r) for r in rows])
        if path == "/api/admin/posts" and method == "GET":
            if not authed:
                return self.response(401, {"error": "需要管理员登录"})
            with self.connect() as db:
                rows = db.execute("SELECT * FROM posts ORDER BY updated_at DESC,id DESC").fetchall()
            return self.response(200, [self.serialize(r) for r in rows])
        if path == "/api/posts" and method == "POST":
            if not authed:
                return self.response(401, {"error": "需要管理员登录"})
            data = self.validate_post(self.parse_json(body))
            if not data:
                return self.response(422, {"error": "标题、分类、正文或状态无效"})
            now = datetime.now(timezone.utc).isoformat()
            title, category, content, status, cover = data
            with self.connect() as db:
                cur = db.execute("INSERT INTO posts(slug,title,category,content,status,created_at,updated_at,published_at,cover) VALUES(NULL,?,?,?,?,?,?,?,?)", (title, category, content, status, now, now, now if status == "published" else None, cover))
                pid = cur.lastrowid
                slug = f"post-{pid}"
                db.execute("UPDATE posts SET slug=? WHERE id=?", (slug, pid))
                row = db.execute("SELECT * FROM posts WHERE id=?", (pid,)).fetchone()
            return self.response(201, self.serialize(row))
        if path.startswith("/api/posts/") and method in ("PUT", "DELETE"):
            if not authed:
                return self.response(401, {"error": "需要管理员登录"})
            try:
                pid = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self.response(404, {"error": "文章不存在"})
            with self.connect() as db:
                old = db.execute("SELECT * FROM posts WHERE id=?", (pid,)).fetchone()
                if not old:
                    return self.response(404, {"error": "文章不存在"})
                if method == "DELETE":
                    db.execute("DELETE FROM posts WHERE id=?", (pid,))
                    return self.response(204)
                data = self.validate_post(self.parse_json(body))
                if not data:
                    return self.response(422, {"error": "标题、分类、正文或状态无效"})
                title, category, content, status, cover = data
                now = datetime.now(timezone.utc).isoformat()
                published_at = old["published_at"] or (now if status == "published" else None)
                db.execute("UPDATE posts SET title=?,category=?,content=?,status=?,updated_at=?,published_at=?,cover=? WHERE id=?", (title, category, content, status, now, published_at, cover, pid))
                row = db.execute("SELECT * FROM posts WHERE id=?", (pid,)).fetchone()
            return self.response(200, self.serialize(row))
        return self.response(404, {"error": "接口不存在"})

    def handle(self, method, raw_path, body=b"", headers=None):
        path = urlsplit(raw_path).path
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        if path.startswith("/api/"):
            return self.handle_api(method, path, body, headers)
        return self.serve_file(path)

    def serve_file(self, path):
        if path == "/":
            rel = "index.html"
        elif path.startswith("/assets/"):
            rel = path.lstrip("/")
        else:
            return self.response(404, {"error": "页面不存在"})
        target = (self.root / rel).resolve()
        if self.root not in target.parents and target != self.root:
            return self.response(403, {"error": "禁止访问"})
        if not target.is_file():
            return self.response(404, {"error": "资源不存在"})
        content = target.read_bytes()
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        cache = "public, max-age=86400" if target.parent.name == "assets" else "no-cache"
        return 200, {**SECURITY_HEADERS, "content-type": ctype, "content-length": str(len(content)), "cache-control": cache}, content


class Handler(BaseHTTPRequestHandler):
    server_version = "KokkoroBlog/1.0"
    def dispatch(self):
        try:
            requested_length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            requested_length = -1
        if requested_length < 0 or requested_length > 300000:
            self.send_error(413, "Invalid request size")
            return
        body = self.rfile.read(requested_length) if requested_length else b""
        request_headers = dict(self.headers)
        request_headers["x-peer-address"] = self.client_address[0]
        status, headers, payload = self.server.app.handle(self.command, self.path, body, request_headers)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = dispatch
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    root = Path(os.environ.get("BLOG_ROOT", Path(__file__).parent))
    password = os.environ.get("BLOG_ADMIN_PASSWORD")
    secret = os.environ.get("BLOG_SESSION_SECRET")
    if not password or not secret:
        raise SystemExit("BLOG_ADMIN_PASSWORD and BLOG_SESSION_SECRET are required")
    app = BlogApp(root, os.environ.get("BLOG_DB", root / "data" / "blog.db"), password, secret)
    host, port = os.environ.get("BLOG_HOST", "127.0.0.1"), int(os.environ.get("BLOG_PORT", "8090"))
    server = ThreadingHTTPServer((host, port), Handler)
    server.app = app
    print(f"Kokkoro Blog listening on http://{host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
