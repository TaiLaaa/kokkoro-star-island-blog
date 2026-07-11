import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# Production API contract tests. They intentionally fail until server.py exists.
ROOT = Path(__file__).resolve().parents[1]


class BlogAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("blog_server", ROOT / "server.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.app = cls.module.BlogApp(
            root=ROOT,
            db_path=Path(cls.tmp.name) / "blog.db",
            admin_password="correct horse",
            session_secret="test-secret",
        )

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def call(self, method, path, body=None, cookie=None):
        payload = None if body is None else json.dumps(body).encode()
        status, headers, raw = self.app.handle(method, path, payload, {"cookie": cookie or ""})
        data = json.loads(raw) if raw and headers.get("content-type", "").startswith("application/json") else raw
        return status, headers, data

    def login(self):
        status, headers, data = self.call("POST", "/api/login", {"password": "correct horse"})
        self.assertEqual(status, 200)
        self.assertTrue(data["authenticated"])
        return headers["set-cookie"].split(";", 1)[0]

    def test_login_rejects_bad_password_and_accepts_configured_password(self):
        status, _, data = self.call("POST", "/api/login", {"password": "wrong"})
        self.assertEqual(status, 401)
        self.assertFalse(data["authenticated"])
        cookie = self.login()
        status, _, data = self.call("GET", "/api/session", cookie=cookie)
        self.assertEqual((status, data["authenticated"]), (200, True))

    def test_anonymous_cannot_create_update_or_delete(self):
        for method, path in [("POST", "/api/posts"), ("PUT", "/api/posts/1"), ("DELETE", "/api/posts/1")]:
            status, _, _ = self.call(method, path, {"title": "x", "content": "y"})
            self.assertEqual(status, 401)

    def test_admin_can_create_publish_list_update_and_delete(self):
        cookie = self.login()
        post = {"title": "第一颗新星", "category": "随笔", "content": "第一段\n\n第二段", "status": "published"}
        status, _, created = self.call("POST", "/api/posts", post, cookie)
        self.assertEqual(status, 201)
        self.assertEqual(created["slug"], "post-1")
        status, _, public = self.call("GET", "/api/posts")
        self.assertEqual([p["title"] for p in public], ["第一颗新星"])
        status, _, updated = self.call("PUT", f"/api/posts/{created['id']}", {**post, "title": "更新后的星星", "status": "draft"}, cookie)
        self.assertEqual((status, updated["status"]), (200, "draft"))
        status, _, public = self.call("GET", "/api/posts")
        self.assertEqual(public, [])
        status, _, admin = self.call("GET", "/api/admin/posts", cookie=cookie)
        self.assertEqual(admin[0]["title"], "更新后的星星")
        status, _, _ = self.call("DELETE", f"/api/posts/{created['id']}", cookie=cookie)
        self.assertEqual(status, 204)

    def test_validation_rejects_blank_and_oversized_fields(self):
        cookie = self.login()
        bad = [
            {"title": "", "content": "body", "status": "published"},
            {"title": "x", "content": "", "status": "published"},
            {"title": "x" * 121, "content": "body", "status": "published"},
            {"title": "x", "content": "body", "status": "invalid"},
        ]
        for item in bad:
            status, _, data = self.call("POST", "/api/posts", item, cookie)
            self.assertEqual(status, 422, data)

    def test_session_cookie_is_signed_and_logout_invalidates_browser_session(self):
        cookie = self.login()
        forged = cookie.rsplit(".", 1)[0] + ".forged"
        self.assertFalse(self.call("GET", "/api/session", cookie=forged)[2]["authenticated"])
        status, headers, data = self.call("POST", "/api/logout", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["set-cookie"])

    def test_sensitive_and_unknown_static_paths_are_not_served(self):
        for path in ("/.env", "/data/blog.db", "/server.py", "/tests/test_server.py", "/missing.txt"):
            status, _, _ = self.app.handle("GET", path)
            self.assertEqual(status, 404, path)

    def test_session_token_expires_server_side(self):
        token = self.app.token(now=int(time.time()) - self.app.session_ttl - 1)
        self.assertFalse(self.app.authenticated({"cookie": f"session={token}"}))

    def test_failed_logins_are_rate_limited(self):
        headers = {"x-peer-address": "203.0.113.7", "x-forwarded-for": "198.51.100.1"}
        for i in range(self.app.login_limit):
            headers["x-forwarded-for"] = f"198.51.100.{i + 1}"
            status, _, _ = self.app.handle("POST", "/api/login", b'{"password":"wrong"}', headers)
        self.assertEqual(status, 401)
        status, response_headers, body = self.app.handle("POST", "/api/login", b'{"password":"wrong"}', headers)
        self.assertEqual(status, 429)
        self.assertIn("retry-after", response_headers)
        self.assertIn("稍后", body.decode())

    def test_rate_limit_table_is_bounded_and_prunes_stale_entries(self):
        self.app.login_attempts.clear()
        self.app.login_key_limit = 3
        now = time.time()
        self.app.login_attempts["stale"] = [now - self.app.login_window - 1]
        for i in range(6):
            self.app.record_failed_login(f"peer-{i}", now=now)
        self.assertNotIn("stale", self.app.login_attempts)
        self.assertLessEqual(len(self.app.login_attempts), self.app.login_key_limit)
        self.app.login_attempts.clear()
        self.app.login_key_limit = 2048


if __name__ == "__main__":
    unittest.main(verbosity=2)
