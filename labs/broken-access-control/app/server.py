from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


USERS = {
    "kim": {"id": 1, "username": "kim", "role": "user"},
    "lee": {"id": 2, "username": "lee", "role": "user"},
    "admin": {"id": 99, "username": "admin", "role": "admin"},
}

TOKENS = {
    "kim-token": "kim",
    "lee-token": "lee",
    "admin-token": "admin",
}

PROFILES = {
    1: {"user_id": 1, "username": "kim", "email": "kim@example.test"},
    2: {"user_id": 2, "username": "lee", "email": "lee@example.test"},
}

DOCUMENTS = {
    1: {"document_id": 1, "owner_id": 1, "title": "Kim quarterly notes"},
    2: {"document_id": 2, "owner_id": 2, "title": "Lee payroll draft"},
    1001: {"document_id": 1001, "owner_id": 1, "title": "Kim contract packet"},
    1002: {"document_id": 1002, "owner_id": 2, "title": "Lee salary memo"},
}

POSTS = {
    1: {"post_id": 1, "owner_id": 1, "title": "Kim private post"},
    2: {"post_id": 2, "owner_id": 2, "title": "Lee private post"},
}

PUBLIC_LEAK = {
    "tenant_id": 777,
    "plan": "enterprise-trial",
    "billing_contact": "finance@example.test",
}


def to_json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")


def first_query_value(query, key, default=None):
    values = query.get(key)
    if not values:
        return default
    return values[0]


def parse_int(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


class BrokenAccessControlLab(BaseHTTPRequestHandler):
    server_version = "BrokenAccessControlLab/1.0"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args))

    def send_json(self, status, body, headers=None):
        payload = to_json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}

        raw = self.rfile.read(length).decode("utf-8")
        content_type = self.headers.get("Content-Type", "").lower()

        if "application/x-www-form-urlencoded" in content_type:
            return {key: values[0] for key, values in parse_qs(raw).items()}

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}

        return parsed if isinstance(parsed, dict) else {}

    def current_user(self):
        cookie_header = self.headers.get("Cookie", "")
        cookies = SimpleCookie()
        cookies.load(cookie_header)

        session = cookies.get("session")
        if session and session.value in USERS:
            return USERS[session.value]

        authorization = self.headers.get("Authorization", "")
        prefix = "Bearer "
        if authorization.startswith(prefix):
            username = TOKENS.get(authorization[len(prefix):])
            if username:
                return USERS[username]

        return None

    def require_user(self):
        user = self.current_user()
        if user:
            return user

        self.send_json(
            HTTPStatus.UNAUTHORIZED,
            {"error": "unauthorized", "message": "login required"},
        )
        return None

    def route(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ok"})
            return

        if parsed.path == "/login" and self.command == "GET":
            self.handle_login(query)
            return

        if parsed.path == "/catalog":
            self.handle_catalog()
            return

        routes = {
            ("GET", "/vuln/profile"): self.handle_vuln_profile,
            ("GET", "/safe/profile"): self.handle_safe_profile,
            ("POST", "/vuln/document"): self.handle_vuln_document,
            ("POST", "/safe/document"): self.handle_safe_document,
            ("DELETE", "/vuln/post"): self.handle_vuln_delete_post,
            ("DELETE", "/safe/post"): self.handle_safe_delete_post,
            ("GET", "/vuln/private-dashboard"): self.handle_vuln_private_dashboard,
            ("GET", "/safe/private-dashboard"): self.handle_safe_private_dashboard,
            ("GET", "/vuln/admin/users"): self.handle_vuln_admin_users,
            ("GET", "/safe/admin/users"): self.handle_safe_admin_users,
        }

        handler = routes.get((self.command, parsed.path))
        if not handler:
            self.send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "not_found", "path": parsed.path, "method": self.command},
            )
            return

        handler(query)

    def handle_login(self, query):
        username = first_query_value(query, "user", "kim")
        user = USERS.get(username)
        if not user:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "unknown_user", "valid_users": sorted(USERS)},
            )
            return

        token = f"{username}-token"
        self.send_json(
            HTTPStatus.OK,
            {
                "message": "lab session issued",
                "user": user,
                "cookie": f"session={username}",
                "authorization": f"Bearer {token}",
            },
            headers={"Set-Cookie": f"session={username}; Path=/; HttpOnly; SameSite=Lax"},
        )

    def handle_catalog(self):
        self.send_json(
            HTTPStatus.OK,
            {
                "sessions": {
                    "normal_user_cookie": "session=kim",
                    "normal_user_authorization": "Bearer kim-token",
                    "admin_cookie": "session=admin",
                },
                "vulnerable_endpoints": [
                    {
                        "method": "GET",
                        "path": "/vuln/profile",
                        "query_params": {"user_id": 1},
                        "poc": "idor_query_read_resource",
                    },
                    {
                        "method": "POST",
                        "path": "/vuln/document",
                        "body_params": {"document_id": 1001},
                        "poc": "idor_body_resource",
                    },
                    {
                        "method": "DELETE",
                        "path": "/vuln/post",
                        "query_params": {"post_id": 1},
                        "allow_destructive_probe": True,
                        "poc": "idor_query_delete_resource",
                    },
                    {
                        "method": "GET",
                        "path": "/vuln/private-dashboard",
                        "poc": "unauth_response_matches_auth",
                    },
                    {
                        "method": "GET",
                        "path": "/vuln/admin/users",
                        "poc": "normal_user_admin_access",
                    },
                ],
                "safe_endpoints": [
                    "/safe/profile",
                    "/safe/document",
                    "/safe/post",
                    "/safe/private-dashboard",
                    "/safe/admin/users",
                ],
            },
        )

    def handle_vuln_profile(self, query):
        if not self.require_user():
            return

        user_id = parse_int(first_query_value(query, "user_id"))
        profile = PROFILES.get(user_id)
        if not profile:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        self.send_json(HTTPStatus.OK, {"profile": profile})

    def handle_safe_profile(self, query):
        user = self.require_user()
        if not user:
            return

        user_id = parse_int(first_query_value(query, "user_id"))
        if user_id != user["id"]:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return

        self.send_json(HTTPStatus.OK, {"profile": PROFILES[user_id]})

    def handle_vuln_document(self, query):
        if not self.require_user():
            return

        body = self.read_body()
        document_id = parse_int(body.get("document_id"))
        document = DOCUMENTS.get(document_id)
        if not document:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        self.send_json(HTTPStatus.OK, {"document": document})

    def handle_safe_document(self, query):
        user = self.require_user()
        if not user:
            return

        body = self.read_body()
        document_id = parse_int(body.get("document_id"))
        document = DOCUMENTS.get(document_id)
        if not document:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        if document["owner_id"] != user["id"]:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return

        self.send_json(HTTPStatus.OK, {"document": document})

    def handle_vuln_delete_post(self, query):
        if not self.require_user():
            return

        post_id = parse_int(first_query_value(query, "post_id"))
        post = POSTS.get(post_id)
        if not post:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        self.send_json(
            HTTPStatus.OK,
            {"deleted": True, "post": post, "simulation": "state is not mutated"},
        )

    def handle_safe_delete_post(self, query):
        user = self.require_user()
        if not user:
            return

        post_id = parse_int(first_query_value(query, "post_id"))
        post = POSTS.get(post_id)
        if not post:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        if post["owner_id"] != user["id"]:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return

        self.send_json(
            HTTPStatus.OK,
            {"deleted": True, "post": post, "simulation": "state is not mutated"},
        )

    def handle_vuln_private_dashboard(self, query):
        self.send_json(HTTPStatus.OK, PUBLIC_LEAK)

    def handle_safe_private_dashboard(self, query):
        user = self.require_user()
        if not user:
            return

        self.send_json(HTTPStatus.OK, {"user": user, "dashboard": PUBLIC_LEAK})

    def handle_vuln_admin_users(self, query):
        if not self.require_user():
            return

        self.send_json(HTTPStatus.OK, {"admin_users": list(USERS.values())})

    def handle_safe_admin_users(self, query):
        user = self.require_user()
        if not user:
            return

        if user["role"] != "admin":
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
            return

        self.send_json(HTTPStatus.OK, {"admin_users": list(USERS.values())})

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def do_DELETE(self):
        self.route()


def main():
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "9000"))
    server = ThreadingHTTPServer((host, port), BrokenAccessControlLab)
    print(f"Broken access control lab listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
