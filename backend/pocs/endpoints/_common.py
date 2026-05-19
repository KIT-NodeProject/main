"""Shared constants and helpers for endpoint PoCs."""
from __future__ import annotations

import argparse
import hashlib
import json
import re

import requests


USER_AGENT = "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809"
REQUEST_TIMEOUT_SECONDS = 3


# ---------- key / value heuristics ----------

IGNORE_KEYS = frozenset({
    "page",
    "size",
    "limit",
    "offset",
    "sort",
    "order",
    "year",
    "month",
    "day",
    "count",
    "total",
    "amount",
    "price",
    "quantity",
    "qty",
    "csrf",
    "csrf_token",
    "_csrf",
    "token",
    "access_token",
    "refresh_token",
    "password",
})

ID_KEY_PATTERN = re.compile(
    r"(^id$|(^|[_\-.])(id|user_id|owner_id|account_id|member_id|post_id|"
    r"article_id|item_id|resource_id|order_id|invoice_id|tenant_id|org_id|"
    r"organization_id|team_id|project_id|document_id|file_id|profile_id)$|"
    r"(^|[_\-.])[a-z0-9]+_id$)",
    re.IGNORECASE,
)


# ---------- response signatures ----------

DENIAL_SIGNATURES = (
    "access denied",
    "permission denied",
    "forbidden",
    "not authorized",
    "not authorised",
    "unauthorized",
    "unauthorised",
    "insufficient privilege",
    "insufficient permission",
    "권한 없음",
    "권한이 없습니다",
    "접근 거부",
)

ADMIN_DENIAL_SIGNATURES = DENIAL_SIGNATURES + (
    "requires admin",
    "admin only",
    "administrator only",
    "role required",
    "관리자 권한",
)

APPLICATION_FAILURE_SIGNATURES = (
    "not found",
    "not_found",
    "no such",
    "does not exist",
    "invalid id",
    "invalid resource",
    "resource not found",
    "record not found",
    "already deleted",
    "존재하지",
    "찾을 수 없",
)

LOGIN_REDIRECT_KEYWORDS = (
    "account",
    "login",
    "signin",
    "sign-in",
    "sign_in",
    "auth",
    "authenticate",
    "authentication",
    "oauth",
    "sso",
    "saml",
    "idp",
    "identity",
    "realm",
    "realms",
    "keycloak",
    "cas",
    "session",
)

LOGIN_FORM_PATTERN = re.compile(
    r"<form\b[^>]*>.*?<input\b[^>]*type=[\"']?password",
    re.IGNORECASE | re.DOTALL,
)

STRONG_LOGIN_PAGE_SIGNATURES = (
    'type="password"',
    "type='password'",
    "name=\"password\"",
    "name='password'",
    "id=\"password\"",
    "id='password'",
    "login form",
    "login-form",
    "please sign in",
    "please log in",
    "please login",
    "session expired",
    "session: null",
    '"session":null',
)

WEAK_LOGIN_PAGE_SIGNATURES = (
    "sign in",
    "log in",
    "href=\"/login",
    "href='/login",
    "action=\"/login",
    "action='/login",
)

SPA_SHELL_SIGNATURES = (
    'id="root"',
    "id='root'",
    'id="app"',
    "id='app'",
    "__next_data__",
    "__nuxt",
    "vite",
    "static/js",
)


# ---------- value helpers ----------

def is_number(value):
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    if text == "":
        return False
    return text.isdigit()


def normalize_key_for_matching(key):
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    return text.lower()


def is_id_like_key(key):
    normalized = normalize_key_for_matching(key)
    return bool(ID_KEY_PATTERN.search(normalized))


def mutate_numeric_value(value):
    changed = int(str(value).strip()) + 1
    if isinstance(value, int) and not isinstance(value, bool):
        return changed
    return str(changed)


def value_echoed_in_text(value, text):
    pattern = rf"(?<!\w){re.escape(str(value))}(?!\w)"
    return re.search(pattern, text) is not None


# ---------- HTTP helpers ----------

def make_headers(auth_headers, *, body_mode=None):
    headers = {"User-Agent": USER_AGENT}
    headers.update(auth_headers or {})

    if body_mode == "json" and not any(
        key.lower() == "content-type" for key in headers
    ):
        headers["Content-Type"] = "application/json"

    return headers


def request_once(
    method,
    url,
    *,
    query_params=None,
    body_mode=None,
    body_params=None,
    auth_headers=None,
    auth_cookies=None,
    timeout=REQUEST_TIMEOUT_SECONDS,
):
    kwargs = {
        "method": method,
        "url": url,
        "params": query_params or {},
        "headers": make_headers(auth_headers, body_mode=body_mode),
        "cookies": auth_cookies or {},
        "timeout": timeout,
        "allow_redirects": False,
    }

    if body_mode == "form":
        kwargs["data"] = body_params or {}
    elif body_mode == "json":
        kwargs["json"] = body_params or {}

    return requests.request(**kwargs)


def fingerprint(response):
    content = response.content or b""
    return {
        "status_code": response.status_code,
        "length": len(content),
        "sha1": hashlib.sha1(content).hexdigest(),
        "content_type": response.headers.get("Content-Type", ""),
        "location": response.headers.get("Location", ""),
    }


# ---------- response inspection ----------

def response_text_lower(response, limit=4000):
    return response.text[:limit].lower()


def has_text_signature(response, signatures):
    text_lower = response_text_lower(response)
    return any(signature in text_lower for signature in signatures)


def looks_like_html(response):
    content_type = response.headers.get("Content-Type", "").lower()
    text_start = response.text[:200].lower()
    return (
        "html" in content_type
        or "<html" in text_start
        or "<!doctype html" in text_start
    )


def looks_like_login_page(response, *, include_weak=False, extra_weak_signatures=()):
    if not looks_like_html(response):
        return False

    text_lower = response_text_lower(response)

    if LOGIN_FORM_PATTERN.search(response.text[:8000]):
        return True

    if any(signature in text_lower for signature in STRONG_LOGIN_PAGE_SIGNATURES):
        return True

    if include_weak and len(response.content or b"") < 2048:
        weak = WEAK_LOGIN_PAGE_SIGNATURES + tuple(extra_weak_signatures)
        if any(signature in text_lower for signature in weak):
            return True

    return False


def looks_like_spa_shell(response):
    if not looks_like_html(response):
        return False
    return any(s in response_text_lower(response) for s in SPA_SHELL_SIGNATURES)


def looks_like_denial_response(response, *, signatures=None):
    return has_text_signature(response, signatures or DENIAL_SIGNATURES)


# ---------- classification ----------

def classify_response(
    response,
    *,
    detect_application_failure=True,
    detect_login_redirect=False,
    login_page_include_weak=False,
    login_page_extra_weak=(),
    denial_signatures=None,
):
    """Map a response to a coarse-grained state name shared across PoCs."""
    status = response.status_code

    if status >= 500:
        return "server_error"

    if status in (401, 403):
        return "auth_block"

    if status in (301, 302, 303, 307, 308):
        if not detect_login_redirect:
            return "redirect"

        location = response.headers.get("Location", "")
        if not location:
            return "empty_redirect"

        if any(k in location.lower() for k in LOGIN_REDIRECT_KEYWORDS):
            return "auth_redirect"

        return "other_redirect"

    if status == 404:
        return "not_found"

    if status == 405:
        return "method_not_allowed"

    if 400 <= status < 500:
        return "client_error"

    if 200 <= status < 300:
        if looks_like_login_page(
            response,
            include_weak=login_page_include_weak,
            extra_weak_signatures=login_page_extra_weak,
        ):
            return "login_page"

        if has_text_signature(response, denial_signatures or DENIAL_SIGNATURES):
            return "denial_body"

        if detect_application_failure and has_text_signature(
            response, APPLICATION_FAILURE_SIGNATURES
        ):
            return "application_failure"

        if looks_like_spa_shell(response):
            return "spa_shell"

        return "success"

    return "unknown"


# ---------- result helpers ----------

def make_result(
    poc_name,
    status,
    description,
    *,
    evidence="",
    raw_output="",
    vulnerable=False,
):
    return {
        "poc_name": poc_name,
        "status": status,
        "description": description,
        "evidence": evidence,
        "raw_output": raw_output,
        "vulnerable": vulnerable,
    }


def error_result(poc_name, exc):
    return make_result(
        poc_name=poc_name,
        status="Error",
        description="PoC execution failed.",
        evidence=str(exc),
    )


def emit(result):
    print(json.dumps(result, ensure_ascii=False))


def parse_payload():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        return json.load(f)
