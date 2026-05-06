import argparse
import hashlib
import json
import re
import sys
from urllib.parse import unquote, urlsplit

import requests


POC_NAME = "normal_user_admin_access"
REQUEST_TIMEOUT_SECONDS = 3
SAFE_METHODS = {"GET"}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
AUTH_BLOCK_STATES = {"auth_block", "auth_redirect", "login_page", "denial_body"}
NORMAL_USER_AUTH_ASSUMPTION = "입력한 인증 정보가 일반 사용자 세션이라고 가정합니다."

ADMIN_INDICATOR_PATTERNS = (
    ("admin", re.compile(r"(^|[^a-z0-9])admin", re.IGNORECASE)),
    ("superuser", re.compile(r"super[-_]?user", re.IGNORECASE)),
    ("root", re.compile(r"(^|[^a-z0-9])root($|[^a-z0-9])", re.IGNORECASE)),
    ("staff", re.compile(r"(^|[^a-z0-9])staff($|[^a-z0-9])", re.IGNORECASE)),
    (
        "manager",
        re.compile(r"(^|[^a-z0-9])manage(ment|r|rs)?($|[^a-z0-9])", re.IGNORECASE),
    ),
    (
        "operator",
        re.compile(r"(^|[^a-z0-9])operator(s)?($|[^a-z0-9])", re.IGNORECASE),
    ),
    ("ops", re.compile(r"(^|[^a-z0-9])ops($|[^a-z0-9])", re.IGNORECASE)),
    (
        "moderator",
        re.compile(r"(^|[^a-z0-9])moderator(s)?($|[^a-z0-9])", re.IGNORECASE),
    ),
    ("backoffice", re.compile(r"back[-_]?office", re.IGNORECASE)),
    ("console", re.compile(r"(^|[^a-z0-9])console($|[^a-z0-9])", re.IGNORECASE)),
    ("cms", re.compile(r"(^|[^a-z0-9])cms($|[^a-z0-9])", re.IGNORECASE)),
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

DENIAL_RESPONSE_SIGNATURES = (
    "access denied",
    "permission denied",
    "forbidden",
    "not authorized",
    "not authorised",
    "unauthorized",
    "unauthorised",
    "insufficient privilege",
    "insufficient permission",
    "requires admin",
    "admin only",
    "administrator only",
    "role required",
    "접근 거부",
    "권한 없음",
    "권한이 없습니다",
    "관리자 권한",
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


def fingerprint(response):
    content = response.content or b""

    return {
        "status_code": response.status_code,
        "length": len(content),
        "sha1": hashlib.sha1(content).hexdigest(),
        "content_type": response.headers.get("Content-Type", ""),
        "location": response.headers.get("Location", ""),
    }


def looks_like_html(response):
    content_type = response.headers.get("Content-Type", "").lower()
    text_start = response.text[:200].lower()

    return "html" in content_type or "<html" in text_start or "<!doctype html" in text_start


def response_text_lower(response, limit=4000):
    return response.text[:limit].lower()


def looks_like_login_page(response):
    if not looks_like_html(response):
        return False

    text_lower = response_text_lower(response)

    if LOGIN_FORM_PATTERN.search(response.text[:8000]):
        return True

    if any(signature in text_lower for signature in STRONG_LOGIN_PAGE_SIGNATURES):
        return True

    return len(response.content or b"") < 2048 and any(
        signature in text_lower for signature in WEAK_LOGIN_PAGE_SIGNATURES
    )


def looks_like_denial_response(response):
    text_lower = response_text_lower(response)
    return any(signature in text_lower for signature in DENIAL_RESPONSE_SIGNATURES)


def looks_like_spa_shell(response):
    if not looks_like_html(response):
        return False

    text = response_text_lower(response)
    return any(signature in text for signature in SPA_SHELL_SIGNATURES)


def find_admin_indicators(path, query_params=None):
    parsed = urlsplit(path)
    decoded_target = unquote(f"{parsed.path}?{parsed.query}")

    if query_params:
        query_text = " ".join(
            f"{key}={value}" for key, value in sorted(query_params.items())
        )
        decoded_target = f"{decoded_target} {query_text}"

    decoded_target = decoded_target.lower()
    indicators = []

    for name, pattern in ADMIN_INDICATOR_PATTERNS:
        if pattern.search(decoded_target):
            indicators.append(name)

    return sorted(set(indicators))


def make_headers(auth_headers):
    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }
    headers.update(auth_headers or {})
    return headers


def request_once(method, url, query_params, auth_headers, auth_cookies):
    return requests.request(
        method=method,
        url=url,
        params=query_params or {},
        headers=make_headers(auth_headers),
        cookies=auth_cookies or {},
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )


def build_raw_output(
    method,
    path,
    query_params,
    auth_headers,
    auth_cookies,
    admin_indicators,
    unauth_baseline_fp=None,
    normal_user_probe_fp=None,
    unauth_baseline_response=None,
    normal_user_probe_response=None,
    unauth_baseline_state="",
    normal_user_probe_state="",
    note="",
):
    notes = [NORMAL_USER_AUTH_ASSUMPTION]
    if note:
        notes.append(note)

    return json.dumps(
        {
            "request": {
                "method": method,
                "path": path,
                "query_param_keys": sorted((query_params or {}).keys()),
                "auth_header_keys": sorted((auth_headers or {}).keys()),
                "auth_cookie_keys": sorted((auth_cookies or {}).keys()),
            },
            "admin_indicators": admin_indicators,
            "analysis": {
                "unauth_baseline_state": unauth_baseline_state,
                "normal_user_probe_state": normal_user_probe_state,
            },
            "unauth_baseline": unauth_baseline_fp,
            "normal_user_probe": normal_user_probe_fp,
            "unauth_baseline_preview": (
                unauth_baseline_response.text[:500] if unauth_baseline_response else ""
            ),
            "normal_user_probe_preview": (
                normal_user_probe_response.text[:500] if normal_user_probe_response else ""
            ),
            "note": " ".join(notes),
        },
        ensure_ascii=False,
    )


def make_result(status, description, evidence="", raw_output="", vulnerable=False):
    if NORMAL_USER_AUTH_ASSUMPTION not in description:
        description = f"{description} {NORMAL_USER_AUTH_ASSUMPTION}"

    return {
        "poc_name": POC_NAME,
        "status": status,
        "description": description,
        "evidence": evidence,
        "raw_output": raw_output,
        "vulnerable": vulnerable,
    }


def classify_access_state(response):
    status_code = response.status_code
    location = response.headers.get("Location", "")
    location_lower = location.lower()

    if status_code >= 500:
        return "server_error"

    if status_code in (401, 403):
        return "auth_block"

    if status_code in REDIRECT_STATUSES:
        if not location:
            return "empty_redirect"
        if any(keyword in location_lower for keyword in LOGIN_REDIRECT_KEYWORDS):
            return "auth_redirect"
        return "other_redirect"

    if status_code == 404:
        return "not_found"

    if status_code == 405:
        return "method_not_allowed"

    if 400 <= status_code < 500:
        return "client_error"

    if 200 <= status_code < 300:
        if looks_like_login_page(response):
            return "login_page"
        if looks_like_denial_response(response):
            return "denial_body"
        if looks_like_spa_shell(response):
            return "spa_shell"
        return "success"

    return "unknown"


def build_evidence(unauth_baseline, normal_user_probe, baseline_state, probe_state):
    return (
        f"unauth=HTTP {unauth_baseline.status_code} ({baseline_state}), "
        f"normal_user=HTTP {normal_user_probe.status_code} ({probe_state})"
    )


def classify_responses(
    method,
    path,
    query_params,
    auth_headers,
    auth_cookies,
    admin_indicators,
    unauth_baseline,
    normal_user_probe,
):
    baseline_state = classify_access_state(unauth_baseline)
    probe_state = classify_access_state(normal_user_probe)
    baseline_fp = fingerprint(unauth_baseline)
    probe_fp = fingerprint(normal_user_probe)
    evidence = build_evidence(
        unauth_baseline,
        normal_user_probe,
        baseline_state,
        probe_state,
    )
    raw_output = build_raw_output(
        method=method,
        path=path,
        query_params=query_params,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        admin_indicators=admin_indicators,
        unauth_baseline_fp=baseline_fp,
        normal_user_probe_fp=probe_fp,
        unauth_baseline_response=unauth_baseline,
        normal_user_probe_response=normal_user_probe,
        unauth_baseline_state=baseline_state,
        normal_user_probe_state=probe_state,
    )

    if baseline_state == "server_error":
        return make_result(
            status="Skipped",
            description="비인증 baseline 요청이 서버 오류를 반환해 권한 비교를 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "server_error":
        return make_result(
            status="Skipped",
            description="일반 사용자 요청이 서버 오류를 반환해 권한 비교를 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state in AUTH_BLOCK_STATES and baseline_state == "success":
        return make_result(
            status="Completed",
            description="비인증 baseline은 성공하지만 일반 사용자 요청은 차단되어 판단을 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state in AUTH_BLOCK_STATES:
        return make_result(
            status="Completed",
            description="일반 사용자 세션으로도 관리자 경로 접근이 차단되었습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "empty_redirect":
        return make_result(
            status="Completed",
            description="일반 사용자 요청이 Location 없는 리다이렉트를 반환해 판단을 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "other_redirect":
        location = normal_user_probe.headers.get("Location", "")
        return make_result(
            status="Completed",
            description="일반 사용자 요청이 로그인 경로가 아닌 곳으로 리다이렉트되어 수동 확인이 필요합니다.",
            evidence=f"{evidence}, Location={location}",
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "not_found":
        return make_result(
            status="Completed",
            description="관리자 경로가 존재하지 않거나 일반 사용자에게 숨겨진 것으로 보입니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "method_not_allowed":
        return make_result(
            status="Completed",
            description="대상 경로가 GET 접근을 허용하지 않아 관리자 접근 여부를 판단하지 않았습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "client_error":
        return make_result(
            status="Completed",
            description="일반 사용자 요청이 정상 접근으로 처리되지 않았습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state == "spa_shell":
        return make_result(
            status="Completed",
            description="일반 사용자 응답이 SPA 앱 셸로 보여 실제 관리자 API 접근 여부는 수동 확인이 필요합니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if probe_state != "success":
        return make_result(
            status="Completed",
            description="일반 사용자 응답만으로 관리자 접근 여부를 확인하기 어렵습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if baseline_state in AUTH_BLOCK_STATES:
        return make_result(
            status="Completed",
            description="비인증 요청은 차단되지만 일반 사용자 세션은 관리자 경로에서 성공 응답을 받았습니다.",
            evidence=f"{evidence}, indicators={','.join(admin_indicators)}",
            raw_output=raw_output,
            vulnerable=True,
        )

    if baseline_state == "success":
        return make_result(
            status="Completed",
            description="비인증 baseline도 성공 응답을 반환해 일반 사용자 권한 우회로 판단하지 않았습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if baseline_state == "spa_shell":
        return make_result(
            status="Completed",
            description="비인증 baseline이 SPA 앱 셸을 반환해 실제 XHR/API 엔드포인트 확인이 필요합니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if baseline_state == "empty_redirect":
        return make_result(
            status="Completed",
            description="비인증 baseline이 Location 없는 리다이렉트를 반환해 판단을 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if baseline_state == "other_redirect":
        location = unauth_baseline.headers.get("Location", "")
        return make_result(
            status="Completed",
            description="비인증 baseline이 로그인 경로가 아닌 곳으로 리다이렉트되어 수동 확인이 필요합니다.",
            evidence=f"{evidence}, unauth_location={location}",
            raw_output=raw_output,
            vulnerable=False,
        )

    return make_result(
        status="Completed",
        description="비인증 baseline이 명확한 인증 차단 신호가 아니어서 일반 사용자 접근 성공을 취약으로 단정하지 않았습니다.",
        evidence=evidence,
        raw_output=raw_output,
        vulnerable=False,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        payload = json.load(f)

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "GET").upper()
    query_params = payload.get("query_params", {}) or {}
    auth = payload.get("auth", {}) or {}
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    url = f"{base_url}{path}"
    admin_indicators = find_admin_indicators(path, query_params)

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] admin_indicators={admin_indicators}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            result = make_result(
                status="Skipped",
                description=f"{method} 요청은 일반 사용자 probe가 자원 변경을 일으킬 수 있어 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    admin_indicators=admin_indicators,
                    note="안전하지 않은 메서드라 실제 요청 전 검사를 건너뛰었습니다.",
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not admin_indicators:
            result = make_result(
                status="Skipped",
                description="경로에서 관리자/운영자 기능으로 볼 만한 신호를 찾지 못해 검사를 건너뜁니다.",
                evidence="missing admin path indicator",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    admin_indicators=admin_indicators,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not auth_headers and not auth_cookies:
            result = make_result(
                status="Skipped",
                description="일반 사용자 세션으로 사용할 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing normal user auth",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    admin_indicators=admin_indicators,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        unauth_baseline = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers={},
            auth_cookies={},
        )

        normal_user_probe = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )

        result = classify_responses(
            method=method,
            path=path,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            admin_indicators=admin_indicators,
            unauth_baseline=unauth_baseline,
            normal_user_probe=normal_user_probe,
        )

    except Exception as e:
        result = make_result(
            status="Error",
            description="PoC execution failed.",
            evidence=str(e),
            raw_output="",
            vulnerable=False,
        )

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
