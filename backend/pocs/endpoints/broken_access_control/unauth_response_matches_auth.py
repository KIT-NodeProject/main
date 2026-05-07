import argparse
import hashlib
import json
import re
import sys

import requests


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
    "unauthorized",
    "forbidden",
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

REQUEST_TIMEOUT_SECONDS = 3
SAFE_METHODS = {"GET"}


def fingerprint(response):
    content = response.content or b""
    content_type = response.headers.get("Content-Type", "")

    return {
        "status_code": response.status_code,
        "length": len(content),
        "sha1": hashlib.sha1(content).hexdigest(),
        "content_type": content_type,
        "location": response.headers.get("Location", ""),
    }


def looks_like_html(response):
    content_type = response.headers.get("Content-Type", "").lower()
    text_start = response.text[:200].lower()

    return "html" in content_type or "<html" in text_start or "<!doctype html" in text_start


def looks_like_login_page(response):
    if not looks_like_html(response):
        return False

    text = response.text[:4000]
    text_lower = text.lower()

    if LOGIN_FORM_PATTERN.search(response.text[:8000]):
        return True

    if any(signature in text_lower for signature in STRONG_LOGIN_PAGE_SIGNATURES):
        return True

    return len(response.content or b"") < 2048 and any(
        signature in text_lower for signature in WEAK_LOGIN_PAGE_SIGNATURES
    )


def looks_like_spa_shell(response):
    if not looks_like_html(response):
        return False

    text = response.text[:4000].lower()
    return any(signature in text for signature in SPA_SHELL_SIGNATURES)


def lengths_are_close(first, second, tolerance=0.1):
    first_length = first["length"]
    second_length = second["length"]

    if first_length == second_length:
        return True
    if first_length == 0 or second_length == 0:
        return False

    return abs(first_length - second_length) / max(first_length, second_length) <= tolerance


def content_type_group(content_type):
    normalized = content_type.lower()

    if "json" in normalized:
        return "json"
    if "html" in normalized:
        return "html"
    if "xml" in normalized:
        return "xml"
    if "text" in normalized:
        return "text"

    return normalized.split(";")[0].strip()


def content_types_are_similar(first, second):
    first_group = content_type_group(first["content_type"])
    second_group = content_type_group(second["content_type"])

    if not first_group or not second_group:
        return first_group == second_group

    return first_group == second_group


def build_request_kwargs(method, query_params, auth_headers=None, auth_cookies=None):
    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }
    headers.update(auth_headers or {})

    return {
        "params": query_params or {},
        "headers": headers,
        "cookies": auth_cookies or {},
        "timeout": REQUEST_TIMEOUT_SECONDS,
        "allow_redirects": False,
    }


def request_once(method, url, query_params, auth_headers=None, auth_cookies=None):
    return requests.request(
        method=method,
        url=url,
        **build_request_kwargs(method, query_params, auth_headers, auth_cookies),
    )


def build_raw_output(baseline_fp=None, probe_fp=None, probe_response=None, note=""):
    return json.dumps(
        {
            "baseline": baseline_fp,
            "probe": probe_fp,
            "probe_preview": probe_response.text[:500] if probe_response else "",
            "note": note,
        },
        ensure_ascii=False,
    )


def classify_probe(baseline_response, probe_response):
    baseline_fp = fingerprint(baseline_response)
    probe_fp = fingerprint(probe_response)
    status_code = probe_response.status_code
    location = probe_response.headers.get("Location", "")
    location_lower = location.lower()

    raw_output = build_raw_output(baseline_fp, probe_fp, probe_response)

    if status_code >= 500:
        return (
            "Skipped",
            False,
            "비인증 요청이 서버 오류를 반환해 판단을 보류했습니다.",
            f"HTTP {status_code}",
            raw_output,
        )

    if status_code in (401, 403):
        return (
            "Completed",
            False,
            "인증 없이 접근이 차단되었습니다.",
            f"HTTP {status_code}",
            raw_output,
        )

    if status_code in (301, 302, 303, 307, 308):
        if not location:
            return (
                "Completed",
                False,
                "비인증 요청이 Location 없는 리다이렉트를 반환해 판단을 보류했습니다.",
                f"HTTP {status_code}, empty Location",
                raw_output,
            )

        if any(keyword in location_lower for keyword in LOGIN_REDIRECT_KEYWORDS):
            return (
                "Completed",
                False,
                "인증 없이 요청했을 때 로그인/인증 경로로 이동했습니다.",
                f"HTTP {status_code}, Location={location}",
                raw_output,
            )

        return (
            "Completed",
            False,
            "비인증 요청이 로그인 경로가 아닌 곳으로 리다이렉트되어 판단을 보류했습니다.",
            f"HTTP {status_code}, Location={location}",
            raw_output,
        )

    if 200 <= status_code < 300:
        if looks_like_login_page(probe_response):
            return (
                "Completed",
                False,
                "비인증 요청의 응답이 로그인/인증 안내 화면으로 보입니다.",
                f"HTTP {status_code}",
                raw_output,
            )

        same_body = (
            baseline_fp["length"] > 0
            and probe_fp["length"] > 0
            and baseline_fp["sha1"] == probe_fp["sha1"]
        )
        close_length = lengths_are_close(baseline_fp, probe_fp)
        same_type = content_types_are_similar(baseline_fp, probe_fp)
        both_html = looks_like_html(baseline_response) and looks_like_html(probe_response)

        if both_html and (
            looks_like_spa_shell(baseline_response) or looks_like_spa_shell(probe_response)
        ):
            return (
                "Completed",
                False,
                "비인증 요청도 HTML 앱 셸을 반환해 SPA 라우팅 응답으로 판단을 보류했습니다. 실제 XHR/API 엔드포인트를 확인해야 합니다.",
                f"HTTP {status_code}, baseline_length={baseline_fp['length']}, probe_length={probe_fp['length']}",
                raw_output,
            )

        if same_body or (close_length and same_type and not both_html):
            return (
                "Completed",
                True,
                "인증 응답과 비인증 응답이 유사해 보호 엔드포인트 인증 우회 가능성이 있습니다.",
                (
                    f"HTTP {status_code}, same_body={same_body}, "
                    f"close_length={close_length}, same_type={same_type}"
                ),
                raw_output,
            )

        return (
            "Completed",
            False,
            "비인증 요청이 2xx를 반환했습니다. baseline과 본문은 다르지만 수동 확인이 필요합니다.",
            f"HTTP {status_code}, probe returned 2xx without auth, manual review recommended",
            raw_output,
        )

    if 400 <= status_code < 500:
        return (
            "Completed",
            False,
            "인증 제거 후 정상 응답이 사라져 보호 동작으로 판단했습니다.",
            f"HTTP {status_code}",
            raw_output,
        )

    return (
        "Completed",
        False,
        f"상태 코드 {status_code}만으로 인증 우회를 확인하기 어렵습니다.",
        f"HTTP {status_code}",
        raw_output,
    )


def make_result(status, description, evidence="", raw_output="", vulnerable=False):
    return {
        "poc_name": "unauth_response_matches_auth",
        "status": status,
        "description": description,
        "evidence": evidence,
        "raw_output": raw_output,
        "vulnerable": vulnerable,
    }


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

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            result = make_result(
                status="Skipped",
                description=f"{method} 요청은 비인증 probe가 자원 변경을 일으킬 수 있어 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                raw_output=json.dumps(
                    {"method": method, "safe_methods": sorted(SAFE_METHODS)},
                    ensure_ascii=False,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not auth_headers and not auth_cookies:
            result = make_result(
                status="Skipped",
                description="인증 포함 baseline을 만들 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth baseline",
                raw_output=json.dumps({"auth_headers": [], "auth_cookies": []}, ensure_ascii=False),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        baseline_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )
        baseline_fp = fingerprint(baseline_response)

        if baseline_response.status_code >= 500:
            result = make_result(
                status="Skipped",
                description="인증 포함 baseline 요청이 서버 오류를 반환해 검사를 건너뜁니다.",
                evidence=f"HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(baseline_fp=baseline_fp),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not 200 <= baseline_response.status_code < 300:
            result = make_result(
                status="Skipped",
                description="인증 포함 baseline이 정상 동작하지 않아 비인증 비교를 수행하지 않았습니다.",
                evidence=f"HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(baseline_fp=baseline_fp),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        print("[DEBUG] baseline acquired with auth", file=sys.stderr)
        print("[DEBUG] probe auth intentionally omitted", file=sys.stderr)

        probe_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers={},
            auth_cookies={},
        )

        status, vulnerable, description, evidence, raw_output = classify_probe(
            baseline_response,
            probe_response,
        )
        result = make_result(
            status=status,
            description=description,
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=vulnerable,
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
