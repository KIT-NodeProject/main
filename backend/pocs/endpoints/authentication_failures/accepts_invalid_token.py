from __future__ import annotations

import json
import sys

from backend.pocs.endpoints._common import (
    DENIAL_SIGNATURES,
    classify_response,
    emit,
    error_result,
    fingerprint,
    looks_like_html,
    looks_like_spa_shell,
    make_result as common_make_result,
    parse_payload,
    request_once,
)


POC_NAME = "accepts_invalid_token"
SAFE_METHODS = {"GET"}
INVALID_TOKEN = "invalid-scanner-token"
INVALID_COOKIE_VALUE = "invalid-scanner-session"

AUTH_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
}

INVALID_AUTH_DENIAL_SIGNATURES = DENIAL_SIGNATURES + (
    "invalid token",
    "invalid_token",
    "bad token",
    "malformed token",
    "expired token",
    "token expired",
    "invalid session",
    "session expired",
    "invalid cookie",
    "authentication required",
    "login required",
    "로그인이 필요",
    "인증이 필요",
    "세션 만료",
)

AUTH_REJECT_STATES = {
    "auth_block",
    "auth_redirect",
    "login_page",
    "denial_body",
}


def lengths_are_close(first, second, tolerance=0.1):
    first_length = first["length"]
    second_length = second["length"]

    if first_length == 0 or second_length == 0:
        return False
    if first_length == second_length:
        return True

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


def parse_json_body(response):
    content_type = response.headers.get("Content-Type", "").lower()
    text = response.text.strip()

    if not text:
        return None
    if "json" not in content_type and not text.startswith(("{", "[")):
        return None

    try:
        return json.loads(text)
    except ValueError:
        return None


def json_shape(value, depth=3):
    if depth <= 0:
        return type(value).__name__

    if isinstance(value, dict):
        return (
            "dict",
            tuple(
                sorted(
                    (str(key), json_shape(child, depth - 1))
                    for key, child in value.items()
                )
            ),
        )

    if isinstance(value, list):
        if not value:
            return ("list", "empty")
        return ("list", json_shape(value[0], depth - 1))

    return type(value).__name__


def json_shapes_are_similar(first_response, second_response):
    first_json = parse_json_body(first_response)
    second_json = parse_json_body(second_response)

    if first_json is None or second_json is None:
        return None

    return json_shape(first_json) == json_shape(second_json)


def is_auth_header_name(name):
    lowered = str(name).lower()

    if lowered == "cookie" or lowered in AUTH_HEADER_NAMES:
        return True

    if "csrf" in lowered:
        return False

    return (
        "token" in lowered
        or "auth" in lowered
        or "api-key" in lowered
        or "apikey" in lowered
        or "session" in lowered
    )


def invalid_authorization_value(value):
    original = str(value or "").strip()

    if " " in original:
        scheme, _ = original.split(None, 1)
        return f"{scheme} {INVALID_TOKEN}"
    if original:
        return INVALID_TOKEN

    return f"Bearer {INVALID_TOKEN}"


def invalid_cookie_header(value):
    parts = [part.strip() for part in str(value or "").split(";") if part.strip()]

    if not parts:
        return f"session={INVALID_COOKIE_VALUE}"

    mutated = []
    for part in parts:
        if "=" not in part:
            continue
        name, _ = part.split("=", 1)
        name = name.strip()
        if name:
            mutated.append(f"{name}={INVALID_COOKIE_VALUE}")

    if not mutated:
        return f"session={INVALID_COOKIE_VALUE}"

    return "; ".join(mutated)


def mutate_auth_headers(auth_headers):
    mutated_headers = dict(auth_headers or {})
    mutated_keys = []

    candidate_keys = [
        key for key in mutated_headers
        if is_auth_header_name(key)
    ]

    for key in candidate_keys:
        lowered = key.lower()

        if lowered == "authorization" or lowered == "proxy-authorization":
            mutated_headers[key] = invalid_authorization_value(mutated_headers.get(key))
        elif lowered == "cookie":
            mutated_headers[key] = invalid_cookie_header(mutated_headers.get(key))
        else:
            mutated_headers[key] = INVALID_TOKEN

        mutated_keys.append(f"header:{key}")

    return mutated_headers, mutated_keys


def mutate_auth_cookies(auth_cookies):
    mutated_cookies = {
        key: INVALID_COOKIE_VALUE
        for key in (auth_cookies or {})
    }
    mutated_keys = [f"cookie:{key}" for key in sorted(mutated_cookies)]

    return mutated_cookies, mutated_keys


def classify_token_response(response):
    return classify_response(
        response,
        detect_application_failure=True,
        detect_login_redirect=True,
        login_page_include_weak=True,
        login_page_extra_weak=("invalid token", "invalid session"),
        denial_signatures=INVALID_AUTH_DENIAL_SIGNATURES,
    )


def build_raw_output(
    method,
    path,
    query_params,
    auth_headers,
    auth_cookies,
    mutated_keys,
    baseline_fp=None,
    invalid_fp=None,
    baseline_response=None,
    invalid_response=None,
    baseline_state="",
    invalid_state="",
    note="",
):
    return json.dumps(
        {
            "request": {
                "method": method,
                "path": path,
                "query_param_keys": sorted((query_params or {}).keys()),
                "auth_header_keys": sorted((auth_headers or {}).keys()),
                "auth_cookie_keys": sorted((auth_cookies or {}).keys()),
            },
            "mutated_auth_keys": sorted(mutated_keys),
            "analysis": {
                "baseline_state": baseline_state,
                "invalid_token_state": invalid_state,
            },
            "baseline": baseline_fp,
            "invalid_token_probe": invalid_fp,
            "baseline_preview": (
                baseline_response.text[:500] if baseline_response else ""
            ),
            "invalid_token_preview": (
                invalid_response.text[:500] if invalid_response else ""
            ),
            "note": note,
        },
        ensure_ascii=False,
    )


def make_result(status, description, evidence="", raw_output="", vulnerable=False):
    return common_make_result(
        poc_name=POC_NAME,
        status=status,
        description=description,
        evidence=evidence,
        raw_output=raw_output,
        vulnerable=vulnerable,
    )


def build_evidence(baseline_response, invalid_response, baseline_state, invalid_state):
    return (
        f"baseline=HTTP {baseline_response.status_code} ({baseline_state}), "
        f"invalid_token=HTTP {invalid_response.status_code} ({invalid_state})"
    )


def classify_invalid_token_result(
    method,
    path,
    query_params,
    auth_headers,
    auth_cookies,
    mutated_keys,
    baseline_response,
    invalid_response,
):
    baseline_state = classify_token_response(baseline_response)
    invalid_state = classify_token_response(invalid_response)
    baseline_fp = fingerprint(baseline_response)
    invalid_fp = fingerprint(invalid_response)
    evidence = build_evidence(
        baseline_response,
        invalid_response,
        baseline_state,
        invalid_state,
    )
    raw_output = build_raw_output(
        method=method,
        path=path,
        query_params=query_params,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        mutated_keys=mutated_keys,
        baseline_fp=baseline_fp,
        invalid_fp=invalid_fp,
        baseline_response=baseline_response,
        invalid_response=invalid_response,
        baseline_state=baseline_state,
        invalid_state=invalid_state,
    )

    if baseline_state == "server_error":
        return make_result(
            status="Skipped",
            description="정상 인증 baseline 요청이 서버 오류를 반환해 검사를 건너뜁니다.",
            evidence=f"HTTP {baseline_response.status_code}",
            raw_output=raw_output,
            vulnerable=False,
        )

    if baseline_state != "success":
        return make_result(
            status="Skipped",
            description="정상 인증 baseline이 보호 리소스 접근 성공으로 보이지 않아 invalid token 비교를 수행하지 않았습니다.",
            evidence=f"HTTP {baseline_response.status_code} ({baseline_state})",
            raw_output=raw_output,
            vulnerable=False,
        )

    if invalid_state == "server_error":
        return make_result(
            status="Skipped",
            description="invalid token 요청이 서버 오류를 반환해 판단을 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if invalid_state in AUTH_REJECT_STATES:
        return make_result(
            status="Completed",
            description="잘못된 인증값으로 접근했을 때 요청이 차단되었습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if invalid_state == "empty_redirect":
        return make_result(
            status="Completed",
            description="invalid token 요청이 Location 없는 리다이렉트를 반환해 판단을 보류했습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if invalid_state == "other_redirect":
        location = invalid_response.headers.get("Location", "")
        return make_result(
            status="Completed",
            description="invalid token 요청이 로그인 경로가 아닌 곳으로 리다이렉트되어 수동 확인이 필요합니다.",
            evidence=f"{evidence}, Location={location}",
            raw_output=raw_output,
            vulnerable=False,
        )

    if invalid_state in {
        "not_found",
        "method_not_allowed",
        "client_error",
        "application_failure",
    }:
        return make_result(
            status="Completed",
            description="잘못된 인증값 요청이 정상 리소스 접근으로 처리되지 않았습니다.",
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=False,
        )

    if invalid_state == "spa_shell":
        return make_result(
            status="Completed",
            description="invalid token 요청이 HTML 앱 셸을 반환해 SPA 라우팅 응답으로 판단을 보류했습니다. 실제 XHR/API 엔드포인트를 확인해야 합니다.",
            evidence=(
                f"{evidence}, baseline_length={baseline_fp['length']}, "
                f"invalid_length={invalid_fp['length']}"
            ),
            raw_output=raw_output,
            vulnerable=False,
        )

    if 200 <= invalid_response.status_code < 300:
        same_body = (
            baseline_fp["length"] > 0
            and invalid_fp["length"] > 0
            and baseline_fp["sha1"] == invalid_fp["sha1"]
        )
        close_length = lengths_are_close(baseline_fp, invalid_fp)
        same_type = content_types_are_similar(baseline_fp, invalid_fp)
        both_html = looks_like_html(baseline_response) and looks_like_html(invalid_response)
        same_json_shape = json_shapes_are_similar(baseline_response, invalid_response)
        similar_body = same_body or (
            same_type
            and not both_html
            and (
                same_json_shape is True
                or (same_json_shape is None and close_length)
            )
        )

        if both_html and (
            looks_like_spa_shell(baseline_response) or looks_like_spa_shell(invalid_response)
        ):
            return make_result(
                status="Completed",
                description="invalid token 요청도 HTML 앱 셸을 반환해 SPA 라우팅 응답으로 판단을 보류했습니다. 실제 XHR/API 엔드포인트를 확인해야 합니다.",
                evidence=(
                    f"{evidence}, baseline_length={baseline_fp['length']}, "
                    f"invalid_length={invalid_fp['length']}"
                ),
                raw_output=raw_output,
                vulnerable=False,
            )

        if similar_body:
            return make_result(
                status="Completed",
                description="잘못된 인증값으로도 정상 인증 baseline과 유사한 응답을 받아 토큰 검증 우회 가능성이 있습니다.",
                evidence=(
                    f"{evidence}, same_body={same_body}, "
                    f"close_length={close_length}, same_type={same_type}, "
                    f"same_json_shape={same_json_shape}"
                ),
                raw_output=raw_output,
                vulnerable=True,
            )

        return make_result(
            status="Completed",
            description="invalid token 요청이 2xx를 반환했습니다. baseline과 본문은 다르지만 수동 확인이 필요합니다.",
            evidence=f"{evidence}, invalid token returned 2xx",
            raw_output=raw_output,
            vulnerable=False,
        )

    return make_result(
        status="Completed",
        description=f"상태 코드 {invalid_response.status_code}만으로 invalid token 허용 여부를 확인하기 어렵습니다.",
        evidence=evidence,
        raw_output=raw_output,
        vulnerable=False,
    )


def main():
    payload = parse_payload()

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
            emit(make_result(
                status="Skipped",
                description=f"{method} 요청은 invalid token probe가 자원 변경을 일으킬 수 있어 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                raw_output=json.dumps(
                    {"method": method, "safe_methods": sorted(SAFE_METHODS)},
                    ensure_ascii=False,
                ),
                vulnerable=False,
            ))
            return

        if not auth_headers and not auth_cookies:
            emit(make_result(
                status="Skipped",
                description="정상 인증 baseline을 만들 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth baseline",
                raw_output=json.dumps({"auth_headers": [], "auth_cookies": []}, ensure_ascii=False),
                vulnerable=False,
            ))
            return

        mutated_headers, mutated_header_keys = mutate_auth_headers(auth_headers)
        mutated_cookies, mutated_cookie_keys = mutate_auth_cookies(auth_cookies)
        mutated_keys = mutated_header_keys + mutated_cookie_keys

        if not mutated_keys:
            emit(make_result(
                status="Skipped",
                description="무효화할 인증 헤더 또는 쿠키를 찾지 못해 검사를 건너뜁니다.",
                evidence="no mutable auth values",
                raw_output=json.dumps(
                    {
                        "auth_header_keys": sorted(auth_headers.keys()),
                        "auth_cookie_keys": sorted(auth_cookies.keys()),
                    },
                    ensure_ascii=False,
                ),
                vulnerable=False,
            ))
            return

        baseline_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )

        print("[DEBUG] baseline acquired with provided auth", file=sys.stderr)
        print(f"[DEBUG] mutated_auth_keys={sorted(mutated_keys)}", file=sys.stderr)

        invalid_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers=mutated_headers,
            auth_cookies=mutated_cookies,
        )

        emit(classify_invalid_token_result(
            method=method,
            path=path,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            mutated_keys=mutated_keys,
            baseline_response=baseline_response,
            invalid_response=invalid_response,
        ))

    except Exception as exc:
        emit(error_result(POC_NAME, exc))


if __name__ == "__main__":
    main()
