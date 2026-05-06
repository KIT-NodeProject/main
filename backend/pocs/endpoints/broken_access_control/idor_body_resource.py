import argparse
import copy
import hashlib
import json
import re
import sys
from urllib.parse import unquote, urlsplit

import requests


POC_NAME = "idor_body_resource"
REQUEST_TIMEOUT_SECONDS = 3
SAFE_METHODS = {"POST"}
MAX_PROBES = 2

IGNORE_KEYS = {
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
}

ID_KEY_PATTERN = re.compile(
    r"(^id$|(^|[_\-.])(id|user_id|owner_id|account_id|member_id|post_id|"
    r"article_id|item_id|resource_id|order_id|invoice_id|tenant_id|org_id|"
    r"organization_id|team_id|project_id|document_id|file_id|profile_id)$|"
    r"(^|[_\-.])[a-z0-9]+_id$)",
    re.IGNORECASE,
)

DANGEROUS_KEYWORDS = (
    "add",
    "assign",
    "approve",
    "ban",
    "block",
    "cancel",
    "create",
    "delete",
    "deposit",
    "disable",
    "edit",
    "enable",
    "grant",
    "insert",
    "mutation",
    "pay",
    "payment",
    "publish",
    "refund",
    "reject",
    "remove",
    "revoke",
    "save",
    "submit",
    "transfer",
    "update",
    "withdraw",
)

LOGIN_FORM_PATTERN = re.compile(
    r"<form\b[^>]*>.*?<input\b[^>]*type=[\"']?password",
    re.IGNORECASE | re.DOTALL,
)

LOGIN_PAGE_SIGNATURES = (
    'type="password"',
    "type='password'",
    "name=\"password\"",
    "name='password'",
    "id=\"password\"",
    "id='password'",
    "please sign in",
    "please log in",
    "please login",
    "session expired",
    "session: null",
    '"session":null',
)

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

APPLICATION_FAILURE_SIGNATURES = (
    "not found",
    "not_found",
    "no such",
    "does not exist",
    "invalid id",
    "invalid resource",
    "resource not found",
    "record not found",
    "존재하지",
    "찾을 수 없",
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

    return any(signature in text_lower for signature in LOGIN_PAGE_SIGNATURES)


def has_text_signature(response, signatures):
    text_lower = response_text_lower(response)
    return any(signature in text_lower for signature in signatures)


def looks_like_spa_shell(response):
    if not looks_like_html(response):
        return False

    text_lower = response_text_lower(response)
    return any(signature in text_lower for signature in SPA_SHELL_SIGNATURES)


def classify_response(response, detect_application_failure=True):
    status_code = response.status_code

    if status_code >= 500:
        return "server_error"

    if status_code in (401, 403):
        return "auth_block"

    if status_code in (301, 302, 303, 307, 308):
        return "redirect"

    if status_code == 404:
        return "not_found"

    if status_code == 405:
        return "method_not_allowed"

    if 400 <= status_code < 500:
        return "client_error"

    if 200 <= status_code < 300:
        if looks_like_login_page(response):
            return "login_page"
        if has_text_signature(response, DENIAL_SIGNATURES):
            return "denial_body"
        if detect_application_failure and has_text_signature(
            response,
            APPLICATION_FAILURE_SIGNATURES,
        ):
            return "application_failure"
        if looks_like_spa_shell(response):
            return "spa_shell"
        return "success"

    return "unknown"


def is_number(value):
    if value is None or isinstance(value, bool):
        return False

    value = str(value).strip()

    if value == "":
        return False

    return value.isdigit()


def mutate_numeric_value(value):
    changed = int(str(value).strip()) + 1

    if isinstance(value, int) and not isinstance(value, bool):
        return changed

    return str(changed)


def normalized_key(key_path):
    return ".".join(str(part) for part in key_path).lower()


def is_candidate_key(key_path, value):
    key = normalized_key(key_path)
    leaf_key = str(key_path[-1]).lower()

    if leaf_key in IGNORE_KEYS or key in IGNORE_KEYS:
        return False

    if not is_number(value):
        return False

    return bool(ID_KEY_PATTERN.search(key) or ID_KEY_PATTERN.search(leaf_key))


def iter_candidate_paths(value, path=None):
    path = path or []

    if isinstance(value, dict):
        for key, child in value.items():
            next_path = path + [key]

            if is_candidate_key(next_path, child):
                yield next_path, child

            if isinstance(child, (dict, list)):
                yield from iter_candidate_paths(child, next_path)

    elif isinstance(value, list):
        for index, child in enumerate(value):
            next_path = path + [index]

            if is_candidate_key(next_path, child):
                yield next_path, child

            if isinstance(child, (dict, list)):
                yield from iter_candidate_paths(child, next_path)


def set_nested_value(value, path, new_value):
    cursor = value

    for key in path[:-1]:
        cursor = cursor[key]

    cursor[path[-1]] = new_value


def contains_nested_value(value):
    if isinstance(value, dict):
        return any(isinstance(child, (dict, list)) for child in value.values())

    if isinstance(value, list):
        return any(isinstance(child, (dict, list)) for child in value)

    return False


def body_target_text(path, body_params):
    parsed = urlsplit(path)
    pieces = [unquote(parsed.path), unquote(parsed.query)]

    if isinstance(body_params, dict):
        pieces.extend(f"{key}={value}" for key, value in body_params.items())

    return " ".join(str(piece) for piece in pieces if piece)


def path_query_text(path):
    parsed = urlsplit(path)
    return " ".join(
        piece for piece in (unquote(parsed.path), unquote(parsed.query)) if piece
    )


def path_query_tokens(path):
    target = path_query_text(path)
    separated = re.sub(r"([a-z])([A-Z])", r"\1 \2", target)
    return {
        token
        for token in re.split(r"[^a-z0-9]+", separated.lower())
        if token
    }


def looks_dangerous(path):
    tokens = path_query_tokens(path)

    return any(keyword in tokens for keyword in DANGEROUS_KEYWORDS)


def make_headers(auth_headers, body_mode):
    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }
    headers.update(auth_headers or {})

    if body_mode == "json" and not any(
        key.lower() == "content-type" for key in headers
    ):
        headers["Content-Type"] = "application/json"

    return headers


def select_body_mode(auth_headers, path, body_params):
    content_type = ""

    for key, value in (auth_headers or {}).items():
        if key.lower() == "content-type":
            content_type = str(value).lower()
            break

    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        return "form"

    if "json" in content_type:
        return "json"

    target = body_target_text(path, body_params).lower()
    if "graphql" in target or "query=" in target:
        return "json"

    return "json"


def request_once(method, url, query_params, body_params, auth_headers, auth_cookies, body_mode):
    kwargs = {
        "method": method,
        "url": url,
        "params": query_params or {},
        "headers": make_headers(auth_headers, body_mode),
        "cookies": auth_cookies or {},
        "timeout": REQUEST_TIMEOUT_SECONDS,
        "allow_redirects": False,
    }

    if body_mode == "form":
        kwargs["data"] = body_params or {}
    else:
        kwargs["json"] = body_params or {}

    return requests.request(**kwargs)


def build_raw_output(
    method,
    path,
    query_params,
    body_params,
    auth_headers,
    auth_cookies,
    candidate_paths,
    body_mode="",
    baseline_state="",
    baseline_fp=None,
    baseline_response=None,
    probes=None,
    note="",
):
    return json.dumps(
        {
            "request": {
                "method": method,
                "path": path,
                "query_param_keys": sorted((query_params or {}).keys()),
                "body_param_keys": sorted((body_params or {}).keys())
                if isinstance(body_params, dict)
                else [],
                "auth_header_keys": sorted((auth_headers or {}).keys()),
                "auth_cookie_keys": sorted((auth_cookies or {}).keys()),
                "body_mode": body_mode,
            },
            "candidate_paths": candidate_paths,
            "baseline": {
                "state": baseline_state,
                "fingerprint": baseline_fp,
                "preview": baseline_response.text[:500] if baseline_response else "",
            },
            "probes": probes or [],
            "note": note,
        },
        ensure_ascii=False,
    )


def make_result(status, description, evidence="", raw_output="", vulnerable=False):
    return {
        "poc_name": POC_NAME,
        "status": status,
        "description": description,
        "evidence": evidence,
        "raw_output": raw_output,
        "vulnerable": vulnerable,
    }


def evaluate_probe(baseline_fp, probe_fp, probe_state, probe_response, changed_value):
    changed_value_echoed = str(changed_value) in probe_response.text

    if probe_state != "success":
        return (
            False,
            False,
            changed_value_echoed,
            "변경한 ID 요청이 정상 리소스 응답으로 처리되지 않았습니다.",
        )

    if baseline_fp and probe_fp and baseline_fp["sha1"] == probe_fp["sha1"]:
        return (
            False,
            True,
            changed_value_echoed,
            "변경한 ID 요청이 2xx를 반환했지만 baseline과 응답 본문이 같습니다.",
        )

    if not changed_value_echoed:
        return (
            False,
            True,
            changed_value_echoed,
            "변경한 ID 요청이 2xx와 다른 본문을 반환했지만 변경 ID echo가 없어 수동 확인이 필요합니다.",
        )

    return (
        True,
        False,
        changed_value_echoed,
        "변경한 ID 요청이 2xx와 다른 본문을 반환했고 변경 ID가 응답에 포함되었습니다.",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        payload = json.load(f)

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "POST").upper()
    query_params = payload.get("query_params", {}) or {}
    body_params = payload.get("body_params", {}) or {}
    auth = payload.get("auth", {}) or {}
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    url = f"{base_url}{path}"
    candidate_pairs = list(iter_candidate_paths(body_params))
    candidate_paths = [normalized_key(path_parts) for path_parts, _ in candidate_pairs]
    body_mode = select_body_mode(auth_headers, path, body_params)

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] original_body={body_params}", file=sys.stderr)
    print(f"[DEBUG] candidate_paths={candidate_paths}", file=sys.stderr)
    print(f"[DEBUG] body_mode={body_mode}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            result = make_result(
                status="Skipped",
                description=f"{method} 요청은 body IDOR probe가 자원 변경을 일으킬 수 있어 자동 검사를 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=candidate_paths,
                    note="PUT/PATCH 기반 body IDOR은 테스트 전용 리소스나 명시적 opt-in이 필요합니다.",
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not isinstance(body_params, dict) or not body_params:
            result = make_result(
                status="Skipped",
                description="body_params가 없어 body 기반 IDOR 테스트를 수행할 수 없습니다.",
                evidence="missing body_params",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=[],
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
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=candidate_paths,
                    body_mode=body_mode,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not candidate_pairs:
            result = make_result(
                status="Skipped",
                description="테스트할 숫자 ID 성격의 body 필드를 찾지 못했습니다.",
                evidence="no numeric id-like body field",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=[],
                    body_mode=body_mode,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if body_mode == "form" and contains_nested_value(body_params):
            result = make_result(
                status="Skipped",
                description="form-urlencoded body에 중첩 구조가 있어 원본 요청과 같은 형태로 안전하게 재현하기 어렵습니다.",
                evidence="nested form body unsupported",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=candidate_paths,
                    body_mode=body_mode,
                    note="중첩 form body는 서버별 인코딩 규칙이 달라 수동 검증이 필요합니다.",
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if looks_dangerous(path):
            result = make_result(
                status="Skipped",
                description="대상 요청이 생성/수정/삭제 계열로 보여 body IDOR 자동 probe를 건너뜁니다.",
                evidence="dangerous body operation heuristic matched",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=candidate_paths,
                    body_mode=body_mode,
                    note="테스트 전용 계정/리소스가 확인된 경우 수동 검증이 필요합니다.",
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        baseline_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            body_params=body_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            body_mode=body_mode,
        )
        baseline_state = classify_response(
            baseline_response,
            detect_application_failure=False,
        )
        baseline_fp = fingerprint(baseline_response)

        if baseline_state != "success":
            result = make_result(
                status="Skipped",
                description="인증 포함 baseline 요청이 정상 리소스 응답으로 보이지 않아 ID 변경 probe를 수행하지 않았습니다.",
                evidence=f"baseline_state={baseline_state}, HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidate_paths=candidate_paths,
                    body_mode=body_mode,
                    baseline_state=baseline_state,
                    baseline_fp=baseline_fp,
                    baseline_response=baseline_response,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        probes = []
        vulnerable_found = False
        manual_review_found = False

        for path_parts, original_value in candidate_pairs[:MAX_PROBES]:
            changed_value = mutate_numeric_value(original_value)
            test_body = copy.deepcopy(body_params)
            set_nested_value(test_body, path_parts, changed_value)

            print(f"[DEBUG] target_key={normalized_key(path_parts)}", file=sys.stderr)
            print(f"[DEBUG] original_value={original_value}", file=sys.stderr)
            print(f"[DEBUG] changed_value={changed_value}", file=sys.stderr)

            probe_response = request_once(
                method=method,
                url=url,
                query_params=query_params,
                body_params=test_body,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
            )
            probe_state = classify_response(probe_response)
            probe_fp = fingerprint(probe_response)
            vulnerable, manual_review, changed_value_echoed, note = evaluate_probe(
                baseline_fp,
                probe_fp,
                probe_state,
                probe_response,
                changed_value,
            )

            vulnerable_found = vulnerable_found or vulnerable
            manual_review_found = manual_review_found or manual_review

            probes.append(
                {
                    "target_key": normalized_key(path_parts),
                    "original_value": original_value,
                    "changed_value": changed_value,
                    "state": probe_state,
                    "fingerprint": probe_fp,
                    "changed_value_echoed": changed_value_echoed,
                    "vulnerable": vulnerable,
                    "manual_review": manual_review,
                    "note": note,
                    "response_preview": probe_response.text[:500],
                }
            )

        raw_output = build_raw_output(
            method=method,
            path=path,
            query_params=query_params,
            body_params=body_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            candidate_paths=candidate_paths,
            body_mode=body_mode,
            baseline_state=baseline_state,
            baseline_fp=baseline_fp,
            baseline_response=baseline_response,
            probes=probes,
        )

        if vulnerable_found:
            result = make_result(
                status="Completed",
                description="body의 숫자 ID 값을 변경한 요청이 성공했고 baseline과 다른 응답 및 변경 ID echo를 반환했습니다. 다른 사용자 리소스 접근 가능성이 있습니다.",
                evidence="changed id-like body field returned 2xx with different body and echoed changed ID",
                raw_output=raw_output,
                vulnerable=True,
            )
        elif manual_review_found:
            result = make_result(
                status="Completed",
                description="body의 숫자 ID 값을 변경한 요청이 2xx를 반환했지만 취약으로 단정할 응답 증거가 부족해 수동 확인이 필요합니다.",
                evidence="changed id-like body field returned 2xx but needs manual review",
                raw_output=raw_output,
                vulnerable=False,
            )
        else:
            result = make_result(
                status="Completed",
                description="body의 숫자 ID 값을 변경한 요청이 정상 리소스 응답으로 처리되지 않았습니다.",
                evidence="changed id-like body field did not return successful resource response",
                raw_output=raw_output,
                vulnerable=False,
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
