import json
import sys

from _common import (
    IGNORE_KEYS,
    classify_response,
    emit,
    error_result,
    fingerprint,
    is_id_like_key,
    is_number,
    make_result,
    mutate_numeric_value,
    normalize_key_for_matching,
    parse_payload,
    request_once,
)


POC_NAME = "idor_query_delete_resource"
SAFE_METHODS = {"DELETE"}
MAX_PROBES = 1


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


def main():
    payload = parse_payload()

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
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="DELETE 요청이 아니어서 query DELETE IDOR 테스트를 수행하지 않았습니다.",
                evidence=f"method={method}",
                raw_output=build_raw_output(
                    method, path, query_params, auth_headers, auth_cookies, candidates,
                ),
            ))
            return

        if not query_params:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="query_params가 없어 query DELETE IDOR 테스트를 수행할 수 없습니다.",
                evidence="missing query_params",
                raw_output=build_raw_output(
                    method, path, query_params, auth_headers, auth_cookies, [],
                ),
            ))
            return

        if not auth_headers and not auth_cookies:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 DELETE probe에 사용할 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth",
                raw_output=build_raw_output(
                    method, path, query_params, auth_headers, auth_cookies, candidates,
                ),
            ))
            return

        if not candidates:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="테스트할 숫자 query value를 찾지 못했습니다.",
                evidence="no numeric query value",
                raw_output=build_raw_output(
                    method, path, query_params, auth_headers, auth_cookies, [],
                ),
            ))
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

            probes.append({
                "target_key": target_key,
                "candidate_reason": candidate["reason"],
                "original_value": original_value,
                "changed_value": changed_value,
                "state": state,
                "fingerprint": fingerprint(response),
                "success": success,
                "response_preview": response.text[:500],
            })

        raw_output = build_raw_output(
            method, path, query_params, auth_headers, auth_cookies, candidates,
            probes=probes,
            note="원본 ID 삭제 baseline은 부작용 방지를 위해 보내지 않고, 변경한 query ID에 대해서만 DELETE probe를 보냅니다.",
        )

        if vulnerable_found:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="숫자 query 값을 변경한 DELETE 요청이 성공 응답을 반환했습니다. 다른 사용자 리소스 삭제 가능성이 있습니다.",
                evidence="changed numeric query value returned successful DELETE response",
                raw_output=raw_output,
                vulnerable=True,
            )
        else:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="숫자 query 값을 변경한 DELETE 요청이 성공 응답으로 처리되지 않았습니다.",
                evidence="changed numeric query value did not return successful DELETE response",
                raw_output=raw_output,
                vulnerable=False,
            )

    except Exception as e:
        result = error_result(POC_NAME, e)

    emit(result)


if __name__ == "__main__":
    main()
