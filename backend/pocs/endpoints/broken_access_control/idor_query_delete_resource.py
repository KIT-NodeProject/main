import argparse
import json
import sys
import requests

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        payload = json.load(f)

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "GET").upper()
    query_params = payload.get("query_params", {})

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] original_query_params={query_params}", file=sys.stderr)

    auth = payload.get("auth", {})
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }
    headers.update(auth_headers)

    results = []
    found = False

    try:
        if method != "DELETE":
            result = {
                "poc_name": "idor_query_read_resource",
                "status": "Skipped",
                "description": "GET 요청이 아니어서 IDOR GET 테스트를 수행하지 않았습니다.",
                "evidence": f"method={method}",
                "raw_output": "",
                "vulnerable": False,
            }
            print(json.dumps(result, ensure_ascii=False))
            return

        if not query_params:
            result = {
                "poc_name": "idor_query_read_resource",
                "status": "Skipped",
                "description": "query_params가 없어 IDOR GET 테스트를 수행할 수 없습니다.",
                "evidence": "missing query_params",
                "raw_output": "",
                "vulnerable": False,
            }
            print(json.dumps(result, ensure_ascii=False))
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

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=auth_cookies,
                params=test_params,
                timeout=5,
                allow_redirects=False,
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
            result = {
                "poc_name": "idor_query_read_resource",
                "status": "Skipped",
                "description": "테스트할 숫자 query value를 찾지 못했습니다.",
                "evidence": "no numeric query value",
                "raw_output": "",
                "vulnerable": False,
            }

        elif found:
            result = {
                "poc_name": "idor_query_read_resource",
                "status": "Completed",
                "description": "숫자 query 값을 변경한 GET 요청이 성공했습니다. 다른 사용자 리소스 조회 가능성이 있습니다.",
                "evidence": "changed numeric query value returned 200",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": True,
            }

        else:
            result = {
                "poc_name": "idor_query_read_resource",
                "status": "Completed",
                "description": "숫자 query 값을 변경한 GET 요청이 성공하지 않았습니다.",
                "evidence": "changed numeric query value did not return 200",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "idor_query_read_resource",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()