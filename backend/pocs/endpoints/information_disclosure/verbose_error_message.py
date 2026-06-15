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

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    test_values = [
        "'",
        "\"",
        "<script>",
        "{{7*7}}",
        "../../../../etc/passwd",
        "A" * 200,
    ]

    error_keywords = [
        "exception",
        "traceback",
        "stack trace",
        "sql syntax",
        "database error",
        "internal server error",
        "undefined",
        "nullreference",
        "null pointer",
        "typeerror",
        "valueerror",
        "syntax error",
        "warning",
        "fatal error",
    ]

    results = []
    found = False

    try:
        if not query_params:
            result = {
                "poc_name": "verbose_error_message",
                "status": "Skipped",
                "description": "query_params가 없어 상세 에러 메시지 테스트를 수행하지 않았습니다.",
                "evidence": "missing query_params",
                "raw_output": "",
                "vulnerable": False,
            }
            print(json.dumps(result, ensure_ascii=False))
            return

        for target_key in query_params.keys():
            for test_value in test_values:
                test_params = query_params.copy()
                test_params[target_key] = test_value

                print(f"[DEBUG] target_key={target_key}", file=sys.stderr)
                print(f"[DEBUG] test_value={test_value}", file=sys.stderr)
                print(f"[DEBUG] test_params={test_params}", file=sys.stderr)

                response = requests.request(
                    method=method,
                    url=url,
                    params=test_params,
                    headers=headers,
                    timeout=5,
                    allow_redirects=False,
                )

                response_text = response.text
                response_lower = response_text.lower()

                matched_keywords = []
                for keyword in error_keywords:
                    if keyword in response_lower:
                        matched_keywords.append(keyword)

                matched = len(matched_keywords) > 0

                results.append({
                    "target_key": target_key,
                    "test_value": test_value,
                    "status_code": response.status_code,
                    "matched_keywords": matched_keywords,
                    "response_preview": response_text[:200],
                })

                if matched:
                    found = True

        if found:
            result = {
                "poc_name": "verbose_error_message",
                "status": "Completed",
                "description": "상세 에러 메시지 또는 내부 예외 정보가 응답에 노출되었습니다.",
                "evidence": "verbose error keywords detected",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": True,
            }
        else:
            result = {
                "poc_name": "verbose_error_message",
                "status": "Completed",
                "description": "일반화된 에러 응답만 확인되었으며, 상세 예외 정보 노출은 확인되지 않았습니다.",
                "evidence": "no verbose error keyword detected",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "verbose_error_message",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()