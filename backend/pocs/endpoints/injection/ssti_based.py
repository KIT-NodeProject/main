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

    print(f"[DEBUG] base_url={base_url}", file=sys.stderr)
    print(f"[DEBUG] path={path}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] original_query_params={query_params}", file=sys.stderr)

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    test_values = ["{{7*7}}", "${7*7}"]
    results = []
    found = False

    try:
        if not query_params:
            result = {
                "poc_name": "ssti_based",
                "status": "Error",
                "description": "query_params가 없어 SSTI 테스트를 수행할 수 없습니다.",
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
                parts = []

                for key, value in test_params.items():
                    parts.append(f"{key}={value}")

                query_string = "?" + "&".join(parts)
                query_url = f"{url}{query_string}"

                print(f"[DEBUG] target_key={target_key}", file=sys.stderr)
                print(f"[DEBUG] test_value={test_value}", file=sys.stderr)
                print(f"[DEBUG] query_url={query_url}", file=sys.stderr)

                response = requests.request(
                    method=method,
                    url=query_url,
                    headers=headers,
                    timeout=5,
                )

                matched = "49" in response.text

                results.append({
                    "target_key": target_key,
                    "test_value": test_value,
                    "status_code": response.status_code,
                    "matched": matched,
                    "response_preview": response.text[:200],
                })

                if matched:
                    found = True

        if found:
            result = {
                "poc_name": "ssti_based",
                "status": "Completed",
                "description": "SSTI 취약점이 의심되는 응답이 확인되었습니다.",
                "evidence": "expression evaluated to 49",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": True,
            }
        else:
            result = {
                "poc_name": "ssti_based",
                "status": "Completed",
                "description": "SSTI 취약점이 발견되지 않았습니다.",
                "evidence": "no evaluated expression found",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "ssti_based",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()