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
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    sensitive_fields = [
        "password",
        "password_hash",
        "passwd",
        "reset_token",
        "access_token",
        "refresh_token",
        "secret",
        "api_key",
        "private_key",
        "is_admin",
        "role",
        "internal_id",
        "deleted_at",
        "internal_notes",
    ]

    try:
        response = requests.request(
            method=method,
            url=url,
            params=query_params,
            headers=headers,
            timeout=5,
            allow_redirects=False,
        )

        response_text = response.text
        response_lower = response_text.lower()

        found_fields = []
        for field in sensitive_fields:
            if field.lower() in response_lower:
                found_fields.append(field)

        if found_fields:
            result = {
                "poc_name": "sensitive_field_exposure",
                "status": "Completed",
                "description": "공개 응답에서 민감 필드가 확인되었습니다.",
                "evidence": json.dumps(found_fields, ensure_ascii=False),
                "raw_output": response_text[:500],
                "vulnerable": True,
            }
        else:
            result = {
                "poc_name": "sensitive_field_exposure",
                "status": "Completed",
                "description": "민감 필드 노출은 확인되지 않았습니다.",
                "evidence": f"HTTP {response.status_code}",
                "raw_output": response_text[:500],
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "sensitive_field_exposure",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()