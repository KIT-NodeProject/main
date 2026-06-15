import argparse
import json
import sys
import requests

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    with open(args.input, "r", encoding="UTF-8") as f:
        payload = json.load(f)

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path","")
    method = payload.get("method", "GET").upper()

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    try:
        response = requests.request(method=method, url=url, headers=headers, timeout=5, allow_redirects=False,)

        found_headers = {}
        for header_name in security_headers:
            if header_name in response.headers:
                found_headers[header_name] = response.headers.get(header_name, "")

        if found_headers:
            result = {
                "poc_name": "missing_security_headers",
                "status": "Completed",
                "description": "점검 대상 보안 헤더가 확인되지 않았습니다.",
                "evidence": json.dumps(found_headers, ensure_ascii=False),
                "raw_output": json.dumps(dict(response.headers), ensure_ascii=False)[:500],
                "vulnerable": False,
            }
        else:
            result = {
                "poc_name": "missing_security_headers",
                "status": "Completed",
                "description": "응답 헤더에서 점검 대상 보안 헤더가 발견되지 않았습니다.",
                "evidence": f"HTTP {response.status_code}",
                "raw_output": json.dumps(dict(response.headers), ensure_ascii=False)[:500],
                "vulnerable": True,
            }

    except Exception as e:
        result = {
            "poc_name": "missing_security_headers",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }
       
    print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()