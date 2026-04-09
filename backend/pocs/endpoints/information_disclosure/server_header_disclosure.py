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

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    disclosure_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
        "Via",
        "X-Runtime",
        "X-Version",
    ]

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=5,
            allow_redirects=False,
        )

        found_headers = {}

        for header_name in disclosure_headers:
            if header_name in response.headers:
                found_headers[header_name] = response.headers.get(header_name, "")

        if found_headers:
            result = {
                "poc_name": "server_header_disclosure",
                "status": "Completed",
                "description": "응답 헤더에서 서버 또는 프레임워크 정보가 노출되었습니다.",
                "evidence": json.dumps(found_headers, ensure_ascii=False),
                "raw_output": json.dumps(dict(response.headers), ensure_ascii=False)[:500],
                "vulnerable": True,
            }
        else:
            result = {
                "poc_name": "server_header_disclosure",
                "status": "Completed",
                "description": "의미 있는 서버 헤더 정보 노출은 확인되지 않았습니다.",
                "evidence": f"HTTP {response.status_code}",
                "raw_output": json.dumps(dict(response.headers), ensure_ascii=False)[:500],
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "server_header_disclosure",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()