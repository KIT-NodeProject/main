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

    print(f"[DEBUG] target={base_url}", file=sys.stderr)
    print(f"[DEBUG] path={path}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)

    try:
        headers = {
            "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
        }

        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=5,
            allow_redirects=False,
        )

        status_code = response.status_code
        body_preview = response.text[:200]
        location = response.headers.get("Location", "")

        vulnerable = False
        description = "인증 우회는 확인되지 않았다."

        if status_code in (401, 403):
            vulnerable = False
            description = "인증 없이 접근이 차단되었다."

        elif status_code in (301, 302, 303, 307, 308):
            if "login" in location.lower() or "signin" in location.lower():
                vulnerable = False
                description = "로그인 페이지로 이동되어 인증이 필요한 것으로 보인다."
            else:
                vulnerable = True
                description = "인증 없이 리다이렉트가 발생했으며 보호 우회 가능성이 있다."

        elif status_code in (200, 201, 202, 204):
            vulnerable = True
            description = "인증 없이 보호 엔드포인트 접근이 가능하다."

        else:
            vulnerable = False
            description = f"명확한 인증 실패 응답은 아니지만, 상태 코드 {status_code}만으로 취약하다고 보기 어렵다."

        result = {
            "poc_name": "missing_auth_on_protected_endpoint",
            "status": "Completed",
            "description": description,
            "evidence": f"HTTP {status_code}",
            "raw_output": body_preview,
            "vulnerable": vulnerable,
        }

    except Exception as e:
        result = {
            "poc_name": "missing_auth_on_protected_endpoint",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()