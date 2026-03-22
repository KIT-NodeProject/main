from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request


def load_input(path: str) -> dict:
    # 백엔드가 만든 임시 JSON 파일에서 실행 입력값을 읽는다.
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def fetch(url: str, timeout: int, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(1024).decode("utf-8", errors="replace")
            return response.getcode(), dict(response.headers.items()), body
    except urllib.error.HTTPError as exc:
        # HTTP 에러여도 응답 자체는 취약점 근거가 될 수 있어 함께 반환한다.
        body = exc.read(1024).decode("utf-8", errors="replace")
        return exc.code, dict(exc.headers.items()), body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    payload = load_input(args.input)
    timeout = int(payload.get("timeout_seconds", 10))

    try:
        status_code, headers, body = fetch(
            payload["base_url"],
            timeout,
            payload.get("headers") or {},
        )
        server_header = headers.get("Server", "")
        # 프로토타입 단계에서는 nginx Server 헤더 노출을 단순 조건으로 본다.
        vulnerable = "nginx" in server_header.lower()

        result = {
            "poc_name": "nginx_header_version_probe",
            "vulnerable": vulnerable,
            "vuln_category": "CVE",
            "cve_id": None,
            "severity": "High",
            "description": (
                "Targeted version range matched and the response exposes an nginx Server header."
                if vulnerable
                else "The response did not expose an nginx Server header."
            ),
            "evidence": f"HTTP {status_code}, Server header: {server_header or 'missing'}",
            "raw_output": body,
            "status": "Found" if vulnerable else "NotFound",
        }
    except Exception as exc:
        result = {
            "poc_name": "nginx_header_version_probe",
            "vulnerable": False,
            "vuln_category": "CVE",
            "cve_id": None,
            "severity": "Info",
            "description": "The nginx prototype probe could not complete.",
            "evidence": str(exc),
            "raw_output": "",
            "status": "Error",
        }

    # 모든 PoC는 결과 JSON 한 개를 stdout으로 출력해야 한다.
    print(json.dumps(result))


if __name__ == "__main__":
    main()
