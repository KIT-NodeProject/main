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
            body = response.read(2048).decode("utf-8", errors="replace")
            return response.getcode(), dict(response.headers.items()), body
    except urllib.error.HTTPError as exc:
        # 실패 응답도 판단 근거가 될 수 있어 그대로 반환한다.
        body = exc.read(2048).decode("utf-8", errors="replace")
        return exc.code, dict(exc.headers.items()), body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    payload = load_input(args.input)
    base_url = payload["base_url"].rstrip("/")
    # 스프링 부트에서 자주 노출되는 관리용 엔드포인트를 확인한다.
    actuator_url = f"{base_url}/actuator"
    timeout = int(payload.get("timeout_seconds", 10))

    try:
        status_code, headers, body = fetch(
            actuator_url,
            timeout,
            payload.get("headers") or {},
        )
        content_type = headers.get("Content-Type", "").lower()
        looks_like_actuator = "_links" in body or "health" in body or "actuator" in body
        # 인증 없이 접근 가능한 actuator 응답처럼 보이면 발견으로 본다.
        vulnerable = status_code == 200 and (
            "spring" in content_type or "json" in content_type or looks_like_actuator
        )

        result = {
            "poc_name": "springboot_actuator_exposure",
            "vulnerable": vulnerable,
            "vuln_category": "Misconfiguration",
            "cve_id": None,
            "severity": "Medium",
            "description": (
                "The actuator endpoint appears reachable without authentication."
                if vulnerable
                else "The actuator endpoint did not appear to be publicly accessible."
            ),
            "evidence": f"GET {actuator_url} -> HTTP {status_code}",
            "raw_output": body,
            "status": "Found" if vulnerable else "NotFound",
        }
    except Exception as exc:
        result = {
            "poc_name": "springboot_actuator_exposure",
            "vulnerable": False,
            "vuln_category": "Misconfiguration",
            "cve_id": None,
            "severity": "Info",
            "description": "The Spring Boot actuator probe could not complete.",
            "evidence": str(exc),
            "raw_output": "",
            "status": "Error",
        }

    # 모든 PoC는 결과 JSON 한 개를 stdout으로 출력해야 한다.
    print(json.dumps(result))


if __name__ == "__main__":
    main()
