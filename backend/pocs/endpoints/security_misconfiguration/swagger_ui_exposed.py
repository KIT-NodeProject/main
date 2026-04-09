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

    print(f"[DEBUG] base_url={base_url}", file=sys.stderr)

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    swagger_paths = [
        "/swagger-ui",
        "/swagger-ui/",
        "/swagger-ui/index.html",
        "/swagger",
        "/swagger.json",
        "/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/openapi.json",
        "/openapi.yaml",
    ]

    swagger_keywords = [
        "swagger",
        "swagger-ui",
        "openapi",
        "api-docs",
        "swagger-ui-bundle",
        "\"openapi\"",
        "\"swagger\"",
        "openapi:",
    ]

    results = []
    found = False

    try:
        for path in swagger_paths:
            target_url = f"{base_url}{path}"
            print(f"[DEBUG] target_url={target_url}", file=sys.stderr)

            response = requests.request(
                method="GET",
                url=target_url,
                headers=headers,
                timeout=5,
                allow_redirects=False,
            )

            response_text = response.text
            response_lower = response_text.lower()

            matched_keywords = []
            for keyword in swagger_keywords:
                if keyword.lower() in response_lower:
                    matched_keywords.append(keyword)

            matched = response.status_code == 200 and len(matched_keywords) > 0

            results.append({
                "path": path,
                "status_code": response.status_code,
                "matched_keywords": matched_keywords,
                "response_preview": response_text[:200],
            })

            if matched:
                found = True

        if found:
            result = {
                "poc_name": "swagger_ui_exposed",
                "status": "Completed",
                "description": "Swagger/OpenAPI 문서 경로가 외부에 공개되어 있습니다.",
                "evidence": "swagger or openapi related content detected",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": True,
            }
        else:
            result = {
                "poc_name": "swagger_ui_exposed",
                "status": "Completed",
                "description": "공개된 Swagger/OpenAPI 문서는 확인되지 않았습니다.",
                "evidence": "no public swagger/openapi endpoint detected",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "swagger_ui_exposed",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()