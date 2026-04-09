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
    path = payload.get("path", "")
    method = payload.get("method", "GET").upper()

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)

    headers = {
        "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
    }

    backupfile_lists = [
        ".bak",
        ".old",
        ".backup",
        ".orig",
        "~",
        ".copy",
        ".zip",
        ".tar",
        ".tar.gz",
    ]

    results = []
    found = False

    try:
        for item in backupfile_lists:
            backup_url = f"{url}{item}"
            print(f"[DEBUG] backup_url={backup_url}", file=sys.stderr)

            response = requests.request(
                method=method,
                url=backup_url,
                headers=headers,
                timeout=5,
                allow_redirects=False,
            )

            results.append({
                "suffix": item,
                "url": backup_url,
                "status_code": response.status_code,
                "response_preview": response.text[:200],
            })

            if response.status_code == 200:
                found = True

        if found:
            result = {
                "poc_name": "backup_file_exposed",
                "status": "Completed",
                "description": "백업 파일이 감지되었습니다.",
                "evidence": "backup candidate returned HTTP 200",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": True,
            }
        else:
            result = {
                "poc_name": "backup_file_exposed",
                "status": "Completed",
                "description": "백업 파일이 감지되지 않았습니다.",
                "evidence": "no backup candidate returned HTTP 200",
                "raw_output": json.dumps(results, ensure_ascii=False),
                "vulnerable": False,
            }

    except Exception as e:
        result = {
            "poc_name": "backup_file_exposed",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()