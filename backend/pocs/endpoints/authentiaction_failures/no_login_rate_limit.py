# import argparse
# import json
# import sys
# import time
# import requests


# def main():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--input", required=True)
#     args = parser.parse_args()

#     with open(args.input, "r", encoding="utf-8") as f:
#         payload = json.load(f)

#     base_url = payload["base_url"].rstrip("/")
#     path = payload.get("path", "")
#     method = payload.get("method", "POST").upper()
#     body_params = payload.get("body_params", {})
#     max_attempts = payload.get("max_attempts", 5)
#     delay_seconds = payload.get("delay_seconds", 0.3)

#     url = f"{base_url}{path}"

#     print(f"[DEBUG] url={url}", file=sys.stderr)
#     print(f"[DEBUG] method={method}", file=sys.stderr)
#     print(f"[DEBUG] body_params={body_params}", file=sys.stderr)
#     print(f"[DEBUG] max_attempts={max_attempts}", file=sys.stderr)

#     headers = {
#         "User-Agent": "Scanner-033ca182-dcdd-406b-bcb5-816d726ca809",
#         "Content-Type": "application/x-www-form-urlencoded",
#     }

#     results = []

#     try:
#         for attempt in range(1, max_attempts + 1):
#             start_time = time.time()

#             response = requests.request(
#                 method=method,
#                 url=url,
#                 data=body_params,
#                 headers=headers,
#                 timeout=5,
#                 allow_redirects=False,
#             )

#             elapsed = round(time.time() - start_time, 3)

#             attempt_result = {
#                 "attempt": attempt,
#                 "status_code": response.status_code,
#                 "response_preview": response.text[:200],
#                 "elapsed_seconds": elapsed,
#                 "location": response.headers.get("Location", ""),
#             }
#             results.append(attempt_result)

#             print(f"[DEBUG] attempt_result={attempt_result}", file=sys.stderr)

#             time.sleep(delay_seconds)

#         blocked = False
#         block_evidence = ""

#         for item in results:
#             status_code = item["status_code"]
#             body = item["response_preview"].lower()
#             location = item["location"].lower()

#             if status_code == 429:
#                 blocked = True
#                 block_evidence = "429 Too Many Requests 응답 확인"
#                 break

#             if status_code in (403, 423):
#                 blocked = True
#                 block_evidence = f"HTTP {status_code} 차단 응답 확인"
#                 break

#             if "too many" in body or "rate limit" in body or "temporarily locked" in body:
#                 blocked = True
#                 block_evidence = "본문에서 시도 제한 메시지 확인"
#                 break

#             if "captcha" in body:
#                 blocked = True
#                 block_evidence = "본문에서 CAPTCHA 요구 확인"
#                 break

#             if "lock" in body or "blocked" in body:
#                 blocked = True
#                 block_evidence = "본문에서 계정 잠금/차단 메시지 확인"
#                 break

#             if "captcha" in location:
#                 blocked = True
#                 block_evidence = "리다이렉트 위치에서 CAPTCHA 확인"
#                 break

#         if blocked:
#             result = {
#                 "poc_name": "no_login_rate_limit",
#                 "status": "Completed",
#                 "description": "로그인 실패 반복 시 차단 또는 제한 동작이 확인되었다.",
#                 "evidence": block_evidence,
#                 "raw_output": json.dumps(results, ensure_ascii=False),
#                 "vulnerable": False,
#             }
#         else:
#             result = {
#                 "poc_name": "no_login_rate_limit",
#                 "status": "Completed",
#                 "description": "여러 번 로그인 실패 후에도 차단 또는 시도 제한이 확인되지 않았다.",
#                 "evidence": f"attempts={max_attempts}",
#                 "raw_output": json.dumps(results, ensure_ascii=False),
#                 "vulnerable": True,
#             }

#     except Exception as e:
#         result = {
#             "poc_name": "no_login_rate_limit",
#             "status": "Error",
#             "description": "PoC execution failed.",
#             "evidence": str(e),
#             "raw_output": "",
#             "vulnerable": False,
#         }

#     print(json.dumps(result, ensure_ascii=False))


# if __name__ == "__main__":
#     main()