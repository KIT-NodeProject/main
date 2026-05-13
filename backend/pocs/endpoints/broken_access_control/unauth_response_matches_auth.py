import json
import sys

from _common import (
    classify_response,
    emit,
    error_result,
    fingerprint,
    looks_like_html,
    looks_like_login_page,
    looks_like_spa_shell,
    make_result,
    parse_payload,
    request_once,
)


POC_NAME = "unauth_response_matches_auth"
SAFE_METHODS = {"GET"}

EXTRA_LOGIN_PAGE_WEAK_SIGNATURES = ("unauthorized", "forbidden")


def lengths_are_close(first, second, tolerance=0.1):
    first_length = first["length"]
    second_length = second["length"]

    if first_length == second_length:
        return True
    if first_length == 0 or second_length == 0:
        return False

    return abs(first_length - second_length) / max(first_length, second_length) <= tolerance


def content_type_group(content_type):
    normalized = content_type.lower()

    if "json" in normalized:
        return "json"
    if "html" in normalized:
        return "html"
    if "xml" in normalized:
        return "xml"
    if "text" in normalized:
        return "text"

    return normalized.split(";")[0].strip()


def content_types_are_similar(first, second):
    first_group = content_type_group(first["content_type"])
    second_group = content_type_group(second["content_type"])

    if not first_group or not second_group:
        return first_group == second_group

    return first_group == second_group


def build_raw_output(baseline_fp=None, probe_fp=None, probe_response=None, note=""):
    return json.dumps(
        {
            "baseline": baseline_fp,
            "probe": probe_fp,
            "probe_preview": probe_response.text[:500] if probe_response else "",
            "note": note,
        },
        ensure_ascii=False,
    )


def classify_probe(baseline_response, probe_response):
    baseline_fp = fingerprint(baseline_response)
    probe_fp = fingerprint(probe_response)
    status_code = probe_response.status_code
    location = probe_response.headers.get("Location", "")

    raw_output = build_raw_output(baseline_fp, probe_fp, probe_response)

    probe_state = classify_response(
        probe_response,
        detect_application_failure=False,
        detect_login_redirect=True,
        login_page_include_weak=True,
        login_page_extra_weak=EXTRA_LOGIN_PAGE_WEAK_SIGNATURES,
    )

    if probe_state == "server_error":
        return (
            "Skipped", False,
            "비인증 요청이 서버 오류를 반환해 판단을 보류했습니다.",
            f"HTTP {status_code}", raw_output,
        )

    if probe_state == "auth_block":
        return (
            "Completed", False,
            "인증 없이 접근이 차단되었습니다.",
            f"HTTP {status_code}", raw_output,
        )

    if probe_state == "empty_redirect":
        return (
            "Completed", False,
            "비인증 요청이 Location 없는 리다이렉트를 반환해 판단을 보류했습니다.",
            f"HTTP {status_code}, empty Location", raw_output,
        )

    if probe_state == "auth_redirect":
        return (
            "Completed", False,
            "인증 없이 요청했을 때 로그인/인증 경로로 이동했습니다.",
            f"HTTP {status_code}, Location={location}", raw_output,
        )

    if probe_state == "other_redirect":
        return (
            "Completed", False,
            "비인증 요청이 로그인 경로가 아닌 곳으로 리다이렉트되어 판단을 보류했습니다.",
            f"HTTP {status_code}, Location={location}", raw_output,
        )

    if probe_state == "login_page":
        return (
            "Completed", False,
            "비인증 요청의 응답이 로그인/인증 안내 화면으로 보입니다.",
            f"HTTP {status_code}", raw_output,
        )

    if 200 <= status_code < 300:
        same_body = (
            baseline_fp["length"] > 0
            and probe_fp["length"] > 0
            and baseline_fp["sha1"] == probe_fp["sha1"]
        )
        close_length = lengths_are_close(baseline_fp, probe_fp)
        same_type = content_types_are_similar(baseline_fp, probe_fp)
        both_html = looks_like_html(baseline_response) and looks_like_html(probe_response)

        if both_html and (
            looks_like_spa_shell(baseline_response) or looks_like_spa_shell(probe_response)
        ):
            return (
                "Completed", False,
                "비인증 요청도 HTML 앱 셸을 반환해 SPA 라우팅 응답으로 판단을 보류했습니다. 실제 XHR/API 엔드포인트를 확인해야 합니다.",
                f"HTTP {status_code}, baseline_length={baseline_fp['length']}, probe_length={probe_fp['length']}",
                raw_output,
            )

        if same_body or (close_length and same_type and not both_html):
            return (
                "Completed", True,
                "인증 응답과 비인증 응답이 유사해 보호 엔드포인트 인증 우회 가능성이 있습니다.",
                (
                    f"HTTP {status_code}, same_body={same_body}, "
                    f"close_length={close_length}, same_type={same_type}"
                ),
                raw_output,
            )

        return (
            "Completed", False,
            "비인증 요청이 2xx를 반환했습니다. baseline과 본문은 다르지만 수동 확인이 필요합니다.",
            f"HTTP {status_code}, probe returned 2xx without auth, manual review recommended",
            raw_output,
        )

    if 400 <= status_code < 500:
        return (
            "Completed", False,
            "인증 제거 후 정상 응답이 사라져 보호 동작으로 판단했습니다.",
            f"HTTP {status_code}", raw_output,
        )

    return (
        "Completed", False,
        f"상태 코드 {status_code}만으로 인증 우회를 확인하기 어렵습니다.",
        f"HTTP {status_code}", raw_output,
    )


def main():
    payload = parse_payload()

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "GET").upper()
    query_params = payload.get("query_params", {}) or {}
    auth = payload.get("auth", {}) or {}
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    url = f"{base_url}{path}"

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description=f"{method} 요청은 비인증 probe가 자원 변경을 일으킬 수 있어 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                raw_output=json.dumps(
                    {"method": method, "safe_methods": sorted(SAFE_METHODS)},
                    ensure_ascii=False,
                ),
            ))
            return

        if not auth_headers and not auth_cookies:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 baseline을 만들 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth baseline",
                raw_output=json.dumps({"auth_headers": [], "auth_cookies": []}, ensure_ascii=False),
            ))
            return

        baseline_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )
        baseline_fp = fingerprint(baseline_response)

        if baseline_response.status_code >= 500:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 baseline 요청이 서버 오류를 반환해 검사를 건너뜁니다.",
                evidence=f"HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(baseline_fp=baseline_fp),
            ))
            return

        if not 200 <= baseline_response.status_code < 300:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 baseline이 정상 동작하지 않아 비인증 비교를 수행하지 않았습니다.",
                evidence=f"HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(baseline_fp=baseline_fp),
            ))
            return

        print("[DEBUG] baseline acquired with auth", file=sys.stderr)
        print("[DEBUG] probe auth intentionally omitted", file=sys.stderr)

        probe_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            auth_headers={},
            auth_cookies={},
        )

        status, vulnerable, description, evidence, raw_output = classify_probe(
            baseline_response,
            probe_response,
        )
        result = make_result(
            poc_name=POC_NAME,
            status=status,
            description=description,
            evidence=evidence,
            raw_output=raw_output,
            vulnerable=vulnerable,
        )

    except Exception as e:
        result = error_result(POC_NAME, e)

    emit(result)


if __name__ == "__main__":
    main()
