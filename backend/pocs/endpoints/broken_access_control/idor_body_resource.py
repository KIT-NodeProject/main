import copy
import json
import re
import sys
from urllib.parse import unquote, urlsplit

from backend.pocs.endpoints._common import (
    ID_KEY_PATTERN,
    IGNORE_KEYS,
    classify_response,
    emit,
    error_result,
    fingerprint,
    is_number,
    make_result,
    mutate_numeric_value,
    normalize_key_for_matching,
    parse_payload,
    request_once,
    value_echoed_in_text,
)


POC_NAME = "idor_body_resource"
SAFE_METHODS = {"POST"}
MAX_PROBES = 2

DANGEROUS_KEYWORDS = (
    "add",
    "assign",
    "approve",
    "ban",
    "block",
    "cancel",
    "create",
    "delete",
    "deposit",
    "disable",
    "edit",
    "enable",
    "grant",
    "insert",
    "mutation",
    "pay",
    "payment",
    "publish",
    "refund",
    "reject",
    "remove",
    "revoke",
    "save",
    "submit",
    "transfer",
    "update",
    "withdraw",
)


def normalized_key(key_path):
    return ".".join(str(part) for part in key_path).lower()


def is_candidate_key(key_path, value):
    leaf_key = normalize_key_for_matching(str(key_path[-1]))
    key = ".".join(normalize_key_for_matching(str(part)) for part in key_path)

    if leaf_key in IGNORE_KEYS or key in IGNORE_KEYS:
        return False

    if not is_number(value):
        return False

    return bool(ID_KEY_PATTERN.search(key) or ID_KEY_PATTERN.search(leaf_key))


def iter_candidate_paths(value, path=None):
    path = path or []

    if isinstance(value, dict):
        for key, child in value.items():
            next_path = path + [key]

            if is_candidate_key(next_path, child):
                yield next_path, child

            if isinstance(child, (dict, list)):
                yield from iter_candidate_paths(child, next_path)

    elif isinstance(value, list):
        for index, child in enumerate(value):
            next_path = path + [index]

            if is_candidate_key(next_path, child):
                yield next_path, child

            if isinstance(child, (dict, list)):
                yield from iter_candidate_paths(child, next_path)


def set_nested_value(value, path, new_value):
    cursor = value
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = new_value


def contains_nested_value(value):
    if isinstance(value, dict):
        return any(isinstance(child, (dict, list)) for child in value.values())
    if isinstance(value, list):
        return any(isinstance(child, (dict, list)) for child in value)
    return False


def body_target_text(path, body_params):
    parsed = urlsplit(path)
    pieces = [unquote(parsed.path), unquote(parsed.query)]

    if isinstance(body_params, dict):
        pieces.extend(f"{key}={value}" for key, value in body_params.items())

    return " ".join(str(piece) for piece in pieces if piece)


def path_query_text(path):
    parsed = urlsplit(path)
    return " ".join(
        piece for piece in (unquote(parsed.path), unquote(parsed.query)) if piece
    )


def tokenize_text(value):
    separated = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(value))
    return {
        token
        for token in re.split(r"[^a-z0-9]+", separated.lower())
        if token
    }


def iter_body_tokens(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from tokenize_text(key)
            yield from iter_body_tokens(child)
        return

    if isinstance(value, list):
        for child in value:
            yield from iter_body_tokens(child)
        return

    if value is not None:
        yield from tokenize_text(value)


def looks_dangerous(path, body_params):
    tokens = tokenize_text(path_query_text(path))
    tokens.update(iter_body_tokens(body_params))
    return any(keyword in tokens for keyword in DANGEROUS_KEYWORDS)


def select_body_mode(auth_headers, path, body_params):
    content_type = ""

    for key, value in (auth_headers or {}).items():
        if key.lower() == "content-type":
            content_type = str(value).lower()
            break

    if "multipart/form-data" in content_type:
        return "multipart"

    if "application/x-www-form-urlencoded" in content_type:
        return "form"

    if "json" in content_type:
        return "json"

    target = body_target_text(path, body_params).lower()
    if "graphql" in target or "query=" in target:
        return "json"

    return "json"


def build_raw_output(
    method,
    path,
    query_params,
    body_params,
    auth_headers,
    auth_cookies,
    candidate_paths,
    body_mode="",
    baseline_state="",
    baseline_fp=None,
    baseline_response=None,
    probes=None,
    note="",
):
    return json.dumps(
        {
            "request": {
                "method": method,
                "path": path,
                "query_param_keys": sorted((query_params or {}).keys()),
                "body_param_keys": sorted((body_params or {}).keys())
                if isinstance(body_params, dict)
                else [],
                "auth_header_keys": sorted((auth_headers or {}).keys()),
                "auth_cookie_keys": sorted((auth_cookies or {}).keys()),
                "body_mode": body_mode,
            },
            "candidate_paths": candidate_paths,
            "baseline": {
                "state": baseline_state,
                "fingerprint": baseline_fp,
                "preview": baseline_response.text[:500] if baseline_response else "",
            },
            "probes": probes or [],
            "note": note,
        },
        ensure_ascii=False,
    )


def evaluate_probe(baseline_fp, probe_fp, probe_state, probe_response, changed_value):
    changed_value_text = str(changed_value)
    changed_value_echoed = value_echoed_in_text(changed_value_text, probe_response.text)

    if probe_state != "success":
        return (
            False,
            False,
            changed_value_echoed,
            "변경한 ID 요청이 정상 리소스 응답으로 처리되지 않았습니다.",
        )

    if baseline_fp and probe_fp and baseline_fp["sha1"] == probe_fp["sha1"]:
        return (
            False,
            True,
            changed_value_echoed,
            "변경한 ID 요청이 2xx를 반환했지만 baseline과 응답 본문이 같습니다.",
        )

    if not changed_value_echoed:
        return (
            False,
            True,
            changed_value_echoed,
            "변경한 ID 요청이 2xx와 다른 본문을 반환했지만 변경 ID echo가 없어 수동 확인이 필요합니다.",
        )

    if len(changed_value_text) <= 2:
        return (
            False,
            True,
            changed_value_echoed,
            "변경 ID가 너무 짧아 echo만으로 취약 단정이 어려워 수동 확인이 필요합니다.",
        )

    return (
        True,
        False,
        changed_value_echoed,
        "변경한 ID 요청이 2xx와 다른 본문을 반환했고 변경 ID가 응답에 포함되었습니다.",
    )


def main():
    payload = parse_payload()

    base_url = payload["base_url"].rstrip("/")
    path = payload.get("path", "")
    method = payload.get("method", "POST").upper()
    query_params = payload.get("query_params", {}) or {}
    body_params = payload.get("body_params", {}) or {}
    auth = payload.get("auth", {}) or {}
    auth_headers = auth.get("headers", {}) or {}
    auth_cookies = auth.get("cookies", {}) or {}

    url = f"{base_url}{path}"
    candidate_pairs = list(iter_candidate_paths(body_params))
    candidate_paths = [normalized_key(p) for p, _ in candidate_pairs]
    body_mode = select_body_mode(auth_headers, path, body_params)

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] original_body={body_params}", file=sys.stderr)
    print(f"[DEBUG] candidate_paths={candidate_paths}", file=sys.stderr)
    print(f"[DEBUG] body_mode={body_mode}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description=f"{method} 요청은 body IDOR probe가 자원 변경을 일으킬 수 있어 자동 검사를 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    candidate_paths,
                    note="PUT/PATCH 기반 body IDOR은 테스트 전용 리소스나 명시적 opt-in이 필요합니다.",
                ),
            ))
            return

        if not isinstance(body_params, dict) or not body_params:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="body_params가 없어 body 기반 IDOR 테스트를 수행할 수 없습니다.",
                evidence="missing body_params",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies, [],
                ),
            ))
            return

        if not auth_headers and not auth_cookies:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 baseline을 만들 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth baseline",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    candidate_paths, body_mode=body_mode,
                ),
            ))
            return

        if not candidate_pairs:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="테스트할 숫자 ID 성격의 body 필드를 찾지 못했습니다.",
                evidence="no numeric id-like body field",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    [], body_mode=body_mode,
                ),
            ))
            return

        if body_mode == "multipart":
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="multipart/form-data 요청은 원본 boundary와 파일 파트를 안전하게 재현하기 어려워 자동 probe를 건너뜁니다.",
                evidence="multipart body unsupported",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    candidate_paths, body_mode=body_mode,
                    note="multipart 요청은 실제 업로드 파트와 boundary를 보존한 수동 검증이 필요합니다.",
                ),
            ))
            return

        if body_mode == "form" and contains_nested_value(body_params):
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="form-urlencoded body에 중첩 구조가 있어 원본 요청과 같은 형태로 안전하게 재현하기 어렵습니다.",
                evidence="nested form body unsupported",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    candidate_paths, body_mode=body_mode,
                    note="중첩 form body는 서버별 인코딩 규칙이 달라 수동 검증이 필요합니다.",
                ),
            ))
            return

        if looks_dangerous(path, body_params):
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="대상 요청의 path 또는 body가 생성/수정/삭제 계열로 보여 body IDOR 자동 probe를 건너뜁니다.",
                evidence="dangerous path/body operation heuristic matched",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    candidate_paths, body_mode=body_mode,
                    note="테스트 전용 계정/리소스가 확인된 경우 수동 검증이 필요합니다.",
                ),
            ))
            return

        baseline_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            body_mode=body_mode,
            body_params=body_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )
        baseline_state = classify_response(
            baseline_response,
            detect_application_failure=False,
        )
        baseline_fp = fingerprint(baseline_response)

        if baseline_state != "success":
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 baseline 요청이 정상 리소스 응답으로 보이지 않아 ID 변경 probe를 수행하지 않았습니다.",
                evidence=f"baseline_state={baseline_state}, HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(
                    method, path, query_params, body_params, auth_headers, auth_cookies,
                    candidate_paths, body_mode=body_mode,
                    baseline_state=baseline_state,
                    baseline_fp=baseline_fp,
                    baseline_response=baseline_response,
                ),
            ))
            return

        probes = []
        vulnerable_found = False
        manual_review_found = False

        for path_parts, original_value in candidate_pairs[:MAX_PROBES]:
            changed_value = mutate_numeric_value(original_value)
            test_body = copy.deepcopy(body_params)
            set_nested_value(test_body, path_parts, changed_value)

            print(f"[DEBUG] target_key={normalized_key(path_parts)}", file=sys.stderr)
            print(f"[DEBUG] original_value={original_value}", file=sys.stderr)
            print(f"[DEBUG] changed_value={changed_value}", file=sys.stderr)

            probe_response = request_once(
                method=method,
                url=url,
                query_params=query_params,
                body_mode=body_mode,
                body_params=test_body,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            probe_state = classify_response(probe_response)
            probe_fp = fingerprint(probe_response)
            vulnerable, manual_review, changed_value_echoed, note = evaluate_probe(
                baseline_fp,
                probe_fp,
                probe_state,
                probe_response,
                changed_value,
            )

            vulnerable_found = vulnerable_found or vulnerable
            manual_review_found = manual_review_found or manual_review

            probes.append({
                "target_key": normalized_key(path_parts),
                "original_value": original_value,
                "changed_value": changed_value,
                "state": probe_state,
                "fingerprint": probe_fp,
                "changed_value_echoed": changed_value_echoed,
                "vulnerable": vulnerable,
                "manual_review": manual_review,
                "note": note,
                "response_preview": probe_response.text[:500],
            })

        raw_output = build_raw_output(
            method, path, query_params, body_params, auth_headers, auth_cookies,
            candidate_paths, body_mode=body_mode,
            baseline_state=baseline_state,
            baseline_fp=baseline_fp,
            baseline_response=baseline_response,
            probes=probes,
        )

        if vulnerable_found:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="body의 숫자 ID 값을 변경한 요청이 성공했고 baseline과 다른 응답 및 변경 ID echo를 반환했습니다. 다른 사용자 리소스 접근 가능성이 있습니다.",
                evidence="changed id-like body field returned 2xx with different body and echoed changed ID",
                raw_output=raw_output,
                vulnerable=True,
            )
        elif manual_review_found:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="body의 숫자 ID 값을 변경한 요청이 2xx를 반환했지만 취약으로 단정할 응답 증거가 부족해 수동 확인이 필요합니다.",
                evidence="changed id-like body field returned 2xx but needs manual review",
                raw_output=raw_output,
                vulnerable=False,
            )
        else:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description="body의 숫자 ID 값을 변경한 요청이 정상 리소스 응답으로 처리되지 않았습니다.",
                evidence="changed id-like body field did not return successful resource response",
                raw_output=raw_output,
                vulnerable=False,
            )

    except Exception as e:
        result = error_result(POC_NAME, e)

    emit(result)


if __name__ == "__main__":
    main()
