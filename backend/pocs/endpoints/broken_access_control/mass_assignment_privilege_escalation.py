from __future__ import annotations

import copy
import json
import re
import sys
from urllib.parse import unquote, urlsplit

from backend.pocs.endpoints._common import (
    classify_response,
    emit,
    error_result,
    fingerprint,
    make_result,
    normalize_key_for_matching,
    parse_payload,
    request_once,
)


POC_NAME = "mass_assignment_privilege_escalation"
SAFE_METHODS = {"POST"}

DANGEROUS_KEYWORDS = (
    "ban",
    "delete",
    "grant",
    "payment",
    "refund",
    "revoke",
    "transfer",
    "withdraw",
)

PRIVILEGE_FIELD_VALUES_JSON = {
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "role": "admin",
    "roles": ["admin"],
    "authority": "admin",
    "permissions": ["admin"],
}

PRIVILEGE_FIELD_VALUES_FORM = {
    "is_admin": "true",
    "isAdmin": "true",
    "admin": "true",
    "role": "admin",
    "authority": "admin",
    "permissions": "admin",
}

PRIVILEGE_KEYS = {
    "admin",
    "is_admin",
    "isadmin",
    "super_admin",
    "superuser",
    "is_superuser",
    "role",
    "roles",
    "authority",
    "authorities",
    "permission",
    "permissions",
    "privilege",
    "privileges",
}

ADMIN_TEXT_VALUES = {"admin", "administrator", "superadmin", "super_admin", "root"}
TRUE_TEXT_VALUES = {"true", "1", "yes", "y", "on"}
NON_AUTH_HEADER_NAMES = {
    "accept",
    "content-type",
    "origin",
    "referer",
    "user-agent",
}


def normalize_privilege_key(key):
    return normalize_key_for_matching(str(key)).replace("-", "_")


def is_privilege_key(key):
    normalized = normalize_privilege_key(key)
    compact = normalized.replace("_", "")
    return normalized in PRIVILEGE_KEYS or compact in PRIVILEGE_KEYS


def is_auth_header_name(key):
    lowered = str(key).lower()
    if lowered in NON_AUTH_HEADER_NAMES or "csrf" in lowered:
        return False
    return True


def has_auth_context(auth_headers, auth_cookies):
    return bool(auth_cookies) or any(
        is_auth_header_name(key) for key in (auth_headers or {})
    )


def stringify_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip().lower()


def is_admin_value(key, value):
    normalized_key = normalize_privilege_key(key)
    compact_key = normalized_key.replace("_", "")

    if compact_key in {"admin", "isadmin", "issuperuser", "superuser", "superadmin"}:
        if isinstance(value, bool):
            return value
        return stringify_value(value) in TRUE_TEXT_VALUES

    if normalized_key in {"role", "authority", "permission", "privilege"}:
        return stringify_value(value) in ADMIN_TEXT_VALUES

    if normalized_key in {
        "roles",
        "authorities",
        "permissions",
        "privileges",
    }:
        if isinstance(value, list):
            return any(stringify_value(item) in ADMIN_TEXT_VALUES for item in value)
        return stringify_value(value) in ADMIN_TEXT_VALUES

    return False


def iter_privilege_signals(value, path=None):
    path = path or []

    if isinstance(value, dict):
        for key, child in value.items():
            next_path = path + [str(key)]

            if is_privilege_key(key) and is_admin_value(key, child):
                yield {
                    "path": ".".join(next_path),
                    "key": str(key),
                    "value": child,
                }

            if isinstance(child, (dict, list)):
                yield from iter_privilege_signals(child, next_path)

    elif isinstance(value, list):
        for index, child in enumerate(value):
            next_path = path + [str(index)]
            if isinstance(child, (dict, list)):
                yield from iter_privilege_signals(child, next_path)


def parse_json_body(response):
    content_type = response.headers.get("Content-Type", "").lower()
    text = response.text.strip()

    if not text:
        return None
    if "json" not in content_type and not text.startswith(("{", "[")):
        return None

    try:
        return json.loads(text)
    except ValueError:
        return None


def find_admin_privilege_signals(response):
    body = parse_json_body(response)

    if body is None:
        return []

    return list(iter_privilege_signals(body))


def iter_body_key_paths(value, path=None):
    path = path or []

    if isinstance(value, dict):
        for key, child in value.items():
            next_path = path + [str(key)]
            yield next_path, child
            if isinstance(child, (dict, list)):
                yield from iter_body_key_paths(child, next_path)

    elif isinstance(value, list):
        for index, child in enumerate(value):
            next_path = path + [str(index)]
            if isinstance(child, (dict, list)):
                yield from iter_body_key_paths(child, next_path)


def existing_privilege_paths(body_params):
    return [
        ".".join(path)
        for path, _ in iter_body_key_paths(body_params)
        if path and is_privilege_key(path[-1])
    ]


def admin_replacement_for_value(key, current_value):
    normalized = normalize_privilege_key(key)
    compact = normalized.replace("_", "")

    if compact in {"admin", "isadmin", "issuperuser", "superuser", "superadmin"}:
        if isinstance(current_value, bool):
            return True
        return "true"

    if normalized in {"roles", "authorities", "permissions", "privileges"}:
        if isinstance(current_value, list):
            return ["admin"]
        return "admin"

    return "admin"


def _apply_privilege_mutations(value, path):
    mutated_paths = []

    if isinstance(value, dict):
        for key in list(value.keys()):
            child = value[key]
            next_path = path + [str(key)]
            replaced = False

            if is_privilege_key(key):
                replacement = admin_replacement_for_value(key, child)
                if replacement != child:
                    value[key] = replacement
                    mutated_paths.append(".".join(next_path))
                    replaced = True

            if not replaced and isinstance(child, (dict, list)):
                mutated_paths.extend(_apply_privilege_mutations(child, next_path))

    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                mutated_paths.extend(
                    _apply_privilege_mutations(child, path + [str(index)])
                )

    return mutated_paths


def mutate_privilege_values(body_params):
    mutated_body = copy.deepcopy(body_params)
    mutated_paths = _apply_privilege_mutations(mutated_body, path=[])
    return mutated_body, mutated_paths


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


def contains_nested_value(value):
    if isinstance(value, dict):
        return any(isinstance(child, (dict, list)) for child in value.values())
    if isinstance(value, list):
        return any(isinstance(child, (dict, list)) for child in value)
    return False


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


def privilege_field_values(body_mode):
    if body_mode == "form":
        return PRIVILEGE_FIELD_VALUES_FORM

    return PRIVILEGE_FIELD_VALUES_JSON


def build_probe_body(body_params, body_mode):
    probe_body = copy.deepcopy(body_params)
    existing_top_level = {
        normalize_privilege_key(key)
        for key in probe_body
    }
    added_fields = {}

    for key, value in privilege_field_values(body_mode).items():
        normalized = normalize_privilege_key(key)
        compact = normalized.replace("_", "")

        if normalized in existing_top_level or compact in existing_top_level:
            continue

        probe_body[key] = value
        added_fields[key] = value

    return probe_body, added_fields


def build_raw_output(
    method,
    path,
    query_params,
    body_params,
    auth_headers,
    auth_cookies,
    body_mode="",
    added_fields=None,
    mutated_paths=None,
    baseline_state="",
    baseline_fp=None,
    baseline_response=None,
    probe_state="",
    probe_fp=None,
    probe_response=None,
    baseline_admin_signals=None,
    probe_admin_signals=None,
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
            "added_privilege_fields": sorted((added_fields or {}).keys()),
            "mutated_privilege_paths": sorted(mutated_paths or []),
            "baseline": {
                "state": baseline_state,
                "fingerprint": baseline_fp,
                "admin_signals": baseline_admin_signals or [],
                "preview": baseline_response.text[:500] if baseline_response else "",
            },
            "probe": {
                "state": probe_state,
                "fingerprint": probe_fp,
                "admin_signals": probe_admin_signals or [],
                "preview": probe_response.text[:500] if probe_response else "",
            },
            "note": note,
        },
        ensure_ascii=False,
    )


def make_skip_result(
    description,
    evidence,
    method,
    path,
    query_params,
    body_params,
    auth_headers,
    auth_cookies,
    body_mode="",
    added_fields=None,
    mutated_paths=None,
    note="",
):
    return make_result(
        poc_name=POC_NAME,
        status="Skipped",
        description=description,
        evidence=evidence,
        raw_output=build_raw_output(
            method=method,
            path=path,
            query_params=query_params,
            body_params=body_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            body_mode=body_mode,
            added_fields=added_fields,
            mutated_paths=mutated_paths,
            note=note,
        ),
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
    options = payload.get("options", {}) or {}
    allow_priv_mutation = bool(options.get("allow_privilege_field_mutation", False))

    url = f"{base_url}{path}"
    body_mode = select_body_mode(auth_headers, path, body_params)

    print(f"[DEBUG] url={url}", file=sys.stderr)
    print(f"[DEBUG] method={method}", file=sys.stderr)
    print(f"[DEBUG] query_params={query_params}", file=sys.stderr)
    print(f"[DEBUG] original_body={body_params}", file=sys.stderr)
    print(f"[DEBUG] body_mode={body_mode}", file=sys.stderr)
    print(f"[DEBUG] auth_header_count={len(auth_headers)}", file=sys.stderr)
    print(f"[DEBUG] auth_cookie_count={len(auth_cookies)}", file=sys.stderr)

    try:
        if method not in SAFE_METHODS:
            emit(make_skip_result(
                description=f"{method} 요청은 권한 필드 추가 probe가 자원 변경을 일으킬 수 있어 자동 검사를 건너뜁니다.",
                evidence=f"unsafe_method={method}",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
                note="PUT/PATCH 기반 mass assignment 검사는 테스트 전용 리소스나 명시적 opt-in이 필요합니다.",
            ))
            return

        if not isinstance(body_params, dict) or not body_params:
            emit(make_skip_result(
                description="body_params가 없어 권한 필드 추가 테스트를 수행할 수 없습니다.",
                evidence="missing body_params",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
            ))
            return

        if not has_auth_context(auth_headers, auth_cookies):
            emit(make_skip_result(
                description="인증 포함 baseline을 만들 Cookie 또는 Authorization 값이 없어 검사를 건너뜁니다.",
                evidence="missing auth baseline",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
            ))
            return

        if body_mode == "multipart":
            emit(make_skip_result(
                description="multipart/form-data 요청은 원본 boundary와 파일 파트를 안전하게 재현하기 어려워 자동 probe를 건너뜁니다.",
                evidence="multipart body unsupported",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
                note="multipart 요청은 실제 업로드 파트와 boundary를 보존한 수동 검증이 필요합니다.",
            ))
            return

        if body_mode == "form" and contains_nested_value(body_params):
            emit(make_skip_result(
                description="form-urlencoded body에 중첩 구조가 있어 원본 요청과 같은 형태로 안전하게 재현하기 어렵습니다.",
                evidence="nested form body unsupported",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
                note="중첩 form body는 서버별 인코딩 규칙이 달라 수동 검증이 필요합니다.",
            ))
            return

        privilege_paths = existing_privilege_paths(body_params)
        if privilege_paths and not allow_priv_mutation:
            emit(make_skip_result(
                description="원본 body에 이미 권한 관련 필드가 있어 자동으로 값을 바꾸지 않고 검사를 건너뜁니다. options.allow_privilege_field_mutation=true 로 명시적 opt-in 시 mutation을 수행합니다.",
                evidence=f"existing privilege-like fields={', '.join(privilege_paths)}",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
                note="기존 권한 필드 변경은 계정 권한 변경 부작용이 있어 opt-in이 필요합니다.",
            ))
            return

        if looks_dangerous(path, body_params):
            emit(make_skip_result(
                description="대상 요청의 path 또는 body가 생성/수정/삭제 계열로 보여 권한 필드 추가 자동 probe를 건너뜁니다.",
                evidence="dangerous path/body operation heuristic matched",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
                note="테스트 전용 계정/리소스가 확인된 경우 수동 검증이 필요합니다.",
            ))
            return

        if privilege_paths:
            probe_body, mutated_paths = mutate_privilege_values(body_params)
            added_fields = {}
        else:
            probe_body, added_fields = build_probe_body(body_params, body_mode)
            mutated_paths = []

        if not added_fields and not mutated_paths:
            emit(make_skip_result(
                description="추가하거나 변경할 권한 관련 필드를 만들지 못해 검사를 건너뜁니다.",
                evidence="no privilege fields to probe",
                method=method,
                path=path,
                query_params=query_params,
                body_params=body_params,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
                body_mode=body_mode,
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
        baseline_admin_signals = find_admin_privilege_signals(baseline_response)

        if baseline_state != "success":
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="인증 포함 baseline 요청이 정상 리소스 응답으로 보이지 않아 권한 필드 추가 probe를 수행하지 않았습니다.",
                evidence=f"baseline_state={baseline_state}, HTTP {baseline_response.status_code}",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    body_mode=body_mode,
                    added_fields=added_fields,
                    mutated_paths=mutated_paths,
                    baseline_state=baseline_state,
                    baseline_fp=baseline_fp,
                    baseline_response=baseline_response,
                    baseline_admin_signals=baseline_admin_signals,
                ),
            ))
            return

        if baseline_admin_signals:
            emit(make_result(
                poc_name=POC_NAME,
                status="Skipped",
                description="baseline 응답에 이미 관리자 권한 신호가 있어 권한 상승 여부를 비교할 수 없습니다.",
                evidence="baseline already contains admin privilege signal",
                raw_output=build_raw_output(
                    method=method,
                    path=path,
                    query_params=query_params,
                    body_params=body_params,
                    auth_headers=auth_headers,
                    auth_cookies=auth_cookies,
                    body_mode=body_mode,
                    added_fields=added_fields,
                    mutated_paths=mutated_paths,
                    baseline_state=baseline_state,
                    baseline_fp=baseline_fp,
                    baseline_response=baseline_response,
                    baseline_admin_signals=baseline_admin_signals,
                ),
            ))
            return

        print(f"[DEBUG] added_fields={sorted(added_fields)}", file=sys.stderr)
        print(f"[DEBUG] mutated_paths={sorted(mutated_paths)}", file=sys.stderr)

        probe_response = request_once(
            method=method,
            url=url,
            query_params=query_params,
            body_mode=body_mode,
            body_params=probe_body,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )
        probe_state = classify_response(probe_response)
        probe_fp = fingerprint(probe_response)
        probe_admin_signals = find_admin_privilege_signals(probe_response)

        raw_output = build_raw_output(
            method=method,
            path=path,
            query_params=query_params,
            body_params=body_params,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            body_mode=body_mode,
            added_fields=added_fields,
            mutated_paths=mutated_paths,
            baseline_state=baseline_state,
            baseline_fp=baseline_fp,
            baseline_response=baseline_response,
            probe_state=probe_state,
            probe_fp=probe_fp,
            probe_response=probe_response,
            baseline_admin_signals=baseline_admin_signals,
            probe_admin_signals=probe_admin_signals,
        )

        probe_kind = "mutated_paths" if mutated_paths else "added_fields"
        probe_summary = (
            ",".join(sorted(mutated_paths))
            if mutated_paths
            else ",".join(sorted(added_fields))
        )
        action_label = "변경" if mutated_paths else "추가"
        evidence = (
            f"baseline=HTTP {baseline_response.status_code} ({baseline_state}), "
            f"probe=HTTP {probe_response.status_code} ({probe_state}), "
            f"{probe_kind}={probe_summary}"
        )

        if probe_state != "success":
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description=f"권한 관련 필드를 {action_label}한 요청이 정상 리소스 응답으로 처리되지 않았습니다.",
                evidence=evidence,
                raw_output=raw_output,
                vulnerable=False,
            )
        elif probe_admin_signals:
            signal_paths = ",".join(signal["path"] for signal in probe_admin_signals)
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description=f"권한 관련 필드를 {action_label}한 요청의 응답에 관리자 권한 신호가 반영되어 mass assignment 권한 상승 가능성이 있습니다.",
                evidence=f"{evidence}, admin_signals={signal_paths}",
                raw_output=raw_output,
                vulnerable=True,
            )
        elif baseline_fp["sha1"] != probe_fp["sha1"]:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description=(
                    f"권한 관련 필드를 {action_label}한 요청이 2xx와 다른 응답 본문을 반환했지만 관리자 권한 반영 신호가 없습니다. "
                    "서버가 mass assignment를 수용해도 응답에 admin 필드를 echo하지 않으면 자동 탐지로는 확인이 어려우니, "
                    "별도 GET 등으로 권한 반영 여부를 수동 확인하세요."
                ),
                evidence=f"{evidence}, response body changed without admin signal (echo-based detection limit)",
                raw_output=raw_output,
                vulnerable=False,
            )
        else:
            result = make_result(
                poc_name=POC_NAME,
                status="Completed",
                description=f"권한 관련 필드를 {action_label}해도 baseline과 같은 응답으로 처리되어 권한 상승 신호가 확인되지 않았습니다.",
                evidence=f"{evidence}, response body unchanged",
                raw_output=raw_output,
                vulnerable=False,
            )

    except Exception as exc:
        result = error_result(POC_NAME, exc)

    emit(result)


if __name__ == "__main__":
    main()
