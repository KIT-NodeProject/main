from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

from ..config import settings
from .registry import PoCDefinition


@dataclass
class PoCExecutionInput:
    # 모든 PoC가 같은 형태로 받는 실행 입력값이다.
    base_url: str
    stack_name: str
    stack_version: str
    timeout_seconds: int
    headers: dict[str, str]


def run_poc(definition: PoCDefinition, execution_input: PoCExecutionInput) -> dict[str, Any]:
    payload = {
        "base_url": execution_input.base_url,
        "stack_name": execution_input.stack_name,
        "stack_version": execution_input.stack_version,
        "timeout_seconds": execution_input.timeout_seconds,
        "headers": execution_input.headers,
    }

    temp_path: Optional[Path] = None
    try:
        # 입력값을 임시 JSON 파일로 넘기면 PoC 구현 방식이 단순해진다.
        with tempfile.NamedTemporaryFile(
            "w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as temp_file:
            json.dump(payload, temp_file)
            temp_path = Path(temp_file.name)

        # PoC는 별도 프로세스로 실행해서 앱 본체와 격리한다.
        completed = subprocess.run(
            [sys.executable, str(definition.entrypoint_path), "--input", str(temp_path)],
            capture_output=True,
            text=True,
            timeout=execution_input.timeout_seconds,
            check=False,
        )

        if completed.returncode != 0:
            return _build_result(
                definition=definition,
                vulnerable=False,
                status="Error",
                description="PoC exited with a non-zero status.",
                evidence=f"Exit code: {completed.returncode}",
                raw_output=_merge_output(completed.stdout, completed.stderr),
            )

        try:
            data = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            return _build_result(
                definition=definition,
                vulnerable=False,
                status="Error",
                description="PoC did not return valid JSON output.",
                evidence="The runner stdout could not be parsed as JSON.",
                raw_output=_merge_output(completed.stdout, completed.stderr),
            )

        # 누락된 필드는 메타데이터 기본값으로 보정한다.
        return _normalize_result(definition, data, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return _build_result(
            definition=definition,
            vulnerable=False,
            status="Timeout",
            description="PoC execution timed out.",
            evidence=f"Timed out after {execution_input.timeout_seconds} seconds.",
            raw_output=_merge_output(exc.stdout, exc.stderr),
        )
    except OSError as exc:
        return _build_result(
            definition=definition,
            vulnerable=False,
            status="Error",
            description="PoC runner could not be executed.",
            evidence=str(exc),
            raw_output="",
        )
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def _normalize_result(
    definition: PoCDefinition,
    data: dict[str, Any],
    stderr_output: str,
) -> dict[str, Any]:
    vulnerable = bool(data.get("vulnerable"))
    status = data.get("status") or ("Found" if vulnerable else "NotFound")

    return _build_result(
        definition=definition,
        vulnerable=vulnerable,
        status=status,
        description=data.get("description") or definition.description or "PoC executed.",
        evidence=data.get("evidence") or "",
        raw_output=data.get("raw_output") or _merge_output("", stderr_output),
        cve_id=data.get("cve_id"),
        vuln_category=data.get("vuln_category") or definition.category,
        severity=data.get("severity") or definition.severity,
        poc_name=data.get("poc_name") or definition.name,
    )


def _build_result(
    definition: PoCDefinition,
    vulnerable: bool,
    status: str,
    description: str,
    evidence: str,
    raw_output: str,
    cve_id: Optional[str] = None,
    vuln_category: Optional[str] = None,
    severity: Optional[str] = None,
    poc_name: Optional[str] = None,
) -> dict[str, Any]:
    # 어떤 PoC가 실행되든 DB에 저장되는 결과 형태는 같게 맞춘다.
    return {
        "poc_name": poc_name or definition.name,
        "vulnerable": vulnerable,
        "vuln_category": vuln_category or definition.category,
        "cve_id": cve_id,
        "severity": severity or definition.severity,
        "description": description,
        "evidence": evidence,
        "raw_output": _truncate(raw_output),
        "status": status,
    }


def _merge_output(
    stdout: Optional[Union[str, bytes]],
    stderr: Optional[Union[str, bytes]],
) -> str:
    parts: list[str] = []
    if stdout:
        parts.append(_to_text(stdout))
    if stderr:
        parts.append(_to_text(stderr))
    return "\n".join(part for part in parts if part)


def _to_text(value: Union[str, bytes]) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _truncate(raw_output: str) -> str:
    # 원본 출력이 너무 길면 리포트와 DB가 과하게 커지는 것을 막는다.
    if len(raw_output) <= settings.max_raw_output_chars:
        return raw_output
    return raw_output[: settings.max_raw_output_chars] + "\n...[truncated]"
