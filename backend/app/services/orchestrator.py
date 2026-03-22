from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..database import SessionLocal
from ..models import ScanResult, ScanRun
from .registry import PoCRegistry
from .runner import PoCExecutionInput, run_poc


logger = logging.getLogger(__name__)

FAILURE_STATUSES = {"Timeout", "Error", "Failed"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def load_scan_run(db: Session, scan_run_id: int) -> Optional[ScanRun]:
    # 상태 조회와 리포트 렌더링에서 함께 쓰는 연관 데이터를 미리 읽는다.
    statement = (
        select(ScanRun)
        .options(
            selectinload(ScanRun.target),
            selectinload(ScanRun.stack),
            selectinload(ScanRun.results),
        )
        .where(ScanRun.scan_run_id == scan_run_id)
    )
    return db.execute(statement).scalar_one_or_none()


def build_summary(scan_run: ScanRun) -> dict[str, int]:
    # 집계는 저장된 결과 기준으로 다시 계산해 응답 포맷을 단순하게 유지한다.
    registry = PoCRegistry(settings.pocs_dir)
    matched_pocs = registry.find_matching(
        scan_run.stack.stack_name,
        scan_run.stack.version or "",
    )
    vulnerabilities_found = sum(1 for result in scan_run.results if result.status == "Found")
    failed_pocs = sum(1 for result in scan_run.results if result.status in FAILURE_STATUSES)

    return {
        "total_pocs": len(matched_pocs),
        "completed_pocs": len(scan_run.results),
        "vulnerabilities_found": vulnerabilities_found,
        "failed_pocs": failed_pocs,
    }


def run_scan_job(scan_run_id: int) -> None:
    db = SessionLocal()
    try:
        scan_run = load_scan_run(db, scan_run_id)
        if scan_run is None:
            logger.warning("scan_run_id=%s was not found.", scan_run_id)
            return

        # 백그라운드 작업이 스캔 상태를 직접 전이시킨다.
        scan_run.status = "RUNNING"
        scan_run.started_at = utcnow()
        scan_run.error_message = None
        scan_run.target.status = "Scanning"
        db.commit()

        registry = PoCRegistry(settings.pocs_dir)
        # 입력한 스택/버전에 맞는 PoC만 실제로 실행한다.
        matched_pocs = registry.find_matching(
            scan_run.stack.stack_name,
            scan_run.stack.version or "",
        )
        execution_input = PoCExecutionInput(
            base_url=scan_run.target.base_url,
            stack_name=scan_run.stack.stack_name,
            stack_version=scan_run.stack.version or "",
            timeout_seconds=settings.default_poc_timeout_seconds,
            headers={},
        )

        for definition in matched_pocs:
            # 중간에 실패하더라도 앞선 결과는 남도록 한 건씩 바로 저장한다.
            result_payload = run_poc(
                definition,
                PoCExecutionInput(
                    base_url=execution_input.base_url,
                    stack_name=execution_input.stack_name,
                    stack_version=execution_input.stack_version,
                    timeout_seconds=definition.timeout_seconds
                    or execution_input.timeout_seconds,
                    headers=execution_input.headers,
                ),
            )

            db.add(
                ScanResult(
                    target_id=scan_run.target_id,
                    scan_run_id=scan_run.scan_run_id,
                    endpoint_id=None,
                    vuln_category=result_payload["vuln_category"],
                    cve_id=result_payload.get("cve_id"),
                    severity=result_payload["severity"],
                    description=result_payload.get("description"),
                    evidence=result_payload.get("evidence"),
                    status=result_payload["status"],
                    poc_name=result_payload.get("poc_name"),
                    raw_output=result_payload.get("raw_output"),
                )
            )
            db.commit()

        scan_run = load_scan_run(db, scan_run_id)
        if scan_run is None:
            return

        # 여기까지 왔다는 것은 오케스트레이션 자체는 정상 종료됐다는 뜻이다.
        scan_run.status = "COMPLETED"
        scan_run.finished_at = utcnow()
        scan_run.report_path = f"/reports/{scan_run.scan_run_id}"
        scan_run.target.status = "Completed"
        db.commit()
    except Exception as exc:
        logger.exception("Scan job failed for scan_run_id=%s", scan_run_id)
        db.rollback()

        failed_scan_run = load_scan_run(db, scan_run_id)
        if failed_scan_run is not None:
            # 전체 스캔을 FAILED로 바꾸는 것은 시스템 레벨 오류일 때만 한다.
            failed_scan_run.status = "FAILED"
            failed_scan_run.finished_at = utcnow()
            failed_scan_run.error_message = str(exc)
            failed_scan_run.target.status = "Failed"
            db.commit()
    finally:
        db.close()
