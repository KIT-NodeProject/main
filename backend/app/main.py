from __future__ import annotations

from contextlib import asynccontextmanager
from urllib.parse import urlparse, urlunparse

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db, init_db
from .models import ScanRun, ScanTarget, TechStack
from .schemas import (
    CreateScanRequest,
    ScanCreatedResponse,
    ScanResultResponse,
    ScanResultsEnvelope,
    ScanStatusResponse,
    ScanSummaryResponse,
)
from .services.orchestrator import build_summary, load_scan_run, run_scan_job
from .services.reporter import render_report


@asynccontextmanager
async def lifespan(_: FastAPI):
    # 서버 시작 시점에 필요한 테이블을 자동으로 만든다.
    init_db()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)


@app.get("/")
def read_root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "docs": "/docs",
    }


@app.post("/api/v1/scans", response_model=ScanCreatedResponse, status_code=202)
def create_scan(
    payload: CreateScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> ScanCreatedResponse:
    # 입력값은 저장 전에 한 번 정규화해서 중복을 줄인다.
    base_url = normalize_base_url(payload.base_url)
    stack_name = payload.stack_name.strip()
    stack_version = payload.stack_version.strip()

    if not stack_name:
        raise HTTPException(status_code=422, detail="stack_name must not be empty.")
    if not stack_version:
        raise HTTPException(status_code=422, detail="stack_version must not be empty.")

    target = db.execute(
        select(ScanTarget).where(ScanTarget.base_url == base_url)
    ).scalar_one_or_none()
    if target is None:
        target = ScanTarget(base_url=base_url, status="Ready")
        db.add(target)
        db.flush()

    # 현재 프로토타입은 실행 시점의 스택 정보를 별도 행으로 남긴다.
    stack = TechStack(
        target_id=target.target_id,
        stack_name=stack_name,
        version=stack_version,
        identify_method="Manual_Input",
    )
    db.add(stack)
    db.flush()

    scan_run = ScanRun(
        target_id=target.target_id,
        stack_id=stack.stack_id,
        status="QUEUED",
        report_path=None,
    )
    db.add(scan_run)
    db.flush()

    scan_run.report_path = f"/reports/{scan_run.scan_run_id}"
    db.commit()
    db.refresh(scan_run)

    # 실제 PoC 실행은 응답을 먼저 돌려준 뒤 백그라운드에서 진행한다.
    background_tasks.add_task(run_scan_job, scan_run.scan_run_id)

    return ScanCreatedResponse(
        scan_run_id=scan_run.scan_run_id,
        target_id=target.target_id,
        status=scan_run.status,
    )


@app.get("/api/v1/scans/{scan_run_id}", response_model=ScanStatusResponse)
def get_scan_status(
    scan_run_id: int,
    db: Session = Depends(get_db),
) -> ScanStatusResponse:
    scan_run = require_scan_run(db, scan_run_id)
    summary = build_summary(scan_run)

    return ScanStatusResponse(
        scan_run_id=scan_run.scan_run_id,
        status=scan_run.status,
        base_url=scan_run.target.base_url,
        stack_name=scan_run.stack.stack_name,
        stack_version=scan_run.stack.version or "",
        started_at=scan_run.started_at,
        finished_at=scan_run.finished_at,
        error_message=scan_run.error_message,
        summary=ScanSummaryResponse(
            total_pocs=summary["total_pocs"],
            completed_pocs=summary["completed_pocs"],
            vulnerabilities_found=summary["vulnerabilities_found"],
        ),
    )


@app.get(
    "/api/v1/scans/{scan_run_id}/results",
    response_model=ScanResultsEnvelope,
)
def get_scan_results(
    scan_run_id: int,
    db: Session = Depends(get_db),
) -> ScanResultsEnvelope:
    scan_run = require_scan_run(db, scan_run_id)

    return ScanResultsEnvelope(
        scan_run_id=scan_run.scan_run_id,
        status=scan_run.status,
        results=[
            ScanResultResponse(
                result_id=result.result_id,
                vuln_category=result.vuln_category,
                cve_id=result.cve_id,
                severity=result.severity,
                description=result.description,
                evidence=result.evidence,
                status=result.status,
                poc_name=result.poc_name,
                raw_output=result.raw_output,
            )
            for result in scan_run.results
        ],
    )


@app.get("/reports/{scan_run_id}", response_class=HTMLResponse)
def get_report(
    scan_run_id: int,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    scan_run = require_scan_run(db, scan_run_id)
    return HTMLResponse(render_report(scan_run))


def require_scan_run(db: Session, scan_run_id: int) -> ScanRun:
    # 공통 조회 함수를 써서 상태 API와 리포트가 같은 기준으로 데이터를 읽는다.
    scan_run = load_scan_run(db, scan_run_id)
    if scan_run is None:
        raise HTTPException(status_code=404, detail="Scan run not found.")
    return scan_run


def normalize_base_url(base_url: str) -> str:
    # 스킴/호스트가 없는 값은 초기에 차단한다.
    candidate = base_url.strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=422,
            detail="base_url must be a valid http or https URL.",
        )

    # 해시 조각과 끝 슬래시는 제거해서 같은 URL을 같은 값으로 저장한다.
    normalized = parsed._replace(fragment="")
    path = normalized.path.rstrip("/")
    normalized = normalized._replace(path=path)
    return urlunparse(normalized)
