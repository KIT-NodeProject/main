from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CreateScanRequest(BaseModel):
    # 스캔 생성 시 클라이언트가 보내는 최소 입력값이다.
    base_url: str
    stack_name: str
    stack_version: str


class ScanCreatedResponse(BaseModel):
    # 스캔 등록 직후 바로 돌려주는 응답이다.
    scan_run_id: int
    target_id: int
    status: str


class ScanSummaryResponse(BaseModel):
    # 상태 화면에서 바로 보여줄 집계 정보다.
    total_pocs: int
    completed_pocs: int
    vulnerabilities_found: int


class ScanStatusResponse(BaseModel):
    # 스캔 진행 상태와 요약을 함께 내려준다.
    scan_run_id: int
    status: str
    base_url: str
    stack_name: str
    stack_version: str
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    summary: ScanSummaryResponse


class ScanResultResponse(BaseModel):
    # 저장된 결과 한 건을 API 응답 형태로 노출한다.
    result_id: int
    vuln_category: str
    cve_id: Optional[str] = None
    severity: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    status: str
    poc_name: Optional[str] = None
    raw_output: Optional[str] = None


class ScanResultsEnvelope(BaseModel):
    # 결과 목록 응답의 최상위 포맷이다.
    scan_run_id: int
    status: str
    results: list[ScanResultResponse]
