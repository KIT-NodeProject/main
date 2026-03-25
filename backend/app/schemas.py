from typing import Any

from pydantic import BaseModel, HttpUrl


class ScanCreateRequest(BaseModel):
    base_url: HttpUrl
    stack_name: str


class ScanResultItem(BaseModel):
    poc_name: str
    status: str
    description: str
    evidence: str
    raw_output: str
    vulnerable: bool
    debug_log: str | None = None


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    base_url: str
    stack_name: str
    results: list[dict[str, Any]]


class ScanReadResponse(BaseModel):
    scan_id: str
    status: str
    base_url: str
    stack_name: str
    results: list[dict[str, Any]]