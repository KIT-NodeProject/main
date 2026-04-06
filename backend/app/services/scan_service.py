import uuid
from typing import Any

from sqlalchemy.orm import Session

from ..models import EndpointScanRun, EndpointScanResult, StackScanResult, StackScanRun, EndpointScanTarget
from .registry import match_pocs, match_endpoint_pocs
from .runner import run_poc


def create_and_run_stack_scan(
    db: Session,
    base_url: str,
    stack_name: str,
) -> StackScanRun:
    scan_id = str(uuid.uuid4())

    scan_run = StackScanRun(
        id=scan_id,
        base_url=base_url,
        stack_name=stack_name,
        status="Running",
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    matched_pocs = match_pocs(stack_name)

    if not matched_pocs:
        scan_run.status = "NoPoC"
        db.commit()
        db.refresh(scan_run)
        return scan_run

    execution_input = {
        "base_url": base_url,
        "stack_name": stack_name,
    }

    for poc in matched_pocs:
        result = run_poc(poc, execution_input)

        row = StackScanResult(
            scan_run_id=scan_run.id,
            poc_name=result.get("poc_name", poc.name),
            status=result.get("status", "Unknown"),
            description=result.get("description", ""),
            evidence=result.get("evidence", ""),
            raw_output=result.get("raw_output", ""),
            vulnerable=bool(result.get("vulnerable", False)),
        )
        db.add(row)

    scan_run.status = "Completed"
    db.commit()
    db.refresh(scan_run)
    return scan_run


def create_and_run_endpoints_scan(db, base_url: str, endpoints: list[dict]):
    scan_id = str(uuid.uuid4())

    scan_run = EndpointScanRun(
        id=scan_id,
        base_url=base_url,
        status="Running",
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    for endpoint in endpoints:
        endpoint_row = EndpointScanTarget(
            scan_run_id=scan_run.id,
            path=endpoint["path"],
            method=endpoint.get("method"),
            endpoint_type=endpoint.get("endpoint_type", "public"),
            query_params=endpoint.get("query_params"),
            body_params=endpoint.get("body_params"),
        )
        db.add(endpoint_row)
        db.commit()
        db.refresh(endpoint_row)

        matched_pocs = match_endpoint_pocs(endpoint)

        if not matched_pocs:
            db.add(
                EndpointScanResult(
                    scan_run_id=scan_run.id,
                    endpoint_id=endpoint_row.id,
                    poc_name="no_matched_poc",
                    status="NoPoC",
                    description="No endpoint PoC matched current input",
                    evidence="",
                    raw_output="",
                    vulnerable=False,
                )
            )
            continue

        execution_input = {
            "base_url": base_url,
            "path": endpoint["path"],
            "method": (endpoint.get("method") or "GET").upper(),
            "query_params": endpoint.get("query_params", {}),
            "body_params": endpoint.get("body_params", {}),
            "endpoint_type": endpoint.get("endpoint_type", "public"),
        }

        for poc in matched_pocs:
            result = run_poc(poc, execution_input)

            db.add(
                EndpointScanResult(
                    scan_run_id=scan_run.id,
                    endpoint_id=endpoint_row.id,
                    poc_name=result.get("poc_name", poc.poc_name),
                    status=result.get("status", "Completed"),
                    description=result.get("description", ""),
                    evidence=result.get("evidence", ""),
                    raw_output=result.get("raw_output", ""),
                    vulnerable=result.get("vulnerable", False),
                )
            )

    scan_run.status = "Completed"
    db.commit()
    db.refresh(scan_run)
    return scan_run

def get_stack_scan_by_id(db: Session, scan_id: str) -> StackScanRun | None:
    return db.query(StackScanRun).filter(StackScanRun.id == scan_id).first()


def get_endpoints_scan_by_id(db: Session, scan_id: str) -> StackScanRun | None:
    return db.query(StackScanRun).filter(StackScanRun.id == scan_id).first()