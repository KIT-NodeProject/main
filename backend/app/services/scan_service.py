import uuid
from typing import Any

from sqlalchemy.orm import Session

from ..models import ScanEndpoint, ScanResult, ScanRun
from .registry import match_pocs
from .runner import run_poc


def create_and_run_scan(
    db: Session,
    base_url: str,
    stack_name: str,
    endpoints: list[dict[str, Any]],
) -> ScanRun:
    scan_id = str(uuid.uuid4())

    scan_run = ScanRun(
        id=scan_id,
        base_url=base_url,
        stack_name=stack_name,
        status="Running",
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    execution_endpoints: list[dict[str, Any]] = []
    for endpoint in endpoints:
        execution_endpoints.append(
            {
                "path": endpoint["path"],
                "method": endpoint.get("method"),
                "endpoint_type": endpoint.get("endpoint_type", "public"),
            }
        )

        db.add(
            ScanEndpoint(
                scan_run_id=scan_run.id,
                path=endpoint["path"],
                method=endpoint.get("method"),
                endpoint_type=endpoint.get("endpoint_type", "public"),
            )
        )

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
        "endpoints": execution_endpoints,
    }

    for poc in matched_pocs:
        result = run_poc(poc, execution_input)

        row = ScanResult(
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


def get_scan_by_id(db: Session, scan_id: str) -> ScanRun | None:
    return db.query(ScanRun).filter(ScanRun.id == scan_id).first()
