from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan_results import ScanResult


def create_scan_results(
    db: Session,
    target_id: int,
    results_data: list[dict],
) -> list[ScanResult]:
    scan_results = []

    for item in results_data:
        scan_result = ScanResult(
            target_id=target_id,
            vuln_category=item["vuln_category"],
            cve_id=item["cve_id"],
            severity=item["severity"],
            description=item["description"],
            evidence=item["evidence"],
            status=item["status"],
        )
        db.add(scan_result)
        scan_results.append(scan_result)

    db.flush()

    for scan_result in scan_results:
        db.refresh(scan_result)

    return scan_results


def delete_scan_results_by_target_id(db: Session, target_id: int) -> None:
    statement = select(ScanResult).where(ScanResult.target_id == target_id)
    scan_results = db.execute(statement).scalars().all()

    for scan_result in scan_results:
        db.delete(scan_result)

    db.flush()


def get_scan_results_by_target_id(db: Session, target_id: int) -> list[ScanResult]:
    statement = (
        select(ScanResult)
        .where(ScanResult.target_id == target_id)
        .order_by(ScanResult.result_id)
    )
    return db.execute(statement).scalars().all()
