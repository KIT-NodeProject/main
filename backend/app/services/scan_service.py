from sqlalchemy.orm import Session

from app.core.constants import (
    TARGET_STATUS_COMPLETED,
    TARGET_STATUS_FAILED,
    TARGET_STATUS_SCANNING,
)
from app.repositories.cve_repository import get_cves_by_product_name
from app.repositories.result_repository import (
    create_scan_results,
    delete_scan_results_by_target_id,
)
from app.repositories.target_repository import (
    get_target_by_id,
    get_tech_stack_by_target_id,
    update_target_status,
)
from app.scanner.engine import build_scan_results


class TargetNotFoundError(Exception):
    pass


class TechStackNotFoundError(Exception):
    pass


def run_scan_for_target(db: Session, target_id: int):
    target = get_target_by_id(db=db, target_id=target_id)
    if target is None:
        raise TargetNotFoundError("Target not found")

    tech_stack = get_tech_stack_by_target_id(db=db, target_id=target_id)
    if tech_stack is None:
        raise TechStackNotFoundError("Tech stack not found")

    try:
        update_target_status(
            db=db,
            target=target,
            status=TARGET_STATUS_SCANNING,
        )
        db.commit()

        cve_rows = get_cves_by_product_name(db=db, product_name=tech_stack.stack_name)
        cve_items = [
            {
                "cve_id": row.cve_id,
                "product_name": row.product_name,
                "vendor_name": row.vendor_name,
                "affected_version_start": row.affected_version_start,
                "affected_version_end": row.affected_version_end,
                "severity": row.severity,
                "summary": row.summary,
                "reference_url": row.reference_url,
            }
            for row in cve_rows
        ]

        results_data = build_scan_results(
            stack_name=tech_stack.stack_name,
            version=tech_stack.version,
            cve_items=cve_items,
        )

        delete_scan_results_by_target_id(db=db, target_id=target_id)

        scan_results = create_scan_results(
            db=db,
            target_id=target_id,
            results_data=results_data,
        )

        update_target_status(
            db=db,
            target=target,
            status=TARGET_STATUS_COMPLETED,
        )
        db.commit()
        return scan_results
    except Exception:
        db.rollback()
        try:
            update_target_status(
                db=db,
                target=target,
                status=TARGET_STATUS_FAILED,
            )
            db.commit()
        except Exception:
            db.rollback()
        raise
