from sqlalchemy.orm import Session

from app.repositories.result_repository import get_scan_results_by_target_id


def get_results_for_target(db: Session, target_id: int):
    return get_scan_results_by_target_id(db=db, target_id=target_id)
