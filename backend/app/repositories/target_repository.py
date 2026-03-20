from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import TARGET_STATUS_PENDING
from app.models.scan_targets import ScanTarget
from app.models.tech_stack import TechStack


def create_target(
    db: Session,
    base_url: str,
    status: str = TARGET_STATUS_PENDING,
) -> ScanTarget:
    target = ScanTarget(base_url=base_url, status=status)
    db.add(target)
    db.flush()
    db.refresh(target)
    return target


def create_tech_stack(
    db: Session,
    target_id: int,
    stack_name: str,
    version: str,
    identify_method: str,
) -> TechStack:
    tech_stack = TechStack(
        target_id=target_id,
        stack_name=stack_name,
        version=version,
        identify_method=identify_method,
    )
    db.add(tech_stack)
    db.flush()
    db.refresh(tech_stack)
    return tech_stack


def update_target_status(
    db: Session,
    target: ScanTarget,
    status: str,
) -> ScanTarget:
    target.status = status
    db.flush()
    db.refresh(target)
    return target


def get_target_by_id(db: Session, target_id: int) -> ScanTarget | None:
    statement = select(ScanTarget).where(ScanTarget.target_id == target_id)
    return db.execute(statement).scalar_one_or_none()


def get_tech_stack_by_target_id(db: Session, target_id: int) -> TechStack | None:
    statement = select(TechStack).where(TechStack.target_id == target_id)
    return db.execute(statement).scalar_one_or_none()
