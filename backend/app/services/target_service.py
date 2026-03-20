from sqlalchemy.orm import Session

from app.core.constants import IDENTIFY_METHOD_MANUAL_INPUT
from app.repositories.target_repository import create_target, create_tech_stack
from app.schemas.target import TargetCreate


def create_target_with_stack(db: Session, target_data: TargetCreate):
    try:
        target = create_target(db=db, base_url=str(target_data.base_url))
        tech_stack = create_tech_stack(
            db=db,
            target_id=target.target_id,
            stack_name=target_data.tech_stack.stack_name,
            version=target_data.tech_stack.version,
            identify_method=IDENTIFY_METHOD_MANUAL_INPUT,
        )
        db.commit()
        target.tech_stack = tech_stack
        return target
    except Exception:
        db.rollback()
        raise
