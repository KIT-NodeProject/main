from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.cve_catalog import CVECatalog


def get_cves_by_product_name(db: Session, product_name: str) -> list[CVECatalog]:
    statement = select(CVECatalog).where(
        func.lower(CVECatalog.product_name) == product_name.lower()
    )
    return db.execute(statement).scalars().all()
