from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class CVECatalog(Base):
    __tablename__ = "cve_catalog"

    cve_id: Mapped[str] = mapped_column(String(50), primary_key=True)
    product_name: Mapped[str] = mapped_column(String(100))
    vendor_name: Mapped[str] = mapped_column(String(100))
    affected_version_start: Mapped[str] = mapped_column(String(50))
    affected_version_end: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    summary: Mapped[str] = mapped_column(Text)
    reference_url: Mapped[str] = mapped_column(String(255))
