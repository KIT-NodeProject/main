from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class TechStack(Base):
    __tablename__ = "tech_stacks"

    stack_id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("scan_targets.target_id"))
    stack_name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(50))
    identify_method: Mapped[str] = mapped_column(String(50))
