from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class StackScanRun(Base):
    __tablename__ = "stack_scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    stack_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="Pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    results: Mapped[list["StackScanResult"]] = relationship(
        "StackScanResult",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )


class StackScanResult(Base):
    __tablename__ = "stack_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("stack_scan_runs.id"),
        nullable=False,
        index=True,
    )

    poc_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw_output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan_run: Mapped["StackScanRun"] = relationship(
        "StackScanRun",
        back_populates="results",
    )


class EndpointScanRun(Base):
    __tablename__ = "endpoint_scan_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="Pending")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    auth_context_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("auth_contexts.id"),
        nullable=True,
    )

    endpoints: Mapped[list["EndpointScanTarget"]] = relationship(
        "EndpointScanTarget",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    results: Mapped[list["EndpointScanResult"]] = relationship(
        "EndpointScanResult",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    auth_context: Mapped["AuthContext | None"] = relationship(
        "AuthContext",
        back_populates="scan_runs",
    )

    


class EndpointScanTarget(Base):
    __tablename__ = "endpoint_scan_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("endpoint_scan_runs.id"),
        nullable=False,
        index=True,
    )

    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    endpoint_type: Mapped[str] = mapped_column(String(50), nullable=False, default="public")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    query_params: Mapped[dict[str, str | bool | int] | None] = mapped_column(JSON, nullable=True)
    body_params: Mapped[dict[str, str | bool | int] | None] = mapped_column(JSON, nullable=True)

    scan_run: Mapped["EndpointScanRun"] = relationship(
        "EndpointScanRun",
        back_populates="endpoints",
    )

    results: Mapped[list["EndpointScanResult"]] = relationship(
        "EndpointScanResult",
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )


class EndpointScanResult(Base):
    __tablename__ = "endpoint_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("endpoint_scan_runs.id"),
        nullable=False,
        index=True,
    )
    endpoint_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("endpoint_scan_targets.id"),
        nullable=False,
        index=True,
    )

    poc_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw_output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    vulnerable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan_run: Mapped["EndpointScanRun"] = relationship(
        "EndpointScanRun",
        back_populates="results",
    )

    endpoint: Mapped["EndpointScanTarget"] = relationship(
        "EndpointScanTarget",
        back_populates="results",
    )


class AuthContext(Base):
    __tablename__ = "auth_contexts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(String(100), nullable=False, default="default")

    auth_type: Mapped[str] = mapped_column(String(50), nullable=False, default="cookie")
    # cookie, bearer, custom_header 등

    headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cookies: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan_runs: Mapped[list["EndpointScanRun"]] = relationship(
        "EndpointScanRun",
        back_populates="auth_context",
    )
