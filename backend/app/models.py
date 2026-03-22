from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanTarget(Base):
    # 사용자가 등록한 검사 대상의 기준 URL을 저장한다.
    __tablename__ = "scan_targets"

    target_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    base_url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        index=True,
        unique=True,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Ready")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )
    tech_stacks: Mapped[list["TechStack"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )
    auth_setting: Mapped[Optional["AuthSetting"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
        uselist=False,
    )
    scan_runs: Mapped[list["ScanRun"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )
    scan_results: Mapped[list["ScanResult"]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
    )


class Endpoint(Base):
    # 엔드포인트 단위 확장을 고려해 남겨둔 테이블이다.
    __tablename__ = "endpoints"

    endpoint_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("scan_targets.target_id"),
        nullable=False,
    )
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_excluded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    target: Mapped["ScanTarget"] = relationship(back_populates="endpoints")
    scan_results: Mapped[list["ScanResult"]] = relationship(back_populates="endpoint")


class TechStack(Base):
    # 사용자가 입력한 서버/프레임워크 정보를 저장한다.
    __tablename__ = "tech_stacks"

    stack_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("scan_targets.target_id"),
        nullable=False,
    )
    stack_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    identify_method: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    target: Mapped["ScanTarget"] = relationship(back_populates="tech_stacks")
    scan_runs: Mapped[list["ScanRun"]] = relationship(back_populates="stack")


class AuthSetting(Base):
    # 현재 프로토타입 범위에서는 축소 사용하지만 스키마는 유지한다.
    __tablename__ = "auth_settings"

    auth_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("scan_targets.target_id"),
        nullable=False,
        unique=True,
    )
    login_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    auth_type: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    target: Mapped["ScanTarget"] = relationship(back_populates="auth_setting")


class ScanRun(Base):
    # 같은 대상에 대해 여러 번 실행되는 스캔 이력을 구분한다.
    __tablename__ = "scan_runs"

    scan_run_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("scan_targets.target_id"),
        nullable=False,
    )
    stack_id: Mapped[int] = mapped_column(
        ForeignKey("tech_stacks.stack_id"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    report_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["ScanTarget"] = relationship(back_populates="scan_runs")
    stack: Mapped["TechStack"] = relationship(back_populates="scan_runs")
    results: Mapped[list["ScanResult"]] = relationship(
        back_populates="scan_run",
        cascade="all, delete-orphan",
        order_by="ScanResult.result_id",
    )


class ScanResult(Base):
    # 개별 PoC 실행 결과와 증거를 저장한다.
    __tablename__ = "scan_results"

    result_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("scan_targets.target_id"),
        nullable=False,
    )
    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.scan_run_id"),
        nullable=False,
    )
    endpoint_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("endpoints.endpoint_id"),
        nullable=True,
    )
    vuln_category: Mapped[str] = mapped_column(String(255), nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="Found")
    poc_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    target: Mapped["ScanTarget"] = relationship(back_populates="scan_results")
    endpoint: Mapped[Optional["Endpoint"]] = relationship(back_populates="scan_results")
    scan_run: Mapped["ScanRun"] = relationship(back_populates="results")
