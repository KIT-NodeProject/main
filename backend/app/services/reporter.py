from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import settings
from ..models import ScanRun
from .orchestrator import FAILURE_STATUSES, build_summary


def format_datetime(value: Optional[datetime]) -> str:
    # 템플릿에서 그대로 쓰기 좋게 날짜 문자열 형식을 통일한다.
    if value is None:
        return "-"

    if value.tzinfo is None:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


environment = Environment(
    loader=FileSystemLoader(str(settings.templates_dir)),
    autoescape=select_autoescape(["html", "xml"]),
)
environment.filters["datetime"] = format_datetime


def render_report(scan_run: ScanRun) -> str:
    # 리포트에 필요한 파생 데이터는 렌더링 직전에 계산한다.
    summary = build_summary(scan_run)
    vulnerabilities = [result for result in scan_run.results if result.status == "Found"]
    failures = [result for result in scan_run.results if result.status in FAILURE_STATUSES]
    template = environment.get_template("report.html")

    return template.render(
        generated_at=format_datetime(datetime.now(timezone.utc)),
        scan_run=scan_run,
        target=scan_run.target,
        stack=scan_run.stack,
        summary=summary,
        vulnerabilities=vulnerabilities,
        failures=failures,
    )
