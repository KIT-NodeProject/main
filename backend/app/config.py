from __future__ import annotations

import os
from pathlib import Path


class Settings:
    def __init__(self) -> None:
        # 기본 경로는 backend 디렉터리를 기준으로 계산한다.
        root_dir = Path(__file__).resolve().parents[1]
        default_database_path = root_dir / "scanner.db"

        # 환경변수가 없으면 프로토타입 기본값을 사용한다.
        self.app_name = os.getenv("SCANNER_APP_NAME", "Security Scanner Prototype")
        self.database_url = os.getenv(
            "SCANNER_DATABASE_URL",
            f"sqlite:///{default_database_path}",
        )
        self.pocs_dir = Path(os.getenv("SCANNER_POCS_DIR", root_dir / "pocs"))
        self.templates_dir = Path(
            os.getenv("SCANNER_TEMPLATES_DIR", root_dir / "templates")
        )
        self.default_poc_timeout_seconds = int(
            os.getenv("SCANNER_DEFAULT_POC_TIMEOUT_SECONDS", "15")
        )
        self.max_raw_output_chars = int(
            os.getenv("SCANNER_MAX_RAW_OUTPUT_CHARS", "4000")
        )


settings = Settings()
