from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings


connect_args = {}
if settings.database_url.startswith("sqlite"):
    # SQLite는 같은 연결을 여러 스레드에서 다루지 않도록 옵션을 맞춘다.
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    future=True,
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)
Base = declarative_base()


def get_db() -> Generator:
    # 요청마다 세션을 열고, 끝나면 반드시 닫는다.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # 모델을 먼저 로드해야 메타데이터에 테이블 정의가 등록된다.
    from . import models as _models

    _ = _models

    Base.metadata.create_all(bind=engine)
