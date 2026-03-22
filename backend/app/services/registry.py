from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PoCDefinition:
    # metadata.yaml 한 개를 메모리에서 다루기 위한 형태다.
    name: str
    category: str
    stack_name: str
    version_rules: tuple[str, ...]
    severity: str
    entrypoint: str
    directory: Path
    timeout_seconds: int = 15
    description: str = ""

    @property
    def entrypoint_path(self) -> Path:
        return self.directory / self.entrypoint


class PoCRegistry:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)

    def load_all(self) -> list[PoCDefinition]:
        # pocs 아래의 하위 폴더 하나를 PoC 한 개로 본다.
        if not self.base_dir.exists():
            return []

        definitions: list[PoCDefinition] = []
        for metadata_path in sorted(self.base_dir.glob("*/metadata.yaml")):
            definition = self._load_definition(metadata_path)
            if definition:
                definitions.append(definition)
        return definitions

    def find_matching(self, stack_name: str, stack_version: str) -> list[PoCDefinition]:
        # 스택 이름과 버전 규칙이 둘 다 맞는 PoC만 실행 대상으로 고른다.
        normalized_stack_name = stack_name.strip().casefold()
        return [
            definition
            for definition in self.load_all()
            if definition.stack_name.strip().casefold() == normalized_stack_name
            and self._matches_version(definition.version_rules, stack_version)
        ]

    def _load_definition(self, metadata_path: Path) -> Optional[PoCDefinition]:
        try:
            with metadata_path.open("r", encoding="utf-8") as file:
                raw_data = yaml.safe_load(file) or {}
        except OSError:
            logger.exception("Unable to read PoC metadata: %s", metadata_path)
            return None

        try:
            version_rules = tuple(raw_data.get("version_rules") or [])
            return PoCDefinition(
                name=raw_data["name"],
                category=raw_data.get("category", "Info"),
                stack_name=raw_data["stack_name"],
                version_rules=version_rules,
                severity=raw_data.get("severity", "Info"),
                entrypoint=raw_data.get("entrypoint", "runner.py"),
                directory=metadata_path.parent,
                timeout_seconds=int(raw_data.get("timeout_seconds", 15)),
                description=raw_data.get("description", ""),
            )
        except (KeyError, TypeError, ValueError):
            logger.exception("Invalid PoC metadata format: %s", metadata_path)
            return None

    @staticmethod
    def _matches_version(version_rules: tuple[str, ...], stack_version: str) -> bool:
        if not version_rules:
            return True

        try:
            # 문자열 비교 대신 버전 객체로 변환해야 범위 비교가 안전하다.
            candidate_version = Version(stack_version)
        except InvalidVersion:
            return False

        for rule in version_rules:
            try:
                specifier_set = SpecifierSet(rule)
            except InvalidSpecifier:
                logger.warning("Skipping invalid version rule: %s", rule)
                continue

            if specifier_set.contains(candidate_version, prereleases=True):
                return True

        return False
