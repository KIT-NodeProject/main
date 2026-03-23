from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


POCS_DIR = Path(__file__).resolve().parents[2] / "pocs"


@dataclass
class PoCDefinition:
    name: str
    stack_name: str
    entrypoint_path: Path
    description: str = ""


def load_pocs() -> list[PoCDefinition]:
    definitions: list[PoCDefinition] = []

    if not POCS_DIR.exists():
        return definitions

    for metadata_path in POCS_DIR.glob("*/metadata.yaml"):
        with open(metadata_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        definition = PoCDefinition(
            name=data["name"],
            stack_name=data["stack_name"],
            entrypoint_path=metadata_path.parent / data["entrypoint"],
            description=data.get("description", ""),
        )
        definitions.append(definition)

    return definitions


def match_pocs(stack_name: str) -> list[PoCDefinition]:
    matched: list[PoCDefinition] = []

    for definition in load_pocs():
        if definition.stack_name.strip().lower() == stack_name.strip().lower():
            matched.append(definition)

    return matched