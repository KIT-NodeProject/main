from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


STACK_DIR = Path(__file__).resolve().parents[2] / "pocs" / "stack"
ENDPOINT_DIR = Path(__file__).resolve().parents[2] / "pocs" / "endpoints"


@dataclass
class PoCDefinition:
    name: str
    stack_name: str
    entrypoint_path: Path
    description: str = ""

def load_pocs() -> list[PoCDefinition]:
    definitions: list[PoCDefinition] = []

    if not STACK_DIR.exists():
        return definitions

    for metadata_path in STACK_DIR.glob("*/metadata.yaml"):
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

@dataclass
class EndPointDefinition:
    name: str
    poc_name: str
    entrypoint_path: Path
    entrypoint_type: str
    method: str
    requires_query_params: bool
    requires_body_params: bool
    description: str = ""

def load_endpoint_pocs() -> list[EndPointDefinition]:
    definitions: list[EndPointDefinition] = []

    if not ENDPOINT_DIR.exists():
        return definitions

    for metadata_path in ENDPOINT_DIR.glob("*/metadata.yaml"):
        with open(metadata_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        category_description = data.get("description", "")
        pocs = data.get("pocs", [])

        for poc in pocs:
            definition = EndPointDefinition(
                name=poc["name"],
                poc_name=poc["name"],
                entrypoint_path=metadata_path.parent / poc["entrypoint"],
                entrypoint_type=poc.get("entrypoint_type", "public"),
                method=poc.get("method", "GET"),
                requires_query_params=poc.get("requires_query_params", False),
                requires_body_params=poc.get("requires_body_params", False),
                description=poc.get("description", category_description),
            )
            definitions.append(definition)

    return definitions

def normalize_method(value: Any) -> str:
    if isinstance(value, list):
        value = value[0] if value else "GET"
    return str(value or "GET").upper()

def match_endpoint_pocs(endpoint: dict[str, Any]) -> list[EndPointDefinition]:
    definitions = load_endpoint_pocs()

    method = normalize_method(endpoint.get("method"))
    endpoint_type = endpoint.get("endpoint_type", "public")
    has_query = bool(endpoint.get("query_params"))
    has_body = bool(endpoint.get("body_params"))

    matched: list[EndPointDefinition] = []

    for definition in definitions:
        if normalize_method(definition.method) != method:
            continue
        if definition.entrypoint_type != endpoint_type:
            continue
        if definition.requires_query_params and not has_query:
            continue
        if definition.requires_body_params and not has_body:
            continue
        matched.append(definition)

    return matched