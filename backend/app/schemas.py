from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

EndpointType = Literal["public", "login_required", "login_page"]
SupportedMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


class ScanEndpointCreate(BaseModel):
    path: str
    method: SupportedMethod | None = None
    endpoint_type: EndpointType = "public"

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Endpoint path must not be empty.")
        return normalized


class ScanEndpointItem(BaseModel):
    id: int
    path: str
    method: SupportedMethod | None = None
    endpoint_type: EndpointType


class ScanCreateRequest(BaseModel):
    base_url: HttpUrl
    stack_name: str
    endpoints: list[ScanEndpointCreate] = Field(min_length=1)

    @field_validator("stack_name")
    @classmethod
    def validate_stack_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Stack name must not be empty.")
        return normalized

    # 프론트가 아직 문자열 배열 형태의 endpoints를 보내므로 엔드포인트 객체 형태로 보정
    @field_validator("endpoints", mode="before")
    @classmethod
    def coerce_endpoints(cls, value):
        if not isinstance(value, list):
            raise TypeError("endpoints must be a list")

        normalized = []
        for item in value:
            if isinstance(item, str):
                normalized.append({"path": item})
            else:
                normalized.append(item)
        return normalized

    @model_validator(mode="after")
    def normalize_endpoints(self):
        base_parts = urlsplit(str(self.base_url))
        normalized_items: list[ScanEndpointCreate] = []

        for endpoint in self.endpoints:
            path = endpoint.path

            if path.startswith("/"):
                normalized_path = path
            else:
                endpoint_parts = urlsplit(path)
                if not endpoint_parts.scheme or not endpoint_parts.netloc:
                    raise ValueError(
                        "Endpoint path must start with / or be a same-origin absolute URL."
                    )

                if (
                    endpoint_parts.scheme != base_parts.scheme
                    or endpoint_parts.netloc != base_parts.netloc
                ):
                    raise ValueError(
                        "Endpoint absolute URL must use the same origin as base_url."
                    )

                normalized_path = endpoint_parts.path or "/"
                if endpoint_parts.query:
                    normalized_path = f"{normalized_path}?{endpoint_parts.query}"
                if endpoint_parts.fragment:
                    normalized_path = f"{normalized_path}#{endpoint_parts.fragment}"

            endpoint.path = normalized_path
            normalized_items.append(endpoint)

        self.endpoints = normalized_items
        return self


class ScanResultItem(BaseModel):
    poc_name: str
    status: str
    description: str
    evidence: str
    raw_output: str
    vulnerable: bool
    debug_log: str | None = None


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    base_url: str
    stack_name: str
    endpoints: list[ScanEndpointItem]
    results: list[ScanResultItem]


class ScanReadResponse(BaseModel):
    scan_id: str
    status: str
    base_url: str
    stack_name: str
    endpoints: list[ScanEndpointItem]
    results: list[ScanResultItem]
