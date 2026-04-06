from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

EndpointType = Literal["public", "login_required", "login_page"]
SupportedMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


class ScanEndpointCreate(BaseModel):  # 프론트엔드가 보내는 엔드포인트 1개 입력값
    path: str  
    method: SupportedMethod | None = None  
    endpoint_type: EndpointType = "public"  
    query_params: dict[str, str | bool | int] | None = None  
    body_params: dict[str, str | bool | int] | None = None  

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        normalized = value.strip()  # 앞뒤 공백 제거
        if not normalized:
            raise ValueError("Endpoint path must not be empty.")  # 비어 있으면 에러
        return normalized


class ScanEndpointItem(BaseModel):  # 엔드포인트 스캔 응답/조회 시 보여주는 엔드포인트 정보
    id: int  # DB에 저장된 엔드포인트 ID
    path: str  
    method: SupportedMethod | None = None  
    endpoint_type: EndpointType  


class StackScanResultItem(BaseModel):  # 기술 스택 스캔 결과 1개
    poc_name: str  # 실행한 POC 이름
    status: str  # 실행 상태
    description: str  # 결과 설명
    evidence: str  # 탐지 근거
    raw_output: str  # 원본 출력값
    vulnerable: bool  # 취약 여부
    debug_log: str | None = None  # 디버그 로그


class EndpointScanResultItem(BaseModel):  
    endpoint_id: int  
    poc_name: str 
    status: str  
    description: str 
    evidence: str  
    raw_output: str 
    vulnerable: bool 
    debug_log: str | None = None  

 
class EndpointsScanCreateRequest(BaseModel):  # 프론트엔드가 엔드포인트 스캔 생성 요청 시 보내는 전체 body
    base_url: HttpUrl  
    endpoints: list[ScanEndpointCreate] = Field(min_length=1) 
    
    @field_validator("endpoints", mode="before")
    @classmethod
    def coerce_endpoints(cls, value):
        # endpoints는 반드시 리스트여야 함
        if not isinstance(value, list):
            raise TypeError("endpoints must be a list")

        normalized = []
        for item in value:
            # 문자열로 들어오면 {"path": "..."} 형태로 변환
            if isinstance(item, str):
                normalized.append({"path": item})
            else:
                normalized.append(item)
        return normalized

    @model_validator(mode="after")
    def normalize_endpoints(self):
        # base_url을 기준으로 endpoint path를 정규화
        base_parts = urlsplit(str(self.base_url))
        normalized_items: list[ScanEndpointCreate] = []

        for endpoint in self.endpoints:
            path = endpoint.path

            # 상대 경로면 그대로 사용
            if path.startswith("/"):
                normalized_path = path
            else:
                # 절대 URL이면 파싱
                endpoint_parts = urlsplit(path)
                if not endpoint_parts.scheme or not endpoint_parts.netloc:
                    raise ValueError(
                        "Endpoint path must start with / or be a same-origin absolute URL."
                    )

                # base_url과 같은 origin인지 확인
                if (
                    endpoint_parts.scheme != base_parts.scheme
                    or endpoint_parts.netloc != base_parts.netloc
                ):
                    raise ValueError(
                        "Endpoint absolute URL must use the same origin as base_url."
                    )

                # 절대 URL을 path 기준으로 변환
                normalized_path = endpoint_parts.path or "/"
                if endpoint_parts.query:
                    normalized_path = f"{normalized_path}?{endpoint_parts.query}"
                if endpoint_parts.fragment:
                    normalized_path = f"{normalized_path}#{endpoint_parts.fragment}"

            endpoint.path = normalized_path
            normalized_items.append(endpoint)

        self.endpoints = normalized_items
        return self


class EndpointsScanCreateResponse(BaseModel):  # 엔드포인트 스캔 생성 후 반환 응답
    scan_id: str  
    status: str 
    base_url: str  
    endpoints: list[ScanEndpointItem]  
    results: list[EndpointScanResultItem]  


class EndpointsScanReadResponse(BaseModel):  # 엔드포인트 스캔 조회 시 반환 응답
    scan_id: str  
    status: str  
    base_url: str  
    endpoints: list[ScanEndpointItem]  
    results: list[EndpointScanResultItem] 


class StackScanCreateRequest(BaseModel):  # 프론트엔드가 기술 스택 스캔 생성 요청 시 보내는 body
    base_url: HttpUrl  
    stack_name: str 

    @field_validator("stack_name")
    @classmethod
    def validate_stack_name(cls, value: str) -> str:
        normalized = value.strip()  # 앞뒤 공백 제거
        if not normalized:
            raise ValueError("Stack name must not be empty.")  # 비어 있으면 에러
        return normalized


class StackScanCreateResponse(BaseModel):  # 기술 스택 스캔 생성 후 반환 응답
    scan_id: str 
    status: str  
    base_url: str  
    stack_name: str  
    results: list[StackScanResultItem] 


class StackScanReadResponse(BaseModel):  # 기술 스택 스캔 조회 시 반환 응답
    scan_id: str  
    status: str  
    base_url: str  
    stack_name: str  
    results: list[StackScanResultItem]  