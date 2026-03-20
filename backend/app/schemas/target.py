from datetime import datetime

from pydantic import BaseModel, ConfigDict, HttpUrl


class TechStackCreate(BaseModel):
    stack_name: str
    version: str


class TargetCreate(BaseModel):
    base_url: HttpUrl
    tech_stack: TechStackCreate


class TechStackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    stack_id: int
    target_id: int
    stack_name: str
    version: str
    identify_method: str


class TargetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    target_id: int
    base_url: HttpUrl
    status: str
    created_at: datetime
    tech_stack: TechStackResponse
