from pydantic import BaseModel, ConfigDict


class ScanRunResponse(BaseModel):
    message: str
    target_id: int
    status: str
    result_count: int


class ScanResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    result_id: int
    target_id: int
    vuln_category: str
    cve_id: str
    severity: str
    description: str
    evidence: str
    status: str
