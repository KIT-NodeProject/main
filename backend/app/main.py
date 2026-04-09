from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import StackScanRun, EndpointScanRun
from .schemas import (
    EndpointsScanCreateRequest,
    EndpointsScanCreateResponse,
    EndpointsScanReadResponse,
)

from .schemas import (
    StackScanCreateRequest,
    StackScanCreateResponse,
    StackScanReadResponse,
)

from .services.scan_service import (
    create_and_run_stack_scan, 
    create_and_run_endpoints_scan, 
    get_stack_scan_by_id, 
    get_endpoints_scan_by_id
)

app = FastAPI(title="PoC Scanner")

def serialize_endpoint(endpoint):
    return {
        "id": endpoint.id,
        "path": endpoint.path,
        "method": endpoint.method,
        "endpoint_type": endpoint.endpoint_type,
    }


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {"message": "PoC Scanner", "docs": "/docs"}

@app.post("/api/v1/stack/scans", response_model=StackScanCreateResponse)
def create_scan(payload: StackScanCreateRequest, db: Session = Depends(get_db)):
    scan_run = create_and_run_stack_scan(
        db=db,
        base_url=str(payload.base_url),
        stack_name=payload.stack_name,
    )

    results = [
        {
            "poc_name": r.poc_name,
            "status": r.status,
            "description": r.description,
            "evidence": r.evidence,
            "raw_output": r.raw_output,
            "vulnerable": r.vulnerable,
        }
        for r in scan_run.results
    ]

    return StackScanCreateResponse(
        scan_id=scan_run.id,
        status=scan_run.status,
        base_url=scan_run.base_url,
        stack_name=scan_run.stack_name,
        results=results,
    )


@app.get("/api/v1/stack/scans/{scan_id}", response_model=StackScanReadResponse)
def read_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_run = get_stack_scan_by_id(db, scan_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan not found")

    results = [
        {
            "poc_name": r.poc_name,
            "status": r.status,
            "description": r.description,
            "evidence": r.evidence,
            "raw_output": r.raw_output,
            "vulnerable": r.vulnerable,
        }
        for r in scan_run.results
    ]

    return StackScanReadResponse(
        scan_id=scan_run.id,
        status=scan_run.status,
        base_url=scan_run.base_url,
        stack_name=scan_run.stack_name,
        results=results,
    )


@app.get("/api/v1/stack/scans/{scan_id}/report")
def read_scan_report(scan_id: str, db: Session = Depends(get_db)):
    scan_run = get_stack_scan_by_id(db, scan_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_run.id,
        "base_url": scan_run.base_url,
        "stack_name": scan_run.stack_name,
        "status": scan_run.status,
        "results": [
            {
                "poc_name": r.poc_name,
                "status": r.status,
                "description": r.description,
                "evidence": r.evidence,
                "raw_output": r.raw_output,
                "vulnerable": r.vulnerable,
            }
            for r in scan_run.results
        ],
    }

@app.post("/api/v1/endpoints/scans", response_model=EndpointsScanCreateResponse)
def create_scan(payload: EndpointsScanCreateRequest, db: Session = Depends(get_db)):
    scan_run = create_and_run_endpoints_scan(
        db=db,
        base_url=str(payload.base_url),
        endpoints=[endpoint.model_dump() for endpoint in payload.endpoints],
    )

    results = [
        {
            "endpoint_id": r.endpoint_id,
            "poc_name": r.poc_name,
            "status": r.status,
            "description": r.description,
            "evidence": r.evidence,
            "raw_output": r.raw_output,
            "debug_log": None,
            "vulnerable": r.vulnerable,
        }
        for r in scan_run.results
    ]
    endpoints = [serialize_endpoint(endpoint) for endpoint in scan_run.endpoints]

    return EndpointsScanCreateResponse(
        scan_id=scan_run.id,
        status=scan_run.status,
        base_url=scan_run.base_url,
        endpoints=endpoints,
        results=results,
    )


@app.get("/api/v1/endpoints/scans/{scan_id}", response_model=EndpointsScanReadResponse)
def read_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_run = get_endpoints_scan_by_id(db, scan_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan not found")

    results = [
        {
            "endpoint_id": r.endpoint_id,
            "poc_name": r.poc_name,
            "status": r.status,
            "description": r.description,
            "evidence": r.evidence,
            "raw_output": r.raw_output,
            "debug_log": None,
            "vulnerable": r.vulnerable,
        }
        for r in scan_run.results
    ]
    endpoints = [serialize_endpoint(endpoint) for endpoint in scan_run.endpoints]

    return EndpointsScanReadResponse(
        scan_id=scan_run.id,
        status=scan_run.status,
        base_url=scan_run.base_url,
        endpoints=endpoints,
        results=results,
    )


@app.get("/api/v1/endpoints/scans/{scan_id}/report")
def read_scan_report(scan_id: str, db: Session = Depends(get_db)):
    scan_run = get_endpoints_scan_by_id(db, scan_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_run.id,
        "base_url": scan_run.base_url,
        "status": scan_run.status,
        "endpoints": [serialize_endpoint(endpoint) for endpoint in scan_run.endpoints],
        "results": [
            {
                "endpoint_id": r.endpoint_id,
                "poc_name": r.poc_name,
                "status": r.status,
                "description": r.description,
                "evidence": r.evidence,
                "raw_output": r.raw_output,
                "debug_log": None,
                "vulnerable": r.vulnerable,
            }
            for r in scan_run.results
        ],
    }