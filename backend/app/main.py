from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import ScanRun
from .schemas import ScanCreateRequest, ScanCreateResponse, ScanReadResponse
from .services.scan_service import create_and_run_scan, get_scan_by_id

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


@app.post("/api/v1/scans", response_model=ScanCreateResponse)
def create_scan(payload: ScanCreateRequest, db: Session = Depends(get_db)):
    scan_run = create_and_run_scan(
        db=db,
        base_url=str(payload.base_url),
        stack_name=payload.stack_name,
        endpoints=[endpoint.model_dump() for endpoint in payload.endpoints],
    )

    results = [
        {
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

    return ScanCreateResponse(
        scan_id=scan_run.id,
        status=scan_run.status,
        base_url=scan_run.base_url,
        stack_name=scan_run.stack_name,
        endpoints=endpoints,
        results=results,
    )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanReadResponse)
def read_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_run = get_scan_by_id(db, scan_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan not found")

    results = [
        {
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

    return ScanReadResponse(
        scan_id=scan_run.id,
        status=scan_run.status,
        base_url=scan_run.base_url,
        stack_name=scan_run.stack_name,
        endpoints=endpoints,
        results=results,
    )


@app.get("/api/v1/scans/{scan_id}/report")
def read_scan_report(scan_id: str, db: Session = Depends(get_db)):
    scan_run = get_scan_by_id(db, scan_id)
    if not scan_run:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_run.id,
        "base_url": scan_run.base_url,
        "stack_name": scan_run.stack_name,
        "status": scan_run.status,
        "endpoints": [serialize_endpoint(endpoint) for endpoint in scan_run.endpoints],
        "results": [
            {
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
