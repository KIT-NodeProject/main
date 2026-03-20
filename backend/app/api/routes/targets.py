from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.constants import TARGET_STATUS_COMPLETED
from app.core.database import get_db
from app.schemas.result import ScanResultResponse, ScanRunResponse
from app.schemas.target import TargetCreate, TargetResponse
from app.services.result_service import get_results_for_target
from app.services.scan_service import (
    TargetNotFoundError,
    TechStackNotFoundError,
    run_scan_for_target,
)
from app.services.target_service import create_target_with_stack


router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=TargetResponse)
def create_target_route(
    target_data: TargetCreate,
    db: Session = Depends(get_db),
):
    return create_target_with_stack(db=db, target_data=target_data)


@router.post("/{target_id}/scan", response_model=ScanRunResponse)
def run_scan_route(
    target_id: int,
    db: Session = Depends(get_db),
):
    try:
        scan_results = run_scan_for_target(db=db, target_id=target_id)
    except TargetNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except TechStackNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return {
        "message": "Scan completed",
        "target_id": target_id,
        "status": TARGET_STATUS_COMPLETED,
        "result_count": len(scan_results),
    }


@router.get("/{target_id}/results", response_model=list[ScanResultResponse])
def get_results_route(
    target_id: int,
    db: Session = Depends(get_db),
):
    return get_results_for_target(db=db, target_id=target_id)
