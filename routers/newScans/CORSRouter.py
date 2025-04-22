# routers/cors_router.py
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, status, Depends
from typing import List, Optional, Dict, Any

from models.newScans.CORSModel import ScanRequest, ScanResponse, ScanStatus, ScanFileRequest
from controllers.newScans.CORSController import CorsController

router = APIRouter()

@router.post("/CORS", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Start a new CORS scan for the provided URLs
    """
    return await CorsController.start_scan(scan_request, background_tasks)

@router.post("/scan/file", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def scan_from_file(scan_request: ScanFileRequest, background_tasks: BackgroundTasks):
    """
    Start a new CORS scan using URLs from a file
    """
    return await CorsController.scan_from_file(scan_request, background_tasks)

@router.get("/scan/{scan_id}", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """
    Get the status of a running or completed scan
    """
    return await CorsController.get_scan_status(scan_id)

@router.get("/scans", response_model=List[str])
async def list_scans():
    """
    List all scan IDs
    """
    return await CorsController.list_scans()

@router.delete("/scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: str):
    """
    Delete a scan from storage
    """
    await CorsController.delete_scan(scan_id)
    return None

@router.post("/scan/{scan_id}/save", response_model=Dict[str, Any])
async def save_results(scan_id: str, file_path: str = Query(..., description="Path to save results")):
    """
    Save scan results to a file
    """
    return await CorsController.save_results_to_file(scan_id, file_path)