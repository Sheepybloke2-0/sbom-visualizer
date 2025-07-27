"""
API routes for SBOM Visualizer.

FastAPI routes for web interface (Stage 2 preparation).
"""

from fastapi import APIRouter, File, HTTPException, UploadFile

router = APIRouter(prefix="/api/v1", tags=["sbom"])


@router.post("/analyze")
async def analyze_sbom(file: UploadFile = File(...)):
    """
    Analyze uploaded SBOM file.

    This endpoint will be implemented in Stage 2.
    """
    # Placeholder for Stage 2 implementation
    raise HTTPException(status_code=501, detail="Not implemented yet - Stage 2 feature")


@router.post("/verify")
async def verify_sbom(file: UploadFile = File(...)):
    """
    Verify uploaded SBOM file.

    This endpoint will be implemented in Stage 2.
    """
    # Placeholder for Stage 2 implementation
    raise HTTPException(status_code=501, detail="Not implemented yet - Stage 2 feature")


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "0.1.0"}
