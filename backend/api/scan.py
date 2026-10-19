from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from pathlib import Path
import uuid
import logging
import shutil
import zipfile

from models.project import ScanRequest, UploadResponse
from utils.workspace import workspace_manager
from utils.git_helper import git_helper
from config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/upload", response_model=UploadResponse)
async def upload_code(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Upload ZIP file for scanning

    Security controls:
    - File size limit
    - Path traversal validation
    - Isolated workspace
    """
    logger.info(f"Upload request received: {file.filename}")

    # Validate file is a ZIP
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported")

    # Check file size
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Reset to start

    max_size_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file_size > max_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size: {settings.MAX_FILE_SIZE_MB}MB"
        )

    scan_id = str(uuid.uuid4())

    try:
        # Create workspace
        workspace = workspace_manager.create_workspace(scan_id)

        # Save uploaded ZIP
        upload_dir = Path(settings.UPLOAD_DIR)
        upload_dir.mkdir(parents=True, exist_ok=True)
        zip_path = upload_dir / f"{scan_id}.zip"

        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Extract ZIP with validations
        workspace_manager.extract_zip(zip_path, workspace)

        # Clean up ZIP file
        zip_path.unlink()

        logger.info(f"Upload successful: {scan_id}")

        # Note: Actual scanning will be added in Phase 3-6
        return UploadResponse(
            scan_id=scan_id,
            status="uploaded",
            message=f"Code uploaded successfully. Workspace: {workspace}"
        )

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except zipfile.BadZipFile as e:
        logger.error(f"Invalid ZIP file: {e}")
        raise HTTPException(status_code=400, detail="Invalid or corrupted ZIP file")
    except Exception as e:
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")


@router.post("/scan-repo", response_model=UploadResponse)
async def scan_repository(request: ScanRequest):
    """
    Scan a Git repository

    Security controls:
    - URL validation
    - Shallow clone (depth=1)
    - Single branch only
    - Timeout protection
    """
    logger.info(f"Scan repository request: {request.repo_url}")

    scan_id = str(uuid.uuid4())

    try:
        # Create workspace
        workspace = workspace_manager.create_workspace(scan_id)

        # Clone repository
        repo_path = git_helper.clone_repository(
            repo_url=request.repo_url,
            workspace=workspace,
            branch=request.branch,
            depth=1
        )

        # Get commit SHA
        commit_sha = git_helper.get_commit_sha(repo_path)

        logger.info(f"Repository cloned: {scan_id} (commit: {commit_sha})")

        # Note: Actual scanning will be added in Phase 3-6
        return UploadResponse(
            scan_id=scan_id,
            status="cloned",
            message=f"Repository cloned successfully. Commit: {commit_sha}"
        )

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        logger.error(f"Clone error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Repository scan failed")


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan results by ID"""
    logger.info(f"Get scan request: {scan_id}")

    # Placeholder for Phase 6
    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Scan retrieval - implementation in Phase 6"
    }


@router.post("/cleanup")
async def cleanup_old_workspaces():
    """Clean up old workspaces (admin endpoint)"""
    count = workspace_manager.cleanup_old_workspaces()
    return {"cleaned": count, "message": f"Cleaned up {count} old workspaces"}
