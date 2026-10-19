"""
Workspace management for isolated code scanning
"""

import tempfile
import shutil
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import zipfile

from config import settings

logger = logging.getLogger(__name__)


class WorkspaceManager:
    """Manages temporary workspaces for code scanning"""

    def __init__(self):
        self.workspace_dir = Path(settings.WORKSPACE_DIR)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def create_workspace(self, project_id: str) -> Path:
        """
        Create isolated temporary workspace for scanning

        Args:
            project_id: Unique project identifier

        Returns:
            Path to created workspace
        """
        workspace = self.workspace_dir / f"scan_{project_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        workspace.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created workspace: {workspace}")
        return workspace

    def extract_zip(self, zip_file_path: Path, workspace: Path, max_size_mb: int = None, max_file_count: int = 10000) -> None:
        """
        Extract ZIP file with security validations

        Args:
            zip_file_path: Path to ZIP file
            workspace: Destination workspace
            max_size_mb: Maximum allowed size in MB
            max_file_count: Maximum allowed number of files in archive

        Raises:
            ValueError: If ZIP contains path traversal, symlinks, or exceeds limits
        """
        max_size = max_size_mb or settings.MAX_FILE_SIZE_MB
        max_size_bytes = max_size * 1024 * 1024
        resolved_workspace = workspace.resolve()

        try:
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                entries = zip_ref.infolist()
                if len(entries) > max_file_count:
                    raise ValueError(f"ZIP contains too many files ({len(entries)} > {max_file_count})")

                total_declared_size = 0
                # Pre-validation pass
                for file_info in entries:
                    filename = file_info.filename

                    # Check for path traversal indicators
                    raw_path = Path(filename)
                    if raw_path.is_absolute() or ".." in raw_path.parts:
                        raise ValueError(f"Path traversal detected: {filename}")

                    # Check resolved destination path stays strictly inside workspace
                    try:
                        target_path = (resolved_workspace / filename).resolve()
                    except Exception as e:
                        raise ValueError(f"Invalid path in archive {filename}: {e}")

                    if not target_path.is_relative_to(resolved_workspace):
                        raise ValueError(f"Path traversal detected: {filename}")

                    # Reject symlinks (Unix external_attr & 0o170000 == 0o120000)
                    unix_mode = file_info.external_attr >> 16
                    if (unix_mode & 0o170000) == 0o120000:
                        raise ValueError(f"Symlinks not allowed in archive: {filename}")

                    # Validate declared uncompressed size
                    total_declared_size += file_info.file_size
                    if total_declared_size > max_size_bytes:
                        raise ValueError(f"ZIP exceeds size limit: {max_size}MB")

                # Safe extraction pass with byte budgeting
                extracted_bytes = 0
                for file_info in entries:
                    target_path = (resolved_workspace / file_info.filename).resolve()
                    if file_info.is_dir():
                        target_path.mkdir(parents=True, exist_ok=True)
                        continue

                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zip_ref.open(file_info) as source, open(target_path, "wb") as dest:
                        while chunk := source.read(65536):
                            extracted_bytes += len(chunk)
                            if extracted_bytes > max_size_bytes:
                                raise ValueError(f"ZIP uncompressed data exceeds limit: {max_size}MB")
                            dest.write(chunk)

                logger.info(f"Extracted {len(entries)} entries safely to {workspace}")

        except Exception:
            # Clean up partial extractions on failure
            self.cleanup_workspace(workspace)
            raise

    def cleanup_workspace(self, workspace: Path) -> None:
        """
        Clean up workspace directory

        Args:
            workspace: Path to workspace to remove
        """
        try:
            if workspace.exists():
                shutil.rmtree(workspace)
                logger.info(f"Cleaned up workspace: {workspace}")
        except Exception as e:
            logger.error(f"Error cleaning up workspace {workspace}: {e}")

    def cleanup_old_workspaces(self, max_age_minutes: int = None) -> int:
        """
        Clean up workspaces older than specified age

        Args:
            max_age_minutes: Maximum age in minutes

        Returns:
            Number of workspaces cleaned up
        """
        max_age = max_age_minutes or settings.WORKSPACE_CLEANUP_MINUTES
        cutoff_time = datetime.now() - timedelta(minutes=max_age)

        cleaned = 0
        for workspace in self.workspace_dir.glob("scan_*"):
            if not workspace.is_dir():
                continue

            # Check creation time
            ctime = datetime.fromtimestamp(workspace.stat().st_ctime)
            if ctime < cutoff_time:
                self.cleanup_workspace(workspace)
                cleaned += 1

        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old workspaces")

        return cleaned


# Global workspace manager instance
workspace_manager = WorkspaceManager()
