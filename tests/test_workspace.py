import io
import pytest
import sys
import zipfile
from pathlib import Path

# Ensure backend is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from utils.workspace import WorkspaceManager


class TestWorkspaceExtractionSecurity:
    """Verify ZIP extraction security protections (zip slip, symlinks, size limits)"""

    def test_valid_zip_extraction(self, tmp_path):
        """Valid zip extracts files properly inside workspace"""
        manager = WorkspaceManager()
        manager.workspace_dir = tmp_path / "workspaces"
        manager.workspace_dir.mkdir(parents=True, exist_ok=True)

        workspace = manager.create_workspace("test_valid")
        zip_path = tmp_path / "valid.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.py", "print('hello world')")
            zf.writestr("sub/nested.py", "x = 42")

        manager.extract_zip(zip_path, workspace)

        assert (workspace / "hello.py").exists()
        assert (workspace / "hello.py").read_text() == "print('hello world')"
        assert (workspace / "sub" / "nested.py").exists()

        # Clean up
        manager.cleanup_workspace(workspace)
        assert not workspace.exists()

    def test_path_traversal_rejection_parent_dirs(self, tmp_path):
        """Zip entries with .. path traversal must be rejected"""
        manager = WorkspaceManager()
        manager.workspace_dir = tmp_path / "workspaces"
        manager.workspace_dir.mkdir(parents=True, exist_ok=True)

        workspace = manager.create_workspace("test_traversal")
        zip_path = tmp_path / "traversal.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../escaped.txt", "evil payload")

        with pytest.raises(ValueError) as exc_info:
            manager.extract_zip(zip_path, workspace)
        assert "Path traversal detected" in str(exc_info.value)
        # Workspace should be cleaned up on failure
        assert not workspace.exists()

    def test_path_traversal_rejection_nested_traversal(self, tmp_path):
        """Zip entries with nested traversal like foo/../../bar must be rejected"""
        manager = WorkspaceManager()
        manager.workspace_dir = tmp_path / "workspaces"
        manager.workspace_dir.mkdir(parents=True, exist_ok=True)

        workspace = manager.create_workspace("test_nested_traversal")
        zip_path = tmp_path / "nested_traversal.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("foo/../../escaped.txt", "evil payload")

        with pytest.raises(ValueError) as exc_info:
            manager.extract_zip(zip_path, workspace)
        assert "Path traversal detected" in str(exc_info.value)
        assert not workspace.exists()

    def test_symlink_rejection(self, tmp_path):
        """Zip archives containing symlinks must be rejected to prevent symlink escape"""
        manager = WorkspaceManager()
        manager.workspace_dir = tmp_path / "workspaces"
        manager.workspace_dir.mkdir(parents=True, exist_ok=True)

        workspace = manager.create_workspace("test_symlink")
        zip_path = tmp_path / "symlink.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            # Create a zip entry with Unix symlink attribute: mode 0o120777
            zinfo = zipfile.ZipInfo("symlink_entry")
            zinfo.create_system = 3  # Unix
            zinfo.external_attr = 0o120777 << 16  # Symlink bit
            zf.writestr(zinfo, "/etc/passwd")

        with pytest.raises(ValueError) as exc_info:
            manager.extract_zip(zip_path, workspace)
        assert "Symlinks not allowed" in str(exc_info.value)
        assert not workspace.exists()

    def test_max_size_limit_enforcement(self, tmp_path):
        """Archives exceeding max_size_mb must be rejected"""
        manager = WorkspaceManager()
        manager.workspace_dir = tmp_path / "workspaces"
        manager.workspace_dir.mkdir(parents=True, exist_ok=True)

        workspace = manager.create_workspace("test_size")
        zip_path = tmp_path / "large.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            # 2 MB uncompressed
            zf.writestr("bigfile.bin", b"A" * (2 * 1024 * 1024))

        # Enforce max 1 MB
        with pytest.raises(ValueError) as exc_info:
            manager.extract_zip(zip_path, workspace, max_size_mb=1)
        assert "exceeds size limit" in str(exc_info.value)
        assert not workspace.exists()

    def test_max_file_count_enforcement(self, tmp_path):
        """Archives with too many files must be rejected"""
        manager = WorkspaceManager()
        manager.workspace_dir = tmp_path / "workspaces"
        manager.workspace_dir.mkdir(parents=True, exist_ok=True)

        workspace = manager.create_workspace("test_file_count")
        zip_path = tmp_path / "many_files.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(15):
                zf.writestr(f"file_{i}.txt", f"content {i}")

        # Enforce max 10 files
        with pytest.raises(ValueError) as exc_info:
            manager.extract_zip(zip_path, workspace, max_file_count=10)
        assert "too many files" in str(exc_info.value)
        assert not workspace.exists()
