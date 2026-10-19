import io
import pytest
import sys
import zipfile
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure backend is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from main import app

client = TestClient(app)


def test_health_check_contract():
    """Verify health endpoint response schema"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "security-debt-scorer"
    assert data["version"] == "1.0.0"


def test_root_endpoint_contract():
    """Verify root endpoint response schema"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["docs"] == "/docs"
    assert data["health"] == "/health"


def test_upload_non_zip_rejected():
    """Verify upload rejects non-ZIP files with 400"""
    file_content = b"Not a zip file"
    response = client.post(
        "/api/upload",
        files={"file": ("test.txt", io.BytesIO(file_content), "text/plain")}
    )
    assert response.status_code == 400
    assert "Only ZIP files are supported" in response.json()["detail"]


def test_upload_oversize_file_rejected(monkeypatch):
    """Verify upload rejects files exceeding MAX_FILE_SIZE_MB with 413"""
    from config import settings
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 1)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("large.dat", b"0" * (int(1.5 * 1024 * 1024)))
    buf.seek(0)

    response = client.post(
        "/api/upload",
        files={"file": ("large.zip", buf, "application/zip")}
    )
    assert response.status_code == 413
    assert "File too large" in response.json()["detail"]


def test_upload_corrupted_zip_rejected():
    """Verify upload rejects corrupted ZIP files with 400 Bad Request"""
    corrupted_data = b"PK\x03\x04corrupted-content-not-a-real-zip"
    response = client.post(
        "/api/upload",
        files={"file": ("corrupted.zip", io.BytesIO(corrupted_data), "application/zip")}
    )
    assert response.status_code == 400
    assert "Invalid or corrupted ZIP" in response.json()["detail"]


def test_upload_valid_zip_success():
    """Verify upload accepts a valid ZIP file and creates workspace"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("test.py", "x = 1")
    buf.seek(0)

    response = client.post(
        "/api/upload",
        files={"file": ("project.zip", buf, "application/zip")}
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "uploaded"
    assert "Code uploaded successfully" in data["message"]


def test_scan_repo_invalid_url_rejected():
    """Verify /api/scan-repo rejects file:// and localhost URLs"""
    response = client.post(
        "/api/scan-repo",
        json={"repo_url": "file:///etc/passwd", "branch": "main"}
    )
    assert response.status_code == 400
    assert "Invalid repository URL" in response.json()["detail"]

    response2 = client.post(
        "/api/scan-repo",
        json={"repo_url": "http://localhost:8080/repo.git", "branch": "main"}
    )
    assert response2.status_code == 400
    assert "Invalid repository URL" in response2.json()["detail"]


def test_get_scan_contract():
    """Verify /api/scans/{scan_id} contract returns scan info"""
    response = client.get("/api/scans/sample-scan-123")
    assert response.status_code == 200
    data = response.json()
    assert data["scan_id"] == "sample-scan-123"
    assert "status" in data
