import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration"""

    # API Keys
    CLAUDE_API_KEY: str = ""
    GITHUB_TOKEN: str = ""
    GITHUB_WEBHOOK_SECRET: str = ""

    # Database
    DATABASE_PATH: str = "./security_debt.db"

    # File paths
    UPLOAD_DIR: str = "./uploads"
    WORKSPACE_DIR: str = "./workspaces"
    LOG_DIR: str = "./logs"

    # Scanner paths
    GITLEAKS_PATH: str = "gitleaks"  # Assumes in PATH, or set to C:\tools\gitleaks\gitleaks.exe
    SEMGREP_PATH: str = "semgrep"  # Assumes in PATH, or python scripts directory

    # Limits
    MAX_FILE_SIZE_MB: int = 50
    MAX_SCAN_TIME_SECONDS: int = 300  # 5 minutes
    WORKSPACE_CLEANUP_MINUTES: int = 30

    # AI Settings
    AI_MAX_TOKENS: int = 1024
    AI_TEMPERATURE: float = 0.3
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_CONCURRENT: int = 10

    # Scoring
    PROJECT_CAPACITY: int = 100

    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: list = ["http://localhost:3000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )


# Global settings instance
settings = Settings()

# Ensure directories exist
for directory in [settings.UPLOAD_DIR, settings.WORKSPACE_DIR, settings.LOG_DIR]:
    Path(directory).mkdir(parents=True, exist_ok=True)
