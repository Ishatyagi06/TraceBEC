"""Core Configuration & Retention Settings."""

import os
from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "TraceBEC — Business Email Compromise Intelligence"
    api_v1_str: str = "/api/v1"
    version: str = "1.0.0"
    cors_origins: list[str] = ["*"]
    
    # Retention & Privacy settings
    retention_mode: str = os.getenv("PHISGUARD_RETENTION_MODE", "investigation")  # 'ephemeral' or 'investigation'
    max_upload_size_bytes: int = 10 * 1024 * 1024  # 10 MB cap for safe MIME ingestion


settings = Settings()
