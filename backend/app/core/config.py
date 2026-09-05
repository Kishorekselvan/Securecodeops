import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "SecureCodeOps AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Storage and DB
    DATABASE_URL: str = "sqlite+aiosqlite:///./securecodeops.db"
    SYNC_DATABASE_URL: str = "sqlite:///./securecodeops.db"
    UPLOAD_DIR: str = "./storage/uploads"
    SANDBOX_DIR: str = "./storage/sandboxes"
    REPORTS_DIR: str = "./storage/reports"
    
    # Upload limits
    MAX_UPLOAD_SIZE_MB: int = 50
    MAX_FILES_COUNT: int = 2000
    MAX_TOTAL_UNCOMPRESSED_SIZE_MB: int = 200
    
    # LLM Settings
    LLM_PROVIDER: str = "offline"  # "openai", "gemini", "anthropic", "offline"
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GOOGLE_API_KEY: Optional[str] = None
    MODEL_NAME: Optional[str] = None
    
    # Security
    SECRET_KEY: str = "securecodeops-dev-secret-key-change-in-prod-2026"
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "*"]
    
    # External Scanners enable flags
    ENABLE_SEMGREP: bool = True
    ENABLE_BANDIT: bool = True
    ENABLE_TRIVY: bool = True
    ENABLE_GITLEAKS: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

# Ensure local directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.SANDBOX_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
