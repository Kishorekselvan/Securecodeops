import shutil
from fastapi import APIRouter
from app.core.config import settings
from app.scanners.semgrep import SemgrepScanner
from app.scanners.bandit import BanditScanner
from app.scanners.gitleaks import GitLeaksScanner
from app.scanners.trivy import TrivyScanner

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.get("/status")
async def get_system_settings_status():
    semgrep_scanner = SemgrepScanner()
    bandit_scanner = BanditScanner()
    gitleaks_scanner = GitLeaksScanner()
    trivy_scanner = TrivyScanner()

    return {
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "llm_provider": settings.LLM_PROVIDER,
        "model_name": settings.MODEL_NAME or "default-model",
        "has_openai_key": bool(settings.OPENAI_API_KEY),
        "has_gemini_key": bool(settings.GOOGLE_API_KEY),
        "has_anthropic_key": bool(settings.ANTHROPIC_API_KEY),
        "scanners": {
            "semgrep": {
                "installed": semgrep_scanner.is_available(),
                "enabled": settings.ENABLE_SEMGREP,
                "mode": "Native Binary" if semgrep_scanner.is_available() else "Deterministic Rules Engine (Fallback)"
            },
            "bandit": {
                "installed": bandit_scanner.is_available(),
                "enabled": settings.ENABLE_BANDIT,
                "mode": "Native Binary" if bandit_scanner.is_available() else "AST Security Engine (Fallback)"
            },
            "gitleaks": {
                "installed": gitleaks_scanner.is_available(),
                "enabled": settings.ENABLE_GITLEAKS,
                "mode": "Native Binary" if gitleaks_scanner.is_available() else "Entropy Regex Engine (Fallback)"
            },
            "trivy": {
                "installed": trivy_scanner.is_available(),
                "enabled": settings.ENABLE_TRIVY,
                "mode": "Native Binary" if trivy_scanner.is_available() else "Manifest Advisory Scanner (Fallback)"
            }
        },
        "limits": {
            "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB,
            "max_files_count": settings.MAX_FILES_COUNT,
            "max_uncompressed_size_mb": settings.MAX_TOTAL_UNCOMPRESSED_SIZE_MB
        }
    }
