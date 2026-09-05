import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseScanner(ABC):
    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def is_available(self) -> bool:
        """Checks whether the native CLI tool is installed and executable on the host system."""
        pass

    @abstractmethod
    def scan(self, target_dir: str) -> Dict[str, Any]:
        """
        Executes scan on the target repository directory.
        Returns:
            {
                "scanner": self.name,
                "is_native": bool,
                "executed": bool,
                "findings": List[Dict[str, Any]],
                "error": Optional[str],
                "duration_seconds": float
            }
        """
        pass

    def run_cli_command(self, cmd: List[str], cwd: str, timeout_seconds: int = 60) -> Optional[str]:
        try:
            res = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False
            )
            return res.stdout
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None
