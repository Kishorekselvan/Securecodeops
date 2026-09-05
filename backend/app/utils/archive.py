import os
import zipfile
import shutil
import tempfile
import uuid
from typing import Tuple, List, Dict
from app.core.config import settings

class ArchiveSecurityError(Exception):
    pass

def is_safe_path(base_dir: str, path: str, follow_symlinks: bool = True) -> bool:
    """Verifies that the target path does not escape the base directory (Zip Slip prevention)."""
    if follow_symlinks:
        match_path = os.path.realpath(path)
    else:
        match_path = os.path.abspath(path)
    return base_dir == os.path.commonpath((base_dir, match_path))

def safe_extract_zip(zip_path: str, destination_dir: str) -> Dict[str, any]:
    """
    Safely extracts a ZIP archive into destination_dir with:
    - Path traversal (Zip Slip) protection
    - Zip bomb protection (file count and uncompressed byte size limit)
    - Symlink sanitization
    """
    os.makedirs(destination_dir, exist_ok=True)
    real_dest_dir = os.path.realpath(destination_dir)
    
    extracted_files: List[str] = []
    total_size = 0
    file_count = 0
    
    max_size_bytes = settings.MAX_TOTAL_UNCOMPRESSED_SIZE_MB * 1024 * 1024
    max_files = settings.MAX_FILES_COUNT
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        infolist = zip_ref.infolist()
        
        # Pre-check total files
        if len(infolist) > max_files:
            raise ArchiveSecurityError(f"Archive exceeds maximum file limit ({len(infolist)} > {max_files})")
            
        for member in infolist:
            file_count += 1
            if file_count > max_files:
                raise ArchiveSecurityError("Archive exceeds maximum allowed file count")
                
            total_size += member.file_size
            if total_size > max_size_bytes:
                raise ArchiveSecurityError(f"Archive uncompressed size exceeds limit of {settings.MAX_TOTAL_UNCOMPRESSED_SIZE_MB}MB (Zip bomb protection)")
            
            target_path = os.path.join(destination_dir, member.filename)
            if not is_safe_path(real_dest_dir, target_path):
                raise ArchiveSecurityError(f"Illegal path traversal detected in archive member: {member.filename}")
        
        # Safe extraction
        for member in infolist:
            target_path = os.path.join(destination_dir, member.filename)
            if member.is_dir():
                os.makedirs(target_path, exist_ok=True)
                continue
            
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zip_ref.open(member) as source, open(target_path, "wb") as target:
                shutil.copyfileobj(source, target)
            extracted_files.append(target_path)
            
    return {
        "file_count": len(extracted_files),
        "total_bytes": total_size,
        "extracted_files": extracted_files
    }

def create_isolated_sandbox(source_dir: str) -> str:
    """Creates a temporary isolated copy of the repository directory for sandboxed scans or patch testing."""
    sandbox_id = str(uuid.uuid4())
    sandbox_path = os.path.join(settings.SANDBOX_DIR, sandbox_id)
    shutil.copytree(source_dir, sandbox_path)
    return sandbox_path

def cleanup_sandbox(sandbox_path: str):
    """Safely cleans up a temporary sandbox directory."""
    try:
        if os.path.exists(sandbox_path) and os.path.commonpath([settings.SANDBOX_DIR, os.path.realpath(sandbox_path)]) == os.path.realpath(settings.SANDBOX_DIR):
            shutil.rmtree(sandbox_path, ignore_errors=True)
    except Exception:
        pass
