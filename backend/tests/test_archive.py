import os
import zipfile
import tempfile
import pytest
from app.utils.archive import safe_extract_zip, ArchiveSecurityError

def test_safe_zip_extraction(tmp_path):
    zip_path = os.path.join(tmp_path, "valid.zip")
    extract_dir = os.path.join(tmp_path, "extracted")
    
    # Create valid ZIP
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("test.py", "print('hello world')")
        zf.writestr("src/module.py", "x = 1")

    res = safe_extract_zip(zip_path, extract_dir)
    assert res["file_count"] == 2
    assert os.path.exists(os.path.join(extract_dir, "test.py"))
    assert os.path.exists(os.path.join(extract_dir, "src", "module.py"))

def test_zip_slip_rejection(tmp_path):
    zip_path = os.path.join(tmp_path, "evil.zip")
    extract_dir = os.path.join(tmp_path, "extracted")
    
    # Create malicious ZIP with path traversal
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("../../evil.txt", "malicious content")

    with pytest.raises(ArchiveSecurityError):
        safe_extract_zip(zip_path, extract_dir)
