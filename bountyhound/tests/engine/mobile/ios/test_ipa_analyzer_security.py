import pytest
import zipfile
import tempfile
from pathlib import Path
from engine.mobile.ios.ipa_analyzer import IPAAnalyzer

def test_rejects_path_traversal_in_zip():
    """Test that malicious ZIP paths are rejected"""
    # Create malicious ZIP with path traversal
    with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as f:
        evil_ipa = f.name

    with zipfile.ZipFile(evil_ipa, 'w') as zf:
        zf.writestr('../../etc/passwd', 'hacked')

    analyzer = IPAAnalyzer(evil_ipa)

    with pytest.raises(ValueError, match="Path traversal detected"):
        analyzer.extract_ipa()

    # Cleanup
    Path(evil_ipa).unlink()
