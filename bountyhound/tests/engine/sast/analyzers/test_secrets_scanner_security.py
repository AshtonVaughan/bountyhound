import pytest
import tempfile
import json
from pathlib import Path
from engine.sast.analyzers.secrets_scanner import SecretsScanner

def test_secrets_masked_in_terminal_output(capsys):
    """Test that secrets are masked when printed to terminal"""
    # Create isolated test directory
    import tempfile
    test_dir = tempfile.mkdtemp()
    test_file = Path(test_dir) / "test.py"

    try:
        # Use a realistic AWS key that won't trigger false positive detection
        test_file.write_text('AWS_KEY = AKIAIOSFODNN7REALKEY\n')

        scanner = SecretsScanner(test_dir)
        scanner.scan()

        # Capture terminal output
        captured = capsys.readouterr()

        # Full secret should NOT appear in terminal output
        assert "AKIAIOSFODNN7REALKEY" not in captured.out, \
            "Full secret leaked to terminal"

        # Masked version should appear (first 4 + last 4 chars)
        assert "AKIA...LKEY" in captured.out, \
            "Secret should be masked in terminal output"

    finally:
        test_file.unlink(missing_ok=True)
        Path(test_dir).rmdir()

def test_full_secrets_in_json_report():
    """Test that full secrets are preserved in JSON reports"""
    # Create isolated test directory
    import tempfile
    test_dir = tempfile.mkdtemp()
    test_file = Path(test_dir) / "test.py"

    try:
        # Use a realistic GitHub token (36 chars after prefix)
        test_file.write_text('GITHUB_TOKEN = ghp_Ab9Cd3Ef7Gh1Ij5Kl2Mn6Op8Qr4St0Uv2WxY\n')

        scanner = SecretsScanner(test_dir)
        results = scanner.scan()

        # JSON results should contain full secret
        assert len(results) > 0, "Should find secret"

        # Find the GitHub token in results
        github_findings = [r for r in results if r['type'] == 'GitHub Token']
        assert len(github_findings) > 0, "Should find GitHub token"
        assert github_findings[0]['secret'] == "ghp_Ab9Cd3Ef7Gh1Ij5Kl2Mn6Op8Qr4St0Uv2WxY", \
            "Full secret should be in JSON results"

    finally:
        test_file.unlink(missing_ok=True)
        Path(test_dir).rmdir()

def test_mask_secret_function():
    """Test the secret masking function"""
    from engine.sast.analyzers.secrets_scanner import mask_secret

    # Test AWS key masking
    masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked == "AKIA...MPLE", f"Expected 'AKIA...MPLE', got '{masked}'"

    # Test short secret (show minimal info)
    masked = mask_secret("short")
    assert "****" in masked, "Short secrets should be heavily masked"

    # Test empty secret
    masked = mask_secret("")
    assert masked == "****", "Empty secret should be masked"
