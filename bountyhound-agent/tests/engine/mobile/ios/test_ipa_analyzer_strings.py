import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock
from engine.mobile.ios.ipa_analyzer import IPAAnalyzer

def test_extract_strings_finds_urls():
    """Test that string extraction finds URLs"""
    # Mock the strings command output
    mock_strings_output = """
Some random text
https://api.example.com/v1/users
http://insecure-endpoint.com
More text here
api_key=sk_test_1234567890
"""

    with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as f:
        ipa_path = Path(f.name)

    try:
        analyzer = IPAAnalyzer(ipa_path)
        analyzer.output_dir = ipa_path.parent / "test_output"
        analyzer.output_dir.mkdir(exist_ok=True)

        # Create mock .app directory and binary
        app_dir = analyzer.output_dir / "extracted" / "Payload"
        app_dir.mkdir(parents=True, exist_ok=True)

        # Create a fake .app directory
        fake_app = app_dir / "TestApp.app"
        fake_app.mkdir(exist_ok=True)

        # Create a fake binary file
        fake_binary = fake_app / "TestApp"
        fake_binary.touch()

        # Mock subprocess to return our test strings
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = mock_strings_output
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            results = analyzer.extract_strings()

            # Should categorize findings
            assert 'urls' in results, "Should have 'urls' category"
            assert len(results['urls']) >= 2, "Should find at least 2 URLs"

            # Check for the specific URLs
            urls = [item['value'] for item in results['urls']]
            assert 'https://api.example.com/v1/users' in urls

    finally:
        ipa_path.unlink(missing_ok=True)

def test_extract_strings_finds_api_keys():
    """Test that string extraction finds potential API keys"""
    mock_strings_output = """
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
stripe_key=sk_test_abcdef123456
github_token=ghp_1234567890abcdefghij
"""

    with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as f:
        ipa_path = Path(f.name)

    try:
        analyzer = IPAAnalyzer(ipa_path)
        analyzer.output_dir = ipa_path.parent / "test_output"
        analyzer.output_dir.mkdir(exist_ok=True)

        # Create mock .app directory and binary
        app_dir = analyzer.output_dir / "extracted" / "Payload"
        app_dir.mkdir(parents=True, exist_ok=True)

        # Create a fake .app directory
        fake_app = app_dir / "TestApp.app"
        fake_app.mkdir(exist_ok=True)

        # Create a fake binary file
        fake_binary = fake_app / "TestApp"
        fake_binary.touch()

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = mock_strings_output
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            results = analyzer.extract_strings()

            # Should find potential secrets
            assert 'potential_secrets' in results
            secrets = [item['value'] for item in results['potential_secrets']]

            # Should detect the AWS key
            assert any('AKIA' in s for s in secrets), "Should detect AWS key pattern"

    finally:
        ipa_path.unlink(missing_ok=True)

def test_extract_strings_handles_no_binary():
    """Test graceful handling when binary not found"""
    with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as f:
        ipa_path = Path(f.name)

    try:
        analyzer = IPAAnalyzer(ipa_path)
        analyzer.output_dir = ipa_path.parent / "test_output"
        analyzer.output_dir.mkdir(exist_ok=True)

        # Mock subprocess to simulate binary not found
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("Binary not found")

            # Should not raise exception
            results = analyzer.extract_strings()

            # Should return empty results
            assert isinstance(results, dict)

    finally:
        ipa_path.unlink(missing_ok=True)
