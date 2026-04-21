import pytest
from unittest.mock import Mock, patch
from engine.core.h1_disclosed_checker import H1DisclosedChecker
from engine.core.database import BountyHoundDB

@pytest.fixture
def checker():
    return H1DisclosedChecker()

@pytest.fixture
def test_db():
    db = BountyHoundDB(":memory:")
    yield db
    # BountyHoundDB doesn't have close method, connection closes automatically

def test_fetch_disclosed_reports():
    """Test fetching disclosed reports from HackerOne API"""
    # Mock environment variables for credentials
    with patch.dict('os.environ', {'H1_API_TOKEN': 'test_token', 'H1_USERNAME': 'test_user'}):
        checker = H1DisclosedChecker()

        with patch('engine.core.h1_disclosed_checker.requests.get') as mock_get:
            # Mock API response
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {
                    "data": [
                        {
                            "id": "12345",
                            "type": "report",
                            "attributes": {
                                "title": "XSS in search parameter",
                                "vulnerability_information": "Reflected XSS via ?q= parameter",
                                "disclosed_at": "2024-01-15T10:00:00.000Z",
                                "bounty_amount": "500.0"
                            }
                        }
                    ]
                }
            )

            reports = checker.fetch_disclosed_reports("test-program")

            assert len(reports) == 1
            assert reports[0]["id"] == "12345"
            assert reports[0]["title"] == "XSS in search parameter"
            assert reports[0]["bounty_amount"] == "500.0"

def test_fetch_disclosed_reports_no_credentials(checker):
    """Test graceful handling when no API credentials"""
    with patch.dict('os.environ', {}, clear=True):
        checker_no_creds = H1DisclosedChecker()
        reports = checker_no_creds.fetch_disclosed_reports("test-program")
        assert reports == []

def test_check_duplicate_against_disclosed(checker, test_db):
    """Test checking if finding matches disclosed report"""
    from engine.core.semantic_dedup import SemanticDuplicateDetector

    # Mock disclosed reports - use very similar text to ensure high similarity
    disclosed = [
        {
            "id": "12345",
            "title": "IDOR allows unauthorized access to user data",
            "vulnerability_information": "The /api/users/{id} endpoint does not verify ownership. Any authenticated user can access /api/users/{id} without permission check leading to IDOR vulnerability.",
            "disclosed_at": "2024-01-15T10:00:00.000Z",
            "bounty_amount": "1500.0"
        }
    ]

    new_finding = {
        "title": "IDOR allows unauthorized access to user data",
        "description": "Any authenticated user can access /api/users/{id} without permission check IDOR vulnerability",
        "vuln_type": "IDOR"
    }

    result = checker.check_duplicate(new_finding, disclosed, threshold=0.75)

    assert result["is_duplicate"] is True
    assert result["match_type"] == "disclosed_report"
    assert len(result["matches"]) > 0
    assert result["matches"][0]["similarity_score"] > 0.75
    assert "12345" in result["matches"][0]["id"]

def test_check_duplicate_no_match(checker, test_db):
    """Test when finding does not match any disclosed reports"""
    disclosed = [
        {
            "id": "12345",
            "title": "XSS in comments section",
            "vulnerability_information": "Stored cross-site scripting vulnerability in comment field allows attackers to inject malicious JavaScript code",
            "disclosed_at": "2024-01-15T10:00:00.000Z",
            "bounty_amount": "300.0"
        }
    ]

    new_finding = {
        "title": "SQL injection in authentication endpoint",
        "description": "The username parameter in /api/login is vulnerable to blind SQL injection attacks using time-based payloads",
        "vuln_type": "SQLi"
    }

    result = checker.check_duplicate(new_finding, disclosed, threshold=0.75)

    assert result["is_duplicate"] is False
    assert result["match_type"] is None
    assert len(result["matches"]) == 0

def test_build_cache(checker, test_db):
    """Test building local cache of disclosed reports"""
    with patch.object(checker, 'fetch_disclosed_reports') as mock_fetch:
        mock_fetch.return_value = [
            {"id": "1", "title": "Test 1", "vulnerability_information": "Info 1"},
            {"id": "2", "title": "Test 2", "vulnerability_information": "Info 2"}
        ]

        programs = ["shopify", "github"]
        cache = checker.build_cache(programs)

        assert "shopify" in cache
        assert "github" in cache
        assert len(cache["shopify"]) == 2
        assert len(cache["github"]) == 2

def test_load_from_cache(checker, test_db):
    """Test loading disclosed reports from cache"""
    import json
    from pathlib import Path
    from datetime import datetime

    cache_path = Path("C:/Users/vaugh/BountyHound/database/disclosed_cache.json")
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Write test cache with current timestamp (not expired)
    current_time = datetime.utcnow().isoformat() + "Z"
    cache_data = {
        "shopify": [
            {"id": "1", "title": "Test", "vulnerability_information": "Info"}
        ],
        "cached_at": current_time
    }

    with open(cache_path, 'w') as f:
        json.dump(cache_data, f)

    # Load from cache
    reports = checker.load_from_cache("shopify")

    assert len(reports) == 1
    assert reports[0]["id"] == "1"

    # Cleanup
    cache_path.unlink()

def test_cache_expiry(checker):
    """Test that cache expires after 24 hours"""
    import json
    from pathlib import Path
    from datetime import datetime, timedelta

    cache_path = Path("C:/Users/vaugh/BountyHound/database/disclosed_cache.json")
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Write expired cache (25 hours old)
    expired_time = (datetime.utcnow() - timedelta(hours=25)).isoformat() + "Z"
    cache_data = {
        "shopify": [{"id": "1", "title": "Test"}],
        "cached_at": expired_time
    }

    with open(cache_path, 'w') as f:
        json.dump(cache_data, f)

    # Should return empty list (cache expired)
    reports = checker.load_from_cache("shopify")
    assert reports == []

    # Cleanup
    cache_path.unlink()
