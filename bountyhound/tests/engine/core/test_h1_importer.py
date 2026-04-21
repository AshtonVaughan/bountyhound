"""
Tests for HackerOne API payout importer
"""
import pytest
import tempfile
import os
from unittest.mock import Mock, patch
from engine.core.h1_importer import HackerOneImporter
from engine.core.database import BountyHoundDB


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = BountyHoundDB(db_path=db_path)
        yield db


def test_import_payouts_from_h1_with_credentials():
    """Test importing real payout data from HackerOne API with credentials"""
    # Mock environment variables
    with patch.dict('os.environ', {'H1_API_TOKEN': 'test_token', 'H1_USERNAME': 'test_user'}):
        importer = HackerOneImporter()

        # Mock the API call
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
            "data": [
                {
                    "id": "1234",
                    "attributes": {
                        "title": "XSS in login form",
                        "bounty_amount": "500.00",
                        "currency": "USD",
                        "bounty_awarded_at": "2024-01-15T10:30:00Z"
                    }
                },
                {
                    "id": "5678",
                    "attributes": {
                        "title": "IDOR in profile API",
                        "bounty_amount": "1000.00",
                        "currency": "USD",
                        "bounty_awarded_at": "2024-02-20T14:45:00Z"
                    }
                }
            ]
            }
            mock_get.return_value = mock_response

            # Should fetch reports with bounty awards
            payouts = importer.fetch_payouts()

            assert len(payouts) == 2
            assert payouts[0]["report_id"] == "1234"
            assert payouts[0]["amount"] == 500.0
            assert payouts[0]["currency"] == "USD"
            assert payouts[0]["title"] == "XSS in login form"
            assert payouts[1]["report_id"] == "5678"
            assert payouts[1]["amount"] == 1000.0


def test_import_payouts_without_credentials():
    """Test that importer returns empty list without credentials"""
    with patch.dict('os.environ', {}, clear=True):
        importer = HackerOneImporter()
        payouts = importer.fetch_payouts()
        assert payouts == []


def test_import_payouts_api_failure():
    """Test handling of API failures"""
    with patch.dict('os.environ', {'H1_API_TOKEN': 'test_token', 'H1_USERNAME': 'test_user'}):
        importer = HackerOneImporter()

        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 401
            mock_get.return_value = mock_response

            payouts = importer.fetch_payouts()
            assert payouts == []


def test_sync_payouts_to_database(temp_db):
    """Test syncing HackerOne payouts to database"""
    importer = HackerOneImporter()
    db = temp_db

    # Mock API response
    mock_payouts = [
        {
            "report_id": "1234",
            "title": "XSS in login",
            "amount": 500.0,
            "currency": "USD",
            "awarded_at": "2024-01-15T10:30:00Z"
        },
        {
            "report_id": "5678",
            "title": "IDOR in API",
            "amount": 1000.0,
            "currency": "USD",
            "awarded_at": "2024-02-20T14:45:00Z"
        }
    ]

    importer.sync_to_database(db, mock_payouts)

    # Verify stored in database
    finding1 = db.get_finding_by_id("1234")
    assert finding1 is not None
    assert finding1["payout"] == 500.0
    assert finding1["currency"] == "USD"
    assert finding1["title"] == "XSS in login"

    finding2 = db.get_finding_by_id("5678")
    assert finding2 is not None
    assert finding2["payout"] == 1000.0


def test_sync_updates_existing_payout(temp_db):
    """Test that syncing updates existing finding payouts"""
    importer = HackerOneImporter()
    db = temp_db

    # Insert initial finding without payout
    db.insert_finding(
        target="example.com",
        vuln_type="XSS",
        title="XSS in login",
        severity="HIGH",
        report_id="1234"
    )

    # Sync with payout data
    mock_payouts = [
        {
            "report_id": "1234",
            "title": "XSS in login",
            "amount": 750.0,
            "currency": "USD",
            "awarded_at": "2024-01-15T10:30:00Z"
        }
    ]

    importer.sync_to_database(db, mock_payouts)

    # Verify payout was updated
    finding = db.get_finding_by_id("1234")
    assert finding is not None
    assert finding["payout"] == 750.0
    assert finding["currency"] == "USD"


def test_full_import_workflow(temp_db):
    """Test complete workflow: fetch from API and sync to database"""
    with patch.dict('os.environ', {'H1_API_TOKEN': 'test_token', 'H1_USERNAME': 'test_user'}):
        importer = HackerOneImporter()
        db = temp_db

        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": [
                    {
                        "id": "9999",
                        "attributes": {
                            "title": "Critical SQLi",
                            "bounty_amount": "5000.00",
                            "currency": "USD",
                            "bounty_awarded_at": "2024-03-10T08:00:00Z"
                        }
                    }
                ]
            }
            mock_get.return_value = mock_response

            # Fetch and sync
            payouts = importer.fetch_payouts()
            importer.sync_to_database(db, payouts)

            # Verify complete workflow
            finding = db.get_finding_by_id("9999")
            assert finding is not None
            assert finding["payout"] == 5000.0
            assert finding["title"] == "Critical SQLi"
