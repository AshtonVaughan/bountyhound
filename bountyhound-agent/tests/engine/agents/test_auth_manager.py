"""
Comprehensive tests for AuthManager
"""

import pytest
import os
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, Mock
import jwt as pyjwt

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../'))

from engine.agents.auth_manager import AuthManager


@pytest.fixture
def temp_home(tmp_path):
    """Create temporary home directory for testing"""
    home = tmp_path / "test_home"
    home.mkdir()

    with patch.dict(os.environ, {'HOME': str(home), 'USERPROFILE': str(home)}):
        with patch('pathlib.Path.home', return_value=home):
            yield home


@pytest.fixture
def auth_manager(temp_home):
    """Create AuthManager instance for testing"""
    return AuthManager(target="example.com", hunt_id="H-test-001")


class TestInitialization:
    """Test AuthManager initialization"""

    def test_creates_auth_directories(self, auth_manager, temp_home):
        """Test that required directories are created"""
        auth_dir = temp_home / ".bountyhound" / "hunts" / "H-test-001" / "auth"
        assert auth_dir.exists()
        assert auth_dir.is_dir()

    def test_sets_target(self, auth_manager):
        """Test that target is set correctly"""
        assert auth_manager.target == "example.com"

    def test_sets_hunt_id(self, auth_manager):
        """Test that hunt_id is set correctly"""
        assert auth_manager.hunt_id == "H-test-001"

    def test_generates_hunt_id_if_not_provided(self, temp_home):
        """Test that hunt_id is auto-generated if not provided"""
        manager = AuthManager(target="example.com")
        assert manager.hunt_id.startswith("H-")
        assert len(manager.hunt_id) > 5

    def test_initializes_empty_collections(self, auth_manager):
        """Test that user/credential/token dicts are initialized empty"""
        assert auth_manager.users == {}
        assert auth_manager.credentials == {}
        assert auth_manager.tokens == {}


class TestIdentityGeneration:
    """Test test identity generation"""

    def test_generates_user_a_identity(self, auth_manager):
        """Test generating identity for User A"""
        identity = auth_manager.generate_test_identity("user_a")

        assert "email" in identity
        assert identity["email"].startswith("bh.test.")
        assert identity["email"].endswith("@gmail.com")
        assert "password" in identity
        assert identity["password"].startswith("BhTest!")
        assert "username" in identity
        assert identity["username"].startswith("bhtest_")
        assert identity["name"] == "Test User A"

    def test_generates_user_b_identity(self, auth_manager):
        """Test generating identity for User B"""
        identity = auth_manager.generate_test_identity("user_b")

        assert identity["email"].startswith("bh.test2.")
        assert identity["password"].startswith("BhTest2!")
        assert identity["username"].startswith("bhtest2_")
        assert identity["name"] == "Test User B"

    def test_identities_are_unique(self, auth_manager):
        """Test that each generated identity is unique"""
        identity1 = auth_manager.generate_test_identity("user_a")
        identity2 = auth_manager.generate_test_identity("user_a")

        assert identity1["email"] != identity2["email"]
        assert identity1["password"] != identity2["password"]
        assert identity1["username"] != identity2["username"]

    def test_identity_email_format(self, auth_manager):
        """Test that email follows expected format"""
        identity = auth_manager.generate_test_identity("user_a")
        email = identity["email"]

        # Should be bh.test.{8chars}@gmail.com
        parts = email.split("@")
        assert len(parts) == 2
        assert parts[1] == "gmail.com"
        assert parts[0].startswith("bh.test.")

    def test_identity_password_complexity(self, auth_manager):
        """Test that password has sufficient complexity"""
        identity = auth_manager.generate_test_identity("user_a")
        password = identity["password"]

        # Should contain uppercase, lowercase, special chars, numbers
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c in "!@#$%^&*" for c in password)
        assert any(c.isdigit() for c in password)


class TestCredentialLoading:
    """Test loading credentials from .env files"""

    def test_loads_credentials_successfully(self, auth_manager, temp_home):
        """Test loading valid credentials file"""
        # Create test .env file
        env_file = temp_home / "test.env"
        env_content = """
USER_A_EMAIL=user_a@test.com
USER_A_PASSWORD=TestPass123!
USER_A_AUTH_TOKEN=Bearer token_a
USER_A_SESSION_COOKIE=session_a
USER_A_CSRF_TOKEN=csrf_a
USER_A_REFRESH_TOKEN=refresh_a
USER_A_TOKEN_EXPIRY=2026-12-31T00:00:00

USER_B_EMAIL=user_b@test.com
USER_B_PASSWORD=TestPass456!
USER_B_AUTH_TOKEN=Bearer token_b
USER_B_SESSION_COOKIE=session_b
USER_B_CSRF_TOKEN=csrf_b
USER_B_REFRESH_TOKEN=refresh_b
USER_B_TOKEN_EXPIRY=2026-12-31T00:00:00
"""
        env_file.write_text(env_content)

        result = auth_manager.load_credentials(str(env_file))

        assert result is True
        assert "user_a" in auth_manager.credentials
        assert "user_b" in auth_manager.credentials
        assert auth_manager.credentials["user_a"]["email"] == "user_a@test.com"
        assert auth_manager.credentials["user_b"]["email"] == "user_b@test.com"

    def test_returns_false_when_file_not_found(self, auth_manager):
        """Test that load_credentials returns False for missing file"""
        result = auth_manager.load_credentials("/nonexistent/file.env")
        assert result is False

    def test_handles_malformed_env_file(self, auth_manager, temp_home):
        """Test that load_credentials handles corrupted files gracefully"""
        env_file = temp_home / "bad.env"
        env_file.write_text("INVALID CONTENT!!!")

        result = auth_manager.load_credentials(str(env_file))
        # Should not crash, just load what it can
        assert result is True


class TestCredentialSaving:
    """Test saving credentials and tokens"""

    def test_saves_credentials_to_json(self, auth_manager, temp_home):
        """Test saving user credentials to JSON file"""
        creds = {
            "email": "test@example.com",
            "password": "TestPass123!"
        }
        tokens = {
            "headers": {
                "Authorization": "Bearer test_token"
            },
            "cookies": [
                {"name": "session", "value": "abc123"}
            ]
        }

        result = auth_manager.save_credentials("user_a", creds, tokens)

        # Check JSON file was created
        json_file = temp_home / ".bountyhound" / "hunts" / "H-test-001" / "auth" / "user_a.json"
        assert json_file.exists()

        # Verify content
        with open(json_file, 'r') as f:
            data = json.load(f)

        assert data["user_id"] == "user_a"
        assert data["target"] == "example.com"
        assert data["credentials"]["email"] == "test@example.com"
        assert data["tokens"]["headers"]["Authorization"] == "Bearer test_token"

    def test_saves_credentials_to_env_file(self, auth_manager, temp_home):
        """Test saving credentials to .env file"""
        creds = {
            "email": "test@example.com",
            "password": "TestPass123!"
        }
        tokens = {
            "headers": {
                "Authorization": "Bearer test_token",
                "X-CSRF-Token": "csrf_token"
            },
            "cookies": [
                {"name": "session", "value": "abc123"}
            ]
        }

        auth_manager.save_credentials("user_a", creds, tokens)

        # Check .env file was created
        env_file = temp_home / "bounty-findings" / "example.com" / "credentials" / "example.com-creds.env"
        assert env_file.exists()

        # Verify content contains expected keys
        content = env_file.read_text()
        assert "USER_A_EMAIL" in content
        assert "USER_A_AUTH_TOKEN" in content

    def test_generates_curl_template(self, auth_manager):
        """Test that curl template is generated correctly"""
        tokens = {
            "headers": {
                "Authorization": "Bearer test_token",
                "X-CSRF-Token": "csrf_123"
            },
            "cookies": [
                {"name": "session", "value": "abc123"}
            ]
        }

        curl_template = auth_manager._generate_curl_template(tokens)

        assert "curl" in curl_template
        assert "Authorization: Bearer test_token" in curl_template
        assert "X-CSRF-Token: csrf_123" in curl_template
        assert "Cookie:" in curl_template


class TestAuthentication:
    """Test authentication methods"""

    def test_authenticate_jwt(self, auth_manager):
        """Test JWT authentication"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSIsImV4cCI6MTk5OTk5OTk5OX0.test"
        }

        with patch('requests.post', return_value=mock_response):
            result = auth_manager.authenticate(
                "jwt",
                username="test",
                password="pass",
                endpoint="https://example.com/login"
            )

        assert "headers" in result
        assert "Authorization" in result["headers"]
        assert result["headers"]["Authorization"].startswith("Bearer ")

    def test_authenticate_oauth2(self, auth_manager):
        """Test OAuth2 client credentials authentication"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }

        with patch('requests.post', return_value=mock_response):
            result = auth_manager.authenticate(
                "oauth2",
                client_id="test_client",
                client_secret="test_secret",
                token_endpoint="https://example.com/oauth/token"
            )

        assert result["access_token"] == "test_access_token"
        assert result["refresh_token"] == "test_refresh_token"
        assert result["headers"]["Authorization"] == "Bearer test_access_token"

    def test_authenticate_session(self, auth_manager):
        """Test session cookie authentication"""
        cookies = [
            {"name": "session", "value": "abc123"},
            {"name": "csrf", "value": "xyz789"}
        ]

        result = auth_manager.authenticate("session", cookies=cookies)

        assert "cookies" in result
        assert "headers" in result
        assert "Cookie" in result["headers"]
        assert "session=abc123" in result["headers"]["Cookie"]

    def test_authenticate_api_key(self, auth_manager):
        """Test API key authentication"""
        result = auth_manager.authenticate(
            "api_key",
            api_key="test_api_key_123",
            header_name="X-API-Key"
        )

        assert result["api_key"] == "test_api_key_123"
        assert result["headers"]["X-API-Key"] == "test_api_key_123"

    def test_authenticate_invalid_method(self, auth_manager):
        """Test that invalid auth method raises error"""
        with pytest.raises(ValueError, match="Unknown auth method"):
            auth_manager.authenticate("invalid_method")


class TestTokenManagement:
    """Test token retrieval and refresh"""

    def test_get_token_returns_token(self, auth_manager):
        """Test getting token for existing user"""
        auth_manager.credentials["user_a"] = {
            "auth_token": "Bearer test_token"
        }

        token = auth_manager.get_token("user_a")
        assert token == "Bearer test_token"

    def test_get_token_returns_none_for_missing_user(self, auth_manager):
        """Test getting token for non-existent user"""
        token = auth_manager.get_token("nonexistent")
        assert token is None

    def test_refresh_token_returns_none_without_refresh_token(self, auth_manager):
        """Test refresh fails when no refresh token available"""
        auth_manager.credentials["user_a"] = {
            "auth_token": "Bearer test_token"
        }

        new_token = auth_manager.refresh_token("user_a")
        assert new_token is None

    def test_refresh_token_returns_none_for_missing_user(self, auth_manager):
        """Test refresh fails for non-existent user"""
        new_token = auth_manager.refresh_token("nonexistent")
        assert new_token is None


class TestAuthTesting:
    """Test authentication validation"""

    def test_test_auth_success(self, auth_manager):
        """Test successful auth validation"""
        mock_response = Mock()
        mock_response.status_code = 200

        with patch('requests.get', return_value=mock_response):
            result = auth_manager.test_auth(
                "https://example.com/api/me",
                "Bearer test_token"
            )

        assert result is True

    def test_test_auth_unauthorized(self, auth_manager):
        """Test auth validation with 401"""
        mock_response = Mock()
        mock_response.status_code = 401

        with patch('requests.get', return_value=mock_response):
            result = auth_manager.test_auth(
                "https://example.com/api/me",
                "Bearer invalid_token"
            )

        assert result is False

    def test_test_auth_post_method(self, auth_manager):
        """Test auth validation with POST method"""
        mock_response = Mock()
        mock_response.status_code = 200

        with patch('requests.post', return_value=mock_response):
            result = auth_manager.test_auth(
                "https://example.com/api/test",
                "Bearer test_token",
                method="POST"
            )

        assert result is True

    def test_test_auth_handles_exceptions(self, auth_manager):
        """Test auth validation handles network errors"""
        with patch('requests.get', side_effect=Exception("Network error")):
            result = auth_manager.test_auth(
                "https://example.com/api/me",
                "Bearer test_token"
            )

        assert result is False


class TestSessionCreation:
    """Test session creation"""

    def test_create_session_with_all_tokens(self, auth_manager):
        """Test creating session with complete credentials"""
        auth_manager.credentials["user_a"] = {
            "auth_token": "Bearer test_token",
            "csrf_token": "csrf_123",
            "session_cookie": "session_abc"
        }

        session = auth_manager.create_session("user_a")

        assert session["headers"]["Authorization"] == "Bearer test_token"
        assert session["headers"]["X-CSRF-Token"] == "csrf_123"
        assert session["cookies"]["session"] == "session_abc"

    def test_create_session_partial_credentials(self, auth_manager):
        """Test creating session with partial credentials"""
        auth_manager.credentials["user_a"] = {
            "auth_token": "Bearer test_token"
        }

        session = auth_manager.create_session("user_a")

        assert session["headers"]["Authorization"] == "Bearer test_token"
        assert "X-CSRF-Token" not in session["headers"]

    def test_create_session_missing_user(self, auth_manager):
        """Test creating session for non-existent user"""
        session = auth_manager.create_session("nonexistent")
        assert session == {}


class TestBrowserTokenExtraction:
    """Test extracting tokens from browser automation"""

    def test_extracts_jwt_from_localstorage(self, auth_manager):
        """Test extracting JWT from localStorage"""
        # Create a test JWT
        exp = int((datetime.now() + timedelta(hours=1)).timestamp())
        test_jwt = pyjwt.encode({"sub": "12345", "exp": exp}, "secret", algorithm="HS256")

        local_storage = {
            "auth_token": test_jwt,
            "other_key": "other_value"
        }

        tokens = auth_manager.extract_tokens_from_browser(
            browser_cookies=[],
            local_storage=local_storage,
            session_storage={},
            network_requests=[]
        )

        assert "Authorization" in tokens["headers"]
        assert tokens["headers"]["Authorization"] == f"Bearer {test_jwt}"

    def test_extracts_auth_from_network_requests(self, auth_manager):
        """Test extracting Authorization header from network requests"""
        network_requests = [
            {
                "request": {
                    "headers": {
                        "Authorization": "Bearer network_token"
                    }
                }
            }
        ]

        tokens = auth_manager.extract_tokens_from_browser(
            browser_cookies=[],
            local_storage={},
            session_storage={},
            network_requests=network_requests
        )

        assert tokens["headers"]["Authorization"] == "Bearer network_token"

    def test_extracts_csrf_from_network_requests(self, auth_manager):
        """Test extracting CSRF token from network requests"""
        network_requests = [
            {
                "request": {
                    "headers": {
                        "X-CSRF-Token": "csrf_from_network"
                    }
                }
            }
        ]

        tokens = auth_manager.extract_tokens_from_browser(
            browser_cookies=[],
            local_storage={},
            session_storage={},
            network_requests=network_requests
        )

        assert tokens["headers"]["X-CSRF-Token"] == "csrf_from_network"

    def test_stores_all_browser_data(self, auth_manager):
        """Test that all browser data is stored in tokens dict"""
        cookies = [{"name": "session", "value": "abc"}]
        local_storage = {"key": "value"}
        session_storage = {"session_key": "session_value"}

        tokens = auth_manager.extract_tokens_from_browser(
            browser_cookies=cookies,
            local_storage=local_storage,
            session_storage=session_storage,
            network_requests=[]
        )

        assert tokens["cookies"] == cookies
        assert tokens["local_storage"] == local_storage
        assert tokens["session_storage"] == session_storage


class TestHelperMethods:
    """Test helper and utility methods"""

    def test_format_cookies(self, auth_manager):
        """Test cookie formatting for Cookie header"""
        cookies = [
            {"name": "session", "value": "abc123"},
            {"name": "csrf", "value": "xyz789"}
        ]

        formatted = auth_manager._format_cookies(cookies)
        assert formatted == "session=abc123; csrf=xyz789"

    def test_format_cookies_empty(self, auth_manager):
        """Test formatting empty cookie list"""
        formatted = auth_manager._format_cookies([])
        assert formatted == ""

    def test_extract_profile_from_jwt(self, auth_manager):
        """Test extracting profile from JWT token"""
        exp = int((datetime.now() + timedelta(hours=1)).timestamp())
        test_jwt = pyjwt.encode(
            {"sub": "user_123", "username": "testuser", "role": "admin", "exp": exp},
            "secret",
            algorithm="HS256"
        )

        tokens = {
            "headers": {
                "Authorization": f"Bearer {test_jwt}"
            }
        }

        profile = auth_manager._extract_profile(tokens)
        assert profile["user_id"] == "user_123"
        assert profile["username"] == "testuser"
        assert profile["role"] == "admin"

    def test_calculate_token_expiry_from_jwt(self, auth_manager):
        """Test calculating token expiry from JWT"""
        exp = int((datetime.now() + timedelta(hours=2)).timestamp())
        test_jwt = pyjwt.encode({"exp": exp}, "secret", algorithm="HS256")

        tokens = {
            "headers": {
                "Authorization": f"Bearer {test_jwt}"
            }
        }

        expiry = auth_manager._calculate_token_expiry(tokens)
        assert expiry is not None
        # Should be approximately 2 hours from now
        expiry_dt = datetime.fromisoformat(expiry)
        diff = (expiry_dt - datetime.now()).total_seconds()
        assert 7000 < diff < 7400  # Around 2 hours

    def test_calculate_refresh_time(self, auth_manager):
        """Test calculating when to refresh token"""
        exp = int((datetime.now() + timedelta(hours=1)).timestamp())
        test_jwt = pyjwt.encode({"exp": exp}, "secret", algorithm="HS256")

        tokens = {
            "headers": {
                "Authorization": f"Bearer {test_jwt}"
            }
        }

        refresh_time = auth_manager._calculate_refresh_time(tokens)
        assert refresh_time is not None

        # Should be 10 minutes before expiry (50 minutes from now)
        refresh_dt = datetime.fromisoformat(refresh_time)
        diff = (refresh_dt - datetime.now()).total_seconds()
        assert 2900 < diff < 3100  # Around 50 minutes


class TestSummaryGeneration:
    """Test summary report generation"""

    def test_generates_summary(self, auth_manager, temp_home):
        """Test generating authentication summary"""
        # Create test user data
        user_a_data = {
            "hunt_id": "H-test-001",
            "target": "example.com",
            "user_id": "user_a",
            "credentials": {"email": "user_a@test.com"},
            "profile": {"user_id": "12345", "role": "user"},
            "curl_template": "curl -H 'Authorization: Bearer token'"
        }

        user_file = temp_home / ".bountyhound" / "hunts" / "H-test-001" / "auth" / "user_a.json"
        with open(user_file, 'w') as f:
            json.dump(user_a_data, f)

        summary = auth_manager.generate_summary(["user_a"])

        assert "## Auth Manager Report" in summary
        assert "example.com" in summary
        assert "H-test-001" in summary
        assert "user_a@test.com" in summary
        assert "12345" in summary

    def test_summary_includes_multiple_users(self, auth_manager, temp_home):
        """Test summary with multiple users"""
        # Create test data for both users
        for user_id in ["user_a", "user_b"]:
            user_data = {
                "hunt_id": "H-test-001",
                "target": "example.com",
                "user_id": user_id,
                "credentials": {"email": f"{user_id}@test.com"},
                "profile": {"user_id": f"id_{user_id}", "role": "user"},
                "curl_template": "curl -H 'Authorization: Bearer token'"
            }

            user_file = temp_home / ".bountyhound" / "hunts" / "H-test-001" / "auth" / f"{user_id}.json"
            with open(user_file, 'w') as f:
                json.dump(user_data, f)

        summary = auth_manager.generate_summary(["user_a", "user_b"])

        assert "user_a@test.com" in summary
        assert "user_b@test.com" in summary
        assert "id_user_a" in summary
        assert "id_user_b" in summary
