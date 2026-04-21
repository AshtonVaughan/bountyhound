import pytest
import requests
import json
from tests.fixtures.mock_target import start_mock_target


@pytest.fixture(scope="module")
def target():
    server = start_mock_target(port=18080)
    yield "http://127.0.0.1:18080"
    server.shutdown()


class TestTargetReachability:
    def test_homepage_returns_200(self, target):
        resp = requests.get(target, timeout=5)
        assert resp.status_code == 200

    def test_api_endpoint_exists(self, target):
        resp = requests.get(f"{target}/api/users/1", timeout=5)
        assert resp.status_code == 200
        assert resp.json()["id"] == 1


class TestIDORDetection:
    def test_different_user_data_accessible(self, target):
        resp1 = requests.get(f"{target}/api/users/1", timeout=5)
        resp2 = requests.get(f"{target}/api/users/2", timeout=5)
        assert resp1.json()["email"] != resp2.json()["email"]
        assert resp2.json()["email"] == "admin@test.com"

    def test_no_auth_required_for_other_user(self, target):
        resp = requests.get(f"{target}/api/users/2", timeout=5)
        assert resp.status_code == 200


class TestCORSMisconfiguration:
    def test_origin_reflection(self, target):
        resp = requests.get(target, headers={"Origin": "http://evil.com"}, timeout=5)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        assert acao == "http://evil.com" or acao == "*"

    def test_credentials_allowed(self, target):
        resp = requests.get(target, headers={"Origin": "http://evil.com"}, timeout=5)
        assert resp.headers.get("Access-Control-Allow-Credentials") == "true"

    def test_cors_exploitable(self, target):
        resp = requests.get(target, headers={"Origin": "http://evil.com"}, timeout=5)
        acao = resp.headers.get("Access-Control-Allow-Origin")
        creds = resp.headers.get("Access-Control-Allow-Credentials")
        assert acao and creds == "true"  # CORS + credentials = exploitable


class TestOpenRedirect:
    def test_redirect_to_external(self, target):
        resp = requests.get(f"{target}/redirect?url=http://evil.com", allow_redirects=False, timeout=5)
        assert resp.status_code == 302
        assert "evil.com" in resp.headers.get("Location", "")


class TestInfoDisclosure:
    def test_env_file_exposed(self, target):
        resp = requests.get(f"{target}/.env", timeout=5)
        assert resp.status_code == 200
        assert "DB_PASSWORD" in resp.text
        assert "API_KEY" in resp.text

    def test_server_header_disclosed(self, target):
        resp = requests.get(target, timeout=5)
        assert "Server" in resp.headers


class TestGraphQLIntrospection:
    def test_introspection_enabled(self, target):
        resp = requests.get(f"{target}/graphql", timeout=5)
        data = resp.json()
        assert "__schema" in data.get("data", {})
