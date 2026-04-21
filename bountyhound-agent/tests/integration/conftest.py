"""
Shared fixtures for integration tests.

Provides mock implementations and test utilities for integration testing.
"""

import pytest
from typing import Dict, List, Any
from unittest.mock import AsyncMock, Mock


class MockLLM:
    """Mock LLM for deterministic testing"""

    def __init__(self, responses: List[Dict] = None):
        self.responses = responses or []
        self.call_count = 0

    async def messages_create(self, **kwargs):
        """Mock message creation"""
        response_index = min(self.call_count, len(self.responses) - 1)
        self.call_count += 1

        if self.responses:
            response_data = self.responses[response_index]
        else:
            # Default response
            response_data = {
                "hypotheses": [
                    {
                        "title": "Test hypothesis",
                        "test": "Test action",
                        "rationale": "Test rationale",
                        "confidence": "HIGH"
                    }
                ]
            }

        # Mock response object
        mock_response = Mock()
        mock_response.content = [Mock(text=str(response_data))]
        return mock_response


class MockDiscoveryEngine:
    """Mock discovery engine for testing"""

    async def discover(self, target: str) -> Dict:
        """Mock discovery"""
        return {
            "tech_stack": ["GraphQL", "React", "Node.js"],
            "endpoints": [
                "/api/graphql",
                "/api/users",
                "/api/admin"
            ],
            "findings": []
        }


class MockGraphQLTester:
    """Mock GraphQL tester"""

    async def test(self, instruction: str) -> Dict:
        """Mock GraphQL test"""
        return {
            "success": True,
            "finding": {
                "title": "GraphQL introspection enabled",
                "endpoint": "/api/graphql",
                "severity": "LOW",
                "description": "GraphQL introspection query succeeded"
            }
        }


class MockAPITester:
    """Mock API tester"""

    async def test(self, instruction: str) -> Dict:
        """Mock API test"""
        return {
            "success": False,
            "reason": "Endpoint not vulnerable"
        }


@pytest.fixture
def mock_llm():
    """Fixture providing mock LLM"""
    return MockLLM()


@pytest.fixture
def mock_discovery_engine():
    """Fixture providing mock discovery engine"""
    return MockDiscoveryEngine()


@pytest.fixture
def mock_graphql_tester():
    """Fixture providing mock GraphQL tester"""
    return MockGraphQLTester()


@pytest.fixture
def mock_api_tester():
    """Fixture providing mock API tester"""
    return MockAPITester()


@pytest.fixture
def integration_test_db(tmp_path):
    """Fixture providing isolated test database"""
    import sqlite3
    from pathlib import Path

    db_path = tmp_path / "test_bountyhound.db"

    # Create test database with schema
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Create minimal schema for testing
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            title TEXT NOT NULL,
            vuln_type TEXT,
            severity TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS learned_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            tech JSON NOT NULL,
            success_count INTEGER DEFAULT 0,
            failure_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hypothesis_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            hypothesis_title TEXT NOT NULL,
            result TEXT,
            tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS exploit_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            chain_title TEXT NOT NULL,
            steps JSON NOT NULL,
            impact TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

    return str(db_path)
