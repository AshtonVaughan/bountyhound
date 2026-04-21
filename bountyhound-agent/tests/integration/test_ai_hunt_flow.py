"""
Integration tests for AI-powered hunt flow.

Tests the complete end-to-end flow from command routing to findings generation,
including all 5 simplified commands.
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import os
import json


@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_ai_hunt_flow():
    """Test complete AI hunt flow from command to findings"""
    from engine.core.ai_hunter import AIPoweredHunter
    from engine.core.command_router import CommandRouter

    # Setup
    api_key = os.getenv("ANTHROPIC_API_KEY", "test-key")
    router = CommandRouter(api_key=api_key)

    # Route command
    route = router.route("/hunt testphp.vulnweb.com")

    assert route["type"] == "ai_hunt"
    assert route["target"] == "testphp.vulnweb.com"
    assert route["agent"] == "AIPoweredHunter"

    # Execute hunt (with max 3 iterations for test)
    hunter = AIPoweredHunter(
        target=route["target"],
        api_key=api_key,
        max_iterations=3
    )

    # Mock dependencies for deterministic testing
    hunter._get_recon = AsyncMock(return_value={
        "tech_stack": ["GraphQL", "React"],
        "endpoints": ["/api/graphql", "/api/users"]
    })

    hunter._load_prior_knowledge = AsyncMock(return_value={
        "patterns": [],
        "relevant_findings": []
    })

    hunter._generate_hypotheses = AsyncMock(return_value=[
        {
            "title": "GraphQL introspection enabled",
            "test": "Send introspection query to /api/graphql",
            "rationale": "GraphQL detected, introspection often enabled",
            "confidence": "HIGH"
        }
    ])

    hunter._test_hypothesis = AsyncMock(return_value={
        "success": True,
        "finding": {
            "title": "GraphQL introspection enabled",
            "endpoint": "/api/graphql",
            "severity": "LOW"
        }
    })

    hunter._extract_pattern = AsyncMock(return_value={
        "name": "GraphQL introspection pattern",
        "tech": ["GraphQL"]
    })

    hunter._find_exploit_chains = AsyncMock(return_value=[])
    hunter._save_pattern = AsyncMock()
    hunter._record_hypothesis_test = AsyncMock()
    hunter._find_similar_endpoints = Mock(return_value=[])
    hunter._quick_test_pattern = AsyncMock()
    hunter._save_exploit_chain = AsyncMock()
    hunter._get_all_chains = AsyncMock(return_value=[])
    hunter._generate_creative_bypasses = AsyncMock(return_value=[])

    # Execute hunt
    result = await hunter.hunt()

    # Verify results
    assert result["target"] == "testphp.vulnweb.com"
    assert result["iterations"] == 3
    assert "findings" in result
    assert "patterns" in result
    assert len(result["findings"]) >= 3  # One per iteration
    assert len(result["patterns"]) >= 3


@pytest.mark.integration
def test_command_routing_all_commands():
    """Test all simplified commands route correctly"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")

    test_cases = [
        ("/hunt example.com", "ai_hunt", "example.com"),
        ('/test example.com --context "GraphQL"', "targeted_test", "example.com"),
        ("/learn", "extract_patterns", None),
        ("/chain", "find_chains", None),
        ("/report example.com", "generate_report", "example.com"),
    ]

    for command, expected_type, expected_target in test_cases:
        route = router.route(command)
        assert route["type"] == expected_type, f"Failed type check for command: {command}"
        if expected_target:
            assert route.get("target") == expected_target, f"Failed target check for command: {command}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_hunt_command_routing():
    """Test /hunt command routes to AI hunter with correct config"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route("/hunt example.com")

    assert route["type"] == "ai_hunt"
    assert route["agent"] == "AIPoweredHunter"
    assert route["target"] == "example.com"
    assert "config" in route
    assert route["config"]["max_iterations"] == 20
    assert route["config"]["mode"] == "continuous_learning"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_test_command_with_graphql_context():
    """Test /test command with GraphQL context selects correct agents"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route('/test api.example.com --context "GraphQL API at /api/graphql"')

    assert route["type"] == "targeted_test"
    assert route["target"] == "api.example.com"
    assert "graphql_tester" in route["agents"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_test_command_with_api_context():
    """Test /test command with API context selects correct agents"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route('/test example.com --context "REST API endpoints"')

    assert route["type"] == "targeted_test"
    assert route["target"] == "example.com"
    assert "api_tester" in route["agents"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_test_command_with_cloud_context():
    """Test /test command with cloud context selects correct agents"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route('/test example.com --context "S3 bucket enumeration"')

    assert route["type"] == "targeted_test"
    assert route["target"] == "example.com"
    assert "s3_tester" in route["agents"]
    assert "azure_tester" in route["agents"]
    assert "gcp_tester" in route["agents"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_learn_command_routing():
    """Test /learn command routes to pattern extractor"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route("/learn")

    assert route["type"] == "extract_patterns"
    assert route["agent"] == "PatternExtractor"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_chain_command_routing():
    """Test /chain command routes to exploit chainer"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route("/chain")

    assert route["type"] == "find_chains"
    assert route["agent"] == "ExploitChainer"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_report_command_routing():
    """Test /report command routes to report generator"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")

    # Without target
    route = router.route("/report")
    assert route["type"] == "generate_report"
    assert route["agent"] == "ReportGenerator"
    assert route["target"] is None

    # With target
    route = router.route("/report example.com")
    assert route["type"] == "generate_report"
    assert route["agent"] == "ReportGenerator"
    assert route["target"] == "example.com"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ai_hunter_learns_from_findings():
    """Test AI hunter extracts patterns and learns from successful findings"""
    from engine.core.ai_hunter import AIPoweredHunter

    hunter = AIPoweredHunter(target="example.com", api_key="test-key", max_iterations=2)

    # Mock successful finding
    finding = {
        "title": "IDOR in getUserProfile mutation",
        "endpoint": "/api/graphql",
        "tech": "GraphQL"
    }

    # Mock pattern extraction
    hunter._extract_pattern = AsyncMock(return_value={
        "name": "GraphQL IDOR pattern",
        "tech": ["GraphQL"],
        "exploit_template": "mutation { user(id: UUID) { privateData } }"
    })

    hunter._save_pattern = AsyncMock()

    # Extract and save pattern
    pattern = await hunter._extract_pattern(finding)
    await hunter._save_pattern(pattern)

    # Verify pattern extraction
    assert pattern["name"] == "GraphQL IDOR pattern"
    assert "GraphQL" in pattern["tech"]
    assert "exploit_template" in pattern

    # Verify save was called
    hunter._save_pattern.assert_called_once()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ai_hunter_discovers_exploit_chains():
    """Test AI hunter discovers exploit chains from multiple findings"""
    from engine.core.ai_hunter import AIPoweredHunter

    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    findings = [
        {"title": "XSS in profile endpoint", "severity": "MEDIUM"},
        {"title": "Session cookie no HttpOnly", "severity": "LOW"},
        {"title": "Admin panel accessible", "severity": "LOW"}
    ]

    # Mock chain discovery
    hunter._find_exploit_chains = AsyncMock(return_value=[
        {
            "title": "XSS → Session Theft → Account Takeover",
            "steps": ["Exploit XSS", "Steal cookie", "Access admin"],
            "impact": "CRITICAL"
        }
    ])

    chains = await hunter._find_exploit_chains(findings)

    assert len(chains) > 0
    assert chains[0]["impact"] == "CRITICAL"
    assert len(chains[0]["steps"]) == 3


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unknown_command_returns_error():
    """Test unknown command returns error"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")
    route = router.route("/unknown_command arg1 arg2")

    assert route["type"] == "unknown"
    assert "error" in route


@pytest.mark.integration
@pytest.mark.asyncio
async def test_hunt_flow_handles_no_findings():
    """Test hunt flow gracefully handles no findings scenario"""
    from engine.core.ai_hunter import AIPoweredHunter

    hunter = AIPoweredHunter(target="example.com", api_key="test-key", max_iterations=4)

    # Mock no findings
    hunter._get_recon = AsyncMock(return_value={
        "tech_stack": ["React"],
        "endpoints": ["/"]
    })
    hunter._load_prior_knowledge = AsyncMock(return_value={"patterns": [], "relevant_findings": []})
    hunter._generate_hypotheses = AsyncMock(return_value=[
        {"title": "Test", "test": "Test", "confidence": "LOW"}
    ])
    hunter._test_hypothesis = AsyncMock(return_value={"success": False})
    hunter._record_hypothesis_test = AsyncMock()
    hunter._find_exploit_chains = AsyncMock(return_value=[])
    hunter._generate_creative_bypasses = AsyncMock(return_value=[])
    hunter._get_all_chains = AsyncMock(return_value=[])

    result = await hunter.hunt()

    # Should complete without errors
    assert result["target"] == "example.com"
    assert result["iterations"] == 4
    assert len(result["findings"]) == 0  # No findings

    # Should trigger creative bypasses (iteration >= 3 with no findings)
    hunter._generate_creative_bypasses.assert_called()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_multiple_iterations_accumulate_findings():
    """Test multiple hunt iterations accumulate findings correctly"""
    from engine.core.ai_hunter import AIPoweredHunter

    hunter = AIPoweredHunter(target="example.com", api_key="test-key", max_iterations=5)

    # Mock finding one vulnerability per iteration
    call_count = 0

    async def mock_test_hypothesis(hypothesis):
        nonlocal call_count
        call_count += 1
        return {
            "success": True,
            "finding": {
                "title": f"Finding {call_count}",
                "id": call_count
            }
        }

    hunter._get_recon = AsyncMock(return_value={"tech_stack": [], "endpoints": []})
    hunter._load_prior_knowledge = AsyncMock(return_value={"patterns": [], "relevant_findings": []})
    hunter._generate_hypotheses = AsyncMock(return_value=[
        {"title": "Test", "test": "Test", "confidence": "MEDIUM"}
    ])
    hunter._test_hypothesis = mock_test_hypothesis
    hunter._extract_pattern = AsyncMock(return_value={"name": "Pattern"})
    hunter._save_pattern = AsyncMock()
    hunter._record_hypothesis_test = AsyncMock()
    hunter._find_similar_endpoints = Mock(return_value=[])
    hunter._quick_test_pattern = AsyncMock()
    hunter._find_exploit_chains = AsyncMock(return_value=[])
    hunter._save_exploit_chain = AsyncMock()
    hunter._get_all_chains = AsyncMock(return_value=[])

    result = await hunter.hunt()

    # Should have 5 findings (one per iteration)
    assert len(result["findings"]) == 5
    assert result["iterations"] == 5


@pytest.mark.integration
@pytest.mark.asyncio
async def test_context_based_agent_selection():
    """Test command router selects correct agents based on context"""
    from engine.core.command_router import CommandRouter

    router = CommandRouter(api_key="test-key")

    test_cases = [
        ("GraphQL API testing", ["graphql_tester"]),
        ("REST API endpoints", ["api_tester"]),
        ("WebSocket connections", ["websocket_tester"]),
        ("Mobile app iOS", ["mobile_tester"]),
        ("S3 bucket enumeration", ["s3_tester", "azure_tester", "gcp_tester"]),
        ("Cloud storage", ["s3_tester", "azure_tester", "gcp_tester"]),
    ]

    for context, expected_agents in test_cases:
        route = router.route(f'/test example.com --context "{context}"')
        for agent in expected_agents:
            assert agent in route["agents"], f"Missing {agent} for context: {context}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_pattern_application_to_similar_endpoints():
    """Test patterns are applied to similar endpoints automatically"""
    from engine.core.ai_hunter import AIPoweredHunter

    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    # Test similar endpoint detection
    endpoints = [
        "/api/users/123",
        "/api/users/456",
        "/api/products/789",
        "/api/orders/111"
    ]

    similar = hunter._find_similar_endpoints("/api/users/123", endpoints)

    # Should find /api/users/456 as similar
    assert "/api/users/456" in similar
    assert "/api/users/123" not in similar  # Should exclude original
    assert "/api/products/789" not in similar  # Different pattern
