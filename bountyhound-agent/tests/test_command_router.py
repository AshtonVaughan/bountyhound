import pytest
from engine.core.command_router import CommandRouter

def test_command_router_initialization():
    """Test command router initializes correctly"""
    router = CommandRouter(api_key="test-key")

    assert router.api_key == "test-key"
    assert hasattr(router, 'route')

def test_route_hunt_command():
    """Test routing /hunt command to AI hunter"""
    router = CommandRouter(api_key="test-key")

    command = "/hunt example.com"
    route = router.route(command)

    assert route["type"] == "ai_hunt"
    assert route["target"] == "example.com"
    assert route["agent"] == "AIPoweredHunter"

def test_route_test_command_with_context():
    """Test routing /test with intelligent context detection"""
    router = CommandRouter(api_key="test-key")

    # GraphQL context
    command = "/test example.com --context 'GraphQL API at /api/graphql'"
    route = router.route(command)

    assert route["type"] == "targeted_test"
    assert "graphql_tester" in route["agents"]

def test_route_test_command_without_context():
    """Test routing /test without context uses discovery engine"""
    router = CommandRouter(api_key="test-key")

    command = "/test example.com"
    route = router.route(command)

    assert route["type"] == "targeted_test"
    assert route["target"] == "example.com"
    assert route["agents"] == ["discovery_engine"]

def test_route_learn_command():
    """Test routing /learn command to pattern extraction"""
    router = CommandRouter(api_key="test-key")

    command = "/learn"
    route = router.route(command)

    assert route["type"] == "extract_patterns"
    assert route["agent"] == "PatternExtractor"

def test_route_chain_command():
    """Test routing /chain command to exploit chainer"""
    router = CommandRouter(api_key="test-key")

    command = "/chain"
    route = router.route(command)

    assert route["type"] == "find_chains"
    assert route["agent"] == "ExploitChainer"

def test_route_report_command_with_target():
    """Test routing /report with specific target"""
    router = CommandRouter(api_key="test-key")

    command = "/report example.com"
    route = router.route(command)

    assert route["type"] == "generate_report"
    assert route["agent"] == "ReportGenerator"
    assert route["target"] == "example.com"

def test_route_report_command_without_target():
    """Test routing /report without target (all targets)"""
    router = CommandRouter(api_key="test-key")

    command = "/report"
    route = router.route(command)

    assert route["type"] == "generate_report"
    assert route["agent"] == "ReportGenerator"
    assert route["target"] is None

def test_route_unknown_command():
    """Test routing unknown command returns error"""
    router = CommandRouter(api_key="test-key")

    command = "/unknown xyz"
    route = router.route(command)

    assert route["type"] == "unknown"
    assert "error" in route

def test_select_agents_graphql():
    """Test agent selection for GraphQL context"""
    router = CommandRouter(api_key="test-key")

    agents = router._select_agents_from_context("GraphQL API at /api/graphql")

    assert "graphql_tester" in agents

def test_select_agents_api():
    """Test agent selection for REST API context"""
    router = CommandRouter(api_key="test-key")

    agents = router._select_agents_from_context("REST API endpoints")

    assert "api_tester" in agents

def test_select_agents_websocket():
    """Test agent selection for WebSocket context"""
    router = CommandRouter(api_key="test-key")

    agents = router._select_agents_from_context("WebSocket connection at ws://example.com")

    assert "websocket_tester" in agents

def test_select_agents_cloud():
    """Test agent selection for cloud/S3 context"""
    router = CommandRouter(api_key="test-key")

    agents = router._select_agents_from_context("S3 bucket enumeration and cloud storage")

    assert "s3_tester" in agents
    assert "azure_tester" in agents
    assert "gcp_tester" in agents

def test_select_agents_mobile():
    """Test agent selection for mobile context"""
    router = CommandRouter(api_key="test-key")

    agents = router._select_agents_from_context("Mobile app for iOS and Android")

    assert "mobile_tester" in agents

def test_select_agents_multiple_techs():
    """Test agent selection for multiple technologies"""
    router = CommandRouter(api_key="test-key")

    agents = router._select_agents_from_context("GraphQL API with WebSocket real-time updates")

    assert "graphql_tester" in agents
    assert "websocket_tester" in agents
