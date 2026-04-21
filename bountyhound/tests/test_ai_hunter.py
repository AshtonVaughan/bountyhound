import pytest
from engine.core.ai_hunter import AIPoweredHunter


class MockMessages:
    """Mock Messages API"""
    def __init__(self, response):
        self.response = response

    async def create(self, **kwargs):
        class MockContent:
            def __init__(self, text):
                self.text = text

        class MockMessage:
            def __init__(self, response_dict):
                import json
                if "hypotheses" in response_dict:
                    text = json.dumps(response_dict["hypotheses"])
                elif "chains" in response_dict:
                    text = json.dumps(response_dict["chains"])
                else:
                    text = json.dumps(response_dict)
                self.content = [MockContent(text)]

        return MockMessage(self.response)


class MockLLM:
    """Mock LLM for testing"""
    def __init__(self, response=None):
        self.response = response or {}
        self.messages = MockMessages(self.response)


@pytest.mark.asyncio
async def test_ai_hunter_initialization():
    """Test AI hunter initializes with target and API key"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    assert hunter.target == "example.com"
    assert hunter.api_key == "test-key"
    assert hunter.findings == []
    assert hunter.patterns == []
    assert hunter.iteration == 0


@pytest.mark.asyncio
async def test_generate_hypotheses_from_recon():
    """Test hypothesis generation from reconnaissance data"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    recon = {
        "tech_stack": ["GraphQL", "React", "Node.js"],
        "endpoints": ["/api/graphql", "/api/users"],
        "findings": []
    }

    # Mock LLM response
    hunter.llm = MockLLM(response={
        "hypotheses": [
            {
                "title": "GraphQL introspection may be enabled",
                "test": "Send introspection query to /api/graphql",
                "rationale": "GraphQL detected, introspection often left enabled in production"
            }
        ]
    })

    hypotheses = await hunter._generate_hypotheses(recon, [], [])

    assert len(hypotheses) > 0
    assert hypotheses[0]["title"] == "GraphQL introspection may be enabled"
    assert "test" in hypotheses[0]
    assert "rationale" in hypotheses[0]


@pytest.mark.asyncio
async def test_extract_pattern_from_finding():
    """Test pattern extraction from successful finding"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")
    hunter.llm = MockLLM(response={
        "name": "GraphQL IDOR via UUID enumeration",
        "tech": ["GraphQL"],
        "indicators": ["GraphQL mutation", "UUID parameter", "No auth check"],
        "exploit_template": "mutation { user(id: UUID) { email } }",
        "confidence": "HIGH"
    })

    finding = {
        "title": "IDOR in getUserProfile mutation",
        "endpoint": "/api/graphql",
        "method": "POST",
        "payload": 'mutation { user(id: "123-456") { email privateData } }',
        "response": '{"data": {"user": {"email": "victim@example.com"}}}',
        "tech": "GraphQL"
    }

    pattern = await hunter._extract_pattern(finding)

    assert pattern["name"] == "GraphQL IDOR via UUID enumeration"
    assert "GraphQL" in pattern["tech"]
    assert "exploit_template" in pattern


@pytest.mark.asyncio
async def test_find_exploit_chains():
    """Test finding exploit chains from multiple findings"""
    hunter = AIPoweredHunter(target="example.com", api_key="test-key")
    hunter.llm = MockLLM(response={
        "chains": [
            {
                "title": "XSS → Session Theft → Account Takeover",
                "steps": [
                    "1. Exploit XSS in /profile endpoint",
                    "2. Steal session cookie via XSS payload",
                    "3. Use stolen cookie to access admin panel"
                ],
                "impact": "CRITICAL",
                "confidence": "HIGH"
            }
        ]
    })

    findings = [
        {"title": "XSS in profile endpoint", "severity": "MEDIUM"},
        {"title": "Admin panel accessible with valid session", "severity": "LOW"},
        {"title": "Session cookie has no HttpOnly flag", "severity": "LOW"}
    ]

    chains = await hunter._find_exploit_chains(findings)

    assert len(chains) > 0
    assert "XSS" in chains[0]["title"]
    assert chains[0]["impact"] == "CRITICAL"
    assert len(chains[0]["steps"]) >= 2


@pytest.mark.asyncio
async def test_load_prior_knowledge_from_database():
    """Test loading successful patterns from database"""
    from engine.core.database import BountyHoundDB

    hunter = AIPoweredHunter(target="example.com", api_key="test-key")

    # Mock database with prior successful patterns
    # Use in-memory database for testing
    db = BountyHoundDB(db_path=":memory:")

    # Override the hunter's database
    hunter.db = db

    # Manually insert a test pattern
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO learned_patterns (name, tech, success_count, failure_count, targets_succeeded)
            VALUES (?, ?, ?, ?, ?)
        """, ("GraphQL IDOR", '["GraphQL"]', 3, 1, '["target1.com", "target2.com"]'))

    prior_knowledge = await hunter._load_prior_knowledge()

    assert len(prior_knowledge.get("patterns", [])) > 0
    assert prior_knowledge["patterns"][0]["name"] == "GraphQL IDOR"
    assert prior_knowledge["patterns"][0]["success_rate"] >= 0.5


@pytest.mark.asyncio
async def test_hunt_loop_executes_iterations():
    """Test main hunt loop executes multiple iterations"""
    from unittest.mock import AsyncMock

    hunter = AIPoweredHunter(target="example.com", api_key="test-key", max_iterations=3)

    # Mock all dependencies
    hunter._get_recon = AsyncMock(return_value={
        "tech_stack": ["GraphQL"],
        "endpoints": ["/api/graphql"]
    })
    hunter._load_prior_knowledge = AsyncMock(return_value={"patterns": [], "relevant_findings": []})
    hunter._generate_hypotheses = AsyncMock(return_value=[
        {"title": "Test hypothesis", "test": "Test", "confidence": "HIGH"}
    ])
    hunter._test_hypothesis = AsyncMock(return_value={
        "success": True,
        "finding": {"title": "Test finding", "endpoint": "/api/graphql"}
    })
    hunter._extract_pattern = AsyncMock(return_value={"name": "Test pattern"})
    hunter._find_exploit_chains = AsyncMock(return_value=[])
    hunter._save_pattern = AsyncMock()
    hunter._record_hypothesis_test = AsyncMock()
    hunter._find_similar_endpoints = lambda endpoint, endpoints: []
    hunter._quick_test_pattern = AsyncMock()
    hunter._save_exploit_chain = AsyncMock()
    hunter._get_all_chains = AsyncMock(return_value=[])
    hunter._generate_creative_bypasses = AsyncMock(return_value=[])

    await hunter.hunt()

    assert hunter.iteration == 3
    assert len(hunter.findings) > 0
    assert len(hunter.patterns) > 0
