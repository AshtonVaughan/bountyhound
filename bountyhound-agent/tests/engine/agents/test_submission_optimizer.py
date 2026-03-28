import pytest
from datetime import datetime, timedelta
from engine.agents.submission_optimizer import SubmissionOptimizer
from engine.core.database import BountyHoundDB

@pytest.fixture
def optimizer():
    return SubmissionOptimizer()

@pytest.fixture
def test_db():
    db = BountyHoundDB(":memory:")

    # Populate with historical data
    # Program 1: High acceptance for IDOR, fast response
    for i in range(10):
        db.insert_finding(
            target="shopify.com",
            vuln_type="IDOR",
            title=f"IDOR {i}",
            severity="HIGH",
            status="accepted",
            payout=1500.0,
        )

    # Program 2: Low acceptance for XSS, slow response
    for i in range(5):
        db.insert_finding(
            target="example.com",
            vuln_type="XSS",
            title=f"XSS {i}",
            severity="MEDIUM",
            status="duplicate" if i < 3 else "accepted",
            payout=300.0 if i >= 3 else 0.0,
        )

    yield db
    db.close()

def test_recommend_program_for_vuln_type(optimizer, test_db):
    """Test recommending best program for a vulnerability type"""
    result = optimizer.recommend_program("IDOR", db=test_db)

    assert result is not None
    assert len(result["programs"]) > 0
    assert result["programs"][0]["target"] == "shopify.com"
    assert result["programs"][0]["acceptance_rate"] > 0.8
    assert result["programs"][0]["avg_payout"] > 1000

def test_recommend_program_no_history(optimizer, test_db):
    """Test recommendation when no historical data"""
    result = optimizer.recommend_program("SQLi", db=test_db)

    # Should return empty or fallback recommendation
    assert result is not None
    assert "reasoning" in result

def test_recommend_timing(optimizer, test_db):
    """Test recommending best submission timing"""
    result = optimizer.recommend_timing("shopify", db=test_db)

    assert result is not None
    assert "best_day" in result
    assert "best_hour" in result
    assert "avoid_periods" in result

    # Should avoid weekends
    assert "Saturday" in result["avoid_periods"] or "Sunday" in result["avoid_periods"]

def test_optimize_severity(optimizer, test_db):
    """Test severity optimization based on similar findings"""
    finding = {
        "title": "IDOR in user endpoint",
        "description": "Can access other users' data",
        "vuln_type": "IDOR",
        "suggested_severity": "CRITICAL"
    }

    result = optimizer.optimize_severity(finding, "shopify.com", db=test_db)

    assert result is not None
    assert result["recommended_severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert "reasoning" in result

    # Should recommend downgrade from CRITICAL to HIGH based on historical data
    assert result["recommended_severity"] == "HIGH"

def test_generate_submission_plan(optimizer, test_db):
    """Test creating optimized submission schedule"""
    findings = [
        {
            "id": "1",
            "title": "IDOR in user API",
            "description": "Missing auth",
            "vuln_type": "IDOR",
            "severity": "HIGH"
        },
        {
            "id": "2",
            "title": "XSS in search",
            "description": "Reflected XSS",
            "vuln_type": "XSS",
            "severity": "MEDIUM"
        }
    ]

    plan = optimizer.generate_submission_plan(findings, db=test_db)

    assert len(plan) == 2

    # Should prioritize IDOR to shopify (higher payout)
    assert plan[0]["finding"]["id"] == "1"
    assert plan[0]["program"] == "shopify.com"
    assert "timing" in plan[0]
    assert "expected_payout" in plan[0]

def test_calculate_acceptance_rate(optimizer, test_db):
    """Test calculating program acceptance rate"""
    rate = optimizer._calculate_acceptance_rate("shopify.com", "IDOR", db=test_db)

    assert rate >= 0.0
    assert rate <= 1.0
    assert rate == 1.0  # 10/10 accepted

def test_calculate_avg_payout(optimizer, test_db):
    """Test calculating average payout"""
    avg = optimizer._calculate_avg_payout("shopify.com", "IDOR", db=test_db)

    assert avg > 0
    assert avg == 1500.0  # All payouts are $1500

def test_estimate_time_to_triage(optimizer, test_db):
    """Test estimating time to triage"""
    days = optimizer._estimate_time_to_triage("shopify.com", db=test_db)

    assert days >= 0
    # Should be reasonable (1-30 days)
    assert days <= 30
