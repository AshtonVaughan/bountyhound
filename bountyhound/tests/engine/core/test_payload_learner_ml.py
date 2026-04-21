"""
Integration tests for PayloadLearner with ML optimization
"""
import pytest
from engine.core.payload_learner import PayloadLearner
from engine.core.database import BountyHoundDB


@pytest.fixture
def learner():
    """Create PayloadLearner with in-memory database"""
    db = BountyHoundDB(":memory:")
    learner = PayloadLearner()
    learner.db = db
    learner.ml_optimizer.db = db
    return learner


def test_ml_optimized_payloads_integration(learner):
    """Test ML-optimized payload generation through PayloadLearner"""
    # Add training data
    for i in range(10):
        learner.db.insert_finding(
            target="example.com",
            vuln_type="XSS",
            title=f"XSS {i}",
            severity="MEDIUM",
            poc=f"<script>alert({i})</script>",
            status="accepted" if i % 2 == 0 else "rejected"
        )

    # Get ML-optimized payloads
    payloads = learner.get_ml_optimized_payloads("XSS", count=5)

    assert len(payloads) <= 5
    assert all(isinstance(p, str) for p in payloads)


def test_score_payload_integration(learner):
    """Test payload scoring through PayloadLearner"""
    # Add training data
    for i in range(10):
        learner.db.insert_finding(
            target="example.com",
            vuln_type="XSS",
            title=f"XSS {i}",
            severity="MEDIUM",
            poc=f"<script>alert({i})</script>",
            status="accepted"
        )

    # Score a payload
    score = learner.score_payload("<script>alert('test')</script>", "XSS")

    assert 0.0 <= score <= 1.0


def test_train_ml_model_integration(learner):
    """Test ML model training through PayloadLearner"""
    # Add training data
    for i in range(10):
        learner.db.insert_finding(
            target="example.com",
            vuln_type="XSS",
            title=f"XSS {i}",
            severity="MEDIUM",
            poc=f"<script>alert({i})</script>",
            status="accepted" if i % 2 == 0 else "rejected"
        )

    # Train model
    result = learner.train_ml_model()

    assert result["trained"] is True
    assert result["samples"] >= 10
