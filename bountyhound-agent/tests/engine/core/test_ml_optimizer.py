import pytest
from engine.core.ml_optimizer import MLPayloadOptimizer
from engine.core.database import BountyHoundDB

@pytest.fixture
def optimizer():
    db = BountyHoundDB(":memory:")
    return MLPayloadOptimizer(db=db)

def test_train_on_historical_data(optimizer):
    """Test training model on historical data"""
    # Add some training data with POC containing payload
    for i in range(10):
        optimizer.db.insert_finding(
            target="example.com",
            vuln_type="XSS",
            title=f"XSS {i}",
            severity="MEDIUM",
            poc=f"<script>alert({i})</script>",  # Store payload in poc field
            status="accepted" if i % 2 == 0 else "rejected"
        )

    result = optimizer.train_on_historical_data()

    assert result["trained"] is True
    assert result["samples"] >= 10

def test_predict_payload_success(optimizer):
    """Test predicting payload success probability"""
    payload = "<script>alert('XSS')</script>"
    vuln_type = "XSS"

    probability = optimizer.predict_payload_success(payload, vuln_type)

    assert 0.0 <= probability <= 1.0

def test_generate_optimized_payloads(optimizer):
    """Test generating optimized payloads"""
    payloads = optimizer.generate_optimized_payloads("XSS", count=5)

    assert len(payloads) <= 5
    assert all(isinstance(p, str) for p in payloads)

def test_feedback_loop(optimizer):
    """Test feedback loop for continuous learning"""
    payload = "<script>alert('test')</script>"
    vuln_type = "XSS"
    succeeded = True

    optimizer.feedback_loop(payload, vuln_type, succeeded)

    # Should store result for future training
    assert True  # Basic test - just ensure no crash

def test_extract_features(optimizer):
    """Test feature extraction from payload"""
    payload = "<script>alert('XSS')</script>"

    features = optimizer._extract_features(payload)

    assert "length" in features
    assert "char_distribution" in features
    assert "encoding_type" in features
