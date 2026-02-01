"""Tests for data models."""

from datetime import datetime

from bountyhound.storage.models import Target, Subdomain, Port, Finding, Run


def test_target_model():
    target = Target(id=1, domain="example.com", added_at=datetime.now())
    assert target.domain == "example.com"
    assert target.last_recon is None


def test_subdomain_model():
    sub = Subdomain(
        id=1,
        target_id=1,
        hostname="api.example.com",
        ip_address="1.2.3.4",
        status_code=200,
        technologies=["nginx", "php"],
    )
    assert sub.hostname == "api.example.com"
    assert "nginx" in sub.technologies


def test_finding_model():
    finding = Finding(
        id=1,
        subdomain_id=1,
        name="SQL Injection",
        severity="high",
        url="https://api.example.com/login",
        evidence="Error: SQL syntax",
        template="sqli-detection",
    )
    assert finding.severity == "high"


def test_run_model():
    run = Run(
        id=1,
        target_id=1,
        stage="recon",
        started_at=datetime.now(),
        status="running",
    )
    assert run.status == "running"
