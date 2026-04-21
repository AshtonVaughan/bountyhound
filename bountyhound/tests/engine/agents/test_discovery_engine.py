import pytest
from engine.agents.discovery_engine import DiscoveryEngine, HypothesisCard, Confidence

class TestDiscoveryEngine:
    def setup_method(self):
        self.engine = DiscoveryEngine()

    def test_generates_hypotheses_from_tech_stack(self):
        """Given a tech stack, generate relevant vulnerability hypotheses."""
        recon_data = {
            "tech_stack": ["Rails", "PostgreSQL", "Redis", "GraphQL"],
            "endpoints": ["/api/graphql", "/api/v1/users", "/admin"],
            "subdomains": ["api.example.com", "admin.example.com"],
        }
        cards = self.engine.generate_hypotheses(recon_data)
        assert len(cards) >= 5
        assert all(isinstance(c, HypothesisCard) for c in cards)
        # Rails + GraphQL should trigger specific hypotheses
        titles = [c.title.lower() for c in cards]
        assert any("graphql" in t for t in titles)

    def test_hypothesis_card_has_required_fields(self):
        """Every card must have title, confidence, test_method, success_indicator."""
        recon_data = {
            "tech_stack": ["Node.js", "Express"],
            "endpoints": ["/api/login"],
            "subdomains": ["app.example.com"],
        }
        cards = self.engine.generate_hypotheses(recon_data)
        for card in cards:
            assert card.title
            assert card.confidence in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)
            assert card.test_method
            assert card.success_indicator

    def test_uses_past_payloads_from_database(self):
        """Engine should prioritize hypothesis types that worked before."""
        recon_data = {
            "tech_stack": ["React", "Node.js"],
            "endpoints": ["/api/users"],
            "subdomains": [],
            "successful_vuln_types": ["IDOR", "XSS"],  # From database
        }
        cards = self.engine.generate_hypotheses(recon_data)
        # IDOR and XSS should be HIGH confidence since they worked before
        idor_cards = [c for c in cards if "idor" in c.title.lower()]
        assert len(idor_cards) > 0
        assert idor_cards[0].confidence == Confidence.HIGH

    def test_gap_triggered_second_wave(self):
        """When first wave finds nothing, generate second wave hypotheses."""
        first_wave_results = {
            "tested": ["IDOR", "XSS", "SQLi"],
            "failed": ["IDOR", "XSS", "SQLi"],
            "defenses_observed": ["WAF: Cloudflare", "Rate limit: 100/min"],
            "error_messages": ["403 Forbidden", "Rate limit exceeded"],
        }
        cards = self.engine.generate_second_wave(first_wave_results)
        assert len(cards) >= 3
        # Should suggest WAF bypass, timing attacks, business logic
        titles = [c.title.lower() for c in cards]
        assert any("bypass" in t or "logic" in t or "timing" in t for t in titles)
