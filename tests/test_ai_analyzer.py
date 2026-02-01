"""Tests for AI analyzer."""

import pytest
from unittest.mock import patch, MagicMock

from bountyhound.ai import AIAnalyzer


class TestAIAnalyzer:
    """Tests for AIAnalyzer class."""

    @patch("bountyhound.ai.analyzer.Groq")
    @patch("bountyhound.ai.analyzer.Config")
    def test_select_targets_returns_limited_list(self, mock_config_class, mock_groq):
        """Test that select_targets returns limited high-value targets."""
        mock_config = MagicMock()
        mock_config.api_keys = {"groq": "test-key"}
        mock_config_class.load.return_value = mock_config

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '''
        {
            "selected": [
                {"target": "admin.example.com", "score": 95, "reason": "Admin panel"},
                {"target": "api.example.com", "score": 85, "reason": "API endpoint"}
            ],
            "total_analyzed": 100,
            "skipped": 98
        }
        '''
        mock_groq.return_value.chat.completions.create.return_value = mock_response

        analyzer = AIAnalyzer()
        recon_data = {
            "subdomains": ["admin.example.com", "api.example.com", "www.example.com"],
            "live_hosts": [
                {"host": "admin.example.com", "status_code": 200, "tech": ["Apache"]},
                {"host": "api.example.com", "status_code": 200, "tech": ["nginx"]},
            ]
        }

        result = analyzer.select_targets(recon_data, max_targets=50)

        assert "selected" in result
        assert len(result["selected"]) <= 50
