"""AI-powered analysis using Groq LLM."""

import json
from typing import Optional

from groq import Groq

from bountyhound.config import Config


class AIAnalyzer:
    """AI analyzer using Groq for intelligent bug bounty assistance."""

    def __init__(self, config: Optional[Config] = None) -> None:
        """Initialize with Groq API key from config."""
        self.config = config or Config.load()
        api_key = self.config.api_keys.get("groq")
        if not api_key:
            raise ValueError("Groq API key not found in config. Add it to ~/.bountyhound/config.yaml")
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.3-70b-versatile"

    def _chat(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat completion request to Groq."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=4096,
        )
        return response.choices[0].message.content

    def parse_campaign_scope(self, page_content: str, url: str) -> dict:
        """Parse bug bounty campaign page to extract scope information."""
        system_prompt = """You are a bug bounty scope parser. Extract structured scope information from campaign pages.

Return ONLY valid JSON with this exact structure:
{
    "program_name": "string",
    "in_scope": [
        {"type": "domain", "target": "example.com", "wildcard": false},
        {"type": "domain", "target": "*.example.com", "wildcard": true}
    ],
    "out_of_scope": ["string list of excluded items"],
    "bounty_range": {"low": 0, "high": 0},
    "notes": "any important rules or restrictions"
}

Only include domains and URLs that can be scanned. Ignore mobile apps, hardware, etc.
For wildcards like *.example.com, set wildcard: true."""

        user_prompt = f"""Parse this bug bounty campaign page and extract the scope.

URL: {url}

Page content:
{page_content[:15000]}"""

        response = self._chat(system_prompt, user_prompt)

        # Extract JSON from response
        try:
            # Try to find JSON in the response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        return {
            "program_name": "Unknown",
            "in_scope": [],
            "out_of_scope": [],
            "bounty_range": {"low": 0, "high": 0},
            "notes": "Failed to parse scope automatically",
        }

    def prioritize_findings(self, findings: list[dict]) -> list[dict]:
        """Analyze and prioritize vulnerability findings."""
        if not findings:
            return []

        system_prompt = """You are a bug bounty expert. Analyze these vulnerability findings and prioritize them.

For each finding, assess:
1. Exploitability (how easy to exploit)
2. Impact (what damage could be done)
3. Bounty potential (likely payout)

Return JSON array with original findings plus these added fields:
- priority: 1-5 (1 = highest priority)
- bounty_estimate: estimated bounty in USD
- reasoning: brief explanation
- next_steps: suggested exploitation/verification steps"""

        user_prompt = f"Prioritize these findings:\n{json.dumps(findings, indent=2)}"

        response = self._chat(system_prompt, user_prompt)

        try:
            start = response.find("[")
            end = response.rfind("]") + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        return findings

    def analyze_target(self, target_data: dict) -> dict:
        """Analyze reconnaissance data and suggest attack vectors."""
        system_prompt = """You are a penetration testing expert. Analyze this reconnaissance data and suggest attack vectors.

Provide:
1. High-value targets (interesting subdomains, services)
2. Potential vulnerabilities based on technologies detected
3. Suggested manual testing steps
4. Priority order for scanning

Return JSON with structure:
{
    "high_value_targets": [{"target": "string", "reason": "string"}],
    "potential_vulns": [{"type": "string", "target": "string", "likelihood": "high/medium/low"}],
    "manual_tests": ["string list of suggested tests"],
    "scan_priority": ["ordered list of targets to scan first"]
}"""

        user_prompt = f"Analyze this target data:\n{json.dumps(target_data, indent=2)}"

        response = self._chat(system_prompt, user_prompt)

        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        return {
            "high_value_targets": [],
            "potential_vulns": [],
            "manual_tests": [],
            "scan_priority": [],
        }

    def generate_report_summary(self, report_data: dict) -> str:
        """Generate an executive summary of findings."""
        system_prompt = """You are a security report writer. Generate a concise executive summary of bug bounty findings.

Include:
1. Overall risk assessment
2. Top findings by severity
3. Estimated total bounty potential
4. Recommended immediate actions

Keep it under 500 words. Use markdown formatting."""

        user_prompt = f"Generate executive summary for:\n{json.dumps(report_data, indent=2)}"

        return self._chat(system_prompt, user_prompt)

    def select_targets(self, recon_data: dict, max_targets: int = 100) -> dict:
        """Select high-value targets from reconnaissance data.

        Args:
            recon_data: Dict with subdomains, live_hosts, ports info
            max_targets: Maximum number of targets to select

        Returns:
            Dict with selected targets, scores, and reasoning
        """
        system_prompt = f"""You are a bug bounty target prioritization expert. Analyze reconnaissance data and select the {max_targets} highest-value targets for vulnerability scanning.

Prioritize targets with:
1. Admin/internal keywords (admin., internal., staging., dev., test.)
2. API endpoints (api., gateway., graphql.)
3. Legacy/outdated technologies
4. Non-standard ports or multiple services
5. Error responses (500s) or access denied (403s) that might be bypassable
6. Missing security headers

Return ONLY valid JSON:
{{
    "selected": [
        {{"target": "hostname", "score": 1-100, "reason": "brief reason"}}
    ],
    "total_analyzed": number,
    "skipped": number,
    "skipped_reason": "why these were deprioritized"
}}

Select at most {max_targets} targets. Higher score = higher priority."""

        user_prompt = f"Analyze and select high-value targets:\n{json.dumps(recon_data, indent=2)}"

        response = self._chat(system_prompt, user_prompt)

        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end > start:
                result = json.loads(response[start:end])
                # Ensure we don't exceed max
                if "selected" in result:
                    result["selected"] = result["selected"][:max_targets]
                return result
        except json.JSONDecodeError:
            pass

        # Fallback: return all targets without scoring
        return {
            "selected": [{"target": h, "score": 50, "reason": "default"} for h in recon_data.get("subdomains", [])[:max_targets]],
            "total_analyzed": len(recon_data.get("subdomains", [])),
            "skipped": 0,
        }
