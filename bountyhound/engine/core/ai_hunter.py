import asyncio
import subprocess
import os
import re as regex_module
import tempfile
from typing import List, Dict, Any, Optional
from anthropic import AsyncAnthropic
import json


class AIPoweredHunter:
    """AI-powered continuous learning bug bounty hunter"""

    def __init__(self, target: str, api_key: str, max_iterations: int = 20, db=None):
        self.target = target
        self.api_key = api_key
        self.max_iterations = max_iterations
        self.llm = AsyncAnthropic(api_key=api_key)

        # Database for learning
        if db is None:
            from engine.core.database import BountyHoundDB
            self.db = BountyHoundDB.get_instance()
        else:
            self.db = db

        # State tracking
        self.findings: List[Dict] = []
        self.patterns: List[Dict] = []
        self.iteration: int = 0
        self.tested_hypotheses: List[str] = []

    async def _generate_hypotheses(
        self,
        recon: Dict,
        findings: List[Dict],
        prior_knowledge: List[Dict]
    ) -> List[Dict]:
        """Generate attack hypotheses using AI reasoning"""

        prompt = self._build_hypothesis_prompt(recon, findings, prior_knowledge)

        response = await self.llm.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        return self._parse_hypotheses(response.content[0].text)

    @staticmethod
    def _summarize_findings(findings: List[Dict]) -> str:
        """Summarize findings to minimal prompt-friendly format."""
        if not findings:
            return "None"
        lines = []
        for f in findings[-5:]:
            title = f.get('title', 'Unknown')[:60]
            severity = f.get('severity', '?')
            vtype = f.get('vuln_type', f.get('type', '?'))
            endpoint = f.get('endpoint', '')[:40]
            lines.append(f"- [{severity}] {vtype}: {title} ({endpoint})")
        return '\n'.join(lines)

    @staticmethod
    def _summarize_patterns(patterns: List[Dict]) -> str:
        """Summarize patterns to minimal prompt-friendly format."""
        if not patterns:
            return "None"
        lines = []
        for p in patterns[:10]:
            name = p.get('name', 'Unknown')[:50]
            rate = p.get('success_rate', 0)
            tech = ', '.join(p.get('tech', []))[:30]
            lines.append(f"- {name} (rate:{rate:.0%}, tech:{tech})")
        return '\n'.join(lines)

    def _build_hypothesis_prompt(self, recon: Dict, findings: List[Dict], prior_knowledge: List[Dict]) -> str:
        """Build prompt for hypothesis generation (compact format)"""

        return f"""You are an expert bug bounty hunter analyzing {self.target}.

CURRENT INTELLIGENCE:
- Tech Stack: {', '.join(recon.get('tech_stack', []))}
- Discovered Endpoints: {len(recon.get('endpoints', []))} endpoints
- Findings So Far: {len(findings)} vulnerabilities found
- Prior Successful Patterns: {len(prior_knowledge)} known patterns

FINDINGS SUMMARY:
{self._summarize_findings(findings)}

SUCCESSFUL PATTERNS FROM DATABASE:
{self._summarize_patterns(prior_knowledge)}

TASK: Generate 10 specific, actionable hypotheses for what to test next.

For each hypothesis, provide:
1. Title: Clear, specific vulnerability to test
2. Test: Exact test to perform (endpoint, payload, method)
3. Rationale: Why this is likely to work based on intelligence
4. Confidence: HIGH/MEDIUM/LOW

Think creatively about:
- Patterns from successful findings
- Exploit chaining opportunities
- Unconventional attack vectors
- Cross-domain knowledge transfer
- Tech-specific vulnerabilities

Return ONLY valid JSON array:
[
  {{
    "title": "Specific vulnerability hypothesis",
    "test": "Exact test to perform",
    "rationale": "Why this should work",
    "confidence": "HIGH"
  }}
]"""

    def _parse_hypotheses(self, response_text: str) -> List[Dict]:
        """Parse LLM response into structured hypotheses"""
        try:
            # Extract JSON from response
            start = response_text.find('[')
            end = response_text.rfind(']') + 1

            if start == -1 or end == 0:
                return []

            json_text = response_text[start:end]
            hypotheses = json.loads(json_text)

            return hypotheses
        except Exception as e:
            print(f"Failed to parse hypotheses: {e}")
            return []

    async def _extract_pattern(self, finding: Dict) -> Dict:
        """Extract reusable pattern from successful finding using AI"""

        prompt = f"""You are analyzing a successful bug bounty finding to extract a reusable attack pattern.

FINDING:
{json.dumps(finding, indent=2)}

TASK: Extract a reusable pattern that can be applied to similar targets.

Return ONLY valid JSON object:
{{
  "name": "Descriptive pattern name",
  "tech": ["Technology1", "Technology2"],
  "indicators": ["What signals this pattern might work"],
  "exploit_template": "Generalized exploit payload with <PLACEHOLDER> markers",
  "confidence": "HIGH/MEDIUM/LOW",
  "similar_endpoints": "What other endpoints might be vulnerable",
  "variations": ["Common variations of this attack"]
}}"""

        response = await self.llm.messages.create(
            model="claude-opus-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )

        return self._parse_json_response(response.content[0].text)

    def _parse_json_response(self, response_text: str) -> Dict:
        """Parse JSON object from LLM response"""
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1

            if start == -1 or end == 0:
                return {}

            json_text = response_text[start:end]
            return json.loads(json_text)
        except Exception as e:
            print(f"Failed to parse JSON: {e}")
            return {}

    async def _find_exploit_chains(self, findings: List[Dict]) -> List[Dict]:
        """Discover exploit chains by combining multiple vulnerabilities"""

        if len(findings) < 2:
            return []

        prompt = f"""You are analyzing multiple security findings to discover exploit chains.

FINDINGS:
{self._summarize_findings(findings)}

TASK: Identify up to 5 chains where combining these vulnerabilities creates higher impact.

Look for:
- Information disclosure → Privilege escalation
- XSS → Session theft → Account takeover
- IDOR → Data exfiltration → Business logic abuse
- Auth bypass → IDOR → Critical data access

Return ONLY valid JSON array (max 5 chains):
[
  {{
    "title": "Vulnerability1 → Vulnerability2 → Impact",
    "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
    "findings_used": ["Finding ID 1", "Finding ID 2"],
    "impact": "CRITICAL/HIGH/MEDIUM/LOW",
    "confidence": "HIGH/MEDIUM/LOW",
    "rationale": "Why this chain works"
  }}
]"""

        response = await self.llm.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        chains = self._parse_hypotheses(response.content[0].text)
        return chains[:5]  # Cap at 5 chains to prevent context explosion

    async def _load_prior_knowledge(self) -> Dict:
        """Load successful patterns from database"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            # Get patterns with success rate > 50%
            cursor.execute("""
                SELECT id, name, tech, indicators, exploit_template,
                       success_count, failure_count, success_rate,
                       targets_succeeded, targets_failed
                FROM learned_patterns
                WHERE success_rate >= 0.5
                ORDER BY success_rate DESC, success_count DESC
                LIMIT 20
            """)

            patterns = []
            for row in cursor.fetchall():
                patterns.append({
                    "id": row[0],
                    "name": row[1],
                    "tech": json.loads(row[2]) if row[2] else [],
                    "indicators": json.loads(row[3]) if row[3] else [],
                    "exploit_template": row[4],
                    "success_count": row[5],
                    "failure_count": row[6],
                    "success_rate": row[7],
                    "targets_succeeded": json.loads(row[8]) if row[8] else [],
                    "targets_failed": json.loads(row[9]) if row[9] else []
                })

            # Get recent successful findings (for tech-specific patterns)
            cursor.execute("""
                SELECT f.id, f.title, f.vuln_type, f.severity, f.endpoints, f.poc
                FROM findings f
                JOIN targets t ON f.target_id = t.id
                WHERE f.status = 'accepted'
                ORDER BY f.discovered_date DESC
                LIMIT 10
            """)

            relevant_findings = []
            for row in cursor.fetchall():
                relevant_findings.append({
                    "id": row[0],
                    "title": row[1],
                    "vuln_type": row[2],
                    "severity": row[3],
                    "endpoints": row[4],
                    "poc": row[5]
                })

            return {
                "patterns": patterns,
                "relevant_findings": relevant_findings
            }

    async def _save_pattern(self, pattern: Dict) -> None:
        """Save learned pattern to database"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()

            # Check if pattern already exists
            cursor.execute(
                "SELECT id, success_count, failure_count, targets_succeeded FROM learned_patterns WHERE name = ?",
                (pattern["name"],)
            )
            existing = cursor.fetchone()

            if existing:
                # Update existing pattern
                pattern_id = existing[0]
                success_count = existing[1] + 1
                targets_succeeded = json.loads(existing[3]) if existing[3] else []
                if self.target not in targets_succeeded:
                    targets_succeeded.append(self.target)

                cursor.execute("""
                    UPDATE learned_patterns
                    SET success_count = ?,
                        targets_succeeded = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (success_count, json.dumps(targets_succeeded), pattern_id))
            else:
                # Insert new pattern
                cursor.execute("""
                    INSERT INTO learned_patterns
                    (name, tech, indicators, exploit_template, success_count, failure_count, targets_succeeded)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern["name"],
                    json.dumps(pattern.get("tech", [])),
                    json.dumps(pattern.get("indicators", [])),
                    pattern.get("exploit_template", ""),
                    1,
                    0,
                    json.dumps([self.target])
                ))

    async def _record_hypothesis_test(self, hypothesis: Dict, result: str, finding_id: Optional[int] = None) -> None:
        """Record hypothesis test result in database"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO hypothesis_tests
                (target, hypothesis_title, hypothesis_test, rationale, confidence, result, finding_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target,
                hypothesis["title"],
                hypothesis["test"],
                hypothesis.get("rationale", ""),
                hypothesis.get("confidence", "MEDIUM"),
                result,
                finding_id
            ))

    async def hunt(self) -> Dict:
        """Main continuous learning hunt loop"""

        print(f"\n🎯 Starting AI-powered hunt on {self.target}")
        print(f"Max iterations: {self.max_iterations}\n")

        # Phase 1: Initial reconnaissance
        recon = await self._get_recon()
        print(f"✓ Recon complete: {len(recon.get('endpoints', []))} endpoints, {len(recon.get('tech_stack', []))} technologies")

        # Phase 2: Load prior knowledge
        prior_knowledge = await self._load_prior_knowledge()
        print(f"✓ Loaded {len(prior_knowledge.get('patterns', []))} prior patterns, {len(prior_knowledge.get('relevant_findings', []))} relevant findings\n")

        # Phase 3: Continuous learning loop
        while self.iteration < self.max_iterations:
            self.iteration += 1
            print(f"--- Iteration {self.iteration}/{self.max_iterations} ---")

            # Generate hypotheses using AI reasoning
            hypotheses = await self._generate_hypotheses(recon, self.findings, prior_knowledge)
            print(f"Generated {len(hypotheses)} hypotheses")

            # Test each hypothesis
            iteration_findings = []
            for i, hypothesis in enumerate(hypotheses, 1):
                print(f"  [{i}/{len(hypotheses)}] Testing: {hypothesis['title']}")

                result = await self._test_hypothesis(hypothesis)

                if result["success"]:
                    print(f"    ✓ FOUND: {result['finding']['title']}")
                    self.findings.append(result["finding"])
                    iteration_findings.append(result["finding"])

                    # Extract pattern immediately
                    pattern = await self._extract_pattern(result["finding"])
                    self.patterns.append(pattern)
                    await self._save_pattern(pattern)

                    # Record success
                    await self._record_hypothesis_test(hypothesis, "success", result["finding"].get("id"))

                    # Apply pattern to similar endpoints immediately
                    similar = self._find_similar_endpoints(result["finding"].get("endpoint", ""), recon['endpoints'])
                    if similar:
                        print(f"    → Testing {len(similar)} similar endpoints with pattern")
                        await self._quick_test_pattern(similar, pattern)
                else:
                    await self._record_hypothesis_test(hypothesis, "failure")

            # Look for exploit chains after each iteration (capped at 5)
            if len(self.findings) >= 2:
                chains = await self._find_exploit_chains(self.findings)
                if chains:
                    print(f"  🔗 Discovered {len(chains)} exploit chains")
                    for chain in chains[:5]:
                        await self._save_exploit_chain(chain)

            # Check if we're stuck (no findings in last 3 iterations)
            if self.iteration >= 3 and len(iteration_findings) == 0:
                print("  ⚠ No findings in recent iterations, generating creative bypasses...")
                creative_hypotheses = await self._generate_creative_bypasses(recon, self.findings)
                # Test creative hypotheses...

            print()

        # Final summary
        print(f"\n{'='*60}")
        print(f"Hunt complete: {len(self.findings)} findings, {len(self.patterns)} patterns learned")
        print(f"{'='*60}\n")

        return {
            "target": self.target,
            "findings": self.findings,
            "patterns": self.patterns,
            "iterations": self.iteration,
            "exploit_chains": await self._get_all_chains()
        }

    async def _get_recon(self) -> Dict:
        """Run reconnaissance on target using curl-based probing"""

        recon = {
            "tech_stack": [],
            "endpoints": [],
            "headers": {},
            "findings": []
        }

        # Probe target with curl to detect tech stack and endpoints
        try:
            result = subprocess.run(
                ["curl", "-sI", "-m", "10", f"https://{self.target}"],
                capture_output=True, text=True, timeout=15
            )
            headers_text = result.stdout

            # Parse response headers for tech detection
            for line in headers_text.split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    recon["headers"][key.strip().lower()] = value.strip()

            # Detect tech stack from headers
            server = recon["headers"].get("server", "").lower()
            powered_by = recon["headers"].get("x-powered-by", "").lower()
            all_headers = headers_text.lower()

            tech_indicators = {
                "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
                "express": "Express/Node.js", "next.js": "Next.js", "php": "PHP",
                "asp.net": "ASP.NET", "django": "Django", "rails": "Ruby on Rails",
                "graphql": "GraphQL", "fastapi": "FastAPI", "spring": "Spring/Java",
            }
            for indicator, tech in tech_indicators.items():
                if indicator in server or indicator in powered_by or indicator in all_headers:
                    recon["tech_stack"].append(tech)

        except Exception:
            pass

        # Probe common endpoints
        common_paths = [
            "/api", "/api/v1", "/api/v2", "/graphql", "/api/graphql",
            "/rest", "/swagger.json", "/openapi.json", "/api-docs",
            "/.well-known/openid-configuration", "/robots.txt", "/sitemap.xml",
            "/wp-json", "/admin", "/login", "/health", "/status",
        ]

        for path in common_paths:
            try:
                result = subprocess.run(
                    ["curl", "-so", "/dev/null", "-w", "%{http_code}", "-m", "5",
                     f"https://{self.target}{path}"],
                    capture_output=True, text=True, timeout=8
                )
                code = result.stdout.strip()
                if code and code not in ("000", "404", "503"):
                    recon["endpoints"].append({"path": path, "status": int(code)})
                    # Detect GraphQL
                    if "graphql" in path and code in ("200", "400", "405"):
                        if "GraphQL" not in recon["tech_stack"]:
                            recon["tech_stack"].append("GraphQL")
            except Exception:
                continue

        return recon

    async def _test_hypothesis(self, hypothesis: Dict) -> Dict:
        """Test a hypothesis by having the LLM generate and execute a test"""

        # Ask LLM to generate a concrete curl/python test
        test_code = await self._generate_test_code(hypothesis)

        if not test_code:
            return {"success": False, "error": "Failed to generate test code"}

        # Execute the test
        result = await self._execute_test(test_code)

        if not result:
            return {"success": False, "error": "Test execution failed"}

        # Ask LLM to analyze the result for vulnerabilities
        analysis = await self._analyze_test_result(hypothesis, test_code, result)

        return analysis

    async def _generate_test_code(self, hypothesis: Dict) -> Optional[str]:
        """Have LLM generate a curl command to test the hypothesis"""

        prompt = f"""Generate a single curl command to test this security hypothesis against {self.target}.

HYPOTHESIS: {hypothesis['title']}
TEST DESCRIPTION: {hypothesis['test']}

RULES:
- Return ONLY a single curl command (no explanation)
- Use https://{self.target} as the base URL
- Include -s (silent) and -m 10 (timeout)
- Include -w "\\n%{{http_code}}" to capture status code
- Include relevant headers and payloads for the test
- Do NOT use dangerous payloads that could cause damage
- Focus on detection, not exploitation

EXAMPLE FORMAT:
curl -s -m 10 -w "\\n%{{http_code}}" "https://{self.target}/api/endpoint" -H "Content-Type: application/json" -d '{{"key":"value"}}'

Return ONLY the curl command, nothing else."""

        response = await self.llm.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        cmd = response.content[0].text.strip()

        # Basic safety: ensure it targets our domain only
        if self.target not in cmd:
            return None
        # Block destructive commands
        dangerous = ["rm ", "del ", "format ", "mkfs", "dd if=", "; ", "&&", "|", "`"]
        if any(d in cmd for d in dangerous):
            return None

        return cmd

    async def _execute_test(self, curl_command: str) -> Optional[str]:
        """Execute a curl command and return the output"""
        try:
            result = subprocess.run(
                ["bash", "-c", curl_command],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout
            if result.stderr and not output:
                output = result.stderr
            return output[:5000]  # Cap output size
        except Exception as e:
            return f"Error: {str(e)}"

    async def _analyze_test_result(self, hypothesis: Dict, test_code: str, result: str) -> Dict:
        """Have LLM analyze test result for vulnerability indicators"""

        prompt = f"""Analyze this security test result. Be CONSERVATIVE - only flag genuine vulnerabilities.

TARGET: {self.target}
HYPOTHESIS: {hypothesis['title']}
CURL COMMAND: {test_code}

RESPONSE:
{result[:3000]}

ANALYSIS RULES:
- HTTP 200 alone does NOT prove a vulnerability
- GraphQL always returns 200 - check the data/errors fields
- Look for: leaked sensitive data, unauthorized access, error messages with internals
- A validation error is NOT a vulnerability
- "Access denied" or "Unauthorized" means the test FAILED (auth is working)

Return ONLY valid JSON:
{{
  "is_vulnerable": true/false,
  "confidence": "HIGH/MEDIUM/LOW",
  "evidence": "Specific evidence from the response",
  "title": "Vulnerability title if found",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
  "false_positive_risk": "HIGH/MEDIUM/LOW"
}}"""

        response = await self.llm.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}]
        )

        analysis = self._parse_json_response(response.content[0].text)

        if analysis.get("is_vulnerable") and analysis.get("false_positive_risk") != "HIGH":
            return {
                "success": True,
                "finding": {
                    "title": analysis.get("title", hypothesis["title"]),
                    "severity": analysis.get("severity", "MEDIUM"),
                    "evidence": analysis.get("evidence", ""),
                    "confidence": analysis.get("confidence", "MEDIUM"),
                    "endpoint": self._extract_endpoint(test_code),
                    "test_command": test_code,
                    "response_snippet": result[:500],
                    "hypothesis": hypothesis
                }
            }

        return {"success": False, "analysis": analysis}

    def _extract_endpoint(self, curl_command: str) -> str:
        """Extract endpoint path from curl command"""
        match = regex_module.search(r'https?://[^/\s"]+(/[^\s"]*)', curl_command)
        return match.group(1) if match else "/"

    def _find_similar_endpoints(self, endpoint: str, all_endpoints: List[str]) -> List[str]:
        """Find endpoints similar to the vulnerable one"""
        similar = []

        # Extract pattern (e.g., /api/users/123 → /api/.*/\d+)
        import re
        pattern = re.sub(r'\d+', r'\\d+', endpoint)
        pattern = re.sub(r'[a-f0-9-]{36}', r'[a-f0-9-]{36}', pattern)  # UUIDs

        for ep in all_endpoints:
            if ep != endpoint and re.match(pattern, ep):
                similar.append(ep)

        return similar[:10]  # Limit to 10

    async def _quick_test_pattern(self, endpoints: List[str], pattern: Dict) -> None:
        """Quickly test pattern on similar endpoints"""
        for endpoint in endpoints:
            # Apply pattern's exploit template to endpoint
            payload = pattern.get("exploit_template", "").replace("<ENDPOINT>", endpoint)
            # Test with payload...
            pass

    async def _save_exploit_chain(self, chain: Dict) -> None:
        """Save discovered exploit chain to database"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO exploit_chains (target, chain_title, steps, findings_used, impact)
                VALUES (?, ?, ?, ?, ?)
            """, (
                self.target,
                chain["title"],
                json.dumps(chain["steps"]),
                json.dumps(chain.get("findings_used", [])),
                chain.get("impact", "MEDIUM")
            ))

    async def _get_all_chains(self) -> List[Dict]:
        """Get all exploit chains for this target"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM exploit_chains WHERE target = ? ORDER BY created_at DESC",
                (self.target,)
            )

            chains = []
            for row in cursor.fetchall():
                chains.append({
                    "id": row[0],
                    "target": row[1],
                    "chain_title": row[2],
                    "steps": json.loads(row[3]) if row[3] else [],
                    "findings_used": json.loads(row[4]) if row[4] else [],
                    "impact": row[5],
                    "verified": row[6],
                    "created_at": row[7]
                })

            return chains

    async def _generate_creative_bypasses(self, recon: Dict, findings: List[Dict]) -> List[Dict]:
        """Generate creative bypass hypotheses when stuck"""

        prompt = f"""You are an expert bug bounty hunter. You've been testing {self.target} for a while but recent tests haven't found anything.

CURRENT INTELLIGENCE:
- Tech Stack: {', '.join(recon.get('tech_stack', []))}
- Findings So Far: {len(findings)} vulnerabilities
- Recent Findings:
{self._summarize_findings(findings[-3:])}

TASK: Think creatively about unconventional attack vectors and bypasses.

Consider:
- Unusual HTTP methods (TRACE, TRACK, DEBUG)
- HTTP/2 smuggling via headers
- CRLF injection in headers
- Unicode normalization bypasses
- Race conditions in concurrent requests
- Cache poisoning via HTTP headers
- Protocol-level attacks (WebSocket upgrade, HTTP/2 upgrade)
- Business logic flaws in edge cases

Return ONLY valid JSON array of 5 creative hypotheses.
"""

        response = await self.llm.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )

        return self._parse_hypotheses(response.content[0].text)

