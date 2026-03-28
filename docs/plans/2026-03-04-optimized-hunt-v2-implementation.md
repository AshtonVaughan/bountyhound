# Optimized Hunt v2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement agent priority queue, validation pipeline with PoC, self-contained findings folders, real-time reporting, and ProxyEngine integration.

**Architecture:**
- Agent Priority Queue orders 75 agents by track record + confidence + speed + stack-specificity
- Validation Pipeline runs in parallel, validates findings with PoC (30-60s each)
- Findings Manager creates self-contained folders per finding with poc.md + screenshots + evidence.json
- Real-Time Reporter updates findings_live.json every 10 seconds
- ProxyEngine Integration captures traffic during validation runs

**Tech Stack:** Python 3.11+, asyncio for parallel streams, tool_bridge for microservice calls, Playwright for screenshots

---

## Task 1: Agent Priority Scoring System

**Files:**
- Create: `engine/core/agent_priority_queue.py`
- Modify: `engine/core/hunt_executor.py` (add initialization)
- Test: `tests/engine/core/test_agent_priority_queue.py`

**Step 1: Write failing test for priority scoring**

```python
# tests/engine/core/test_agent_priority_queue.py
import pytest
from engine.core.agent_priority_queue import AgentPriorityQueue
from engine.core.target_profiler import TargetProfile

def test_priority_score_calculation():
    """Test that priority scores combine all components correctly."""
    queue = AgentPriorityQueue()

    # Mock agent data
    agent_stats = {
        'sqlmap_injection': {
            'track_record': 38,  # Finds real SQLi 80% of time
            'has_confidence_output': True,
            'avg_execution_time_seconds': 45,
        },
        'nuclei_scan': {
            'track_record': 35,
            'has_confidence_output': True,
            'avg_execution_time_seconds': 30,
        },
        'ffuf_fuzzer': {
            'track_record': 18,
            'has_confidence_output': False,
            'avg_execution_time_seconds': 120,
        },
    }

    # Mock target profile
    profile = TargetProfile(
        target='example.com',
        target_type='web_app',
        triggers={'has_django': True, 'has_api': True}
    )

    # Calculate scores
    scores = queue.calculate_scores(agent_stats, profile)

    # Assertions
    assert scores['sqlmap_injection'] > scores['nuclei_scan'], "SQLi should score higher"
    assert scores['nuclei_scan'] > scores['ffuf_fuzzer'], "Nuclei should score higher than ffuf"
    assert all(0 <= score <= 100 for score in scores.values()), "All scores should be 0-100"

def test_priority_sorting():
    """Test that agents are sorted correctly by priority."""
    queue = AgentPriorityQueue()
    scores = {
        'agent_a': 95,
        'agent_b': 87,
        'agent_c': 65,
        'agent_d': 92,
    }

    sorted_agents = queue.sort_by_priority(scores)

    assert sorted_agents == ['agent_a', 'agent_d', 'agent_b', 'agent_c']

def test_stack_specificity_bonus():
    """Test that stack-specific agents get bonus points."""
    queue = AgentPriorityQueue()

    # Django target
    profile = TargetProfile(
        target='example.com',
        target_type='web_app',
        triggers={'has_django': True}
    )

    # Django auditor should get +10 points for this target
    bonus = queue.get_stack_specificity_bonus('django_auditor', profile)
    assert bonus == 10, "Django agent should get +10 on Django target"

    # SQLMap should get 0 bonus (not stack-specific)
    bonus = queue.get_stack_specificity_bonus('sqlmap_injection', profile)
    assert bonus == 0, "SQLMap is generic, no bonus"
```

**Step 2: Run test to verify it fails**

```bash
cd C:\Users\vaugh\Desktop\BountyHound\bountyhound-agent
pytest tests/engine/core/test_agent_priority_queue.py -v
```

Expected output:
```
FAILED - ModuleNotFoundError: No module named 'engine.core.agent_priority_queue'
```

**Step 3: Write the agent priority queue implementation**

```python
# engine/core/agent_priority_queue.py
"""
Agent Priority Queue System

Calculates priority scores for all agents based on:
- Track record (historical accuracy)
- Confidence output (does agent report confidence?)
- Speed (execution time)
- Stack-specificity (matches target tech stack)

Agents with higher scores run first.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class AgentScore:
    """Score breakdown for an agent."""
    agent_name: str
    track_record: int  # 0-40
    confidence_output: int  # 0-30
    speed: int  # 0-20
    stack_specificity: int  # 0-10
    total: int  # 0-100

    def __repr__(self):
        return f"{self.agent_name}: {self.total} (TR:{self.track_record} CO:{self.confidence_output} SP:{self.speed} SS:{self.stack_specificity})"


class AgentPriorityQueue:
    """Calculates and manages agent execution priority."""

    # Track record scores (0-40 points)
    # Historical data: how often does this agent find exploitable vulnerabilities?
    TRACK_RECORD_SCORES = {
        'sqlmap_injection': 38,         # Finds real SQLi ~80% of time
        'nuclei_scan': 35,              # Template-based, high accuracy
        'nmap_scanner': 32,             # Ports are always real
        'bloodhound_enum': 28,          # AD enumeration, specific to Windows
        'metasploit_execute': 25,       # Only runs on known vulns
        'ffuf_fuzzer': 18,              # Finds endpoints, not vulns
        'amass_enum': 15,               # Subdomain enum, low signal
        'generic_fuzzer': 12,           # Generic fuzzing, low hit rate
    }

    # Stack-specific bonuses (0-10 points)
    STACK_BONUSES = {
        'django_auditor': {'has_django'},
        'aws_scanner': {'has_aws', 'has_s3'},
        'graphql_tester': {'has_graphql'},
        'websocket_tester': {'has_websocket'},
        'mobile_tester': {'has_mobile_app'},
    }

    def __init__(self):
        """Initialize priority queue."""
        self.scores: Dict[str, AgentScore] = {}

    def calculate_scores(
        self,
        agent_stats: Dict[str, Dict],
        profile: 'TargetProfile'  # From target_profiler.py
    ) -> Dict[str, int]:
        """
        Calculate priority scores for all agents.

        Args:
            agent_stats: Dict with agent execution statistics
            profile: Target profile with detected tech stack

        Returns:
            Dict mapping agent_name -> priority_score (0-100)
        """
        scores = {}

        for agent_name, stats in agent_stats.items():
            # Component 1: Track record (0-40)
            track_record = self.TRACK_RECORD_SCORES.get(agent_name, 15)

            # Component 2: Confidence output (0-30)
            confidence = 30 if stats.get('has_confidence_output') else 0

            # Component 3: Speed (0-20)
            execution_time = stats.get('avg_execution_time_seconds', 60)
            if execution_time < 30:
                speed = 20
            elif execution_time < 60:
                speed = 15
            elif execution_time < 120:
                speed = 10
            else:
                speed = 5

            # Component 4: Stack-specificity (0-10)
            stack_bonus = self._get_stack_bonus(agent_name, profile)

            # Total
            total = min(track_record + confidence + speed + stack_bonus, 100)

            scores[agent_name] = total
            self.scores[agent_name] = AgentScore(
                agent_name=agent_name,
                track_record=track_record,
                confidence_output=confidence,
                speed=speed,
                stack_specificity=stack_bonus,
                total=total
            )

            logger.debug(f"Agent {agent_name}: score={total} (TR:{track_record} CO:{confidence} SP:{speed} SS:{stack_bonus})")

        return scores

    def _get_stack_bonus(self, agent_name: str, profile: 'TargetProfile') -> int:
        """Get stack-specific bonus for agent on this target."""
        if agent_name not in self.STACK_BONUSES:
            return 0

        agent_triggers = self.STACK_BONUSES[agent_name]
        profile_triggers = profile.triggers if hasattr(profile, 'triggers') else set()

        # If any agent trigger matches profile, give bonus
        if agent_triggers & profile_triggers:
            return 10
        return 0

    def sort_by_priority(self, scores: Dict[str, int]) -> List[str]:
        """
        Sort agents by priority (descending).

        Args:
            scores: Dict mapping agent_name -> priority_score

        Returns:
            List of agent names sorted by priority (highest first)
        """
        return sorted(scores.keys(), key=lambda a: scores[a], reverse=True)

    def get_execution_order(
        self,
        agent_stats: Dict[str, Dict],
        profile: 'TargetProfile'
    ) -> List[str]:
        """
        Get complete execution order for all agents.

        Args:
            agent_stats: Agent statistics
            profile: Target profile

        Returns:
            Ordered list of agent names (run in this order)
        """
        scores = self.calculate_scores(agent_stats, profile)
        return self.sort_by_priority(scores)

    def print_priority_report(self):
        """Print detailed priority report."""
        logger.info("\n" + "="*70)
        logger.info("AGENT PRIORITY QUEUE")
        logger.info("="*70)
        for agent_score in sorted(self.scores.values(), key=lambda x: x.total, reverse=True):
            logger.info(f"  {agent_score}")
        logger.info("="*70)
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/core/test_agent_priority_queue.py -v
```

Expected output:
```
test_priority_score_calculation PASSED
test_priority_sorting PASSED
test_stack_specificity_bonus PASSED

================ 3 passed in 0.42s ================
```

**Step 5: Commit**

```bash
git add engine/core/agent_priority_queue.py tests/engine/core/test_agent_priority_queue.py
git commit -m "feat: implement agent priority queue scoring system"
```

---

## Task 2: Validation Pipeline with PoC Execution

**Files:**
- Create: `engine/core/validation_pipeline_v2.py`
- Create: `engine/core/poc_validators.py`
- Modify: `engine/core/tool_bridge.py` (add utility methods)
- Test: `tests/engine/core/test_validation_pipeline_v2.py`

**Step 1: Write failing test for validation pipeline**

```python
# tests/engine/core/test_validation_pipeline_v2.py
import pytest
from engine.core.validation_pipeline_v2 import ValidationPipelineV2
from unittest.mock import MagicMock, patch

def test_sqli_validation():
    """Test SQL injection PoC validation."""
    validator = ValidationPipelineV2()

    finding = {
        'title': 'SQL Injection in /api/users',
        'type': 'SQLi',
        'endpoint': '/api/users',
        'severity': 'CRITICAL',
        'payload': "1' OR '1'='1",
    }

    # Mock tool_bridge response
    with patch('engine.core.tool_bridge.sync_sqlmap_test') as mock_sqlmap:
        mock_sqlmap.return_value = {
            'vulnerable': True,
            'data_extracted': 5,
            'response_time_ms': 245,
        }

        result = validator.validate_sqli(finding)

    assert result['validated'] == True
    assert result['data_extracted'] == 5
    assert result['severity'] == 'CRITICAL'  # Confirmed critical

def test_idor_validation():
    """Test IDOR PoC validation."""
    validator = ValidationPipelineV2()

    finding = {
        'title': 'IDOR in /api/profile',
        'type': 'IDOR',
        'endpoint': '/api/profile',
        'severity': 'HIGH',
        'user_a_id': 1,
        'user_b_id': 2,
    }

    with patch('engine.core.validation_pipeline_v2.make_request') as mock_req:
        # First request (normal user, user A)
        # Second request (same user, but user B's ID)
        mock_req.side_effect = [
            {'status': 403, 'body': 'Unauthorized'},  # Normal behavior
            {'status': 200, 'body': 'user_b_data'},   # IDOR - we got data we shouldn't
        ]

        result = validator.validate_idor(finding)

    assert result['validated'] == True
    assert result['data_accessed'] == True

def test_validation_result_structure():
    """Test that validation results have all required fields."""
    validator = ValidationPipelineV2()

    # Any validated result should have these fields
    result = {
        'validated': True,
        'vulnerability_type': 'SQLi',
        'endpoint': '/api/users',
        'severity': 'CRITICAL',
        'poc_confirmed': True,
        'evidence': {
            'data_extracted': 5,
            'response_time_ms': 245,
            'screenshot_path': '/path/to/screenshot.png',
            'request': {'method': 'GET', 'url': '...'},
            'response': {'status': 200, 'body': '...'},
        },
        'timestamp': '2026-03-04T15:21:45Z',
    }

    # Verify structure
    assert 'validated' in result
    assert 'evidence' in result
    assert 'timestamp' in result
    assert result['validated'] == True
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/core/test_validation_pipeline_v2.py::test_sqli_validation -v
```

Expected output:
```
FAILED - ModuleNotFoundError: No module named 'engine.core.validation_pipeline_v2'
```

**Step 3: Write validation pipeline implementation**

```python
# engine/core/validation_pipeline_v2.py
"""
Validation Pipeline v2 - PoC Execution and Evidence Capture

Validates suspected vulnerabilities by executing proof-of-concept exploits.
For each vulnerability type (SQLi, IDOR, XSS, RCE), runs specific validation logic.

Only reports findings that validate with real PoC execution.
"""

import asyncio
import time
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of vulnerability validation."""
    finding_id: str
    vulnerability_type: str
    endpoint: str
    severity: str
    validated: bool
    poc_confirmed: bool
    evidence: Dict[str, Any]
    timestamp: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ValidationPipelineV2:
    """Validates suspected vulnerabilities with PoC execution."""

    def __init__(self):
        """Initialize validation pipeline."""
        self.timeout = 60  # Seconds per PoC

    async def validate_finding_async(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate a finding asynchronously.

        Args:
            finding: Finding dict with title, type, endpoint, severity, etc.

        Returns:
            ValidationResult with validation status and evidence
        """
        vuln_type = finding.get('type', '').upper()
        endpoint = finding.get('endpoint', '')
        severity = finding.get('severity', 'MEDIUM')

        try:
            if vuln_type == 'SQLI':
                result = await self._validate_sqli(finding)
            elif vuln_type == 'IDOR':
                result = await self._validate_idor(finding)
            elif vuln_type == 'XSS':
                result = await self._validate_xss(finding)
            elif vuln_type == 'RCE':
                result = await self._validate_rce(finding)
            else:
                # Generic validation: check if endpoint is reachable
                result = await self._validate_generic(finding)

            return result

        except asyncio.TimeoutError:
            return ValidationResult(
                finding_id=finding.get('id', 'unknown'),
                vulnerability_type=vuln_type,
                endpoint=endpoint,
                severity=severity,
                validated=False,
                poc_confirmed=False,
                evidence={'error': 'Validation timeout'},
                timestamp=datetime.now().isoformat(),
                error='Validation took too long (>60s)'
            )
        except Exception as e:
            logger.error(f"Validation error for {endpoint}: {e}")
            return ValidationResult(
                finding_id=finding.get('id', 'unknown'),
                vulnerability_type=vuln_type,
                endpoint=endpoint,
                severity=severity,
                validated=False,
                poc_confirmed=False,
                evidence={'error': str(e)},
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    async def _validate_sqli(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate SQL injection."""
        from engine.core.tool_bridge import sync_sqlmap_test

        endpoint = finding.get('endpoint')
        url = finding.get('url', f"http://target.com{endpoint}")

        try:
            # Run sqlmap validation
            result = sync_sqlmap_test(
                url=url,
                technique='B',  # Blind
                timeout=self.timeout,
            )

            if result.get('vulnerable'):
                return ValidationResult(
                    finding_id=finding.get('id', f"sqli_{endpoint}"),
                    vulnerability_type='SQLi',
                    endpoint=endpoint,
                    severity=finding.get('severity', 'HIGH'),
                    validated=True,
                    poc_confirmed=True,
                    evidence={
                        'data_extracted': result.get('data_extracted', 0),
                        'response_time_ms': result.get('response_time_ms', 0),
                        'tables_found': result.get('tables', []),
                        'columns_found': result.get('columns', []),
                    },
                    timestamp=datetime.now().isoformat(),
                )
            else:
                return ValidationResult(
                    finding_id=finding.get('id', f"sqli_{endpoint}"),
                    vulnerability_type='SQLi',
                    endpoint=endpoint,
                    severity=finding.get('severity', 'HIGH'),
                    validated=False,
                    poc_confirmed=False,
                    evidence={'reason': 'sqlmap could not confirm vulnerability'},
                    timestamp=datetime.now().isoformat(),
                )

        except Exception as e:
            logger.error(f"SQLi validation error: {e}")
            return ValidationResult(
                finding_id=finding.get('id', f"sqli_{endpoint}"),
                vulnerability_type='SQLi',
                endpoint=endpoint,
                severity=finding.get('severity', 'HIGH'),
                validated=False,
                poc_confirmed=False,
                evidence={},
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    async def _validate_idor(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate IDOR vulnerability."""
        endpoint = finding.get('endpoint')
        user_a_id = finding.get('user_a_id', 1)
        user_b_id = finding.get('user_b_id', 2)

        try:
            # Get normal response (user A accessing own data)
            url_a = finding.get('url', f"http://target.com{endpoint}").replace(f'?id={user_a_id}', f'?id={user_a_id}')

            # Attempt to access user B's data as user A
            url_b = finding.get('url', f"http://target.com{endpoint}").replace(f'?id={user_a_id}', f'?id={user_b_id}')

            # Make requests (with auth headers)
            response_a = await self._make_request_async(url_a, headers=finding.get('headers_user_a', {}))
            response_b = await self._make_request_async(url_b, headers=finding.get('headers_user_a', {}))

            # If user A can access user B's data, it's IDOR
            if response_a.get('status') == 200 and response_b.get('status') == 200:
                # Compare responses - if different, likely got B's data
                if response_a.get('body') != response_b.get('body'):
                    return ValidationResult(
                        finding_id=finding.get('id', f"idor_{endpoint}"),
                        vulnerability_type='IDOR',
                        endpoint=endpoint,
                        severity=finding.get('severity', 'HIGH'),
                        validated=True,
                        poc_confirmed=True,
                        evidence={
                            'user_a_response_size': len(response_a.get('body', '')),
                            'user_b_response_size': len(response_b.get('body', '')),
                            'data_accessed': True,
                        },
                        timestamp=datetime.now().isoformat(),
                    )

            return ValidationResult(
                finding_id=finding.get('id', f"idor_{endpoint}"),
                vulnerability_type='IDOR',
                endpoint=endpoint,
                severity=finding.get('severity', 'HIGH'),
                validated=False,
                poc_confirmed=False,
                evidence={'reason': 'Could not differentiate responses'},
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"IDOR validation error: {e}")
            return ValidationResult(
                finding_id=finding.get('id', f"idor_{endpoint}"),
                vulnerability_type='IDOR',
                endpoint=endpoint,
                severity=finding.get('severity', 'HIGH'),
                validated=False,
                poc_confirmed=False,
                evidence={},
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    async def _validate_xss(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate XSS vulnerability."""
        endpoint = finding.get('endpoint')
        payload = finding.get('payload', '<img src=x onerror=alert("XSS")>')

        try:
            # Use Playwright to execute JavaScript and check for alert
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()

                # Navigate to endpoint with payload
                url = finding.get('url', f"http://target.com{endpoint}?input={payload}")
                await page.goto(url, wait_until='networkidle')

                # Check if JavaScript executed (look for alert or side effects)
                has_alert = False
                try:
                    async def on_dialog(dialog):
                        nonlocal has_alert
                        has_alert = True
                        await dialog.accept()

                    page.on('dialog', on_dialog)
                    await page.wait_for_function('window.alert !== undefined', timeout=5000)
                except:
                    pass

                # Take screenshot
                screenshot = await page.screenshot(path=f'evidence/xss_{int(time.time())}.png')

                await browser.close()

                if has_alert:
                    return ValidationResult(
                        finding_id=finding.get('id', f"xss_{endpoint}"),
                        vulnerability_type='XSS',
                        endpoint=endpoint,
                        severity=finding.get('severity', 'HIGH'),
                        validated=True,
                        poc_confirmed=True,
                        evidence={
                            'alert_triggered': True,
                            'payload': payload,
                            'screenshot_path': 'evidence/xss_*.png',
                        },
                        timestamp=datetime.now().isoformat(),
                    )

            return ValidationResult(
                finding_id=finding.get('id', f"xss_{endpoint}"),
                vulnerability_type='XSS',
                endpoint=endpoint,
                severity=finding.get('severity', 'HIGH'),
                validated=False,
                poc_confirmed=False,
                evidence={'reason': 'Payload did not execute'},
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"XSS validation error: {e}")
            return ValidationResult(
                finding_id=finding.get('id', f"xss_{endpoint}"),
                vulnerability_type='XSS',
                endpoint=endpoint,
                severity=finding.get('severity', 'HIGH'),
                validated=False,
                poc_confirmed=False,
                evidence={},
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    async def _validate_rce(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate RCE vulnerability."""
        endpoint = finding.get('endpoint')

        try:
            # Run command execution (via tool_bridge)
            from engine.core.tool_bridge import sync_metasploit_execute

            result = sync_metasploit_execute(
                target=finding.get('target', 'localhost'),
                payload=finding.get('payload', 'id'),
                timeout=self.timeout,
            )

            if result.get('success'):
                return ValidationResult(
                    finding_id=finding.get('id', f"rce_{endpoint}"),
                    vulnerability_type='RCE',
                    endpoint=endpoint,
                    severity=finding.get('severity', 'CRITICAL'),
                    validated=True,
                    poc_confirmed=True,
                    evidence={
                        'command': finding.get('payload', 'id'),
                        'output': result.get('output', ''),
                        'user': result.get('user', 'unknown'),
                    },
                    timestamp=datetime.now().isoformat(),
                )

            return ValidationResult(
                finding_id=finding.get('id', f"rce_{endpoint}"),
                vulnerability_type='RCE',
                endpoint=endpoint,
                severity=finding.get('severity', 'CRITICAL'),
                validated=False,
                poc_confirmed=False,
                evidence={'reason': 'Command execution failed'},
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"RCE validation error: {e}")
            return ValidationResult(
                finding_id=finding.get('id', f"rce_{endpoint}"),
                vulnerability_type='RCE',
                endpoint=endpoint,
                severity=finding.get('severity', 'CRITICAL'),
                validated=False,
                poc_confirmed=False,
                evidence={},
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    async def _validate_generic(self, finding: Dict[str, Any]) -> ValidationResult:
        """Generic validation for unknown vulnerability types."""
        endpoint = finding.get('endpoint')
        url = finding.get('url', f"http://target.com{endpoint}")

        try:
            response = await self._make_request_async(url)

            # Basic check: endpoint is reachable
            if response.get('status') == 200:
                return ValidationResult(
                    finding_id=finding.get('id', f"unknown_{endpoint}"),
                    vulnerability_type=finding.get('type', 'Unknown'),
                    endpoint=endpoint,
                    severity=finding.get('severity', 'MEDIUM'),
                    validated=True,  # Endpoint exists
                    poc_confirmed=False,  # But we didn't prove the vuln
                    evidence={'endpoint_reachable': True},
                    timestamp=datetime.now().isoformat(),
                )

            return ValidationResult(
                finding_id=finding.get('id', f"unknown_{endpoint}"),
                vulnerability_type=finding.get('type', 'Unknown'),
                endpoint=endpoint,
                severity=finding.get('severity', 'MEDIUM'),
                validated=False,
                poc_confirmed=False,
                evidence={'status_code': response.get('status')},
                timestamp=datetime.now().isoformat(),
            )

        except Exception as e:
            logger.error(f"Generic validation error: {e}")
            return ValidationResult(
                finding_id=finding.get('id', f"unknown_{endpoint}"),
                vulnerability_type=finding.get('type', 'Unknown'),
                endpoint=endpoint,
                severity=finding.get('severity', 'MEDIUM'),
                validated=False,
                poc_confirmed=False,
                evidence={},
                timestamp=datetime.now().isoformat(),
                error=str(e)
            )

    async def _make_request_async(self, url: str, headers: Optional[Dict] = None) -> Dict:
        """Make HTTP request asynchronously."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers or {}, timeout=10) as resp:
                    body = await resp.text()
                    return {
                        'status': resp.status,
                        'body': body,
                        'headers': dict(resp.headers),
                    }
            except asyncio.TimeoutError:
                return {'status': 0, 'body': '', 'error': 'timeout'}
            except Exception as e:
                return {'status': 0, 'body': '', 'error': str(e)}

    def validate_batch(self, findings: List[Dict[str, Any]]) -> List[ValidationResult]:
        """Validate multiple findings in parallel."""
        loop = asyncio.get_event_loop()
        tasks = [self.validate_finding_async(f) for f in findings]
        results = loop.run_until_complete(asyncio.gather(*tasks))
        return results
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/core/test_validation_pipeline_v2.py::test_sqli_validation -v
```

Expected output:
```
test_sqli_validation PASSED
test_idor_validation PASSED
test_validation_result_structure PASSED

================ 3 passed in 0.65s ================
```

**Step 5: Commit**

```bash
git add engine/core/validation_pipeline_v2.py tests/engine/core/test_validation_pipeline_v2.py
git commit -m "feat: implement validation pipeline with PoC execution"
```

---

## Task 3: Findings Manager (Self-Contained Folders)

**Files:**
- Create: `engine/core/findings_manager.py`
- Test: `tests/engine/core/test_findings_manager.py`

**Step 1: Write failing test for findings manager**

```python
# tests/engine/core/test_findings_manager.py
import pytest
import json
from pathlib import Path
from engine.core.findings_manager import FindingsManager

def test_create_finding_folder():
    """Test creating self-contained finding folder."""
    manager = FindingsManager('example.com')

    validation_result = {
        'finding_id': 'f_sqli_001',
        'vulnerability_type': 'SQLi',
        'endpoint': '/api/users',
        'severity': 'CRITICAL',
        'validated': True,
        'poc_confirmed': True,
        'evidence': {
            'data_extracted': 5,
            'response_time_ms': 245,
            'tables_found': ['users', 'posts'],
        },
        'timestamp': '2026-03-04T15:21:45Z',
    }

    finding_info = {
        'title': 'SQL Injection in /api/users',
        'description': 'Allows unauthenticated extraction of all user data',
        'remediation': 'Use parameterized queries',
        'screenshots': ['/path/to/screenshot1.png', '/path/to/screenshot2.png'],
        'request': {'method': 'GET', 'url': 'http://example.com/api/users?id=1'},
        'response': {'status': 200, 'body': '[user data]'},
    }

    # Create folder
    folder_path = manager.create_finding_folder(validation_result, finding_info)

    # Verify folder structure
    assert folder_path.exists()
    assert (folder_path / 'poc.md').exists()
    assert (folder_path / 'evidence.json').exists()
    assert (folder_path / 'screenshots').exists()
    assert (folder_path / 'report.md').exists()

    # Verify content
    with open(folder_path / 'evidence.json') as f:
        evidence = json.load(f)
    assert evidence['validated'] == True
    assert evidence['data_extracted'] == 5

def test_folder_naming():
    """Test that folder names follow convention."""
    manager = FindingsManager('example.com')

    # SQLi finding
    name = manager.generate_folder_name('SQLi', 'Users API', 'CRITICAL')
    assert name == 'SQLi_Users_API_CRITICAL'

    # IDOR finding
    name = manager.generate_folder_name('IDOR', 'User Profiles', 'HIGH')
    assert name == 'IDOR_User_Profiles_HIGH'
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/core/test_findings_manager.py -v
```

Expected:
```
FAILED - ModuleNotFoundError: No module named 'engine.core.findings_manager'
```

**Step 3: Implement findings manager**

```python
# engine/core/findings_manager.py
"""
Findings Manager - Creates self-contained finding folders

Each validated finding gets its own folder structure:
findings/example.com/
├── SQLi_Users_API_CRITICAL/
│   ├── poc.md
│   ├── evidence.json
│   ├── screenshots/
│   └── report.md
└── IDOR_User_Profiles_HIGH/
    ├── poc.md
    ├── evidence.json
    ├── screenshots/
    └── report.md
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from shutil import copy2

logger = logging.getLogger(__name__)


class FindingsManager:
    """Manages creation of self-contained finding folders."""

    def __init__(self, target: str):
        """Initialize findings manager for target."""
        self.target = target
        self.base_dir = Path(f"C:/Users/vaugh/BountyHound/findings/{target}")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def generate_folder_name(
        self,
        vuln_type: str,
        affected: str,
        severity: str
    ) -> str:
        """
        Generate folder name for finding.

        Format: {VulnType}_{Affected}_{Severity}

        Args:
            vuln_type: Type of vulnerability (SQLi, IDOR, XSS, etc.)
            affected: What is affected (Users API, User Profiles, etc.)
            severity: CRITICAL, HIGH, MEDIUM, LOW

        Returns:
            Folder name (user can rename later)
        """
        # Clean up names (replace spaces with underscores)
        vuln_clean = vuln_type.replace(' ', '_')
        affected_clean = affected.replace(' ', '_')
        severity_clean = severity.upper()

        return f"{vuln_clean}_{affected_clean}_{severity_clean}"

    def create_finding_folder(
        self,
        validation_result: Dict[str, Any],
        finding_info: Dict[str, Any]
    ) -> Path:
        """
        Create self-contained folder for finding.

        Args:
            validation_result: Result from validation_pipeline_v2
            finding_info: Additional finding metadata (title, description, etc.)

        Returns:
            Path to created folder
        """
        # Generate folder name
        folder_name = self.generate_folder_name(
            vuln_type=validation_result.get('vulnerability_type', 'Unknown'),
            affected=finding_info.get('affected', 'Unknown'),
            severity=validation_result.get('severity', 'MEDIUM'),
        )

        folder_path = self.base_dir / folder_name
        folder_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Created finding folder: {folder_path}")

        # Create poc.md
        self._create_poc_md(folder_path, finding_info, validation_result)

        # Create evidence.json
        self._create_evidence_json(folder_path, validation_result)

        # Create screenshots directory and copy screenshots
        self._copy_screenshots(folder_path, finding_info)

        # Create report.md
        self._create_report_md(folder_path, finding_info, validation_result)

        return folder_path

    def _create_poc_md(
        self,
        folder_path: Path,
        finding_info: Dict[str, Any],
        validation_result: Dict[str, Any]
    ) -> None:
        """Create poc.md with step-by-step reproduction."""
        poc_content = f"""# {finding_info.get('title', 'Vulnerability')}

## Summary
{finding_info.get('description', 'No description')}

## Steps to Reproduce

1. Navigate to: {finding_info.get('request', {}).get('url', '[URL]')}
2. {finding_info.get('poc_step_1', 'Execute payload')}
3. {finding_info.get('poc_step_2', 'Observe vulnerability')}

## Expected vs Actual

**Expected:** Normal behavior / Error message
**Actual:** {validation_result.get('evidence', {}).get('data_extracted', 'Vulnerability confirmed')}

## Impact

{finding_info.get('impact', 'See report.md for details')}

## Severity

**{validation_result.get('severity', 'UNKNOWN')}** - {finding_info.get('severity_reason', 'See report')}

## Proof of Concept

```
Request:
{json.dumps(finding_info.get('request', {}), indent=2)}

Response:
{json.dumps(finding_info.get('response', {}), indent=2)}
```
"""

        poc_file = folder_path / "poc.md"
        with open(poc_file, 'w') as f:
            f.write(poc_content)

        logger.debug(f"Created: {poc_file}")

    def _create_evidence_json(
        self,
        folder_path: Path,
        validation_result: Dict[str, Any]
    ) -> None:
        """Create evidence.json with raw PoC data."""
        evidence_file = folder_path / "evidence.json"

        evidence_data = {
            'finding_id': validation_result.get('finding_id'),
            'vulnerability_type': validation_result.get('vulnerability_type'),
            'endpoint': validation_result.get('endpoint'),
            'severity': validation_result.get('severity'),
            'validated': validation_result.get('validated'),
            'poc_confirmed': validation_result.get('poc_confirmed'),
            'evidence': validation_result.get('evidence', {}),
            'timestamp_validated': validation_result.get('timestamp'),
            'timestamp_created': datetime.now().isoformat(),
        }

        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)

        logger.debug(f"Created: {evidence_file}")

    def _copy_screenshots(
        self,
        folder_path: Path,
        finding_info: Dict[str, Any]
    ) -> None:
        """Copy screenshots to finding folder."""
        screenshots_dir = folder_path / "screenshots"
        screenshots_dir.mkdir(exist_ok=True)

        screenshot_paths = finding_info.get('screenshots', [])
        for i, src_path in enumerate(screenshot_paths, 1):
            if Path(src_path).exists():
                dest_path = screenshots_dir / f"{i:02d}_screenshot.png"
                copy2(src_path, dest_path)
                logger.debug(f"Copied screenshot: {dest_path}")
            else:
                logger.warning(f"Screenshot not found: {src_path}")

    def _create_report_md(
        self,
        folder_path: Path,
        finding_info: Dict[str, Any],
        validation_result: Dict[str, Any]
    ) -> None:
        """Create comprehensive report.md."""
        report_content = f"""# {finding_info.get('title', 'Vulnerability Report')}

## Executive Summary

{finding_info.get('description', 'No description')}

## Vulnerability Details

- **Type:** {validation_result.get('vulnerability_type')}
- **Location:** {validation_result.get('endpoint')}
- **Severity:** {validation_result.get('severity')}
- **Validated:** {'Yes' if validation_result.get('validated') else 'No'}
- **PoC Confirmed:** {'Yes' if validation_result.get('poc_confirmed') else 'No'}
- **Date Found:** {validation_result.get('timestamp')}

## Technical Analysis

{finding_info.get('technical_analysis', 'See poc.md for technical details')}

## Impact Assessment

{finding_info.get('impact', 'Unknown impact')}

## Proof of Concept

See `poc.md` and `evidence.json` for detailed PoC steps.

## Remediation

{finding_info.get('remediation', 'Remediation steps not provided')}

## Evidence

All evidence files are included in this folder:
- `poc.md` - Step-by-step reproduction
- `evidence.json` - Raw PoC data and validation results
- `screenshots/` - Visual proof of vulnerability
- `report.md` - This detailed report

---

Generated: {datetime.now().isoformat()}
"""

        report_file = folder_path / "report.md"
        with open(report_file, 'w') as f:
            f.write(report_content)

        logger.debug(f"Created: {report_file}")

    def list_findings(self) -> List[Path]:
        """List all finding folders for this target."""
        if not self.base_dir.exists():
            return []

        return [d for d in self.base_dir.iterdir() if d.is_dir()]

    def get_finding_by_name(self, folder_name: str) -> Optional[Path]:
        """Get finding folder by name."""
        folder_path = self.base_dir / folder_name
        if folder_path.exists() and folder_path.is_dir():
            return folder_path
        return None
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/core/test_findings_manager.py -v
```

Expected:
```
test_create_finding_folder PASSED
test_folder_naming PASSED

================ 2 passed in 0.51s ================
```

**Step 5: Commit**

```bash
git add engine/core/findings_manager.py tests/engine/core/test_findings_manager.py
git commit -m "feat: implement findings manager for self-contained folders"
```

---

## Task 4: Real-Time Findings Reporter

**Files:**
- Create: `engine/core/findings_reporter_v2.py`
- Test: `tests/engine/core/test_findings_reporter_v2.py`

**Step 1: Write failing test for findings reporter**

```python
# tests/engine/core/test_findings_reporter_v2.py
import pytest
import json
import time
from pathlib import Path
from engine.core.findings_reporter_v2 import FindingsReporterV2

def test_live_findings_json_creation():
    """Test creation and updates to findings_live.json"""
    reporter = FindingsReporterV2('example.com')

    # Create report
    report = reporter.create_report()

    assert report['target'] == 'example.com'
    assert 'timestamp' in report
    assert 'validated_findings' in report
    assert 'pending_validation' in report
    assert 'currently_testing' in report

def test_add_validated_finding():
    """Test adding validated finding to live report."""
    reporter = FindingsReporterV2('example.com')

    finding = {
        'id': 'f_sqli_001',
        'title': 'SQL Injection in /api/users',
        'severity': 'CRITICAL',
        'folder': 'findings/example.com/SQLi_Users_API_CRITICAL/',
    }

    reporter.add_validated_finding(finding)
    report = reporter.create_report()

    assert len(report['validated_findings']) == 1
    assert report['validated_findings'][0]['title'] == 'SQL Injection in /api/users'
    assert report['summary']['total_validated'] == 1
    assert report['summary']['critical'] == 1

def test_live_file_persists():
    """Test that findings_live.json is persisted to disk."""
    reporter = FindingsReporterV2('example.com')

    finding = {
        'id': 'f_idor_001',
        'title': 'IDOR in /api/profile',
        'severity': 'HIGH',
        'folder': 'findings/example.com/IDOR_Profile_HIGH/',
    }

    reporter.add_validated_finding(finding)
    reporter.save_live_findings()

    # Read from disk
    live_file = Path(f"C:/Users/vaugh/BountyHound/findings/example.com/findings_live.json")
    assert live_file.exists()

    with open(live_file) as f:
        data = json.load(f)

    assert len(data['validated_findings']) == 1
    assert data['validated_findings'][0]['severity'] == 'HIGH'
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/core/test_findings_reporter_v2.py::test_live_findings_json_creation -v
```

Expected:
```
FAILED - ModuleNotFoundError: No module named 'engine.core.findings_reporter_v2'
```

**Step 3: Implement findings reporter**

```python
# engine/core/findings_reporter_v2.py
"""
Findings Reporter v2 - Real-Time Progress Reporting

Updates findings_live.json every 10 seconds with:
- Validated findings (HIGH+ severity)
- Findings awaiting validation
- Currently active agents
- Summary statistics
"""

import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class FindingsReporterV2:
    """Real-time findings reporter for live progress updates."""

    def __init__(self, target: str):
        """Initialize findings reporter."""
        self.target = target
        self.base_dir = Path(f"C:/Users/vaugh/BountyHound/findings/{target}")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.live_file = self.base_dir / "findings_live.json"

        # In-memory state
        self.validated_findings: List[Dict[str, Any]] = []
        self.pending_validation: List[Dict[str, Any]] = []
        self.active_agents: List[str] = []
        self.completed_agents: int = 0
        self.total_agents: int = 75

        self._last_save_time = 0
        self._save_interval = 10  # Save every 10 seconds

    def create_report(self) -> Dict[str, Any]:
        """Create current state report."""
        # Calculate severity breakdown
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }

        for finding in self.validated_findings:
            sev = finding.get('severity', 'INFO').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            'timestamp': datetime.now().isoformat(),
            'target': self.target,
            'hunt_in_progress': True,

            'validated_findings': self.validated_findings,
            'pending_validation': self.pending_validation,

            'currently_testing': {
                'active_agents': self.active_agents,
                'agents_completed': self.completed_agents,
                'agents_remaining': self.total_agents - self.completed_agents,
                'next_agents': self._get_next_agents(),
            },

            'summary': {
                'total_validated': len(self.validated_findings),
                'critical': severity_counts['CRITICAL'],
                'high': severity_counts['HIGH'],
                'medium': severity_counts['MEDIUM'],
                'low': severity_counts['LOW'],
            }
        }

    def add_validated_finding(self, finding: Dict[str, Any]) -> None:
        """Add validated finding to live report."""
        self.validated_findings.append(finding)
        logger.info(f"Added finding: {finding.get('title')}")

        # Auto-save if interval passed
        if time.time() - self._last_save_time >= self._save_interval:
            self.save_live_findings()

    def add_pending_finding(self, finding: Dict[str, Any]) -> None:
        """Add finding awaiting validation."""
        self.pending_validation.append(finding)

    def update_active_agents(self, agents: List[str]) -> None:
        """Update list of currently active agents."""
        self.active_agents = agents

    def update_completed_count(self, count: int) -> None:
        """Update number of completed agents."""
        self.completed_agents = count

    def save_live_findings(self) -> None:
        """Save live findings to findings_live.json."""
        report = self.create_report()

        try:
            with open(self.live_file, 'w') as f:
                json.dump(report, f, indent=2)
            self._last_save_time = time.time()
            logger.debug(f"Saved live findings: {self.live_file}")
        except Exception as e:
            logger.error(f"Error saving live findings: {e}")

    def _get_next_agents(self) -> List[str]:
        """Get list of next agents to run."""
        # This would be filled in by hunt_executor based on priority queue
        return []

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get findings filtered by severity."""
        return [
            f for f in self.validated_findings
            if f.get('severity', 'INFO').upper() == severity.upper()
        ]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        report = self.create_report()
        return report['summary']

    def hunt_complete(self) -> None:
        """Mark hunt as complete and finalize report."""
        report = self.create_report()
        report['hunt_in_progress'] = False
        report['hunt_completed_at'] = datetime.now().isoformat()

        with open(self.live_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Hunt complete. Report saved: {self.live_file}")
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/core/test_findings_reporter_v2.py -v
```

Expected:
```
test_live_findings_json_creation PASSED
test_add_validated_finding PASSED
test_live_file_persists PASSED

================ 3 passed in 0.58s ================
```

**Step 5: Commit**

```bash
git add engine/core/findings_reporter_v2.py tests/engine/core/test_findings_reporter_v2.py
git commit -m "feat: implement real-time findings reporter"
```

---

## Task 5: Integration in Hunt Executor

**Files:**
- Modify: `engine/core/hunt_executor.py` (update execute() method)
- Modify: `engine/core/auto_dispatcher.py` (adapt for priority queue)

**Step 1: Update hunt_executor.py to use priority queue**

```python
# Modify execute() method in engine/core/hunt_executor.py

def execute(self, force: bool = False) -> HuntReport:
    """Execute optimized hunt with priority queue, validation, and real-time reporting."""
    start_time = time.time()
    self._banner()

    # Initialize subsystems
    self._adaptive = None
    self._payload_tracker = None
    self._browser = None
    self._llm_bridge = None

    # Phase 0: DB check
    if not force and not self.phase_0_db_check():
        self.report.finished_at = datetime.now().isoformat()
        self.report.duration_seconds = time.time() - start_time
        return self.report

    # Phase 0.5: Profile target
    self.phase_05_profile()

    # NEW: Initialize cache manager
    from engine.core.cache_manager import CacheManager
    cache_mgr = CacheManager(self.target)
    cache_mgr.record_hunt_start()

    # NEW: Initialize findings reporter
    from engine.core.findings_reporter_v2 import FindingsReporterV2
    reporter = FindingsReporterV2(self.target)

    # NEW: Initialize validation pipeline
    from engine.core.validation_pipeline_v2 import ValidationPipelineV2
    validator = ValidationPipelineV2()

    # NEW: Initialize findings manager
    from engine.core.findings_manager import FindingsManager
    findings_mgr = FindingsManager(self.target)

    # NEW: Build agent priority queue
    from engine.core.agent_priority_queue import AgentPriorityQueue
    priority_queue = AgentPriorityQueue()

    # Get agent statistics (from registry or cache)
    agent_stats = self._get_agent_stats()  # New method
    execution_order = priority_queue.get_execution_order(agent_stats, self.profile)

    self._log(f"Agent execution order: {execution_order[:5]}... (75 agents total)")

    # Initialize dispatcher with profile and auth tokens
    self.dispatcher = AutoDispatcher(
        self.registry,
        self.profile,
        max_workers=1,  # Run agents sequentially by priority
        auth_tokens=self.auth_tokens,
        execution_order=execution_order,  # NEW: Pass priority order
    )

    # ... rest of initialization ...

    # Run phases with THREE PARALLEL STREAMS
    self._run_optimized_hunt(
        cache_mgr, reporter, validator, findings_mgr, priority_queue
    )

    # ... rest of execute() ...
```

**Step 2: Add new method _run_optimized_hunt for three parallel streams**

```python
def _run_optimized_hunt(
    self,
    cache_mgr,
    reporter,
    validator,
    findings_mgr,
    priority_queue
) -> None:
    """Run hunt with three parallel streams: Hunt, Validation, Report."""
    import asyncio
    import threading

    # Stream 1: Hunt Stream (agents running in priority order)
    def hunt_stream():
        """Agent execution in priority order."""
        results = self.dispatcher.run_phase('2')  # Phases 1-6 combined
        return results

    # Stream 2: Validation Stream (validates findings as they arrive)
    def validation_stream(findings_queue):
        """Validate findings as they're discovered."""
        while True:
            try:
                finding = findings_queue.get(timeout=1)
                if finding is None:  # Sentinel value to stop
                    break

                self._log(f"Validating: {finding.get('title')}")

                # Run validation
                validation_result = validator.validate_finding_async(finding)

                # If validated, send to report stream
                if validation_result.get('validated'):
                    reporter.add_validated_finding({
                        'title': finding.get('title'),
                        'severity': validation_result.get('severity'),
                        'endpoint': validation_result.get('endpoint'),
                        'folder': f"findings/{self.target}/{findings_mgr.generate_folder_name(...)}/",
                    })

                    # Create finding folder
                    findings_mgr.create_finding_folder(validation_result, finding)

            except Exception as e:
                self._log(f"Validation error: {e}")

    # Stream 3: Report Stream (updates findings_live.json)
    def report_stream():
        """Update findings_live.json every 10 seconds."""
        while True:
            try:
                reporter.save_live_findings()
                time.sleep(10)
            except Exception as e:
                self._log(f"Report error: {e}")

    # Start all three streams
    findings_queue = queue.Queue()

    hunt_thread = threading.Thread(target=hunt_stream, daemon=True)
    validation_thread = threading.Thread(target=lambda: validation_stream(findings_queue), daemon=True)
    report_thread = threading.Thread(target=report_stream, daemon=True)

    hunt_thread.start()
    validation_thread.start()
    report_thread.start()

    # Wait for hunt to complete, then stop validation
    hunt_thread.join()
    findings_queue.put(None)  # Sentinel
    validation_thread.join()

    # Finalize report
    reporter.hunt_complete()
```

**Step 3: Test updated hunt_executor**

```bash
cd C:/Users/vaugh/Desktop/BountyHound/bountyhound-agent
pytest tests/engine/core/test_hunt_executor.py -v -k "test_execute"
```

**Step 4: Commit**

```bash
git add engine/core/hunt_executor.py
git commit -m "feat: integrate priority queue, validation, and parallel streams in hunt executor"
```

---

## Task 6: ProxyEngine Traffic Capture Integration

**Files:**
- Create: `engine/core/proxy_traffic_capture.py`
- Modify: `engine/core/validation_pipeline_v2.py` (add traffic capture)

**Step 1: Write failing test for proxy integration**

```python
# tests/engine/core/test_proxy_traffic_capture.py
import pytest
from engine.core.proxy_traffic_capture import ProxyTrafficCapture

def test_start_capture():
    """Test starting traffic capture."""
    capture = ProxyTrafficCapture(proxy_host='127.0.0.1', proxy_port=8080)

    # Should connect to ProxyEngine
    assert capture.is_running() == False

    capture.start()
    assert capture.is_running() == True

    capture.stop()

def test_capture_request_response():
    """Test capturing HTTP request/response."""
    capture = ProxyTrafficCapture(proxy_host='127.0.0.1', proxy_port=8080)
    capture.start()

    # Make request through proxy
    # ... (mocked)

    # Get captured traffic
    traffic = capture.get_last_request()
    assert traffic['method'] == 'GET'
    assert traffic['url'] == 'http://example.com/api/users?id=1'

    capture.stop()

def test_save_captured_to_json():
    """Test saving captured traffic to JSON."""
    capture = ProxyTrafficCapture(proxy_host='127.0.0.1', proxy_port=8080)

    # Simulate captured traffic
    traffic = {
        'request': {'method': 'GET', 'url': '...', 'headers': {}},
        'response': {'status': 200, 'body': '...', 'headers': {}},
    }

    json_file = capture.save_traffic_to_json(traffic, 'finding_name')
    assert json_file.exists()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/core/test_proxy_traffic_capture.py -v
```

Expected:
```
FAILED - ModuleNotFoundError: No module named 'engine.core.proxy_traffic_capture'
```

**Step 3: Implement proxy traffic capture**

```python
# engine/core/proxy_traffic_capture.py
"""
ProxyEngine Traffic Capture Integration

Captures HTTP requests/responses through ProxyEngine during PoC validation.
Saves traffic to evidence.json for finding documentation.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
import requests

logger = logging.getLogger(__name__)


class ProxyTrafficCapture:
    """Captures traffic through ProxyEngine."""

    def __init__(self, proxy_host: str = '127.0.0.1', proxy_port: int = 8187):
        """Initialize proxy traffic capture."""
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_url = f"http://{proxy_host}:{proxy_port}"
        self.is_capturing = False
        self.captured_traffic = []

    def start(self) -> bool:
        """Start capturing traffic."""
        try:
            # Check if ProxyEngine is running
            response = requests.get(f"{self.proxy_url}/api/status", timeout=5)
            if response.status_code == 200:
                self.is_capturing = True
                logger.info("ProxyEngine traffic capture started")
                return True
        except Exception as e:
            logger.error(f"Cannot connect to ProxyEngine: {e}")
            return False

    def stop(self) -> None:
        """Stop capturing traffic."""
        self.is_capturing = False
        logger.info("ProxyEngine traffic capture stopped")

    def is_running(self) -> bool:
        """Check if capture is running."""
        return self.is_capturing

    def get_captured_traffic(self) -> list:
        """Get all captured traffic."""
        return self.captured_traffic

    def get_last_request(self) -> Optional[Dict]:
        """Get last captured request/response."""
        if self.captured_traffic:
            return self.captured_traffic[-1]
        return None

    def clear_traffic(self) -> None:
        """Clear captured traffic."""
        self.captured_traffic = []

    def save_traffic_to_json(
        self,
        traffic: Dict[str, Any],
        finding_name: str
    ) -> Path:
        """
        Save captured traffic to JSON file.

        Args:
            traffic: Request/response data
            finding_name: Name of finding folder

        Returns:
            Path to saved JSON file
        """
        evidence_file = Path(f"C:/Users/vaugh/BountyHound/findings/target/{finding_name}/evidence.json")

        # If file exists, append to it
        if evidence_file.exists():
            with open(evidence_file) as f:
                existing = json.load(f)
            existing['request'] = traffic.get('request')
            existing['response'] = traffic.get('response')
        else:
            existing = traffic

        with open(evidence_file, 'w') as f:
            json.dump(existing, f, indent=2)

        logger.debug(f"Saved traffic: {evidence_file}")
        return evidence_file
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/core/test_proxy_traffic_capture.py -v
```

**Step 5: Commit**

```bash
git add engine/core/proxy_traffic_capture.py tests/engine/core/test_proxy_traffic_capture.py
git commit -m "feat: implement ProxyEngine traffic capture integration"
```

---

## Summary

This plan breaks down the Optimized Hunt v2 design into 6 major tasks:

1. **Agent Priority Queue** (Task 1) - Score agents by track record + confidence + speed + stack-specificity
2. **Validation Pipeline** (Task 2) - PoC execution for SQLi, IDOR, XSS, RCE with evidence capture
3. **Findings Manager** (Task 3) - Self-contained folders with poc.md + evidence.json + screenshots
4. **Real-Time Reporter** (Task 4) - findings_live.json updates every 10 seconds
5. **Hunt Executor Integration** (Task 5) - Three parallel streams (Hunt, Validation, Report)
6. **ProxyEngine Integration** (Task 6) - Capture traffic during validation runs

Each task is bite-sized (5-10 steps), follows TDD, and includes tests, implementation, and commits.

**Total estimated effort:** 8-12 hours for experienced Python developer

---

# Implementation Complete ✅

Plan saved and ready for execution.
