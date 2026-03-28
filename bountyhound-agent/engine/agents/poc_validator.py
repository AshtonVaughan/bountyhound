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
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from colorama import Fore, Style
from engine.core.state_verifier import StateVerifier



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
        """Validate CORS misconfiguration"""
        url = finding.get('url', '')

        try:
            result = subprocess.run(
                ['curl', '-s', '-I', '-H', 'Origin: https://evil.com', '-m', '10', url],
                capture_output=True,
                text=True,
                timeout=15
            )

            headers = result.stdout.lower()

            # Check for reflected origin
            has_reflected_origin = 'access-control-allow-origin: https://evil.com' in headers
            has_credentials = 'access-control-allow-credentials: true' in headers
            has_wildcard = 'access-control-allow-origin: *' in headers

            self._save_curl_output(f'cors_check_{self._request_count}.txt', result.stdout)
            self._request_count += 1

            if has_reflected_origin and has_credentials:
                return {
                    'pass': True,
                    'reason': 'CORS misconfiguration confirmed: arbitrary origin reflected with credentials',
                    'evidence': result.stdout[:500],
                    'severity_note': 'Check if API uses cookie-based auth (medium-high) or token-based (low)'
                }
            elif has_wildcard:
                return {
                    'pass': False,
                    'reason': 'Wildcard CORS is often by design (not a vulnerability)',
                    'evidence': 'Access-Control-Allow-Origin: *'
                }
            else:
                return {
                    'pass': False,
                    'reason': 'No CORS misconfiguration detected',
                    'evidence': result.stdout[:500]
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

            # Task 6: HTTP 200 alone is NOT sufficient - require state change proof
            if status_code == '200' and len(body) > 0:
                # Check using StateVerifier
                verification = self.state_verifier.verify_from_status_code(200)

                return {
                    'pass': False,  # Reject without state change proof
                    'reason': 'IDOR requires state change verification. HTTP 200 alone is insufficient. '
                              'Finding must include before_state, after_state, and mutation_response fields to prove actual exploitation.',
                    'evidence': f'HTTP 200, body: {body[:500]}',
                    'note': 'Add state_change_verified=True with before_state/after_state/mutation_response to confirm this finding',
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
        """Validate XSS vulnerability"""
        url = finding.get('url', '')
        param = finding.get('param', 'q')

        payload = '<script>alert(1)</script>'
        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"

        try:
            result = subprocess.run(
                ['curl', '-s', '-m', '10', test_url],
                capture_output=True,
                text=True,
                timeout=15
            )

            output = result.stdout
            self._save_curl_output(f'xss_check_{self._request_count}.txt', output)
            self._request_count += 1

            # Check if payload appears unencoded
            if payload in output:
                # Check content type
                headers_result = subprocess.run(
                    ['curl', '-s', '-I', '-m', '10', test_url],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                if 'text/html' in headers_result.stdout.lower():
                    return {
                        'pass': True,
                        'reason': 'XSS confirmed: payload appears unencoded in HTML response',
                        'evidence': output[:500],
                        'note': 'Verify payload is in executable context'
                    }
                else:
                    return {
                        'pass': False,
                        'reason': 'Payload reflected but not in HTML context',
                        'evidence': 'Content-Type is not text/html'
                    }

            # Check for encoded version
            if '&lt;script&gt;' in output or '%3Cscript%3E' in output:
                return {
                    'pass': False,
                    'reason': 'Payload is HTML-encoded (not vulnerable)',
                    'evidence': 'Payload appears as &lt;script&gt;'
                }

            return {
                'pass': False,
                'reason': 'Payload does not appear in response',
                'evidence': output[:500]
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'XSS validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_sqli(self, finding: dict) -> dict:
        """Validate SQL injection vulnerability"""
        url = finding.get('url', '')
        param = finding.get('param', 'id')

        # Error-based test
        error_url = f"{url}{'&' if '?' in url else '?'}{param}=1'"
        normal_url = f"{url}{'&' if '?' in url else '?'}{param}=1"

        try:
            # Test with quote
            error_result = subprocess.run(
                ['curl', '-s', '-m', '10', error_url],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Test without quote
            normal_result = subprocess.run(
                ['curl', '-s', '-m', '10', normal_url],
                capture_output=True,
                text=True,
                timeout=15
            )

            error_output = error_result.stdout.lower()
            normal_output = normal_result.stdout.lower()

            self._save_curl_output(f'sqli_error_{self._request_count}.txt', error_output)
            self._save_curl_output(f'sqli_normal_{self._request_count}.txt', normal_output)
            self._request_count += 1

            # Check for SQL error messages
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'oracle', 'syntax error',
                'unclosed quotation', 'quoted string', 'mysql_fetch'
            ]

            has_sql_error = any(err in error_output for err in sql_errors)

            if has_sql_error and error_output != normal_output:
                return {
                    'pass': True,
                    'reason': 'SQL injection confirmed: SQL error in response',
                    'evidence': error_output[:500]
                }

            # Time-based test (basic check)
            time_url = f"{url}{'&' if '?' in url else '?'}{param}=1' AND SLEEP(5)--"

            start = time.time()
            time_result = subprocess.run(
                ['curl', '-s', '-m', '15', time_url],
                capture_output=True,
                text=True,
                timeout=20
            )
            elapsed = time.time() - start

            if elapsed >= 5:
                return {
                    'pass': True,
                    'reason': f'SQL injection confirmed: time-based (delayed {elapsed:.1f}s)',
                    'evidence': f'Request took {elapsed:.1f} seconds (expected 5s delay)'
                }

            return {
                'pass': False,
                'reason': 'No SQL injection detected',
                'evidence': 'No SQL errors or timing differences'
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'SQL injection validation error: {str(e)}',
                'evidence': str(e)
            }

    def validate_ssrf(self, finding: dict) -> dict:
        """Validate SSRF vulnerability"""
        url = finding.get('url', '')
        param = finding.get('param', 'url')

        internal_url = f"{url}{'&' if '?' in url else '?'}{param}=http://127.0.0.1"
        baseline_url = f"{url}{'&' if '?' in url else '?'}{param}=http://example.com"

        try:
            # Test with internal IP
            internal_result = subprocess.run(
                ['curl', '-s', '-m', '10', internal_url],
                capture_output=True,
                text=True,
                timeout=15
            )

            # Test with external domain
            baseline_result = subprocess.run(
                ['curl', '-s', '-m', '10', baseline_url],
                capture_output=True,
                text=True,
                timeout=15
            )

            internal_output = internal_result.stdout
            baseline_output = baseline_result.stdout

            self._save_curl_output(f'ssrf_internal_{self._request_count}.txt', internal_output)
            self._save_curl_output(f'ssrf_baseline_{self._request_count}.txt', baseline_output)
            self._request_count += 1

            # Check for differences indicating server-side fetch
            if internal_output != baseline_output:
                # Look for signs of internal data
                if any(x in internal_output.lower() for x in ['localhost', '127.0.0.1', 'internal', 'private']):
                    return {
                        'pass': True,
                        'reason': 'SSRF confirmed: server fetched internal resource',
                        'evidence': internal_output[:500]
                    }
                else:
                    return {
                        'pass': True,
                        'reason': 'Possible SSRF: different responses for internal vs external',
                        'evidence': f'Internal response differs from baseline',
                        'note': 'Verify server actually made the request'
                    }

            return {
                'pass': False,
                'reason': 'No SSRF detected: identical responses',
                'evidence': 'Same response for internal and external URLs'
            }

        except Exception as e:
            return {
                'pass': False,
                'reason': f'SSRF validation error: {str(e)}',
                'evidence': str(e)
            }

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
