# HTTP Request Smuggling Tester - Usage Guide

## Overview

The HTTP Request Smuggling Tester detects critical vulnerabilities in HTTP request handling when frontend and backend servers disagree on request boundaries. This can lead to:

- Cache poisoning
- Request hijacking
- Authentication bypass
- Web cache deception
- Cross-site scripting (XSS)

**Severity:** CRITICAL (typically $1,500-$5,000+ bounties)

## How It Works

### Vulnerability Types Tested

1. **CL.TE (Content-Length vs Transfer-Encoding)**
   - Frontend uses Content-Length header
   - Backend uses Transfer-Encoding header
   - Smuggled request appended after chunked terminator

2. **TE.CL (Transfer-Encoding vs Content-Length)**
   - Frontend uses Transfer-Encoding header
   - Backend uses Content-Length header
   - Smuggled request hidden in chunk

3. **TE.TE (Obfuscated Transfer-Encoding)**
   - Multiple Transfer-Encoding headers with obfuscation
   - One server accepts, other rejects obfuscated header
   - Tests case variations, double headers, identity encoding

4. **Timing-based Detection**
   - Measures response time differences
   - Detects blind smuggling vulnerabilities
   - Triggers delays via smuggled requests

## Usage

### Standalone Usage

```python
from engine.agents.smuggling_tester import SmugglingTester

tester = SmugglingTester()

# Test single endpoint
endpoint = "https://example.com/api/search"

# Test CL.TE smuggling
findings = tester.test_cl_te(endpoint)

# Test TE.CL smuggling
findings = tester.test_te_cl(endpoint)

# Test TE.TE smuggling
findings = tester.test_te_te(endpoint)

# Test timing-based detection
is_vulnerable = tester.test_timing_detection(endpoint)
```

### Integration with Phased Hunter

The smuggling tester is automatically integrated into the validation phase:

```bash
# Automatically runs during phased hunt
/hunt example.com
```

The phased hunter will:
1. Discover endpoints during recon
2. Test all endpoints for smuggling in validation phase
3. Generate findings with evidence
4. Create POCs for verified vulnerabilities

### Manual Testing

```python
from engine.agents.phased_hunter import PhasedHunter

hunter = PhasedHunter(target='example.com')

# Test specific endpoints
endpoints = [
    'https://example.com/api/search',
    'https://example.com/api/users',
    'https://example.com/checkout'
]

findings = hunter._test_request_smuggling(endpoints)

for finding in findings:
    print(f"{finding.title} - {finding.severity}")
    print(f"Evidence: {finding.evidence}")
```

## Detection Indicators

The tester looks for these smuggling indicators:

- **404 Not Found**: Smuggled request to non-existent endpoint
- **403 Forbidden**: Smuggled request to admin endpoint
- **"Unrecognized method"**: Backend received malformed request
- **"Invalid request"**: Backend received corrupted request
- **Timing delays**: 5+ second delays indicate queued requests

## Example Findings

### CL.TE Smuggling

```
Title: HTTP Request Smuggling (CL.TE)
Severity: CRITICAL
Type: HTTP_Smuggling_CLTE

Description:
Server vulnerable to CL.TE request smuggling. Frontend uses
Content-Length, backend uses Transfer-Encoding.

Evidence:
- URL: https://example.com/api/search
- Type: CL.TE
- Response 1: 200 OK
- Response 2: 404 Not Found (smuggled request detected)

POC:
POST /api/search HTTP/1.1
Host: example.com
Content-Length: 45
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com
```

### TE.TE Smuggling

```
Title: HTTP Request Smuggling (TE.TE)
Severity: CRITICAL
Type: HTTP_Smuggling_TETE

Description:
Server vulnerable to TE.TE request smuggling with obfuscated
Transfer-Encoding headers.

Evidence:
- URL: https://example.com/checkout
- Type: TE.TE
- Obfuscation: Transfer-Encoding: chunked\r\nTransfer-Encoding: identity
- Response indicates smuggling occurred

POC:
POST /checkout HTTP/1.1
Host: example.com
Transfer-Encoding: chunked
Transfer-Encoding: identity

0

GET /admin HTTP/1.1
Host: example.com
```

## Payload Generation

Generate all smuggling payloads for manual testing:

```python
tester = SmugglingTester()
payloads = tester.generate_smuggling_payloads()

for payload in payloads:
    print(payload)
    print("=" * 80)
```

## Configuration

```python
tester = SmugglingTester()

# Adjust timeout (default: 30 seconds)
tester.timeout = 60

# Adjust timing threshold (default: 5 seconds)
tester.timing_threshold = 10.0
```

## Testing Strategy

### 1. Identify Entry Points

Test these endpoint types:
- API gateways
- Load balancers
- CDN endpoints
- Reverse proxies
- Web application firewalls (WAFs)

### 2. Prioritize High-Value Targets

Focus on:
- Authentication endpoints
- Admin panels
- Payment processing
- User profile management
- Cache-backed endpoints

### 3. Test All Variants

Always test all 4 smuggling types:
- CL.TE
- TE.CL
- TE.TE
- Timing-based

### 4. Validate Findings

Confirm smuggling by:
1. Sending smuggling request
2. Sending normal request immediately after
3. Checking if normal request received unexpected response
4. Repeating multiple times to confirm consistency

## Integration with OAST

For blind smuggling detection, integrate with Out-of-Band Application Security Testing (OAST):

```python
# Build payload that callbacks to OAST server
smuggled = f"GET / HTTP/1.1\r\nHost: {oast_domain}\r\n\r\n"

# Monitor OAST server for callback
# If callback received = smuggling confirmed
```

## False Positives

Avoid false positives by:

1. **Testing multiple times**: Confirm behavior is consistent
2. **Checking status codes**: 404/403 alone is not sufficient
3. **Verifying smuggling chain**: Ensure second request is affected
4. **Timing analysis**: Confirm delays are consistent
5. **Manual validation**: Always verify manually before reporting

## Reporting

Include in your report:

1. **Vulnerability type** (CL.TE, TE.CL, TE.TE, or timing)
2. **Affected endpoint** (full URL)
3. **Request payload** (exact bytes sent)
4. **Evidence** (screenshots, responses, timing data)
5. **Impact** (cache poisoning, auth bypass, etc.)
6. **Remediation** (disable Transfer-Encoding, normalize headers, etc.)

## Best Practices

1. **Test on staging first**: Smuggling can break production
2. **Use unique identifiers**: Tag smuggled requests for tracking
3. **Monitor for side effects**: Check if other users affected
4. **Document thoroughly**: Smuggling is complex to explain
5. **Provide POC**: Include working curl commands

## Common Targets

High-value targets for smuggling testing:

- **AWS CloudFront + ALB/ELB**
- **Nginx + Apache**
- **HAProxy + Nginx**
- **Akamai CDN + Origin**
- **Cloudflare + Backend**
- **F5 BIG-IP + Application**
- **IIS + ASP.NET**

## References

- [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [James Kettle's Research](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- [OWASP Request Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)

## Success Metrics

**Revenue Impact:** $1,500-$3,000/month

**Bounty Range:**
- Critical (CVSS 9.0+): $3,000-$10,000
- High (CVSS 7.0-8.9): $1,500-$3,000
- Medium (CVSS 4.0-6.9): $500-$1,500

**Detection Rate:**
- ~5% of tested applications are vulnerable
- Higher rate (10-15%) on complex architectures
- Critical severity accepted >80% of the time
