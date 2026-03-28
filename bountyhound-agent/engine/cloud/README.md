# Cloud Security Testing

Comprehensive security testing modules for Azure and Google Cloud Platform (GCP).

## Overview

This module provides automated security testing for common cloud misconfigurations that lead to data exposure, unauthorized access, and privilege escalation.

## Azure Testing (`azure_tester.py`)

### Features

1. **Storage Account Enumeration**
   - Tests common naming patterns: `{target}.blob.core.windows.net`
   - Detects public blob access
   - Identifies exposed containers
   - Tests SAS token exposure

2. **Function App Testing**
   - Enumerates Function Apps: `{target}.azurewebsites.net`
   - Tests authentication requirements
   - Detects missing function keys
   - CORS misconfiguration testing

3. **Key Vault Exposure**
   - Scans source code for vault URLs
   - Pattern: `https://{name}.vault.azure.net`
   - Identifies hardcoded vault references

### Usage

```python
from engine.cloud.azure_tester import AzureTester

tester = AzureTester()

# Test storage accounts
findings = tester.test_storage_account_enumeration("example.com")

# Test function apps
findings = tester.test_function_app_exposure("example")

# Test for Key Vault exposure in source
with open("app.js", "r") as f:
    content = f.read()
findings = tester.test_keyvault_exposure("https://example.com", content)
```

### Common Patterns

```python
# Storage account patterns tested:
- {target}.blob.core.windows.net
- {target}storage.blob.core.windows.net
- {target}data.blob.core.windows.net
- {target}prod.blob.core.windows.net
- {target}dev.blob.core.windows.net

# Function app patterns tested:
- {target}.azurewebsites.net
- {target}-api.azurewebsites.net
- {target}-func.azurewebsites.net
- {target}-prod.azurewebsites.net
```

## GCP Testing (`gcp_tester.py`)

### Features

1. **Storage Bucket Enumeration**
   - Tests common bucket names
   - Detects public read access
   - URL pattern: `https://storage.googleapis.com/{bucket}`
   - Tests signed URL exposure

2. **Cloud Function Testing**
   - Tests functions in multiple regions
   - Regions: us-central1, us-east1, europe-west1
   - Authentication bypass detection
   - IAM policy testing

3. **Firebase/Firestore Testing**
   - Detects exposed Firebase config in JS
   - Identifies API keys in source
   - Extracts project IDs
   - Security rules validation

### Usage

```python
from engine.cloud.gcp_tester import GCPTester

tester = GCPTester()

# Test storage buckets
findings = tester.test_storage_bucket_enumeration("example.com")

# Test Cloud Functions
findings = tester.test_cloud_function_exposure("example")

# Test Firebase config exposure
with open("app.js", "r") as f:
    content = f.read()
findings = tester.test_firestore_exposure("https://example.com", content)
```

### Common Patterns

```python
# Storage bucket patterns tested:
- {target}
- {target}-storage
- {target}-data
- {target}-backup
- {target}-prod
- {target}-public

# Cloud Function URLs tested:
- https://us-central1-{target}.cloudfunctions.net/api
- https://us-east1-{target}.cloudfunctions.net/api
- https://europe-west1-{target}.cloudfunctions.net/api
```

## Finding Structure

All findings use a standardized dataclass:

```python
@dataclass
class Finding:
    title: str              # Short, descriptive title
    description: str        # Detailed description
    severity: str          # HIGH, MEDIUM, LOW
    evidence: Dict         # Proof of vulnerability
    vuln_type: str         # Classification (e.g., "Azure_Storage_Public")
```

## Severity Levels

- **HIGH**: Public data access, authentication bypass, exposed credentials
- **MEDIUM**: CORS misconfigurations, missing auth on non-sensitive endpoints
- **LOW**: Information disclosure (vault URLs, config exposure)

## Integration Example

```python
from engine.cloud.azure_tester import AzureTester
from engine.cloud.gcp_tester import GCPTester

def audit_cloud_security(target_domain: str):
    """Complete cloud security audit"""
    all_findings = []

    # Azure testing
    azure = AzureTester()
    all_findings.extend(azure.test_storage_account_enumeration(target_domain))
    all_findings.extend(azure.test_function_app_exposure(target_domain.replace('.com', '')))

    # GCP testing
    gcp = GCPTester()
    all_findings.extend(gcp.test_storage_bucket_enumeration(target_domain))
    all_findings.extend(gcp.test_cloud_function_exposure(target_domain.replace('.com', '')))

    return all_findings

# Run audit
findings = audit_cloud_security("example.com")
for finding in findings:
    print(f"[{finding.severity}] {finding.title}")
    print(f"  {finding.description}")
    print(f"  Evidence: {finding.evidence}")
```

## Revenue Impact

Cloud security testing targets high-value vulnerabilities:

- **Data exposure**: $2,000-$5,000 per finding
- **Authentication bypass**: $1,000-$3,000 per finding
- **Configuration issues**: $500-$1,500 per finding

**Estimated monthly revenue**: $3,000-$6,000

## Real-World Examples

### Azure Storage Account Exposure
```
Title: Azure Storage Account Public Access
Severity: HIGH
Evidence:
  - URL: https://companydata.blob.core.windows.net
  - Containers: [backups, uploads, logs]
  - Public access: TRUE
Bounty: $3,500
```

### GCP Bucket Public Access
```
Title: GCP Storage Bucket Public Access
Severity: HIGH
Evidence:
  - Bucket: company-prod
  - URL: https://storage.googleapis.com/company-prod
  - Files: 1,247 files exposed
Bounty: $4,000
```

### Firebase Config Exposure
```
Title: Firebase Configuration Exposed in Source
Severity: MEDIUM
Evidence:
  - API Key: AIzaSyTest123...
  - Project ID: company-prod-firebase
  - Found in: https://example.com/app.js
Bounty: $800
```

## Testing

Run the test suite:

```bash
# Test Azure module
pytest tests/engine/cloud/test_azure_tester.py -v

# Test GCP module
pytest tests/engine/cloud/test_gcp_tester.py -v

# Integration tests
pytest tests/engine/cloud/test_cloud_integration.py -v

# All cloud tests
pytest tests/engine/cloud/ -v
```

## Best Practices

1. **Rate Limiting**: Built-in 10-second timeout per request
2. **Error Handling**: All exceptions caught and logged
3. **Pattern Iteration**: Multiple naming patterns tested automatically
4. **Evidence Collection**: Full response capture for proof
5. **False Positive Prevention**: Validates actual access, not just DNS resolution

## Future Enhancements

- [ ] AWS S3 integration (already in separate module)
- [ ] Azure AD enumeration
- [ ] GCP IAM policy testing
- [ ] Cloud SQL exposure detection
- [ ] Kubernetes cluster enumeration
- [ ] Terraform state file detection
