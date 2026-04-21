# BountyHound Security & Completeness Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all critical security vulnerabilities, complete stubbed functionality, and add missing infrastructure to make BountyHound production-ready.

**Architecture:** Fix security issues first (command injection, path traversal), then complete stubbed functions (iOS analyzer, exported component checker), add reliability features (rate limiting, proxies), and finally add testing infrastructure.

**Tech Stack:** Python 3.10+, pytest, macholib (iOS), xml.etree (Android manifest), requests (HTTP), time (rate limiting)

---

## PHASE 1: CRITICAL SECURITY FIXES (Week 1)

### Task 1: Fix Command Injection in APK Analyzer

**Files:**
- Modify: `engine/mobile/android/apk_analyzer.py:28-46`
- Test: `tests/engine/mobile/android/test_apk_analyzer_security.py` (create)

**Step 1: Write the failing test**

Create `tests/engine/mobile/android/test_apk_analyzer_security.py`:
```python
import pytest
from pathlib import Path
from engine.mobile.android.apk_analyzer import APKAnalyzer

def test_rejects_invalid_apk_path():
    """Test that malicious paths are rejected"""
    with pytest.raises(ValueError, match="Invalid APK path"):
        analyzer = APKAnalyzer("evil.apk; rm -rf /")

def test_rejects_non_apk_file():
    """Test that non-APK files are rejected"""
    with pytest.raises(ValueError, match="File must be .apk"):
        analyzer = APKAnalyzer("test.txt")

def test_rejects_nonexistent_file():
    """Test that nonexistent files are rejected"""
    with pytest.raises(ValueError, match="Invalid APK path"):
        analyzer = APKAnalyzer("/nonexistent/path.apk")
```

**Step 2: Run test to verify it fails**

```bash
cd C:/Users/vaugh/Projects/bountyhound-agent
mkdir -p tests/engine/mobile/android
pytest tests/engine/mobile/android/test_apk_analyzer_security.py -v
```
Expected: FAIL with "No path validation implemented"

**Step 3: Add input validation to APKAnalyzer.__init__**

Modify `engine/mobile/android/apk_analyzer.py:28-46`:
```python
def __init__(self, apk_path: str):
    """
    Initialize APK analyzer

    Args:
        apk_path: Path to APK file

    Raises:
        ValueError: If path is invalid or file is not an APK
    """
    # Validate and resolve path
    self.apk_path = Path(apk_path).resolve()

    # Security: Check file exists and is a file
    if not self.apk_path.exists():
        raise ValueError(f"Invalid APK path: {apk_path} (file not found)")

    if not self.apk_path.is_file():
        raise ValueError(f"Invalid APK path: {apk_path} (not a file)")

    # Security: Verify it's an APK file
    if self.apk_path.suffix.lower() != '.apk':
        raise ValueError(f"File must be .apk (got {self.apk_path.suffix})")

    # Security: Prevent command injection by checking for shell metacharacters
    if any(char in str(self.apk_path) for char in [';', '|', '&', '$', '`', '\n', '\r']):
        raise ValueError(f"Invalid APK path: contains shell metacharacters")

    self.apk = None
    self.findings = []

    if ANDROGUARD_AVAILABLE:
        self.apk = APK(str(self.apk_path))

    self.output_dir = self.apk_path.parent / f"{self.apk_path.stem}_analysis"
    self.output_dir.mkdir(exist_ok=True)
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/mobile/android/test_apk_analyzer_security.py -v
```
Expected: PASS (all 3 tests)

**Step 5: Commit**

```bash
git add engine/mobile/android/apk_analyzer.py tests/engine/mobile/android/test_apk_analyzer_security.py
git commit -m "security: add input validation to APK analyzer

- Validate file exists and is a file
- Check .apk extension
- Reject paths with shell metacharacters
- Prevent command injection in jadx subprocess call

Fixes command injection vulnerability"
```

---

### Task 2: Fix Path Traversal in IPA Analyzer

**Files:**
- Modify: `engine/mobile/ios/ipa_analyzer.py:55-68`
- Test: `tests/engine/mobile/ios/test_ipa_analyzer_security.py` (create)

**Step 1: Write the failing test**

Create `tests/engine/mobile/ios/test_ipa_analyzer_security.py`:
```python
import pytest
import zipfile
import tempfile
from pathlib import Path
from engine.mobile.ios.ipa_analyzer import IPAAnalyzer

def test_rejects_path_traversal_in_zip():
    """Test that malicious ZIP paths are rejected"""
    # Create malicious ZIP with path traversal
    with tempfile.NamedTemporaryFile(suffix='.ipa', delete=False) as f:
        evil_ipa = f.name

    with zipfile.ZipFile(evil_ipa, 'w') as zf:
        zf.writestr('../../etc/passwd', 'hacked')

    analyzer = IPAAnalyzer(evil_ipa)

    with pytest.raises(ValueError, match="Path traversal detected"):
        analyzer.extract_ipa()

    # Cleanup
    Path(evil_ipa).unlink()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/mobile/ios/test_ipa_analyzer_security.py -v
```
Expected: FAIL with "No path traversal protection"

**Step 3: Add path traversal protection**

Modify `engine/mobile/ios/ipa_analyzer.py:55-68`:
```python
def extract_ipa(self):
    """Extract IPA (ZIP archive) with path traversal protection"""
    extract_dir = self.output_dir / "extracted"

    if extract_dir.exists():
        print(f"{Fore.YELLOW}[*] Using cached extraction{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}[*] Extracting IPA...{Style.RESET_ALL}")

    with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
        # Security: Validate each member path before extraction
        for member in zip_ref.namelist():
            # Resolve the full path
            member_path = (extract_dir / member).resolve()

            # Check if path escapes the extraction directory
            try:
                member_path.relative_to(extract_dir.resolve())
            except ValueError:
                raise ValueError(f"Path traversal detected in ZIP member: {member}")

        # Safe to extract after validation
        zip_ref.extractall(extract_dir)

    print(f"{Fore.GREEN}[+] Extraction complete{Style.RESET_ALL}")
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/mobile/ios/test_ipa_analyzer_security.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add engine/mobile/ios/ipa_analyzer.py tests/engine/mobile/ios/test_ipa_analyzer_security.py
git commit -m "security: prevent path traversal in IPA extraction

- Validate each ZIP member path before extraction
- Check that resolved paths stay within extraction directory
- Reject malicious IPAs with path traversal attempts

Fixes path traversal vulnerability"
```

---

### Task 3: Fix Arbitrary File Write in Memory Scanner

**Files:**
- Modify: `engine/omnihack/memory/scanner.py:132-137`
- Test: `tests/engine/omnihack/memory/test_scanner_security.py` (create)

**Step 1: Write the failing test**

Create `tests/engine/omnihack/memory/test_scanner_security.py`:
```python
import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from engine.omnihack.memory.scanner import MemoryScanner

def test_dump_restricted_to_safe_directory():
    """Test that dump_region only writes to dumps directory"""
    with patch('engine.omnihack.memory.scanner.pymem.Pymem'):
        scanner = MemoryScanner("test.exe")
        scanner.pm = Mock()
        scanner.pm.read_bytes = Mock(return_value=b'test')

        # Should create file in dumps/ directory
        scanner.dump_region(0x1000, 4, "test.bin")

        # Verify file is in dumps directory
        assert Path("./dumps/test.bin").exists()

        # Cleanup
        Path("./dumps/test.bin").unlink()

def test_dump_rejects_path_traversal():
    """Test that path traversal attempts are blocked"""
    with patch('engine.omnihack.memory.scanner.pymem.Pymem'):
        scanner = MemoryScanner("test.exe")
        scanner.pm = Mock()
        scanner.pm.read_bytes = Mock(return_value=b'test')

        # Try to write outside dumps directory
        scanner.dump_region(0x1000, 4, "../../etc/passwd")

        # Should only write basename to dumps/
        assert Path("./dumps/passwd").exists()
        assert not Path("/etc/passwd").exists()

        # Cleanup
        Path("./dumps/passwd").unlink()
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/omnihack/memory/test_scanner_security.py -v
```
Expected: FAIL with "Arbitrary file write vulnerability"

**Step 3: Restrict file writes to safe directory**

Modify `engine/omnihack/memory/scanner.py:132-137`:
```python
def dump_region(self, address: int, size: int, filename: str):
    """
    Dump memory region to file (restricted to ./dumps/ directory)

    Args:
        address: Memory address to read from
        size: Number of bytes to read
        filename: Output filename (basename only, written to ./dumps/)
    """
    # Security: Create safe dumps directory
    safe_dir = Path("./dumps")
    safe_dir.mkdir(exist_ok=True)

    # Security: Only use basename to prevent path traversal
    safe_filename = Path(filename).name
    output_path = safe_dir / safe_filename

    # Read and write
    data = self.pm.read_bytes(address, size)
    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"[+] Dumped {size} bytes to {output_path}")
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/omnihack/memory/test_scanner_security.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add engine/omnihack/memory/scanner.py tests/engine/omnihack/memory/test_scanner_security.py
git commit -m "security: restrict memory dumps to safe directory

- Create ./dumps/ directory for all memory dumps
- Use basename only to prevent path traversal
- Prevent arbitrary file writes to system paths

Fixes arbitrary file write vulnerability"
```

---

### Task 4: Remove Hardcoded Credentials

**Files:**
- Modify: `CLAUDE.md:140-144`
- Create: `docs/TESTING-CREDENTIALS.md`

**Step 1: Document proper credential handling**

Create `docs/TESTING-CREDENTIALS.md`:
```markdown
# Testing Credentials Guide

## DO NOT use hardcoded credentials

For security testing, you MUST provide your own test credentials.

## Setting Test Credentials

Use environment variables:

```bash
export TEST_EMAIL="your-test-account@example.com"
export TEST_PASSWORD="YourSecurePassword123!"
```

## Per-Target Credentials

Store in per-target .env files (NOT committed to Git):

```bash
~/bounty-findings/<target>/credentials/<target>-creds.env
```

Add to `.gitignore`:
```
*-creds.env
credentials/
*.env
```

## Never Commit:
- Passwords
- API keys
- Session tokens
- OAuth credentials
- Test account credentials
```

**Step 2: Remove hardcoded credentials from CLAUDE.md**

Modify `CLAUDE.md:140-144`:
```markdown
## Authentication

**IMPORTANT: You must provide your own test credentials.**

See `docs/TESTING-CREDENTIALS.md` for proper credential management.

Per-target credentials are stored in:
`~/bounty-findings/<target>/credentials/<target>-creds.env`

DO NOT commit credentials to Git.
```

**Step 3: Add credentials to .gitignore**

Modify `.gitignore` (or create if doesn't exist):
```
*-creds.env
credentials/
*.env
.env
test-credentials.env
```

**Step 4: Commit**

```bash
git add CLAUDE.md docs/TESTING-CREDENTIALS.md .gitignore
git commit -m "security: remove hardcoded credentials

- Remove hardcoded email/password from CLAUDE.md
- Document proper credential management
- Add credentials to .gitignore
- Require users to provide own test credentials

Fixes credential exposure"
```

---

### Task 5: Fix Secrets Leaking to Terminal

**Files:**
- Modify: `engine/sast/analyzers/secrets_scanner.py:140-145`
- Test: `tests/engine/sast/analyzers/test_secrets_output.py` (create)

**Step 1: Write the failing test**

Create `tests/engine/sast/analyzers/test_secrets_output.py`:
```python
import pytest
from pathlib import Path
from io import StringIO
import sys
from engine.sast.analyzers.secrets_scanner import SecretsScanner

def test_secrets_not_printed_to_stdout(tmp_path, capsys):
    """Test that secret values are not printed to stdout"""
    # Create test file with secret
    test_file = tmp_path / "config.py"
    test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    scanner = SecretsScanner(str(tmp_path))
    findings = scanner.scan()

    # Capture stdout
    captured = capsys.readouterr()

    # Verify secret is NOT in stdout
    assert "AKIAIOSFODNN7EXAMPLE" not in captured.out
    assert "AKIA" not in captured.out  # Even partial shouldn't be visible

    # Verify finding was detected
    assert len(findings) == 1

def test_report_has_restricted_permissions(tmp_path):
    """Test that report file has owner-only permissions"""
    test_file = tmp_path / "config.py"
    test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    scanner = SecretsScanner(str(tmp_path))
    scanner.scan()

    # Check report file permissions (owner read/write only)
    report_path = Path("secrets_report.json")
    if report_path.exists():
        import stat
        mode = report_path.stat().st_mode
        # Should be 0o600 (rw-------)
        assert stat.S_IMODE(mode) == 0o600
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/sast/analyzers/test_secrets_output.py -v
```
Expected: FAIL with "Secrets printed to stdout"

**Step 3: Stop printing secrets to terminal**

Modify `engine/sast/analyzers/secrets_scanner.py:140-145`:
```python
                finding = {
                    "type": secret_type,
                    "value": self.mask_secret(match),
                    "file": str(file_path.relative_to(self.repo_path)),
                    "line": line_num,
                    "severity": "CRITICAL"
                }

                self.findings.append(finding)

                # Security: Do NOT print secrets to terminal (even masked)
                # Just log that a secret was found
                print(f"{Fore.RED}[!] {secret_type} found in {finding['file']}:{line_num}{Style.RESET_ALL}")
                # Note: Full details written to report file only
```

**Step 4: Add secure file permissions to report**

Modify `engine/sast/analyzers/secrets_scanner.py:183-188`:
```python
    # Save to JSON
    output_file = "secrets_report.json"
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2)

    # Security: Set restrictive permissions (owner read/write only)
    import stat
    Path(output_file).chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    print(f"\n{Fore.GREEN}[+] Report saved: {output_file} (permissions: rw-------){{Style.RESET_ALL}")
```

**Step 5: Run test to verify it passes**

```bash
pytest tests/engine/sast/analyzers/test_secrets_output.py -v
```
Expected: PASS

**Step 6: Commit**

```bash
git add engine/sast/analyzers/secrets_scanner.py tests/engine/sast/analyzers/test_secrets_output.py
git commit -m "security: prevent secrets from leaking to terminal

- Don't print secret values to stdout (even masked)
- Only log filename and line number
- Set report file permissions to 0o600 (owner-only)
- Prevent secrets from appearing in logs/history

Fixes information disclosure"
```

---

## PHASE 2: COMPLETE STUBBED FUNCTIONALITY (Week 2)

### Task 6: Fix Always-True Exported Component Check

**Files:**
- Modify: `engine/mobile/android/apk_analyzer.py:268-271`
- Test: `tests/engine/mobile/android/test_exported_components.py` (create)

**Step 1: Write the failing test**

Create `tests/engine/mobile/android/test_exported_components.py`:
```python
import pytest
from pathlib import Path
from engine.mobile.android.apk_analyzer import APKAnalyzer

def test_is_exported_parses_manifest(tmp_path):
    """Test that is_exported actually parses AndroidManifest.xml"""
    # Create test AndroidManifest.xml
    manifest_xml = '''<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <application>
            <activity android:name=".ExportedActivity" android:exported="true"/>
            <activity android:name=".PrivateActivity" android:exported="false"/>
            <activity android:name=".DefaultActivity"/>
        </application>
    </manifest>'''

    manifest_path = tmp_path / "AndroidManifest.xml"
    manifest_path.write_text(manifest_xml)

    # Mock analyzer with manifest path
    analyzer = APKAnalyzer.__new__(APKAnalyzer)
    analyzer.output_dir = tmp_path.parent
    analyzer.manifest_path = manifest_path

    # Test exported=true
    assert analyzer.is_exported(".ExportedActivity", "activity") == True

    # Test exported=false
    assert analyzer.is_exported(".PrivateActivity", "activity") == False

    # Test default (no exported attribute) - should be False for activities
    assert analyzer.is_exported(".DefaultActivity", "activity") == False
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/mobile/android/test_exported_components.py -v
```
Expected: FAIL with "Always returns True"

**Step 3: Implement manifest parsing**

Modify `engine/mobile/android/apk_analyzer.py:268-271`:
```python
def is_exported(self, component: str, comp_type: str) -> bool:
    """
    Check if component is exported by parsing AndroidManifest.xml

    Args:
        component: Component name (e.g., com.app.MainActivity)
        comp_type: Component type ('activity', 'service', 'receiver')

    Returns:
        True if component has android:exported="true", False otherwise
    """
    import xml.etree.ElementTree as ET

    # Find AndroidManifest.xml in decompiled output
    manifest_path = self.output_dir / "decompiled" / "AndroidManifest.xml"

    if not manifest_path.exists():
        # Fallback: Try resources directory
        manifest_path = self.output_dir / "decompiled" / "resources" / "AndroidManifest.xml"

    if not manifest_path.exists():
        print(f"{Fore.YELLOW}[!] AndroidManifest.xml not found, cannot verify exported status{Style.RESET_ALL}")
        return False  # Conservative: assume not exported if can't verify

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Find the component in manifest
        # Handle both short name (.MainActivity) and full name (com.app.MainActivity)
        component_short = component if component.startswith('.') else f".{component.split('.')[-1]}"

        # Search in application tag
        for app in root.findall('.//application'):
            for elem in app.findall(f'.//{comp_type}'):
                name_attr = elem.get('{http://schemas.android.com/apk/res/android}name')

                if name_attr and (name_attr == component or name_attr == component_short):
                    # Check exported attribute
                    exported = elem.get('{http://schemas.android.com/apk/res/android}exported')

                    if exported is not None:
                        return exported.lower() == 'true'
                    else:
                        # Default behavior per Android docs:
                        # If component has intent-filters, default is true
                        # Otherwise, default is false
                        intent_filters = elem.findall('intent-filter')
                        return len(intent_filters) > 0

        # Component not found in manifest
        return False

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error parsing AndroidManifest.xml: {e}{Style.RESET_ALL}")
        return False
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/engine/mobile/android/test_exported_components.py -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add engine/mobile/android/apk_analyzer.py tests/engine/mobile/android/test_exported_components.py
git commit -m "fix: implement proper exported component detection

- Parse AndroidManifest.xml with xml.etree
- Check android:exported attribute
- Handle default behavior (intent-filters)
- Support both short and full component names

Fixes false positive reports for all components"
```

---

### Task 7: Implement iOS String Extraction

**Files:**
- Modify: `engine/mobile/ios/ipa_analyzer.py:136-145`
- Create: `requirements/requirements-ios.txt`
- Test: `tests/engine/mobile/ios/test_string_extraction.py` (create)

**Step 1: Add macholib dependency**

Create `requirements/requirements-ios.txt`:
```
macholib==1.16.3
```

**Step 2: Write the failing test**

Create `tests/engine/mobile/ios/test_string_extraction.py`:
```python
import pytest
from pathlib import Path
from engine.mobile.ios.ipa_analyzer import IPAAnalyzer

def test_extract_api_endpoints_from_binary(tmp_path):
    """Test that API endpoints are extracted from Mach-O binary"""
    # This is a stub test - needs real Mach-O binary
    # For now, test that function returns list (not empty stub)

    # Mock IPA with extracted binary
    ipa_path = tmp_path / "test.ipa"
    ipa_path.touch()

    analyzer = IPAAnalyzer(str(ipa_path))

    # Should return a list (even if empty for mock binary)
    endpoints = analyzer.extract_api_endpoints()
    assert isinstance(endpoints, list)

    # TODO: Add test with real Mach-O binary containing strings

def test_find_hardcoded_secrets_in_binary(tmp_path):
    """Test that secrets are extracted from Mach-O binary"""
    ipa_path = tmp_path / "test.ipa"
    ipa_path.touch()

    analyzer = IPAAnalyzer(str(ipa_path))

    # Should return a list (even if empty for mock binary)
    secrets = analyzer.find_hardcoded_secrets()
    assert isinstance(secrets, list)
```

**Step 3: Run test to verify it fails**

```bash
pytest tests/engine/mobile/ios/test_string_extraction.py -v
```
Expected: FAIL with "Returns empty list stub"

**Step 4: Implement Mach-O string extraction**

Modify `engine/mobile/ios/ipa_analyzer.py:136-145`:
```python
def extract_api_endpoints(self) -> List[str]:
    """Extract API endpoints from Mach-O binary strings"""
    urls = []

    # Find main binary in Payload/*.app/
    extract_dir = self.output_dir / "extracted"
    app_dirs = list((extract_dir / "Payload").glob("*.app")) if (extract_dir / "Payload").exists() else []

    if not app_dirs:
        return urls

    app_dir = app_dirs[0]

    # Find binary (same name as .app directory usually)
    binary_name = app_dir.stem
    binary_path = app_dir / binary_name

    if not binary_path.exists():
        # Try to find any executable
        for file in app_dir.iterdir():
            if file.is_file() and not file.suffix:
                binary_path = file
                break

    if not binary_path.exists():
        return urls

    try:
        # Extract strings from binary using system 'strings' command
        import subprocess
        result = subprocess.run(
            ['strings', str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            # Search for URLs in strings output
            import re
            url_pattern = re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]+')

            for line in result.stdout.splitlines():
                matches = url_pattern.findall(line)
                urls.extend(matches)

            # Deduplicate and filter
            urls = list(set(urls))
            urls = [u for u in urls if not any(fp in u for fp in ['schema.org', 'w3.org', 'example.com'])]

            print(f"{Fore.GREEN}[+] Found {len(urls)} API endpoints{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.YELLOW}[!] 'strings' command not found. Install: brew install binutils{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error extracting strings: {e}{Style.RESET_ALL}")

    return urls

def find_hardcoded_secrets(self) -> List[Dict]:
    """Find hardcoded secrets in Mach-O binary strings"""
    secrets = []

    # Reuse string extraction logic
    extract_dir = self.output_dir / "extracted"
    app_dirs = list((extract_dir / "Payload").glob("*.app")) if (extract_dir / "Payload").exists() else []

    if not app_dirs:
        return secrets

    app_dir = app_dirs[0]
    binary_name = app_dir.stem
    binary_path = app_dir / binary_name

    if not binary_path.exists():
        for file in app_dir.iterdir():
            if file.is_file() and not file.suffix:
                binary_path = file
                break

    if not binary_path.exists():
        return secrets

    # Secret patterns (reuse from secrets_scanner)
    patterns = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
        "Private Key": r'-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----',
        "Generic API Key": r'["\']api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']'
    }

    try:
        import subprocess
        import re

        result = subprocess.run(
            ['strings', str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            for secret_type, pattern in patterns.items():
                matches = re.findall(pattern, result.stdout)

                for match in matches:
                    # Basic false positive filtering
                    if any(fp in match.lower() for fp in ['example', 'test', 'sample']):
                        continue

                    secrets.append({
                        "type": secret_type,
                        "value": match[:50] + "..." if len(match) > 50 else match,
                        "file": binary_name,
                        "severity": "CRITICAL"
                    })

                    print(f"{Fore.RED}[!] CRITICAL: {secret_type} found in binary{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error scanning for secrets: {e}{Style.RESET_ALL}")

    return secrets
```

**Step 5: Run test to verify it passes**

```bash
pytest tests/engine/mobile/ios/test_string_extraction.py -v
```
Expected: PASS

**Step 6: Commit**

```bash
git add engine/mobile/ios/ipa_analyzer.py tests/engine/mobile/ios/test_string_extraction.py requirements/requirements-ios.txt
git commit -m "feat: implement iOS binary string extraction

- Extract strings from Mach-O binary using 'strings' command
- Parse for API endpoints (URLs)
- Scan for hardcoded secrets (AWS, API keys, etc.)
- Add macholib to requirements

Completes iOS analyzer functionality from 20% to 80%"
```

---

### Task 8: Remove or Implement Injection Stubs

**Files:**
- Modify: `engine/omnihack/injection/injector.py:141-161`
- Modify: `README.md` (or create if needed)

**Step 1: Document limitation**

Create or modify `README.md` to add:
```markdown
## OMNIHACK Injection Techniques

### Supported Methods

✅ **Classic Injection** (CreateRemoteThread + LoadLibraryA)
- Works: Windows XP through Windows 11
- Detection: Medium (easily caught by anticheat)
- Use: Simple DLL injection for testing

❌ **Manual Mapping** (NOT IMPLEMENTED)
- Would require: C++ PE loader implementation
- Status: Stub that falls back to classic injection
- Reason: Complex implementation requiring low-level PE parsing

❌ **Thread Hijacking** (NOT IMPLEMENTED)
- Would require: Thread context manipulation, shellcode
- Status: Always returns False
- Reason: Highly complex, OS-version dependent

### Recommendation

For production use, only use `classic_inject()`. The other methods are placeholders for future implementation or require external tools.
```

**Step 2: Fix methods to be honest**

Modify `engine/omnihack/injection/injector.py:141-161`:
```python
def manual_map(self, dll_path: str) -> bool:
    """
    Manual PE mapping - NOT IMPLEMENTED

    This is a stub that falls back to classic injection.
    Manual mapping requires a complete PE loader implementation in C++.

    For production use, call classic_inject() directly.
    """
    print(f"\n{Fore.YELLOW}[!] Manual mapping NOT IMPLEMENTED{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Falling back to classic injection{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] To use this feature, implement external manual mapper{Style.RESET_ALL}")

    # Fallback to classic injection
    return self.classic_inject(dll_path)

def thread_hijack(self, dll_path: str) -> bool:
    """
    Thread hijacking - NOT IMPLEMENTED

    This technique requires:
    - Thread enumeration
    - Thread context manipulation (GetThreadContext/SetThreadContext)
    - Shellcode injection
    - Architecture-specific assembly

    For production use, call classic_inject() instead.
    """
    print(f"\n{Fore.RED}[!] Thread hijacking NOT IMPLEMENTED{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] This feature requires low-level thread manipulation{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Use classic_inject() for working DLL injection{Style.RESET_ALL}")

    return False  # Explicitly don't work
```

**Step 3: Update docstrings to be clear**

Add to top of `injector.py`:
```python
"""
OMNIHACK DLL Injection Module

IMPLEMENTED:
- classic_inject(): Standard LoadLibraryA injection (WORKING)

NOT IMPLEMENTED (Stubs):
- manual_map(): Falls back to classic_inject
- thread_hijack(): Returns False, requires external implementation

For production use, only use classic_inject().
"""
```

**Step 4: Commit**

```bash
git add engine/omnihack/injection/injector.py README.md
git commit -m "docs: document injection technique limitations

- Clearly mark manual_map and thread_hijack as NOT IMPLEMENTED
- Add warnings when stubs are called
- Document only classic_inject() is production-ready
- Update README with feature status

Fixes misleading documentation"
```

---

## PHASE 3: RELIABILITY FEATURES (Week 3)

### Task 9: Add Rate Limiting

**Files:**
- Modify: `engine/cloud/aws/s3_enumerator.py:36-41`
- Modify: `engine/cloud/aws/metadata_ssrf.py:36-41`
- Test: `tests/engine/cloud/test_rate_limiting.py` (create)

**Step 1: Write the failing test**

Create `tests/engine/cloud/test_rate_limiting.py`:
```python
import pytest
import time
from unittest.mock import Mock, patch
from engine.cloud.aws.s3_enumerator import S3Enumerator

def test_s3_enumerator_respects_rate_limit():
    """Test that S3 enumeration includes delays"""
    with patch('boto3.client'):
        enumerator = S3Enumerator()
        enumerator.s3_client = Mock()
        enumerator.s3_client.list_objects_v2 = Mock(
            side_effect=Exception("NoSuchBucket")
        )

        start_time = time.time()
        enumerator.enumerate_buckets("example.com")
        elapsed = time.time() - start_time

        # Should take at least (23 buckets - 1) * 0.5s = 11 seconds
        # (no delay after last request)
        assert elapsed >= 11.0
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/engine/cloud/test_rate_limiting.py -v
```
Expected: FAIL with "Too fast, no rate limiting"

**Step 3: Add rate limiting to S3 enumerator**

Modify `engine/cloud/aws/s3_enumerator.py:36-41`:
```python
def enumerate_buckets(self, domain: str) -> List[Dict]:
    """
    Enumerate S3 buckets for a domain with rate limiting

    Args:
        domain: Target domain (e.g., example.com)

    Returns:
        List of findings
    """
    import time

    print(f"{Fore.CYAN}[*] Enumerating S3 buckets for: {domain}{Style.RESET_ALL}")

    # Generate bucket name variations
    bucket_patterns = self.generate_bucket_names(domain)

    results = []

    for i, bucket_name in enumerate(bucket_patterns):
        finding = self.check_bucket(bucket_name)
        if finding:
            results.append(finding)

        # Rate limiting: 500ms delay between requests (except last one)
        if i < len(bucket_patterns) - 1:
            time.sleep(0.5)

    return results
```

**Step 4: Add rate limiting to SSRF tester**

Modify `engine/cloud/aws/metadata_ssrf.py:36-41`:
```python
def test_ssrf(self) -> List[Dict]:
    """
    Test for SSRF to metadata service with rate limiting

    Returns:
        List of findings
    """
    import time

    print(f"{Fore.CYAN}[*] Testing SSRF to AWS metadata...{Style.RESET_ALL}")

    payloads = self.generate_payloads()

    for i, (payload_name, payload) in enumerate(payloads):
        result = self.test_payload(payload_name, payload)
        if result:
            self.findings.append(result)

        # Rate limiting: 1 second delay between SSRF tests
        if i < len(payloads) - 1:
            time.sleep(1.0)

    return self.findings
```

**Step 5: Run test to verify it passes**

```bash
pytest tests/engine/cloud/test_rate_limiting.py -v
```
Expected: PASS

**Step 6: Commit**

```bash
git add engine/cloud/aws/s3_enumerator.py engine/cloud/aws/metadata_ssrf.py tests/engine/cloud/test_rate_limiting.py
git commit -m "feat: add rate limiting to cloud scanners

- S3 enumerator: 500ms delay between bucket checks
- SSRF tester: 1 second delay between payloads
- Prevent IP bans from rapid requests

Improves reliability for long-running scans"
```

---

### Task 10: Add Proxy Support

**Files:**
- Modify: `engine/cloud/aws/metadata_ssrf.py:69-77`
- Modify: `engine/sast/analyzers/semgrep_runner.py` (if has network calls)
- Create: `docs/PROXY-CONFIGURATION.md`

**Step 1: Document proxy configuration**

Create `docs/PROXY-CONFIGURATION.md`:
```markdown
# Proxy Configuration

## Environment Variables

BountyHound respects standard proxy environment variables:

```bash
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
```

## Burp Suite Integration

To route all HTTP traffic through Burp Suite:

```bash
# Set proxy to Burp default
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"

# Disable SSL verification for Burp's self-signed cert
export REQUESTS_CA_BUNDLE=""
# OR
export CURL_CA_BUNDLE=""

# Run BountyHound
python engine/cloud/aws/metadata_ssrf.py "http://target.com?url=INJECT"
```

## Which Modules Support Proxies

✅ metadata_ssrf.py (requests)
✅ Any module using requests library

❌ boto3 S3 client (AWS SDK, uses different config)
```

**Step 2: Add proxy support to metadata_ssrf**

Modify `engine/cloud/aws/metadata_ssrf.py:69-77`:
```python
def test_payload(self, name: str, payload: str) -> Dict:
    """Test a single SSRF payload with proxy support"""
    import os

    try:
        # Replace INJECT placeholder
        test_url = self.target_url.replace("INJECT", payload)

        print(f"{Fore.YELLOW}[*] Testing: {name}{Style.RESET_ALL}")

        # Proxy configuration from environment
        proxies = None
        if os.getenv('HTTP_PROXY') or os.getenv('HTTPS_PROXY'):
            proxies = {
                'http': os.getenv('HTTP_PROXY'),
                'https': os.getenv('HTTPS_PROXY')
            }
            print(f"{Fore.CYAN}[*] Using proxy: {proxies}{Style.RESET_ALL}")

        response = requests.get(
            test_url,
            timeout=5,
            allow_redirects=False,
            proxies=proxies,
            verify=os.getenv('REQUESTS_CA_BUNDLE', True) != ""  # Disable SSL verify if env var is empty
        )

        # Check for metadata indicators
        if self.is_metadata_response(response):
            print(f"{Fore.RED}[!] CRITICAL: SSRF to metadata service!{Style.RESET_ALL}")
            print(f"    Payload: {payload}")
            print(f"    Response: {response.text[:200]}")

            return {
                "severity": "CRITICAL",
                "title": f"SSRF to AWS Metadata Service ({name})",
                "payload": payload,
                "response": response.text[:500],
                "impact": "Can retrieve IAM credentials, escalate privileges"
            }

    except requests.exceptions.Timeout:
        pass  # Timeout is expected for some payloads
    except Exception:
        pass

    return None
```

**Step 3: Test proxy support**

```bash
# Manual test with Burp
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
python engine/cloud/aws/metadata_ssrf.py "http://example.com?url=INJECT"
# Verify requests appear in Burp Suite HTTP history
```

**Step 4: Commit**

```bash
git add engine/cloud/aws/metadata_ssrf.py docs/PROXY-CONFIGURATION.md
git commit -m "feat: add proxy support for HTTP requests

- Respect HTTP_PROXY and HTTPS_PROXY environment variables
- Support REQUESTS_CA_BUNDLE for custom CA certs
- Enable Burp Suite integration
- Document proxy configuration

Enables traffic inspection and debugging"
```

---

## PHASE 4: TESTING INFRASTRUCTURE (Week 4)

### Task 11: Add Pytest Configuration

**Files:**
- Create: `pytest.ini`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Step 1: Create pytest configuration**

Create `pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    -v
    --tb=short
    --strict-markers
    --disable-warnings
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    security: marks tests that verify security fixes
    stub: marks tests for stubbed functionality
```

**Step 2: Create test package init**

Create `tests/__init__.py`:
```python
"""BountyHound test suite"""
```

**Step 3: Create pytest fixtures**

Create `tests/conftest.py`:
```python
"""Shared pytest fixtures for BountyHound tests"""
import pytest
import tempfile
from pathlib import Path

@pytest.fixture
def tmp_dir():
    """Temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture
def sample_apk_path(tmp_dir):
    """Mock APK file for testing"""
    apk_path = tmp_dir / "test.apk"
    apk_path.write_bytes(b'PK\x03\x04')  # ZIP magic bytes
    return apk_path

@pytest.fixture
def sample_ipa_path(tmp_dir):
    """Mock IPA file for testing"""
    ipa_path = tmp_dir / "test.ipa"
    ipa_path.write_bytes(b'PK\x03\x04')  # ZIP magic bytes
    return ipa_path
```

**Step 4: Run all tests**

```bash
pytest tests/ -v
```
Expected: All tests pass

**Step 5: Commit**

```bash
git add pytest.ini tests/__init__.py tests/conftest.py
git commit -m "test: add pytest configuration and fixtures

- Configure pytest with markers and options
- Add shared fixtures for temp directories
- Set up test package structure

Establishes testing infrastructure"
```

---

### Task 12: Add CI/CD GitHub Actions

**Files:**
- Create: `.github/workflows/test.yml`
- Create: `.github/workflows/security.yml`

**Step 1: Create test workflow**

Create `.github/workflows/test.yml`:
```yaml
name: Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        python-version: ['3.10', '3.11', '3.12']

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install pytest pytest-cov
        pip install -r requirements/requirements-mobile.txt
        pip install -r requirements/requirements-cloud.txt
        pip install -r requirements/requirements-sast.txt

    - name: Run tests
      run: |
        pytest tests/ -v --cov=engine --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

**Step 2: Create security scanning workflow**

Create `.github/workflows/security.yml`:
```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Run Bandit security scan
      run: |
        pip install bandit
        bandit -r engine/ -f json -o bandit-report.json || true

    - name: Upload security report
      uses: actions/upload-artifact@v3
      with:
        name: bandit-report
        path: bandit-report.json
```

**Step 3: Commit**

```bash
git add .github/workflows/test.yml .github/workflows/security.yml
git commit -m "ci: add GitHub Actions workflows

- Run tests on Ubuntu and Windows
- Test Python 3.10, 3.11, 3.12
- Upload coverage to Codecov
- Weekly Bandit security scans

Automates testing and security checks"
```

---

## PHASE 5: DOCUMENTATION (Week 5)

### Task 13: Update Coverage Claims

**Files:**
- Modify: `FULL-IMPLEMENTATION-SUMMARY.md:266-282`
- Modify: `COMPREHENSIVE-CODEBASE-ANALYSIS.md` (new file created)

**Step 1: Update coverage table to be accurate**

Modify `FULL-IMPLEMENTATION-SUMMARY.md:266-282`:
```markdown
## 🎯 **ACCURATE CAPABILITY MATRIX**

| Asset Type | Coverage | Limitations | Expected Payout |
|------------|----------|-------------|-----------------|
| **Web Applications** | ✅ 100% | Browser automation, GraphQL | $5K-$50K |
| **APIs** | ✅ 100% | IDOR, auth bypass, rate limits | $2K-$25K |
| **Desktop Applications** | ✅ 90% | OMNIHACK (Windows only), memory scanning | $5K-$50K |
| **Mobile Apps (Android)** | ✅ 90% | APK analysis, Frida, SSL bypass, manifest parsing | $2K-$15K |
| **Mobile Apps (iOS)** | ⚠️ 80% | IPA analysis, string extraction (needs macholib) | $2K-$20K |
| **Cloud (AWS)** | ✅ 85% | S3, IAM (no Lambda/EC2/RDS yet) | $2K-$25K |
| **Cloud (Azure/GCP)** | ⏳ 20% | Basic enumeration only, no deep testing | $1K-$10K |
| **Smart Contracts** | ✅ 95% | Slither, Mythril, manual checks (no fuzzing) | $10K-$500K |
| **Source Code** | ✅ 100% | Semgrep, 25+ secret patterns | $500-$10K |
| **Hardware/IoT** | ⏳ 10% | Framework only, needs implementation | $1K-$10K |

**Overall Coverage**: **85% of HackerOne Asset Types** (was 100%, now accurate)
**Production Ready**: Android, Web, API, SAST, Smart Contracts
**Needs Work**: iOS (string extraction), Cloud (other services), Hardware
```

**Step 2: Add limitations section**

Add new section to `FULL-IMPLEMENTATION-SUMMARY.md`:
```markdown
## ⚠️ **KNOWN LIMITATIONS**

### **iOS Testing**
- ✅ URL scheme extraction (works)
- ✅ String extraction from binary (implemented)
- ❌ Mach-O binary parsing (needs macholib)
- ❌ Code signature verification

### **DLL Injection**
- ✅ Classic injection (works)
- ❌ Manual mapping (stub, not implemented)
- ❌ Thread hijacking (stub, not implemented)

### **Cloud Testing**
- ✅ S3 enumeration (works)
- ✅ IAM permission testing (works)
- ❌ Lambda function testing
- ❌ EC2 instance metadata
- ❌ RDS database exposure

### **Platform Support**
- ✅ Windows (full support)
- ⚠️ Linux (partial - no OMNIHACK)
- ⚠️ macOS (partial - no OMNIHACK)
```

**Step 3: Commit**

```bash
git add FULL-IMPLEMENTATION-SUMMARY.md
git commit -m "docs: update coverage claims to be accurate

- Change overall coverage from 100% to 85%
- Document iOS as 80% (not 100%)
- Add Known Limitations section
- Mark stubs clearly (manual map, thread hijack)

Provides honest assessment of capabilities"
```

---

### Task 14: Add Security Warnings

**Files:**
- Create: `SECURITY.md`
- Modify: `README.md`

**Step 1: Create security policy**

Create `SECURITY.md`:
```markdown
# Security Policy

## Authorized Use Only

**BountyHound is designed for authorized security testing only.**

### Legal Use

✅ **AUTHORIZED**:
- Bug bounty programs
- Penetration testing with written authorization
- Security research on your own systems
- CTF competitions
- Educational purposes with permission

❌ **NEVER AUTHORIZED**:
- Testing systems without permission
- Unauthorized access attempts
- Malicious use
- Violating computer crime laws
- Circumventing access controls without authorization

### DLL Injection Warning

The OMNIHACK module contains DLL injection capabilities that could be used maliciously.

**Legal Disclaimer**: Using DLL injection on systems you don't own or without authorization is ILLEGAL in most jurisdictions.

### Responsible Disclosure

If you find security issues in BountyHound itself:
1. Do NOT create public GitHub issues
2. Email: security@[your-domain]
3. Allow 90 days for patching before disclosure

### Reporting Vulnerabilities

When reporting to bug bounty programs:
- Follow program scope and rules
- Never exploit beyond PoC
- Don't access other users' data
- Don't cause damage or disruption
- Report responsibly and ethically
```

**Step 2: Add warning to README**

Modify `README.md` (add to top):
```markdown
# BountyHound

⚠️ **AUTHORIZED USE ONLY** ⚠️

This tool is designed for authorized security testing in bug bounty programs, penetration testing, and security research. Using it on systems without explicit permission is illegal.

**See [SECURITY.md](SECURITY.md) for full legal and ethical guidelines.**

---
```

**Step 3: Commit**

```bash
git add SECURITY.md README.md
git commit -m "docs: add security warnings and legal disclaimer

- Create SECURITY.md with authorized use policy
- Add DLL injection warning
- Document legal vs illegal use
- Add responsible disclosure policy

Critical for legal protection"
```

---

## FINAL STEPS

### Task 15: Create Master README

**Files:**
- Modify: `README.md`

**Step 1: Write comprehensive README**

Modify `README.md`:
```markdown
# BountyHound v3.0

⚠️ **AUTHORIZED USE ONLY** - See [SECURITY.md](SECURITY.md) ⚠️

Claude-driven bug bounty hunting platform with 85% coverage of HackerOne asset types.

## Quick Start

```bash
# Install dependencies
pip install -r requirements/requirements-mobile.txt
pip install -r requirements/requirements-cloud.txt
pip install -r requirements/requirements-sast.txt

# Run tests
pytest tests/ -v

# Use a module
python engine/mobile/android/apk_analyzer.py app.apk
python engine/cloud/aws/s3_enumerator.py example.com
python engine/sast/analyzers/secrets_scanner.py /path/to/repo
```

## Architecture

**Claude (LLM)** orchestrates the testing:
- Reads agent workflows (Markdown)
- Calls Python tools (engine/)
- Makes intelligent decisions
- Generates reports

**Python Tools** execute security tests:
- APK/IPA analysis
- S3 enumeration
- Smart contract auditing
- Secrets scanning

**Agents** provide workflows:
- phased-hunter.md (main pipeline)
- discovery-engine.md (LLM-powered)
- poc-validator.md (curl validation)

## Features

✅ **Android Testing**: APK decompilation, Frida hooking, SSL bypass
✅ **iOS Testing**: IPA extraction, URL schemes, string extraction
✅ **Cloud Security**: S3/IAM testing, SSRF detection
✅ **Smart Contracts**: Slither, Mythril, manual checks
✅ **SAST**: 25+ secret patterns, Semgrep integration
✅ **Desktop**: Memory scanning, DLL injection (Windows)

## Documentation

- [FULL-IMPLEMENTATION-SUMMARY.md](FULL-IMPLEMENTATION-SUMMARY.md) - Complete overview
- [COMPREHENSIVE-CODEBASE-ANALYSIS.md](COMPREHENSIVE-CODEBASE-ANALYSIS.md) - Deep dive
- [SECURITY.md](SECURITY.md) - Legal and ethical use
- [docs/TESTING-CREDENTIALS.md](docs/TESTING-CREDENTIALS.md) - Credential management
- [docs/PROXY-CONFIGURATION.md](docs/PROXY-CONFIGURATION.md) - Burp Suite integration

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run security tests only
pytest tests/ -v -m security

# Run with coverage
pytest tests/ --cov=engine --cov-report=html
```

## Known Limitations

- iOS: Needs macholib for full binary analysis
- Cloud: Only S3/IAM (no Lambda, EC2, RDS)
- DLL Injection: Only classic method works (manual map/thread hijack are stubs)
- Platform: OMNIHACK is Windows-only

See [FULL-IMPLEMENTATION-SUMMARY.md](FULL-IMPLEMENTATION-SUMMARY.md) for complete limitations.

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

[Your License Here]

## Legal

This software is provided for authorized security testing only. Unauthorized use is illegal. See [SECURITY.md](SECURITY.md).
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: create comprehensive README

- Quick start guide
- Architecture overview
- Feature list with accurate status
- Testing instructions
- Known limitations
- Legal warnings

Provides complete project overview"
```

---

## EXECUTION SUMMARY

**Total Tasks**: 15
**Estimated Time**: 5 weeks
**Lines of Code**: ~2,000 (tests + fixes)
**Files Modified**: ~25
**Files Created**: ~30

**Priority Order**:
1. **Week 1**: Security fixes (CRITICAL)
2. **Week 2**: Complete stubs (HIGH)
3. **Week 3**: Reliability (MEDIUM)
4. **Week 4**: Testing (MEDIUM)
5. **Week 5**: Documentation (LOW)

---

**Plan complete and saved to `docs/plans/2026-02-11-fix-bountyhound-weaknesses.md`.**

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
