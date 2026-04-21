# APK Decompilation Skill

**Category**: Mobile Analysis | **Difficulty**: Easy
**Description**: Decompile Android APK files to extract source code and resources
**Tools**: apktool, jadx, baksmali, dex2jar
**Time**: 5-15 minutes per APK
**Success Rate**: 95%+

## Technique Overview

APK files are ZIP archives containing:
- **DEX files**: Dalvik bytecode (compiled Java/Kotlin)
- **Resources**: XML layouts, images, strings
- **AndroidManifest.xml**: App configuration
- **lib/**: Native libraries (.so files)
- **assets/**: Additional files

## Tools Comparison

| Tool | Use Case | Output | Best For |
|------|----------|--------|----------|
| **apktool** | Resource extraction | Smali code + XML | Manifest analysis, resources |
| **jadx** | Java decompilation | Java source | Reading code, finding logic |
| **dex2jar + jd-gui** | Alternative decompilation | Java JAR | Legacy workflow |
| **baksmali** | Smali disassembly | Smali bytecode | Low-level analysis |

## Step-by-Step Guide

### 1. Extract with apktool
```bash
# Decompile APK
apktool d app.apk -o output_dir

# Output structure:
# output_dir/
# ├── AndroidManifest.xml  (readable XML)
# ├── res/                 (resources)
# ├── smali/               (disassembled code)
# └── assets/
```

**What to analyze**:
- `AndroidManifest.xml`: Permissions, exported components
- `res/values/strings.xml`: API endpoints, keys
- `res/xml/network_security_config.xml`: Certificate pinning

### 2. Decompile with jadx
```bash
# Decompile to Java
jadx -d output_dir app.apk

# Output structure:
# output_dir/
# └── sources/
#     └── com/company/app/
#         ├── MainActivity.java
#         ├── api/ApiClient.java
#         └── config/Config.java
```

**What to search for**:
```bash
# API endpoints
grep -r "https://" output_dir/

# API keys
grep -r "api_key\|apiKey\|API_KEY" output_dir/

# Secrets
grep -r "secret\|token\|password" output_dir/

# AWS keys
grep -r "AKIA" output_dir/

# Firebase
grep -r "firebaseio.com" output_dir/
```

### 3. Analyze AndroidManifest.xml

```bash
# Extract manifest
apktool d app.apk
cat output_dir/AndroidManifest.xml
```

**Key findings**:

```xml
<!-- Dangerous permissions -->
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CAMERA"/>

<!-- Exported components (attack surface) -->
<activity android:name=".DeepLinkActivity"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="myapp"/>
    </intent-filter>
</activity>

<!-- Debuggable flag (HIGH severity) -->
<application android:debuggable="true">

<!-- Backup enabled for sensitive app -->
<application android:allowBackup="true">

<!-- Cleartext HTTP allowed -->
<application android:usesCleartextTraffic="true">
```

## Common Findings

### CRITICAL
- Hardcoded API keys in `Config.java`
- AWS credentials in strings.xml
- Private keys in assets/

### HIGH
- Exported services without permission
- Debuggable flag enabled
- Custom TrustManager (SSL bypass)

### MEDIUM
- Dangerous permissions
- Exported activities
- Backup enabled

## Automation Script

```python
#!/usr/bin/env python3
"""
Automated APK Analysis
"""

import subprocess
import os

def analyze_apk(apk_path):
    """Full APK analysis"""

    # 1. Decompile with jadx
    print("[*] Decompiling with jadx...")
    subprocess.run(['jadx', '-d', 'output', apk_path])

    # 2. Extract with apktool
    print("[*] Extracting with apktool...")
    subprocess.run(['apktool', 'd', apk_path, '-o', 'apktool_output'])

    # 3. Search for secrets
    print("[*] Searching for secrets...")
    secrets = [
        ('API Keys', 'api[_-]?key'),
        ('AWS Keys', 'AKIA[0-9A-Z]{16}'),
        ('URLs', 'https?://[a-zA-Z0-9./?=_-]+'),
    ]

    for name, pattern in secrets:
        result = subprocess.run(
            ['grep', '-r', '-i', pattern, 'output/'],
            capture_output=True, text=True
        )
        if result.stdout:
            print(f"\n[!] Found {name}:")
            print(result.stdout[:500])

    # 4. Analyze manifest
    print("\n[*] Analyzing AndroidManifest.xml...")
    with open('apktool_output/AndroidManifest.xml') as f:
        manifest = f.read()

        if 'android:debuggable="true"' in manifest:
            print("[!] HIGH: App is debuggable!")

        if 'android:exported="true"' in manifest:
            print("[!] MEDIUM: Exported components found")

if __name__ == '__main__':
    import sys
    analyze_apk(sys.argv[1])
```

## Real-World Example: Instagram

```bash
# 1. Decompile
jadx -d instagram_src instagram.apk

# 2. Find API client
cat instagram_src/sources/com/instagram/api/Api*.java

# 3. Extract endpoints
grep -r "https://i.instagram.com" instagram_src/

# 4. Find secrets
grep -r "client_id\|client_secret" instagram_src/

# Common findings:
# - API endpoint: https://i.instagram.com/api/v1/
# - User-Agent strings
# - Rate limit bypass headers
# - Signature generation algorithms
```

## Reporting Template

```markdown
## APK Decompilation Findings

**App**: [App Name]
**Package**: com.company.app
**Version**: 1.2.3

### Methodology
1. Decompiled APK with jadx v1.4.7
2. Extracted resources with apktool v2.7.0
3. Analyzed AndroidManifest.xml
4. Searched for hardcoded secrets

### Findings

#### F1: Hardcoded API Key (CRITICAL)
**Location**: `com/company/app/Config.java:15`
**Code**:
```java
public static final String API_KEY = "AIzaSy...";
```
**Impact**: Unauthorized API access

#### F2: Exported Activity (MEDIUM)
**Component**: `com.company.app.DeepLinkActivity`
**AndroidManifest.xml**:
```xml
<activity android:name=".DeepLinkActivity" android:exported="true"/>
```
**Impact**: Intent spoofing, deeplink hijacking
```

## Tips & Tricks

1. **Always check both jadx AND apktool output** - different tools find different things
2. **Search for "http://" not just "https://"** - cleartext endpoints
3. **Check res/raw/ and assets/** - often contain config files
4. **Look for .so files** - native code may contain secrets
5. **Analyze ProGuard mappings** - if available, helps understand obfuscated code

## Expected ROI
- **Time**: 15-30 min per APK
- **Findings**: 2-5 per app
- **Value**: $500-$5K per finding
- **Monthly potential**: $10K-$30K (analyzing 20 apps)
