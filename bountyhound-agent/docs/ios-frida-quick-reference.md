# iOS Frida Hooking - Quick Reference Card

## Setup (One-Time)

```bash
# Install Frida
pip install frida frida-tools

# Copy frida-server to iOS device
scp frida-server root@DEVICE_IP:/usr/sbin/frida-server
ssh root@DEVICE_IP "chmod +x /usr/sbin/frida-server"

# Start frida-server on device
ssh root@DEVICE_IP "/usr/sbin/frida-server &"

# Verify connection
frida-ps -U
```

## Common Bug Bounty Scenarios

### 1. MITM Testing (SSL Pinning Bypass)

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

hooker = iOSFridaHooker()
hooker.hook_ssl_pinning("com.target.app")

# Now configure Burp Suite:
# iOS Settings → WiFi → Proxy → Burp IP:8080
# Install Burp CA cert on device
# Launch app → see decrypted HTTPS traffic
```

**Finding**: Insufficient transport layer protection (Medium-High)

### 2. Credential Extraction (Keychain Dump)

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker
import base64

hooker = iOSFridaHooker()
keychain = hooker.dump_keychain("com.target.app")

for item in keychain['items']:
    if item['type'] == 'generic_password':
        password = base64.b64decode(item['data']).decode()
        print(f"Account: {item['account']}")
        print(f"Password: {password}")
```

**Finding**: Insecure keychain storage (Medium-High)

### 3. API Discovery (Monitor Calls)

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

hooker = iOSFridaHooker()
api_calls = hooker.monitor_api_calls("com.target.app", duration=300)

# Find interesting endpoints
for call in api_calls:
    if '/admin' in call['url'] or '/api/internal' in call['url']:
        print(f"{call['method']} {call['url']}")
        print(f"Headers: {call['headers']}")
```

**Finding**: Undocumented API endpoints (Info)

### 4. Auth Bypass (Biometric)

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

hooker = iOSFridaHooker()
hooker.hook_biometric_auth("com.target.app")

# Try to access premium features without Face ID
# Document screenshots before/after
```

**Finding**: Client-side biometric auth bypass (Medium)

### 5. Premium Feature Unlock

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

custom_hook = """
var Purchase = ObjC.classes.PurchaseManager;
Interceptor.attach(
    Purchase['- isPremiumUser'].implementation,
    {
        onLeave: function(retval) {
            console.log('[+] Forcing premium status');
            retval.replace(1);
        }
    }
);
"""

hooker = iOSFridaHooker()
hooker.inject_custom_hook("com.target.app", custom_hook)

# Test premium features
# Document what you can access
```

**Finding**: Client-side premium check bypass (Low-Medium)

## Command Line Quick Reference

```bash
# List running apps
frida-ps -U

# Spawn app with SSL bypass
frida -U -f com.target.app -l engine/mobile/ios/hooks/ssl_pinning.js

# Attach to running app
frida -U -n "Target App" -l engine/mobile/ios/hooks/api_monitor.js

# Multi-hook combo
frida -U -f com.target.app \
  -l engine/mobile/ios/hooks/ssl_pinning.js \
  -l engine/mobile/ios/hooks/jailbreak_detection.js \
  -l engine/mobile/ios/hooks/biometric_auth.js

# Interactive REPL
frida -U com.target.app
```

## Evidence Collection Checklist

- [ ] Screenshot before bypass
- [ ] Screenshot after bypass
- [ ] Frida console output (showing hooks loaded)
- [ ] Burp Suite requests (if MITM)
- [ ] API call logs (if monitoring)
- [ ] Keychain dump output (if credential theft)
- [ ] Screen recording of exploitation
- [ ] Code snippets of hooks used

## Report Template

```markdown
# [Vulnerability Type] in [App Name] iOS

## Summary
[Brief description]

## Steps to Reproduce
1. Install Frida on jailbroken iOS device
2. Run: `python ios_exploit.py`
3. Observe [impact]

## POC Code
```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

hooker = iOSFridaHooker()
hooker.hook_ssl_pinning("com.target.app")
# ... rest of POC
```

## Impact
- [Impact 1]
- [Impact 2]
- [Impact 3]

## Severity
[Low/Medium/High/Critical]

## Remediation
- Implement server-side validation
- Use certificate pinning with backup pins
- Store sensitive data with proper keychain attributes
```

## Common Pitfalls

1. **App crashes on hook** → Attach after launch instead of spawning
2. **Hook not triggering** → Verify method name with `ObjC.classes.ClassName.$ownMethods`
3. **Device not found** → Check frida-server is running on device
4. **Permission denied** → Run frida-server as root on device
5. **SSL bypass doesn't work** → App may use custom TLS implementation

## iOS Version Compatibility

| iOS Version | Status | Notes |
|-------------|--------|-------|
| 14.x | ✅ Full support | Stable |
| 15.x | ✅ Full support | Stable |
| 16.x | ✅ Full support | Stable |
| 17.x | ✅ Full support | Latest tested |
| 18.x | ✅ Beta support | May require updates |

## Bug Bounty Value Ranges

| Finding Type | Typical Payout | Severity |
|--------------|----------------|----------|
| SSL Pinning Bypass | $500-$1,500 | Medium-High |
| Keychain Data Leakage | $1,000-$3,000 | Medium-High |
| Client-Side Auth Bypass | $500-$2,000 | Medium |
| Biometric Bypass | $300-$1,000 | Low-Medium |
| API Endpoint Discovery | $200-$500 | Info |
| Premium Feature Unlock | $200-$800 | Low-Medium |

## Workflow Checklist

1. **Setup**
   - [ ] Jailbroken iOS device ready
   - [ ] Frida installed on host
   - [ ] Frida server running on device
   - [ ] Burp Suite configured (if needed)

2. **Recon**
   - [ ] Monitor API calls for 5 minutes
   - [ ] Dump keychain
   - [ ] List accessible files
   - [ ] Check for hardcoded secrets

3. **Testing**
   - [ ] SSL pinning bypass + MITM
   - [ ] Jailbreak detection bypass
   - [ ] Biometric auth bypass
   - [ ] Premium feature unlock attempts
   - [ ] Business logic manipulation

4. **Validation**
   - [ ] Confirm actual impact
   - [ ] Test from non-jailbroken device (if possible)
   - [ ] Verify server-side validation missing
   - [ ] Check for sensitive data exposure

5. **Reporting**
   - [ ] Evidence collected
   - [ ] POC code prepared
   - [ ] Impact clearly documented
   - [ ] Remediation suggested
   - [ ] Report submitted

## See Also

- [Full iOS Frida Hooking Guide](ios-frida-hooking-guide.md)
- [BountyHound Mobile Testing](../engine/mobile/README.md)
- [Frida Documentation](https://frida.re/docs/ios/)
