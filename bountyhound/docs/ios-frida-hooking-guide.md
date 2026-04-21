# iOS Runtime Hooking with Frida

This guide covers runtime hooking of iOS applications using Frida for bug bounty hunting.

## Table of Contents
1. [Setup](#setup)
2. [Basic Usage](#basic-usage)
3. [Capabilities](#capabilities)
4. [Hook Scripts](#hook-scripts)
5. [Advanced Usage](#advanced-usage)
6. [Troubleshooting](#troubleshooting)

## Setup

### Prerequisites
- iOS device (jailbroken for full capabilities)
- USB cable or WiFi connection
- Frida installed on host machine
- Frida server running on iOS device

### Install Frida

```bash
# Install Frida on host
pip install frida frida-tools

# Verify installation
frida --version
```

### Install Frida Server on iOS

1. **Via Cydia/Sileo (Jailbroken)**:
   ```bash
   # Add Frida repo to Cydia
   # Install "Frida" package
   ```

2. **Manual Installation**:
   ```bash
   # Download frida-server for iOS
   wget https://github.com/frida/frida/releases/download/VERSION/frida-server-VERSION-ios-arm64.xz

   # Extract
   unxz frida-server-VERSION-ios-arm64.xz

   # Copy to device via SSH
   scp frida-server root@<DEVICE_IP>:/usr/sbin/frida-server

   # SSH into device
   ssh root@<DEVICE_IP>

   # Make executable
   chmod +x /usr/sbin/frida-server

   # Run frida-server
   /usr/sbin/frida-server &
   ```

3. **Verify Connection**:
   ```bash
   # List processes on device
   frida-ps -U

   # Should show list of running apps
   ```

## Basic Usage

### Python API

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

# Connect to device
hooker = iOSFridaHooker()

# Bypass SSL pinning
hooker.hook_ssl_pinning("com.example.app")

# Bypass jailbreak detection
hooker.hook_jailbreak_detection("com.example.app")

# Hook biometric auth
hooker.hook_biometric_auth("com.example.app")

# Dump keychain
keychain = hooker.dump_keychain("com.example.app")
print(f"Found {keychain['count']} keychain items")

# Monitor API calls
api_calls = hooker.monitor_api_calls("com.example.app", duration=30)
for call in api_calls:
    print(f"{call['method']} {call['url']}")

# Inject custom hook
custom_script = """
console.log('[*] Custom hook loaded');
Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
    onEnter: function(args) {
        console.log('strcmp called');
    }
});
"""
hooker.inject_custom_hook("com.example.app", custom_script)
```

### Command Line

```bash
# List running apps
frida-ps -U

# Attach to app and run hook
frida -U -f com.example.app -l engine/mobile/ios/hooks/ssl_pinning.js

# Spawn app with hook
frida -U -f com.example.app -l engine/mobile/ios/hooks/jailbreak_detection.js --no-pause
```

## Capabilities

### 1. SSL Pinning Bypass

Bypasses certificate pinning to allow MITM traffic interception.

**Hooks**:
- `NSURLSession didReceiveChallenge` - Forces trust for all certificates
- `SecTrustEvaluate` - Always returns success
- `CFNetwork` SSL validation - Disabled

**Usage**:
```python
hooker.hook_ssl_pinning("com.example.app")
```

**Impact**: Allows Burp Suite/Charles to intercept HTTPS traffic.

### 2. Jailbreak Detection Bypass

Bypasses common jailbreak detection methods.

**Hooks**:
- File existence checks (`/Applications/Cydia.app`, `/bin/bash`, etc.)
- `fork()` - Returns -1 (fails on stock iOS)
- `stat()` - Redirects jailbreak path checks
- `canOpenURL()` - Blocks Cydia URL scheme checks
- `system()` - Blocks shell command execution

**Usage**:
```python
hooker.hook_jailbreak_detection("com.example.app")
```

**Impact**: App runs normally on jailbroken device.

### 3. Biometric Auth Bypass

Forces biometric authentication (Face ID/Touch ID) to succeed.

**Hooks**:
- `LAContext evaluatePolicy` - Forces success callback
- `canEvaluatePolicy` - Returns YES
- `biometryType` - Returns Face ID type

**Usage**:
```python
hooker.hook_biometric_auth("com.example.app")
```

**Impact**: Bypasses Face ID/Touch ID requirements.

### 4. Keychain Dumping

Extracts all accessible keychain items.

**Extracts**:
- Generic passwords
- Internet passwords
- Certificates
- Cryptographic keys

**Usage**:
```python
keychain = hooker.dump_keychain("com.example.app")

for item in keychain['items']:
    if item['type'] == 'generic_password':
        print(f"Account: {item['account']}")
        print(f"Service: {item['service']}")
        print(f"Password: {base64.b64decode(item['data'])}")
```

**Impact**: Reveals stored credentials and tokens.

### 5. API Call Monitoring

Captures all HTTP/HTTPS requests made by the app.

**Hooks**:
- `NSURLSession dataTaskWithRequest`
- `NSURLSession dataTaskWithURL`
- `NSURLConnection` (legacy)
- `CFNetwork` (low-level)

**Usage**:
```python
api_calls = hooker.monitor_api_calls("com.example.app", duration=60)

for call in api_calls:
    print(f"{call['timestamp']}: {call['method']} {call['url']}")
    print(f"Headers: {call['headers']}")
```

**Impact**: Discovers API endpoints and authentication mechanisms.

### 6. Custom Hook Injection

Inject arbitrary Frida JavaScript for custom behavior.

**Usage**:
```python
hook_script = """
// Hook specific method
var ViewController = ObjC.classes.ViewController;
Interceptor.attach(
    ViewController['- checkPremiumStatus'].implementation,
    {
        onLeave: function(retval) {
            console.log('[+] Forcing premium status');
            retval.replace(1); // Return YES
        }
    }
);
"""

hooker.inject_custom_hook("com.example.app", hook_script)
```

## Hook Scripts

Pre-built hook scripts are available in `engine/mobile/ios/hooks/`:

### ssl_pinning.js
Comprehensive SSL pinning bypass for iOS.

**Usage**:
```bash
frida -U -f com.example.app -l engine/mobile/ios/hooks/ssl_pinning.js
```

### jailbreak_detection.js
Bypasses all common jailbreak detection methods.

**Usage**:
```bash
frida -U -f com.example.app -l engine/mobile/ios/hooks/jailbreak_detection.js
```

### biometric_auth.js
Forces biometric authentication to succeed.

**Usage**:
```bash
frida -U -f com.example.app -l engine/mobile/ios/hooks/biometric_auth.js
```

### keychain_dump.js
Dumps all accessible keychain items.

**Usage**:
```bash
frida -U com.example.app -l engine/mobile/ios/hooks/keychain_dump.js
```

### api_monitor.js
Monitors all API calls in real-time.

**Usage**:
```bash
frida -U com.example.app -l engine/mobile/ios/hooks/api_monitor.js
```

## Advanced Usage

### Multi-Hook Combo

Combine multiple hooks for comprehensive testing:

```python
from engine.mobile.ios.frida_hooker import iOSFridaHooker

hooker = iOSFridaHooker()

# Enable all bypasses
hooker.hook_ssl_pinning("com.example.app")
hooker.hook_jailbreak_detection("com.example.app")
hooker.hook_biometric_auth("com.example.app")

# Now test app with Burp Suite
# - SSL pinning bypassed → see HTTPS traffic
# - Jailbreak detection bypassed → app runs
# - Biometric auth bypassed → no Face ID needed
```

### Find Specific Methods

Use Frida to discover methods to hook:

```javascript
// List all methods of a class
var ViewController = ObjC.classes.ViewController;
console.log(Object.keys(ViewController));

// List all classes
for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        console.log(className);
    }
}

// Find method by name
var methods = ObjC.classes.ViewController.$ownMethods;
methods.forEach(function(method) {
    console.log(method);
});
```

### Hook Private Methods

```javascript
// Hook private method with mangled name
var target = ObjC.classes.SomeClass;
var methods = target.$ownMethods;

methods.forEach(function(method) {
    if (method.includes('privateMethod')) {
        Interceptor.attach(
            target[method].implementation,
            {
                onEnter: function(args) {
                    console.log('[*] Private method called');
                }
            }
        );
    }
});
```

### Modify Return Values

```javascript
// Force method to return specific value
var Auth = ObjC.classes.AuthManager;
Interceptor.attach(
    Auth['- isPremiumUser'].implementation,
    {
        onLeave: function(retval) {
            console.log('[+] Forcing premium user status');
            retval.replace(1); // Return YES/true
        }
    }
);
```

### Intercept Arguments

```javascript
// Read and modify method arguments
var API = ObjC.classes.APIClient;
Interceptor.attach(
    API['- sendRequest:withToken:'].implementation,
    {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            var token = ObjC.Object(args[3]);

            console.log('[*] Request: ' + request.toString());
            console.log('[*] Token: ' + token.toString());

            // Modify token
            args[3] = ObjC.classes.NSString.stringWithString_('INJECTED_TOKEN');
        }
    }
);
```

## Troubleshooting

### Device Not Found

```
Error: Unable to connect to USB device
```

**Solutions**:
1. Verify Frida server is running on device:
   ```bash
   ssh root@<DEVICE_IP>
   ps aux | grep frida
   ```

2. Restart Frida server:
   ```bash
   killall frida-server
   /usr/sbin/frida-server &
   ```

3. Check USB connection:
   ```bash
   frida-ps -U
   ```

### App Crashes on Hook

```
Error: Process terminated
```

**Solutions**:
1. Hook after app launches:
   ```bash
   frida -U -n "App Name" -l hook.js
   # Instead of:
   frida -U -f com.example.app -l hook.js
   ```

2. Add error handling:
   ```javascript
   try {
       Interceptor.attach(...);
   } catch(err) {
       console.log('[!] Hook failed: ' + err);
   }
   ```

3. Check method signature:
   ```javascript
   // Verify method exists
   if (ObjC.classes.ClassName['- methodName:']) {
       // Hook it
   }
   ```

### Hook Not Triggering

**Solutions**:
1. Verify method name is correct:
   ```bash
   frida -U -n "App Name" -e "console.log(ObjC.classes.ClassName.$ownMethods)"
   ```

2. Check if method is optimized away:
   ```javascript
   // Use Module.findExportByName for C functions
   var func = Module.findExportByName(null, 'function_name');
   ```

3. Hook at module load time:
   ```javascript
   Module.load('ModuleName', function() {
       // Hook here
   });
   ```

### Permission Denied

```
Error: Unable to access target process
```

**Solutions**:
1. Run as root on device
2. Check Frida server permissions:
   ```bash
   chmod +x /usr/sbin/frida-server
   ```

## Bug Bounty Workflow

### 1. Recon Phase

```python
# Start with API monitoring
hooker = iOSFridaHooker()
api_calls = hooker.monitor_api_calls("com.target.app", duration=300)

# Save API calls
with open('api_calls.json', 'w') as f:
    json.dump(api_calls, f, indent=2)

# Analyze for interesting endpoints
for call in api_calls:
    if '/admin' in call['url'] or '/api/v1' in call['url']:
        print(f"Interesting: {call['method']} {call['url']}")
```

### 2. Auth Testing

```python
# Dump keychain for tokens
keychain = hooker.dump_keychain("com.target.app")

# Extract auth tokens
for item in keychain['items']:
    if 'token' in item['service'].lower():
        token = base64.b64decode(item['data'])
        print(f"Found token: {token}")

# Test tokens with curl
# curl -H "Authorization: Bearer <token>" https://api.target.com/me
```

### 3. SSL Interception

```python
# Bypass SSL pinning
hooker.hook_ssl_pinning("com.target.app")

# Now configure Burp Suite:
# 1. Set iOS proxy to Burp (Settings → WiFi → Proxy)
# 2. Install Burp CA cert on device
# 3. Launch app → see decrypted traffic in Burp
```

### 4. Business Logic Testing

```python
# Hook premium checks
custom_hook = """
var Purchase = ObjC.classes.PurchaseManager;
Interceptor.attach(
    Purchase['- hasPremiumAccess'].implementation,
    {
        onLeave: function(retval) {
            retval.replace(1); // Force premium
        }
    }
);
"""

hooker.inject_custom_hook("com.target.app", custom_hook)

# Test premium features without payment
# Document as "Client-Side Premium Check Bypass"
```

### 5. Evidence Collection

```python
# Screenshot before/after
# Terminal logs showing hook execution
# Burp requests showing exploited API calls

# Generate POC:
poc = f"""
# Vulnerability: SSL Pinning Bypass + Auth Token Leakage

## Steps to Reproduce:
1. Install Frida on jailbroken iOS device
2. Run: frida -U -f com.target.app -l ssl_pinning.js
3. Configure Burp Suite proxy
4. Launch app
5. Observe decrypted API calls containing auth tokens

## Impact:
- MITM attacks possible
- Auth tokens exposed in transit
- Sensitive user data readable

## POC:
{api_calls[0]}
"""

print(poc)
```

## iOS Version Compatibility

| iOS Version | Frida Support | Notes |
|-------------|---------------|-------|
| 14.x | ✅ Full | Stable |
| 15.x | ✅ Full | Stable |
| 16.x | ✅ Full | Stable |
| 17.x | ✅ Full | Latest tested |
| 18.x | ✅ Full | Beta support |

## References

- [Frida iOS Documentation](https://frida.re/docs/ios/)
- [Objection iOS Toolkit](https://github.com/sensepost/objection)
- [iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
