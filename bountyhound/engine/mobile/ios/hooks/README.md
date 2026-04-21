# iOS Frida Hook Scripts

Pre-built Frida JavaScript hooks for iOS application security testing.

## Hook Scripts

### ssl_pinning.js
Comprehensive SSL certificate pinning bypass.

**Hooks**:
- NSURLSession SSL verification
- SecTrustEvaluate

**Usage**:
```bash
frida -U -f com.example.app -l ssl_pinning.js
```

### jailbreak_detection.js
Bypasses common jailbreak detection methods.

**Hooks**:
- File existence checks
- fork() system call
- stat() system call
- canOpenURL() for Cydia detection
- system() command execution

**Usage**:
```bash
frida -U -f com.example.app -l jailbreak_detection.js
```

### biometric_auth.js
Forces biometric authentication (Face ID/Touch ID) to succeed.

**Hooks**:
- LAContext evaluatePolicy
- canEvaluatePolicy
- biometryType

**Usage**:
```bash
frida -U -f com.example.app -l biometric_auth.js
```

### keychain_dump.js
Dumps all accessible keychain items.

**Extracts**:
- Generic passwords
- Internet passwords
- Certificates
- Cryptographic keys

**Usage**:
```bash
frida -U com.example.app -l keychain_dump.js
```

### api_monitor.js
Monitors all API calls in real-time.

**Hooks**:
- NSURLSession dataTaskWithRequest
- NSURLSession dataTaskWithURL
- NSURLConnection (legacy)
- CFNetwork

**Usage**:
```bash
frida -U com.example.app -l api_monitor.js
```

## Loading Multiple Hooks

```bash
# Load SSL pinning + jailbreak detection
frida -U -f com.example.app \
  -l ssl_pinning.js \
  -l jailbreak_detection.js \
  -l biometric_auth.js
```

## Custom Hook Template

```javascript
// Custom hook template
console.log('[*] Hook loaded');

// Hook a method
var ClassName = ObjC.classes.ClassName;
Interceptor.attach(
    ClassName['- methodName:'].implementation,
    {
        onEnter: function(args) {
            // Before method execution
            console.log('[*] Method called');
        },
        onLeave: function(retval) {
            // After method execution
            console.log('[+] Method returned');
        }
    }
);
```

## Bug Bounty Applications

### 1. SSL Pinning Bypass
**Finding**: Insufficient transport layer protection
**Severity**: Medium-High
**Impact**: MITM attacks possible

### 2. Client-Side Jailbreak Detection
**Finding**: Security controls implemented client-side only
**Severity**: Low-Medium
**Impact**: Bypassed restrictions on jailbroken devices

### 3. Insecure Keychain Storage
**Finding**: Sensitive data accessible in keychain
**Severity**: Medium-High
**Impact**: Credential theft

### 4. Client-Side Biometric Bypass
**Finding**: Biometric authentication not validated server-side
**Severity**: Medium
**Impact**: Unauthorized access to features

### 5. Unencrypted API Calls
**Finding**: Sensitive data transmitted without proper encryption
**Severity**: High
**Impact**: Data exposure

## See Also

- [iOS Frida Hooking Guide](../../../docs/ios-frida-hooking-guide.md)
- [Frida Documentation](https://frida.re/docs/ios/)
- [BountyHound Mobile Testing](../../README.md)
