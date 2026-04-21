# Frida Hooking Skill

**Category**: Mobile Dynamic Analysis | **Difficulty**: Medium
**Description**: Hook Android/iOS app functions at runtime using Frida
**Tools**: Frida, frida-tools, objection
**Impact**: MEDIUM-HIGH ($2K-$10K per bypass)

## Quick Start

```bash
# Install Frida
pip install frida frida-tools

# List processes
frida-ps -U

# Attach to app
frida -U -f com.app.package

# Load script
frida -U -l script.js com.app.package
```

## Universal SSL Bypass

```javascript
Java.perform(function() {
    // Hook all TrustManagers
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.hack.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
        };
});
```

## Method Hooking Template

```javascript
Java.perform(function() {
    var TargetClass = Java.use('com.app.security.SecurityCheck');

    // Hook method
    TargetClass.isPremium.implementation = function() {
        console.log('[+] isPremium() called');
        console.log('[+] Original return:', this.isPremium());
        return true; // Force premium access
    };
});
```

## Expected ROI
- SSL bypass: $2K-$5K
- IAP bypass: $3K-$8K
- Root bypass: $1K-$3K
