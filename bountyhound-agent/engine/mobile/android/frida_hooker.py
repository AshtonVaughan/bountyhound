"""
Frida Dynamic Instrumentation Framework
Hook Android app functions and bypass security checks
"""

import time
import sys
from pathlib import Path
from typing import List, Dict, Optional, Callable
from colorama import Fore, Style

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] Frida not installed. Install with: pip install frida frida-tools{Style.RESET_ALL}")


class FridaHooker:
    """
    Frida hooking framework for Android apps
    """

    def __init__(self, package_name: str, device_id: Optional[str] = None):
        """
        Initialize Frida hooker

        Args:
            package_name: Android package name (e.g., com.instagram.android)
            device_id: Optional device ID (USB or emulator)
        """
        if not FRIDA_AVAILABLE:
            raise ImportError("Frida not installed")

        self.package_name = package_name
        self.device_id = device_id
        self.device = None
        self.session = None
        self.script = None

        self.connect_device()

    def connect_device(self):
        """Connect to Android device"""
        try:
            if self.device_id:
                self.device = frida.get_device(self.device_id)
            else:
                # Try USB first, then emulator
                try:
                    self.device = frida.get_usb_device()
                    print(f"{Fore.GREEN}[+] Connected to USB device{Style.RESET_ALL}")
                except:
                    self.device = frida.get_remote_device()
                    print(f"{Fore.GREEN}[+] Connected to emulator{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[-] Failed to connect to device: {e}{Style.RESET_ALL}")
            raise

    def attach(self):
        """Attach to running app"""
        try:
            print(f"{Fore.CYAN}[*] Attaching to {self.package_name}...{Style.RESET_ALL}")
            self.session = self.device.attach(self.package_name)
            print(f"{Fore.GREEN}[+] Attached successfully{Style.RESET_ALL}")
        except frida.ProcessNotFoundError:
            print(f"{Fore.RED}[-] App not running. Starting app...{Style.RESET_ALL}")
            pid = self.device.spawn([self.package_name])
            self.session = self.device.attach(pid)
            self.device.resume(pid)
            print(f"{Fore.GREEN}[+] App started and attached{Style.RESET_ALL}")

    def load_script(self, script_code: str, on_message: Optional[Callable] = None):
        """
        Load and run Frida script

        Args:
            script_code: JavaScript code to inject
            on_message: Callback for script messages
        """
        if not self.session:
            self.attach()

        def default_on_message(message, data):
            if message['type'] == 'send':
                print(f"{Fore.CYAN}[FRIDA] {message['payload']}{Style.RESET_ALL}")
            elif message['type'] == 'error':
                print(f"{Fore.RED}[ERROR] {message['stack']}{Style.RESET_ALL}")

        handler = on_message or default_on_message

        self.script = self.session.create_script(script_code)
        self.script.on('message', handler)
        self.script.load()

        print(f"{Fore.GREEN}[+] Script loaded{Style.RESET_ALL}")

    def load_script_file(self, script_path: str):
        """Load Frida script from file"""
        script_file = Path(script_path)

        if not script_file.exists():
            raise FileNotFoundError(f"Script not found: {script_path}")

        script_code = script_file.read_text()
        self.load_script(script_code)

    def bypass_ssl_pinning(self):
        """Bypass SSL certificate pinning"""
        print(f"{Fore.CYAN}[*] Loading SSL pinning bypass...{Style.RESET_ALL}")

        script_path = Path(__file__).parent / "ssl_bypass.js"

        if not script_path.exists():
            # Inline script if file doesn't exist
            script_code = SSL_BYPASS_SCRIPT
        else:
            script_code = script_path.read_text()

        self.load_script(script_code)
        print(f"{Fore.GREEN}[+] SSL pinning bypassed!{Style.RESET_ALL}")

    def bypass_root_detection(self):
        """Bypass root detection"""
        print(f"{Fore.CYAN}[*] Loading root detection bypass...{Style.RESET_ALL}")

        script_code = ROOT_BYPASS_SCRIPT
        self.load_script(script_code)
        print(f"{Fore.GREEN}[+] Root detection bypassed!{Style.RESET_ALL}")

    def bypass_iap(self):
        """Bypass In-App Purchase verification"""
        print(f"{Fore.CYAN}[*] Loading IAP bypass...{Style.RESET_ALL}")

        script_code = IAP_BYPASS_SCRIPT
        self.load_script(script_code)
        print(f"{Fore.GREEN}[+] IAP verification bypassed!{Style.RESET_ALL}")

    def hook_method(self, class_name: str, method_name: str, callback: str = ""):
        """
        Hook a specific method

        Args:
            class_name: Full Java class name
            method_name: Method to hook
            callback: JavaScript code to run on hook
        """
        script = f"""
        Java.perform(function() {{
            var targetClass = Java.use('{class_name}');

            targetClass.{method_name}.implementation = function() {{
                console.log('[+] Hooked {class_name}.{method_name}');
                console.log('[+] Arguments:', arguments);

                {callback}

                // Call original
                return this.{method_name}.apply(this, arguments);
            }};
        }});
        """

        self.load_script(script)

    def trace_class(self, class_name: str):
        """Trace all methods in a class"""
        script = f"""
        Java.perform(function() {{
            var targetClass = Java.use('{class_name}');
            var methods = targetClass.class.getDeclaredMethods();

            methods.forEach(function(method) {{
                var methodName = method.getName();
                console.log('[*] Hooking:', methodName);

                try {{
                    targetClass[methodName].implementation = function() {{
                        console.log('[+] Called:', methodName);
                        console.log('[+] Args:', arguments);
                        return this[methodName].apply(this, arguments);
                    }};
                }} catch(e) {{
                    console.log('[!] Could not hook:', methodName);
                }}
            }});
        }});
        """

        self.load_script(script)

    def dump_memory(self, address: int, size: int) -> bytes:
        """Dump memory at address"""
        script = f"""
        var baseAddr = ptr("{hex(address)}");
        var data = Memory.readByteArray(baseAddr, {size});
        send(data);
        """

        self.load_script(script)
        # Wait for message...
        time.sleep(1)

    def keep_alive(self):
        """Keep script running"""
        print(f"{Fore.CYAN}[*] Script running. Press Ctrl+C to stop.{Style.RESET_ALL}")
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Stopping...{Style.RESET_ALL}")
            self.detach()

    def detach(self):
        """Detach from app"""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        print(f"{Fore.GREEN}[+] Detached{Style.RESET_ALL}")


# ============================================================================
# BUILT-IN BYPASS SCRIPTS
# ============================================================================

SSL_BYPASS_SCRIPT = """
Java.perform(function() {
    console.log('[+] Loading SSL bypass...');

    // Universal SSL bypass
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // TrustManager bypass
    var TrustManagerImpl = Java.registerClass({
        name: 'com.sensepost.test.TrustManagerImpl',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManagerImpl.$new()];
    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    );

    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] SSL Context bypass');
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };

    console.log('[+] SSL pinning bypassed!');
});
"""

ROOT_BYPASS_SCRIPT = """
Java.perform(function() {
    console.log('[+] Loading root detection bypass...');

    // Common root detection methods
    var RootBeer = null;
    try {
        RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[+] RootBeer.isRooted() bypassed');
            return false;
        };
    } catch(e) {}

    // File.exists() bypass for common root files
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();

        if (path.indexOf('/su') !== -1 ||
            path.indexOf('Superuser') !== -1 ||
            path.indexOf('magisk') !== -1) {
            console.log('[+] Hiding root file:', path);
            return false;
        }

        return this.exists.call(this);
    };

    console.log('[+] Root detection bypassed!');
});
"""

IAP_BYPASS_SCRIPT = """
Java.perform(function() {
    console.log('[+] Loading IAP bypass...');

    // Google Play Billing
    try {
        var BillingClient = Java.use('com.android.billingclient.api.BillingClient');

        BillingClient.isReady.implementation = function() {
            console.log('[+] BillingClient.isReady() = true');
            return true;
        };
    } catch(e) {}

    // Purchase verification bypass
    try {
        var Purchase = Java.use('com.android.billingclient.api.Purchase');

        Purchase.getPurchaseState.implementation = function() {
            console.log('[+] Purchase.getPurchaseState() = PURCHASED');
            return 1; // PURCHASED
        };

        Purchase.isAcknowledged.implementation = function() {
            console.log('[+] Purchase.isAcknowledged() = true');
            return true;
        };
    } catch(e) {}

    console.log('[+] IAP verification bypassed!');
});
"""


def main():
    """CLI interface"""
    import argparse

    parser = argparse.ArgumentParser(description='Frida Android Hooker')
    parser.add_argument('package', help='Package name (e.g., com.instagram.android)')
    parser.add_argument('--ssl', action='store_true', help='Bypass SSL pinning')
    parser.add_argument('--root', action='store_true', help='Bypass root detection')
    parser.add_argument('--iap', action='store_true', help='Bypass IAP')
    parser.add_argument('--script', help='Load custom script file')

    args = parser.parse_args()

    hooker = FridaHooker(args.package)

    if args.ssl:
        hooker.bypass_ssl_pinning()

    if args.root:
        hooker.bypass_root_detection()

    if args.iap:
        hooker.bypass_iap()

    if args.script:
        hooker.load_script_file(args.script)

    hooker.keep_alive()


if __name__ == "__main__":
    main()
