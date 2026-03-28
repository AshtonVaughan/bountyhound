// Jailbreak Detection Bypass for iOS
// Hooks common detection methods

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
                    '/Library/MobileSubstrate',
                    '/bin/bash',
                    '/usr/sbin/sshd',
                    '/etc/apt',
                    '/private/var/lib/apt',
                    '/private/var/lib/cydia',
                    '/private/var/stash',
                    '/usr/libexec/sftp-server',
                    '/usr/bin/ssh',
                    '/Applications/blackra1n.app',
                    '/Applications/FakeCarrier.app',
                    '/Applications/Icy.app',
                    '/Applications/IntelliScreen.app',
                    '/Applications/MxTube.app',
                    '/Applications/RockApp.app',
                    '/Applications/SBSettings.app',
                    '/Applications/WinterBoard.app'
                ];

                if (jbPaths.some(p => path.includes(p))) {
                    console.log('[+] Blocked jailbreak detection for: ' + path);
                    args[2] = ObjC.classes.NSString.stringWithString_('/nonexistent');
                }
            }
        }
    );
}

// Hook fork() - jailbroken devices allow fork()
var fork = Module.findExportByName(null, 'fork');
if (fork) {
    Interceptor.replace(fork, new NativeCallback(function() {
        console.log('[+] fork() bypassed - returning -1');
        return -1; // Fork fails on stock iOS
    }, 'int', []));
}

// Hook stat() checks
var stat = Module.findExportByName(null, 'stat');
if (stat) {
    Interceptor.attach(stat, {
        onEnter: function(args) {
            var path = Memory.readUtf8String(args[0]);
            var jbPaths = ['/Applications/Cydia.app', '/bin/bash', '/usr/sbin/sshd'];

            if (jbPaths.some(p => path.includes(p))) {
                console.log('[+] Blocked stat() check for: ' + path);
                Memory.writeUtf8String(args[0], '/nonexistent');
            }
        }
    });
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

// Hook system() calls
var system = Module.findExportByName(null, 'system');
if (system) {
    Interceptor.attach(system, {
        onEnter: function(args) {
            var cmd = Memory.readUtf8String(args[0]);
            console.log('[+] Blocked system() call: ' + cmd);
            Memory.writeUtf8String(args[0], 'echo');
        }
    });
}

console.log('[+] Jailbreak detection bypass active');
