// SSL Pinning Bypass for iOS
// Comprehensive hook covering multiple SSL verification methods

// NSURLSession
var NSURLSession = ObjC.classes.NSURLSession;
if (NSURLSession) {
    Interceptor.attach(
        NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'].implementation,
        {
            onEnter: function(args) {
                console.log('[+] SSL challenge intercepted');
                var completionHandler = new ObjC.Block(args[4]);
                var credential = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
                completionHandler(0, credential); // NSURLSessionAuthChallengeUseCredential
            }
        }
    );
}

// SecTrustEvaluate
var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
if (SecTrustEvaluate) {
    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
        Memory.writeU8(result, 1); // Success
        return 0;
    }, 'int', ['pointer', 'pointer']));
}

console.log('[+] SSL pinning bypass active');
