// API Call Monitoring for iOS
// Hooks NSURLSession to capture all network requests

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
                var body = request.HTTPBody();

                var requestData = {
                    type: 'request',
                    url: url,
                    method: method,
                    headers: headers ? JSON.parse(headers.toString()) : {},
                    timestamp: new Date().toISOString()
                };

                if (body) {
                    requestData.body = body.base64EncodedStringWithOptions_(0).toString();
                }

                send(requestData);
            }
        }
    );
}

// Hook NSURLSession dataTaskWithURL (simpler variant)
if (NSURLSession) {
    Interceptor.attach(
        NSURLSession['- dataTaskWithURL:'].implementation,
        {
            onEnter: function(args) {
                var url = ObjC.Object(args[2]).absoluteString().toString();

                send({
                    type: 'request',
                    url: url,
                    method: 'GET',
                    headers: {},
                    timestamp: new Date().toISOString()
                });
            }
        }
    );
}

// Hook NSURLConnection (legacy API)
var NSURLConnection = ObjC.classes.NSURLConnection;
if (NSURLConnection) {
    Interceptor.attach(
        NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'].implementation,
        {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().absoluteString().toString();
                var method = request.HTTPMethod().toString();

                send({
                    type: 'request',
                    url: url,
                    method: method,
                    source: 'NSURLConnection',
                    timestamp: new Date().toISOString()
                });
            }
        }
    );
}

// Hook CFNetwork (lower level)
var CFHTTPMessageCreateRequest = Module.findExportByName('CFNetwork', 'CFHTTPMessageCreateRequest');
if (CFHTTPMessageCreateRequest) {
    Interceptor.attach(CFHTTPMessageCreateRequest, {
        onEnter: function(args) {
            var method = Memory.readUtf8String(args[1]);
            var url = ObjC.Object(args[2]).absoluteString().toString();

            send({
                type: 'request',
                url: url,
                method: method,
                source: 'CFNetwork',
                timestamp: new Date().toISOString()
            });
        }
    });
}

console.log('[+] API monitoring active');
