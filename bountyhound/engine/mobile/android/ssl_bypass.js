/**
 * Universal Android SSL Pinning Bypass
 * Works with most common SSL pinning implementations
 */

Java.perform(function() {
    console.log('[+] Loading universal SSL bypass...');

    // ===== TrustManager Bypass =====
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'dev.bountyhound.ssl.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {
                console.log('[+] checkServerTrusted bypassed');
            },
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });

    // Hook SSLContext.init()
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(keyManager, trustManager, secureRandom) {
            console.log('[+] SSLContext.init() hooked');
            this.init(keyManager, [TrustManager.$new()], secureRandom);
        };

    // ===== OkHttp Bypass =====
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp CertificatePinner.check() bypassed for: ' + hostname);
            return;
        };
    } catch(e) {}

    // ===== Trustkit Bypass =====
    try {
        var Activity = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(hostname, session) {
            console.log('[+] Trustkit bypassed for: ' + hostname);
            return true;
        };
    } catch(e) {}

    // ===== Apache HTTP Client =====
    try {
        var TrustAllCerts = Java.use('org.apache.http.conn.ssl.AllowAllHostnameVerifier');
        TrustAllCerts.verify.implementation = function() {
            console.log('[+] Apache AllowAllHostnameVerifier bypassed');
            return true;
        };
    } catch(e) {}

    console.log('[+] SSL pinning bypass loaded successfully');
});
