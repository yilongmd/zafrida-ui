// SSL Pinning Bypass (SSL 证书绑定绕过)
// Bypass SSL certificate pinning on Android. (绕过 Android SSL 证书校验)

Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log('[*] SSL Pinning Bypassed for: ' + host);
        return untrustedChain;
    };
});