// Android Universal SSL Pinning Bypass (Android通用SSL证书绑定绕过)
// Bypasses TrustManager, OkHttp3, TrustKit, Cronet, and more. (绕过TrustManager、OkHttp3、TrustKit、Cronet等SSL固定验证)

function bypass_trust_manager_impl() {
    try {
        var array_list = Java.use("java.util.ArrayList");
        var ApiClient = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        ApiClient.checkTrustedRecursive.implementation = function(a1, a2, a3, a4, a5, a6) {
            return array_list.$new();
        }
        ApiClient.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
    } catch (e) { console.log("[-] TrustManagerImpl hooks failed (might be different Android version)"); }
}

function bypass_okhttp3() {
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, cleanedPeerCertificates) {
            console.log("[+] Bypassing OkHttp3: " + hostname);
        };
        CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(hostname, cert) {
            console.log("[+] Bypassing OkHttp3 (single cert): " + hostname);
        };
    } catch (e) { console.log("[-] OkHttp3 hooks failed"); }
}

function bypass_trustkit() {
    try {
        var OkHostnameVerifier = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        OkHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str, sslSession) {
            console.log('[+] Bypassing Trustkit: ' + str);
            return true;
        };
    } catch (e) { console.log("[-] TrustKit hooks failed"); }
}

function bypass_appcelerator() {
    try {
        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function() {
            console.log('[+] Bypassing Appcelerator PinningTrustManager');
        };
    } catch (e) { }
}

Java.perform(function () {
    console.log("[.] Android Universal SSL Pinning Bypass Loaded");
    bypass_trust_manager_impl();
    bypass_okhttp3();
    bypass_trustkit();
    bypass_appcelerator();
    console.log("[+] SSL Pinning hooks setup complete.");
});