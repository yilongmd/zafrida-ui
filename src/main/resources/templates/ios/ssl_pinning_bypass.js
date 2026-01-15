// iOS SSL Pinning Bypass (iOS SSL 证书绑定绕过)
// Bypass SSL certificate pinning on iOS. (绕过 iOS SSL 证书校验)

var resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[* evaluateServerTrust:*]', {
    onMatch: function(match) {
        Interceptor.attach(match.address, {
            onEnter: function(args) {
                ObjC.Object(args[0]).setAlwaysTrust_(true);
            }
        });
    },
    onComplete: function() {}
});