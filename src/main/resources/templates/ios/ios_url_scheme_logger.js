// iOS URL Scheme Logger (iOS URL Scheme日志记录器)
// Intercepts UIApplication openURL to capture deeplinks. (拦截UIApplication openURL捕获深度链接调用)

function hook_url_scheme_old() {
    var UIApplication = ObjC.classes.UIApplication;
    var hook = UIApplication["- openURL:"];

    if (hook) {
        Interceptor.attach(hook.implementation, {
            onEnter: function(args) {
                // args[2] is the NSURL
                var url = new ObjC.Object(args[2]);
                console.log(url.absoluteString().toString());
            }
        });
    }
}

function hook_url_scheme_new() {
    var UIApplication = ObjC.classes.UIApplication;
    // Newer iOS versions use openURL:options:completionHandler:
    var hookNew = UIApplication["- openURL:options:completionHandler:"];
    if (hookNew) {
        Interceptor.attach(hookNew.implementation, {
            onEnter: function(args) {
                var url = new ObjC.Object(args[2]);
                console.log(url.absoluteString().toString());
            }
        });
    }
}

if (ObjC.available) {
    console.log("[.] iOS URL Scheme Logger Loaded");
    hook_url_scheme_old();
    hook_url_scheme_new();
}
