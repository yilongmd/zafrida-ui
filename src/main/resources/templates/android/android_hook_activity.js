// Android Activity Lifecycle Hook (Android Activity 生命周期钩子)
// Hooks Activity.onCreate to trace which Activities are being launched and capture their Intent. (钩住 Activity.onCreate 方法，追踪启动的 Activity 并捕获 Intent 信息)

Java.perform(function() {
    var Activity = Java.use("android.app.Activity");

    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        var name = this.getClass().getName();
        console.log("[*] Activity Created: " + name);

        var intent = this.getIntent();
        if (intent) {
            console.log("    Intent: " + intent.toString());
            var extras = intent.getExtras();
            if (extras) {
                console.log("    Extras: " + extras.toString());
            }
        }

        return this.onCreate(bundle);
    };
});