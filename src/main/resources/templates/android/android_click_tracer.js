// Android Activity & Click Tracer (Android Activity与点击事件追踪器)
// Logs Activity starts and View OnClick events to help locate UI logic. (记录Activity启动和View点击事件，帮助定位UI逻辑)

Java.perform(function() {
    console.log("[.] UI Tracer Loaded");

    // 1. Trace Activity Start
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
        var component = intent.getComponent();
        var target = component ? component.getClassName() : "Unknown";
        console.log("[Activity] Starting: " + target);
        console.log("  -> Intent: " + intent.toString());
        return this.startActivity(intent);
    }

    // 2. Trace View Clicks
    var View = Java.use("android.view.View");
    View.setOnClickListener.implementation = function(listener) {
        if (listener != null) {
            var listenerClassName = listener.getClass().getName();
            console.log("[UI] setOnClickListener registered: " + listenerClassName);

            // Hook the onClick method of the listener dynamically
            var OnClickListener = Java.use("android.view.View$OnClickListener");
            // Note: This is a simplified logic. Hooking interface implementations dynamically
            // requires finding the actual class implementing it.
        }
        return this.setOnClickListener(listener);
    }
});