// Android Activity & Click Tracer (Android Activity与点击事件追踪器)
// Logs Activity starts and View OnClick events to help locate UI logic. (记录Activity启动和View点击事件，帮助定位UI逻辑)

function trace_activity_start() {
    var Activity = Java.use("android.app.Activity");
    Activity.startActivity.overload("android.content.Intent").implementation = function(intent) {
        var component = intent.getComponent();
        var target = component ? component.getClassName() : "Unknown";
        console.log("[Activity] Starting: " + target);
        console.log("  -> Intent: " + intent.toString());
        return this.startActivity(intent);
    }
}

function trace_view_clicks() {
    var View = Java.use("android.view.View");
    View.setOnClickListener.implementation = function(listener) {
        if (listener != null) {
            var listenerClassName = listener.getClass().getName();
            console.log("[UI] setOnClickListener registered: " + listenerClassName);
        }
        return this.setOnClickListener(listener);
    }
}

Java.perform(function() {
    console.log("[.] UI Tracer Loaded");
    trace_activity_start();
    trace_view_clicks();
});