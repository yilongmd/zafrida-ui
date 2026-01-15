// Android Print StackTrace (Android 打印堆栈跟踪)
// Helper function to print the Java StackTrace at any hook point. (辅助函数，用于在任意钩子点打印 Java 调用堆栈)

function printStackTrace() {
    var Exception = Java.use("java.lang.Exception");
    var Log = Java.use("android.util.Log");
    console.log(Log.getStackTraceString(Exception.$new()));
}

function hook_log_with_stacktrace() {
    var Target = Java.use("android.util.Log"); // Example target

    Target.i.overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
        printStackTrace();
        return this.i(tag, msg);
    }
}

Java.perform(function() {
    // --- USAGE ---
    // Call printStackTrace() inside any hook to print call stack
    // ---------------------
    hook_log_with_stacktrace();
});