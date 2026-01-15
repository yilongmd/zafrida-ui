// Android Print StackTrace (Android 打印堆栈跟踪)
// Helper function to print the Java StackTrace at any hook point. (辅助函数，用于在任意钩子点打印 Java 调用堆栈)

Java.perform(function() {
    // --- USAGE ---
    // Copy the content inside implementation to where you want to trace
    // ---------------------

    var Target = Java.use("android.util.Log"); // Example target

    Target.i.overload('java.lang.String', 'java.lang.String').implementation = function(tag, msg) {
        // Start StackTrace Logic
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");
        console.log(Log.getStackTraceString(Exception.$new()));
        // End StackTrace Logic

        return this.i(tag, msg);
    }
});