// Android Class Method Tracer (Android 类方法追踪器)
// Traces all methods of a specified Java class (Prints Args, Return Value, and Backtrace). (追踪指定 Java 类的所有方法，打印参数、返回值和调用栈)

function trace_class(targetClass) {
    var hook = Java.use(targetClass);
    var methods = hook.class.getDeclaredMethods();

    console.log("[*] Tracing class: " + targetClass);

    methods.forEach(function(method) {
        var methodName = method.getName();
        var overloads = hook[methodName].overloads;

        overloads.forEach(function(overload) {
            overload.implementation = function() {
                console.log("\n[+] Entered: " + targetClass + "." + methodName);

                // Print Arguments
                for (var i = 0; i < arguments.length; i++) {
                    console.log("    Arg[" + i + "]: " + arguments[i]);
                }

                // Call Original
                var retval = this[methodName].apply(this, arguments);

                // Print Return
                console.log("    Return: " + retval);

                return retval;
            }
        });
    });
}

Java.perform(function() {
    // --- CONFIGURATION ---
    var targetClass = "com.example.target.ClassName"; // EDIT THIS
    // ---------------------
    trace_class(targetClass);
});