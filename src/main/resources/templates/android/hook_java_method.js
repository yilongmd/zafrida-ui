// Hook Java Method (Hook Java 方法)
// Hook a specific Java method and log arguments and return value. (钩住指定 Java 方法，打印参数和返回值)

function hook_java_method(className, methodName) {
    var targetClass = Java.use(className);
    targetClass[methodName].implementation = function() {
        console.log("[*] " + className + "." + methodName + " called");
        console.log("[*] Arguments: " + JSON.stringify(arguments));
        var result = this[methodName].apply(this, arguments);
        console.log("[*] Return: " + result);
        return result;
    };
}

Java.perform(function() {
    // --- CONFIGURATION ---
    var targetClassName = "com.example.TargetClass"; // EDIT THIS
    var targetMethodName = "targetMethod"; // EDIT THIS
    // ---------------------
    hook_java_method(targetClassName, targetMethodName);
});