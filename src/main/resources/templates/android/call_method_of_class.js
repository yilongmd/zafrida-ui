// Call Java Method on Live Instance (调用活动实例的 Java 方法)
// Use Java.choose() to locate instances and invoke a method for runtime inspection. (使用 Java.choose() 定位实例并调用方法进行运行时检查)

//Source: https://11x256.github.io/Frida-hooking-android-part-2/

function call_method_on_instance(className, methodName) {
    Java.choose(className, {
        onMatch: function(instance) {
            console.log("Found instance: " + instance);
            console.log("Result of method call: " + instance[methodName]());
        },
        onComplete: function() {}
    });
}

Java.perform(function() {
    // --- CONFIGURATION ---
    var className = "com.example.app.activity_class_name"; // EDIT THIS
    var methodName = "method_name_to_call"; // EDIT THIS
    // ---------------------
    call_method_on_instance(className, methodName);
});
