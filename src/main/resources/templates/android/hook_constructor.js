// Hook Constructor (Hook 构造函数)
// Hook the constructor of a Java class to trace object creation. (钩住 Java 类的构造函数，追踪对象创建)

function hook_constructor(className, overloadTypes) {
    var targetClass = Java.use(className);
    targetClass.$init.overload.apply(targetClass.$init, overloadTypes).implementation = function() {
        console.log("[*] Constructor called: " + className);
        for (var i = 0; i < arguments.length; i++) {
            console.log("    Arg[" + i + "]: " + arguments[i]);
        }
        return this.$init.apply(this, arguments);
    };
}

Java.perform(function() {
    // --- CONFIGURATION ---
    var targetClassName = "com.example.TargetClass"; // EDIT THIS
    var overloadTypes = ['java.lang.String']; // EDIT THIS
    // ---------------------
    hook_constructor(targetClassName, overloadTypes);
});