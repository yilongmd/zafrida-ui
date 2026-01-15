// Hook Java Method (Hook Java 方法)
// Hook a specific Java method and log arguments and return value. (钩住指定 Java 方法，打印参数和返回值)

Java.perform(function() {
    var targetClass = Java.use("com.example.TargetClass");
    targetClass.targetMethod.implementation = function() {
        console.log("[*] targetMethod called");
        console.log("[*] Arguments: " + JSON.stringify(arguments));
        var result = this.targetMethod.apply(this, arguments);
        console.log("[*] Return: " + result);
        return result;
    };
});