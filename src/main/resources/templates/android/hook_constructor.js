// Hook Constructor (Hook 构造函数)
// Hook the constructor of a Java class to trace object creation. (钩住 Java 类的构造函数，追踪对象创建)

Java.perform(function() {
    var targetClass = Java.use("com.example.TargetClass");
    targetClass.$init.overload('java.lang.String').implementation = function(arg) {
        console.log("[*] Constructor called with: " + arg);
        return this.$init(arg);
    };
});