// Hook Objective-C Method (Hook ObjC 方法)
// Hook an Objective-C method and log arguments and return value. (钩住 Objective-C 方法，打印参数和返回值)

// --- CONFIGURATION ---
var className = "TargetClass"; // EDIT THIS
var methodName = "- targetMethod:"; // EDIT THIS
// ---------------------

function hook_objc_method(className, methodName) {
    var hook = ObjC.classes[className][methodName];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            console.log("[*] " + methodName + " called");
            console.log("[*] self: " + ObjC.Object(args[0]));
            console.log("[*] selector: " + ObjC.selectorAsString(args[1]));
        },
        onLeave: function(retval) {
            console.log("[*] Return: " + retval);
        }
    });
}

hook_objc_method(className, methodName);
