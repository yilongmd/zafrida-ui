// Hook Specific ObjC Method of Class (钩住指定 ObjC 类的特定方法)
// Template to hook a single Objective-C method and log arguments (read-only by default). (钩住单个 Objective-C 方法并记录参数的模板，默认只读)

//Source: http://www.mopsled.com/2015/log-ios-method-arguments-with-frida/
//Twitter: https://twitter.com/xploresec
//GitHub: https://github.com/interference-security
//Your class name here
function hook_specific_method_of_class(className, funcName)
{
    var hook = ObjC.classes[className][funcName];
    Interceptor.attach(hook.implementation, {
      onEnter: function(args) {
        // args[0] is self
        // args[1] is selector (SEL "sendMessageWithText:")
        // args[2] holds the first function argument, an NSString
        console.log("[*] Detected call to: " + className + " -> " + funcName);
        //For viewing and manipulating arguments
        //console.log("\t[-] Value1: "+ObjC.Object(args[2]));
        //console.log("\t[-] Value2: "+(ObjC.Object(args[2])).toString());
        //console.log(args[2]);
      }
    });
}

//Your class name  and function name here
hook_specific_method_of_class("className", "funcName")
