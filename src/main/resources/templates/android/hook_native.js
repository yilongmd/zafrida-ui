// Hook Native Function (Hook Native 函数)
// Hook native layer function using Interceptor. (使用 Interceptor 钩住 Native 层函数)
function hook_native_function() {
    Interceptor.attach(Module.findExportByName("libc.so", "open"), {
        onEnter: function(args) {
            this.path = args[0].readUtf8String();
            console.log("[*] open(" + this.path + ")");
        },
        onLeave: function(retval) {
            console.log("[*] open returned: " + retval);
        }
    });
}

hook_native_function();
