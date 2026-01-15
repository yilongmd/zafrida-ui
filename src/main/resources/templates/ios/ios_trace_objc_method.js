// iOS Trace ObjC Method
// Traces a specific Objective-C method, printing arguments and return value.

if (ObjC.available) {
    // --- CONFIGURATION ---
    // Format: "-[ClassName methodName:]" or "+[ClassName staticMethod]"
    var targetMethod = "-[UIViewController viewDidAppear:]";
    // ---------------------

    var resolver = new ApiResolver('objc');
    var matches = resolver.enumerateMatches(targetMethod);

    if (matches.length === 0) {
        console.log("[-] Method not found: " + targetMethod);
    }

    matches.forEach(function(match) {
        console.log("[*] Hooking: " + match.name + " @ " + match.address);

        Interceptor.attach(match.address, {
            onEnter: function(args) {
                console.log("\n[+] Entered: " + match.name);
                // args[0] = self, args[1] = selector, args[2...] = arguments
                var self = new ObjC.Object(args[0]);
                console.log("    Target: " + self.$className);

                // Print Arg 1 (if exists)
                try {
                    var arg1 = new ObjC.Object(args[2]);
                    console.log("    Arg1: " + arg1.toString());
                } catch (e) {}
            },
            onLeave: function(retval) {
                try {
                    var ret = new ObjC.Object(retval);
                    console.log("    Return: " + ret.toString());
                } catch (e) {
                    console.log("    Return: " + retval);
                }
            }
        });
    });
}