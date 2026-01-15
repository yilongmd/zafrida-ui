// iOS Jailbreak Detection Bypass (Simple) (iOS越狱检测绕过 - 简单版)
// Bypasses common file existence checks (Cydia, ssh, bash, etc.). (绕过常见的文件存在检测，如Cydia、ssh、bash等)

var jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt"
];

function bypass_jailbreak_file_check() {
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExists = NSFileManager["- fileExistsAtPath:"];

    Interceptor.attach(fileExists.implementation, {
        onEnter: function(args) {
            this.path = new ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (retval.toInt() === 1) {
                for (var i = 0; i < jailbreakPaths.length; i++) {
                    if (this.path.indexOf(jailbreakPaths[i]) !== -1) {
                        console.log("[!] Bypassing check for: " + this.path);
                        retval.replace(0); // Return False
                        return;
                    }
                }
            }
        }
    });
}

if (ObjC.available) {
    bypass_jailbreak_file_check();
    console.log("[*] Jailbreak detection bypass loaded");
}