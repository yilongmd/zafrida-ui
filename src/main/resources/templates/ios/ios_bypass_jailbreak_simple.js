// iOS Jailbreak Detection Bypass (Simple)
// Bypasses common file existence checks (Cydia, ssh, bash, etc.).

if (ObjC.available) {
    var paths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt"
    ];

    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExists = NSFileManager["- fileExistsAtPath:"];

    Interceptor.attach(fileExists.implementation, {
        onEnter: function(args) {
            this.path = new ObjC.Object(args[2]).toString();
        },
        onLeave: function(retval) {
            if (retval.toInt() === 1) {
                for (var i = 0; i < paths.length; i++) {
                    if (this.path.indexOf(paths[i]) !== -1) {
                        console.log("[!] Bypassing check for: " + this.path);
                        retval.replace(0); // Return False
                        return;
                    }
                }
            }
        }
    });
    console.log("[*] Jailbreak detection bypass loaded");
}