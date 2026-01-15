// Android UI Security Bypass (Android UI安全标志绕过)
// Ported from Objection: Removes FLAG_SECURE to allow screenshots/screen recording. (移除FLAG_SECURE标志，允许截屏和录屏)

function bypass_flag_secure() {
    try {
        var SurfaceView = Java.use("android.view.SurfaceView");
        var Window = Java.use("android.view.Window");
        var LayoutParams = Java.use("android.view.WindowManager$LayoutParams");

        // Value of FLAG_SECURE is usually 8192 (0x2000)
        var FLAG_SECURE = LayoutParams.FLAG_SECURE.value;

        console.log("[ZAFrida] Hooking Window.setFlags to remove FLAG_SECURE...");

        // 1. Hook Window.setFlags
        Window.setFlags.implementation = function(flags, mask) {
            if ((flags & FLAG_SECURE) !== 0) {
                console.log("[ZAFrida] Blocked setting FLAG_SECURE on Window");
                // Remove the bit from the flags
                flags = flags & ~FLAG_SECURE;
            }
            return this.setFlags(flags, mask);
        };

        // 2. Hook SurfaceView.setSecure (often used in video players/banking apps)
        SurfaceView.setSecure.implementation = function(isSecure) {
            if (isSecure) {
                console.log("[ZAFrida] Blocked SurfaceView.setSecure(true)");
                isSecure = false;
            }
            return this.setSecure(isSecure);
        };

        console.log("[ZAFrida] [+] FLAG_SECURE Bypass Active (Screenshots allowed)");

    } catch (e) {
        console.error("[ZAFrida] FLAG_SECURE Bypass Error: " + e.message);
    }
}

if (Java.available) {
    Java.perform(function() {
        bypass_flag_secure();
    });
}