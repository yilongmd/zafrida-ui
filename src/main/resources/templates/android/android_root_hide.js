// Android Root Detection Bypass (Android Root检测绕过)
// Hides su binary, Magisk, SuperSU, and specific package names. (隐藏su二进制文件、Magisk、SuperSU及特定包名，绕过Root检测)

Java.perform(function() {
    console.log("[.] Android Root Hide Loaded");

    var RootPackages = ["com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu", "com.topjohnwu.magisk", "me.weishu.kernelsu"];
    var RootBinaries = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su"];
    var RootProperties = {
        "ro.debuggable": "0",
        "ro.secure": "1"
    };

    // 1. Hook File.exists()
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < RootBinaries.length; i++) {
            if (path === RootBinaries[i]) {
                console.log("[+] Bypassed Root check for file: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // 2. Hook PackageManager
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    try {
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
            if (RootPackages.indexOf(pname) >= 0) {
                console.log("[+] Bypassed Root App check: " + pname);
                // Throw NameNotFoundException to simulate package missing
                var NameNotFoundException = Java.use("android.content.pm.PackageManager$NameNotFoundException");
                throw NameNotFoundException.$new(pname);
            }
            return this.getPackageInfo(pname, flags);
        };
    } catch (e) { console.log("[-] PackageManager hook failed"); }

    // 3. Hook System Properties (getprop)
    var SystemProperties = Java.use("android.os.SystemProperties");
    try {
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            if (RootProperties.hasOwnProperty(key)) {
                console.log("[+] Spoofing property: " + key);
                return RootProperties[key];
            }
            return this.get(key);
        };
    } catch (e) { console.log("[-] SystemProperties hook failed"); }

    console.log("[+] Root detection hooks applied.");
});