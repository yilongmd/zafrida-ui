// Android Hook Base64 (Android 钩子 Base64)
// Base64相关hook(by 小佳)
function hook_base64() {
    var base64 = Java.use("android.util.Base64");
    base64.encodeToString.overload('[B', 'int').implementation = function (a, b) {
        console.log("base64.encodeToString: ", JSON.stringify(a));
        var result = this.encodeToString(a, b);
        console.log("base64.encodeToString result: ", result)
        return result;
    }
}

Java.perform(function() {
    hook_base64();
});
