// Android Hook StringBuilder (Android 钩子 StringBuilder)
// StringBuilder相关hook(by 小佳)
function hook_stringbuilder() {
    var StringBuilder = Java.use("java.lang.StringBuilder");
    StringBuilder.toString.implementation = function () {
        var result = this.toString();
        console.log("StringBuilder.toString: ", result);
        return result;
    }
}

function hook_stringbuffer() {
    var StringBuffer = Java.use("java.lang.StringBuffer");
    StringBuffer.toString.implementation = function () {
        var result = this.toString();
        console.log("StringBuffer.toString: ", result);
        return result;
    }
}

Java.perform(function() {
    hook_stringbuilder();
    hook_stringbuffer();
});
