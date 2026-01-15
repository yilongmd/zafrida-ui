// Android Hook String (Android 钩子 字符串)
// 字符串相关hook(by 小佳)
function hook_string_factory() {
    var stringFactory = Java.use("java.lang.StringFactory");
    stringFactory.newStringFromString.implementation = function (a) {
        var retval = this.newStringFromString(a);
        console.log("stringFactory.newStringFromString: ", retval);
        return retval;
    }
    stringFactory.newStringFromChars.overload('[C').implementation = function (a) {
        var retval = this.newStringFromChars(a);
        console.log("stringFactory.newStringFromChars: ", retval);
        return retval;
    }
}

Java.perform(function() {
    hook_string_factory();
});