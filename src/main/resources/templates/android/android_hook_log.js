// Android Hook Log (Android 钩子 Log)
// 日志(by 小佳)
function hook_log() {
    var log = Java.use("android.util.Log");
    log.w.overload('java.lang.String', 'java.lang.String').implementation = function (tag, message) {
        console.log("log.w: ", tag, message);
        return this.w(tag, message);
    }
}

Java.perform(function() {
    hook_log();
});
