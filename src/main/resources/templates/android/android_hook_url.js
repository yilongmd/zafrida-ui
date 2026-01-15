// Android Hook URL (Android 钩子 URL)
// URL相关hook(by 小佳)
function hook_java_url() {
    var URL = Java.use('java.net.URL');
    URL.$init.overload('java.lang.String').implementation = function (a) {
        console.log('java.net.URL: ' + a);
        this.$init(a);
    }
}

function hook_okhttp_url() {
    var Builder = Java.use('okhttp3.Request$Builder');
    Builder.url.overload('okhttp3.HttpUrl').implementation = function (a) {
        var res = this.url(a);
        console.log("okhttp3.HttpUrl result: " + res);
        return res;
    }
}

Java.perform(function() {
    hook_java_url();
    hook_okhttp_url();
});