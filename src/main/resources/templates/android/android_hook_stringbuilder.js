// Android Hook org.json
// 一般来说json都会使用gson这个库(by  小佳)
Java.perform(function() {
    // JSON处理
    var jSONObject = Java.use("org.json.JSONObject");
    jSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function (a, b) {
        console.log("jSONObject.put: ", a, b);
        return this.put(a, b);
    }
    jSONObject.getString.implementation = function (a) {
        console.log("jSONObject.getString: ", a);
        var result = this.getString(a);
        console.log("jSONObject.getString result: ", result);
        return result;
    }
    JSONObject['optString'].overload('java.lang.String').implementation = function (str) {
        if(str === "data"){
            console.log('str', str)
            getStackTraceString();
        }
        let result = this['optString'](str);
        return result;
    };
});

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
