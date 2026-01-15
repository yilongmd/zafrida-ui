// Android Hook org.json (Android 钩子 org.json)
// JSON处理相关hook(by 小佳)
function hook_jsonobject() {
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
    jSONObject.optString.overload('java.lang.String').implementation = function (str) {
        console.log('jSONObject.optString: ', str);
        var result = this.optString(str);
        console.log('jSONObject.optString result: ', result);
        return result;
    };
}

Java.perform(function() {
    hook_jsonobject();
});

