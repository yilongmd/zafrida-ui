// Android Hook HashMap (Android 钩子 HashMap)
// 由于有些请求头会使用这个添加，可能通过okhttp直接增加(by 小佳)
function hook_hashmap() {
    var hashMap = Java.use("java.util.HashMap");
    hashMap.put.implementation = function (a, b) {
        console.log("hashMap.put: ", a, b);
        return this.put(a, b);
    }
}

function hook_concurrent_hashmap() {
    var ConcurrentHashMap = Java.use("java.util.concurrent.ConcurrentHashMap");
    ConcurrentHashMap.put.implementation = function (a, b) {
        console.log("ConcurrentHashMap.put: ", a, b);
        return this.put(a, b);
    }
}

function hook_linked_hashmap() {
    var LinkedHashMapClass = Java.use("java.util.LinkedHashMap");
    LinkedHashMapClass.put.implementation = function (key, value) {
        console.log("LinkedHashMap key:", key, "value:", value);
        return this.put(key, value);
    };
}

Java.perform(function() {
    hook_hashmap();
    hook_concurrent_hashmap();
    hook_linked_hashmap();
});
