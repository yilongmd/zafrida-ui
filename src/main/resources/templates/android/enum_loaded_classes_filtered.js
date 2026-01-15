// Enumerate Loaded Java Classes (Regex Filter) (枚举已加载的 Java 类 - 正则过滤)
// Enumerate loaded Java classes and print those matching a regex pattern. (枚举已加载的 Java 类，打印匹配正则表达式的类名)

function enumerate_loaded_classes_filtered(pattern) {
    console.log("[*] Enumerating loaded classes (pattern: " + pattern + ")");
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            try {
                if (pattern.test(name)) {
                    console.log("  " + name);
                }
            } catch (e) {}
        },
        onComplete: function () {
            console.log("[*] Done");
        }
    });
}

Java.perform(function () {
    // --- CONFIGURATION ---
    const PATTERN = /com\.example\./; // EDIT THIS
    // ---------------------
    enumerate_loaded_classes_filtered(PATTERN);
});
