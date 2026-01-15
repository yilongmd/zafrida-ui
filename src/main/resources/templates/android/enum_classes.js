// Enumerate Classes (枚举类)
// Enumerate all loaded Java classes and filter by keyword. (枚举所有已加载的 Java 类，按关键字过滤)

function enumerate_classes(keyword) {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes(keyword)) {
                console.log("[*] Found: " + className);
            }
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });
}

Java.perform(function() {
    // --- CONFIGURATION ---
    var keyword = "keyword"; // EDIT THIS
    // ---------------------
    enumerate_classes(keyword);
});