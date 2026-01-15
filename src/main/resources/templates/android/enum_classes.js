// Enumerate Classes (枚举类)
// Enumerate all loaded Java classes and filter by keyword. (枚举所有已加载的 Java 类，按关键字过滤)

Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("keyword")) {
                console.log("[*] Found: " + className);
            }
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });
});