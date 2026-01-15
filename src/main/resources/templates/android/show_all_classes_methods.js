// Show All Java Classes and Methods (显示所有Java类及其方法)
// Enumerate loaded Java classes and print their method signatures. (枚举已加载的Java类并打印其方法签名)

function show_all_classes_methods() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            try {
                console.log("[*] Class Name: " + className);
                var clazz = Java.use(className);
                var methodArr = clazz.class.getMethods();
                for (var m in methodArr) {
                    console.log("\t" + methodArr[m]);
                }
            } catch (e) {
                // Some classes may fail to load
            }
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });
}

Java.perform(function() {
    show_all_classes_methods();
});
