// Show All Java Classes (显示所有Java类)
// Enumerate all loaded Java classes in the current process. (枚举当前进程中所有已加载的Java类)

function show_all_classes() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            console.log(className);
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });
}

Java.perform(function() {
    show_all_classes();
});
