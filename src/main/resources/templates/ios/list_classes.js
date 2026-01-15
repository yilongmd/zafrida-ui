// List ObjC Classes (列出 ObjC 类)
// List all Objective-C classes and filter by keyword. (列出所有 Objective-C 类，按关键字过滤)

for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        if (className.includes("keyword")) {
            console.log("[*] " + className);
        }
    }
}