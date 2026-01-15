// List Class Methods (列出类方法)
// List all methods of a specified Objective-C class. (列出指定 Objective-C 类的所有方法)

// --- CONFIGURATION ---
var className = "TargetClass"; // EDIT THIS
// ---------------------

function list_methods(className) {
    var methods = ObjC.classes[className].$ownMethods;
    console.log("[*] Methods of " + className + ":");
    for (var i = 0; i < methods.length; i++) {
        console.log("  " + methods[i]);
    }
}

list_methods(className);
