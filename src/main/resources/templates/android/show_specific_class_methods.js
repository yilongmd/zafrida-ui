// Show Methods of Specific Java Class (显示指定Java类的方法)
// Print all methods of a specified Java class (including inherited methods). (打印指定Java类的所有方法，包括继承的方法)

function show_specific_class_methods(className) {
    var clazz = Java.use(className);
    var methodArr = clazz.class.getMethods();
    console.log("[*] Class Name: " + className);
    console.log("[*] Method Names:");
    for (var m in methodArr) {
        console.log("    " + methodArr[m]);
    }
}

Java.perform(function() {
    // --- CONFIGURATION ---
    // class inside a class is defined using CLASS_NAME$SUB_CLASS_NAME
    var className = "android.security.keystore.KeyGenParameterSpec$Builder"; // EDIT THIS
    // ---------------------
    show_specific_class_methods(className);
});
