// iOS FileSystem List (Simple) (iOS文件系统目录列表)
// Lists files in the App's Documents and Library directories. (列出应用Documents和Library目录下的文件)

if (ObjC.available) {
    var NSFileManager = ObjC.classes.NSFileManager;
    var manager = NSFileManager.defaultManager();
    var stringClass = ObjC.classes.NSString;

    function listDirectory(path) {
        var error = Memory.alloc(Process.pointerSize);
        error.writePointer(NULL);

        var files = manager.contentsOfDirectoryAtPath_error_(path, error);
        var err = error.readPointer();

        if (!err.isNull()) {
            console.log("[ZAFrida] Access denied or empty: " + path);
            return;
        }

        var count = files.count();
        console.log("\n[ZAFrida] Listing: " + path + " (" + count + " items)");
        console.log("---------------------------------------------------");

        for (var i = 0; i < count; i++) {
            var file = files.objectAtIndex_(i).toString();
            var fullPath = path + "/" + file;
            var isDirPtr = Memory.alloc(Process.pointerSize);
            manager.fileExistsAtPath_isDirectory_(fullPath, isDirPtr);

            var isDir = isDirPtr.readU8() === 1;
            var marker = isDir ? "[DIR]  " : "[FILE] ";
            console.log(marker + file);
        }
    }

    // Get App Home Directory
    var getGlobalExport = Reflect.get(Module, "getGlobalExportByName");
    if (typeof getGlobalExport !== "function") {
        var findExportByName = Reflect.get(Module, "findExportByName");
        getGlobalExport = function(name) {
            return findExportByName.call(Module, null, name);
        };
    }
    var NSHomeDirectory = new NativeFunction(getGlobalExport.call(Module, "NSHomeDirectory"), 'pointer', []);
    var homeDir = new ObjC.Object(NSHomeDirectory()).toString();

    // List common interesting folders
    listDirectory(homeDir + "/Documents");
    listDirectory(homeDir + "/Library/Preferences"); // SharedPrefs (plist) usually here
}
