// Android File System Monitor (Android文件系统监控器)
// Monitors File creation, FileInputStream reading, and FileOutputStream writing. (监控文件创建、FileInputStream读取和FileOutputStream写入操作)

Java.perform(function () {
    console.log("[.] File System Monitor Loaded");

    var File = Java.use("java.io.File");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var FileOutputStream = Java.use("java.io.FileOutputStream");

    // Monitor File(String pathname)
    File.$init.overload("java.lang.String").implementation = function (path) {
        console.log("[File] New File object: " + path);
        return this.$init(path);
    }

    // Monitor FileInputStream(File file)
    FileInputStream.$init.overload("java.io.File").implementation = function (file) {
        var path = file.getAbsolutePath();
        console.log("[Read] FileInputStream open: " + path);
        return this.$init(file);
    }

    // Monitor FileOutputStream(File file)
    FileOutputStream.$init.overload("java.io.File").implementation = function (file) {
        var path = file.getAbsolutePath();
        console.log("[Write] FileOutputStream open: " + path);
        return this.$init(file);
    }

    // Optional: Hook write to see data (warning: heavy output)
    /*
    FileOutputStream.write.overload("[B", "int", "int").implementation = function (buffer, offset, count) {
        console.log("[Write] Writing " + count + " bytes");
        return this.write(buffer, offset, count);
    }
    */
});