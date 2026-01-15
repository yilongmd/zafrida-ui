// Android File System Monitor (Android文件系统监控器)
// Monitors File creation, FileInputStream reading, and FileOutputStream writing. (监控文件创建、FileInputStream读取和FileOutputStream写入操作)

function monitor_file_creation() {
    var File = Java.use("java.io.File");
    File.$init.overload("java.lang.String").implementation = function (path) {
        console.log("[File] New File object: " + path);
        return this.$init(path);
    }
}

function monitor_file_input_stream() {
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload("java.io.File").implementation = function (file) {
        var path = file.getAbsolutePath();
        console.log("[Read] FileInputStream open: " + path);
        return this.$init(file);
    }
}

function monitor_file_output_stream() {
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.io.File").implementation = function (file) {
        var path = file.getAbsolutePath();
        console.log("[Write] FileOutputStream open: " + path);
        return this.$init(file);
    }
}

Java.perform(function () {
    console.log("[.] File System Monitor Loaded");
    monitor_file_creation();
    monitor_file_input_stream();
    monitor_file_output_stream();
});