// iOS Pasteboard Monitor (iOS剪贴板监控器)
// Polls the general pasteboard every 2 seconds for changes. (每2秒轮询剪贴板内容变化)

if (ObjC.available) {
    console.log("[.] iOS Pasteboard Monitor Loaded");

    var UIPasteboard = ObjC.classes.UIPasteboard;
    var generalPasteboard = UIPasteboard.generalPasteboard();
    var lastString = "";

    setInterval(function() {
        try {
            var content = generalPasteboard.string();
            if (content) {
                var str = content.toString();
                if (str !== lastString) {
                    lastString = str;
                    console.log("[Pasteboard] New content: " + str);
                }
            }
        } catch (e) {}
    }, 2000);
}