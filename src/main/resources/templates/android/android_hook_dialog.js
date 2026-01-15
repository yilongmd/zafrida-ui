// Android Hook Toast and Dialog (Android 钩子 Toast 和 Dialog)
// Toast和Dialog相关hook(by 小佳)
function hook_toast() {
    var toast = Java.use("android.widget.Toast");
    toast.show.implementation = function () {
        console.log("toast.show: ");
        return this.show();
    }
}

function hook_dialog() {
    var Dialog = Java.use("android.app.Dialog");
    Dialog.show.implementation = function() {
        console.log("Dialog.show: ");
        this.show();
    };
}

Java.perform(function() {
    hook_toast();
    hook_dialog();
});