// iOS Show Alert Dialog
// Displays a native UIAlertController on the screen (Useful for verifying injection).

if (ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, function () {
        var UIAlertController = ObjC.classes.UIAlertController;
        var UIAlertAction = ObjC.classes.UIAlertAction;
        var UIApplication = ObjC.classes.UIApplication;

        var title = "ZaFrida";
        var message = "Injection Successful!";

        var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(title, message, 1);
        var okAction = UIAlertAction.actionWithTitle_style_handler_("OK", 0, NULL);

        alert.addAction_(okAction);

        // Find top view controller
        var keyWindow = UIApplication.sharedApplication().keyWindow();
        var rootVC = keyWindow.rootViewController();

        if (rootVC) {
            while (rootVC.presentedViewController()) {
                rootVC = rootVC.presentedViewController();
            }
            rootVC.presentViewController_animated_completion_(alert, true, NULL);
            console.log("[*] Alert dialog presented");
        }
    });
}