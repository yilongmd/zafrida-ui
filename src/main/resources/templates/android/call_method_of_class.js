// Call Java Method on Live Instance (调用活动实例的 Java 方法)
// Use Java.choose() to locate instances and invoke a method for runtime inspection. (使用 Java.choose() 定位实例并调用方法进行运行时检查)

//Source: https://11x256.github.io/Frida-hooking-android-part-2/

//Update fully qualified activity class name here
Java.choose("com.example.app.activity_class_name" , {
  onMatch : function(instance){ //This function will be called for every instance found by frida
    console.log("Found instance: "+instance);
    console.log("Result of method call: " + instance.method_name_to_call()); //Update method name here to call
  },
  onComplete:function(){}
});
