// Backtrace Snippet (调用栈回溯代码片段)
// Helper snippet to print an accurate backtrace (use inside Interceptor hooks). (辅助代码片段，用于打印精确的调用栈回溯，在 Interceptor 钩子中使用)

//Credit: github.com/iddoeldor/frida-snippets
var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t");
console.warn("\n[-] ======== Backtrace Start  ========");
console.log(backtrace);
console.warn("\n[-] ======== Backtrace End  ========");
