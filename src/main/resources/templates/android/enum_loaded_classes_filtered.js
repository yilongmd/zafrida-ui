// Enumerate Loaded Java Classes (Regex Filter) (枚举已加载的 Java 类 - 正则过滤)
// Enumerate loaded Java classes and print those matching a regex pattern. (枚举已加载的 Java 类，打印匹配正则表达式的类名)

Java.perform(function () {
  // TODO: edit pattern
  const PATTERN = /com\.example\./;

  console.log("[*] Enumerating loaded classes (pattern: " + PATTERN + ")");
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      try {
        if (PATTERN.test(name)) {
          console.log("  " + name);
        }
      } catch (e) {}
    },
    onComplete: function () {
      console.log("[*] Done");
    }
  });
});
