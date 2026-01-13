import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.nio.charset.StandardCharsets

plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "2.2.21"
    id("org.jetbrains.intellij.platform") version "2.10.5"
}

group = "com.zafrida"
version = "0.0.2"

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    // 不把 Kotlin stdlib 打进插件包（IDE 自带），但编译期需要
    compileOnly(kotlin("stdlib"))

    intellijPlatform {
        // 目标 IDE：PyCharm（2025.3 是当前时间点常见最新线）
        // 如果你本机 PyCharm 版本更低/更高，改成对应版本即可。
        pycharm("2024.3")

        // PyCharm 的 Python 核心插件
        bundledPlugin("PythonCore")
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.withType<KotlinCompile>().configureEach {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = StandardCharsets.UTF_8.name()
}
