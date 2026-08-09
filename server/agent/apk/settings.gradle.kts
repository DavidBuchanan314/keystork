// A standalone Gradle build, not part of the CMake project -- CMake invokes it
// and takes the dex out of the APK it produces. Kept standalone so that the
// daemon's build stays a CMake build and this stays an ordinary Android one.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "keystork-agent"
