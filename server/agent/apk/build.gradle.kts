// The agent's Java half, built as an ordinary Android app.
//
// It is never installed. What is wanted is the dex: an app build is simply the
// supported way to get a dependency like the Play Integrity SDK compiled and
// dexed together with our own classes, transitive dependencies and all. CMake
// extracts classes.dex from the APK and embeds it in the agent, which is
// embedded in the daemon.
//
// Consequences of being a dex and not an app, both load-bearing:
//
//   *Resources are lost.* Only the dex is taken, so anything here that reads
//   its own R.* would fail. The resources the process does have are the target
//   app's, which are untouched.
//
//   *The manifest is lost too.* It is declared below to say what the classes
//   are for, and because a future minified build would need it as the root of
//   the keep graph, but at runtime the framework is told about these classes
//   by the agent rewriting the bind data, not by any manifest.

plugins {
    id("com.android.application") version "8.13.2"
}

android {
    namespace = "keystork"
    compileSdk = 36

    defaultConfig {
        applicationId = "keystork.agent"
        // The daemon's own floor is API 31; there is no reason for this to be
        // lower, and a higher minSdk keeps d8 from desugaring what the device
        // can already do.
        minSdk = 31
        targetSdk = 36
    }

    buildTypes {
        release {
            // Nothing here is shipped as an app, so there is no size argument
            // for shrinking -- and R8 would need a keep graph rooted in a
            // manifest the runtime never reads.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("com.google.android.play:integrity:1.6.0")
}
