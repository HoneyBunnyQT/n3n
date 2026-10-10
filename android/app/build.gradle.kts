plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The app has the version of the core, the VERSION file at the top of the
// tree: 3.4.8 is versionCode 304080, which leaves room for nine builds of
// the app with one version of the core.
val coreVersion = rootProject.file("../VERSION").readText().trim()
val coreVersionCode = Regex("^(\\d+)\\.(\\d+)\\.(\\d+)").find(coreVersion)
    ?.destructured?.let { (major, minor, patch) ->
        major.toInt() * 100000 + minor.toInt() * 1000 + patch.toInt() * 10
    } ?: 1

// A release build is signed with the key that the environment names, as
// release.yml has it (see docs/develop/Releasing.md); without one it is
// left unsigned.
val releaseKeystore: String? = System.getenv("N3N_ANDROID_KEYSTORE")

android {
    namespace = "dev.n3n.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.n3n.android"
        minSdk = 24             // fmemopen() in Bionic, see n3n_config_load_text()
        targetSdk = 35
        versionCode = coreVersionCode
        versionName = coreVersion

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // the core, from ../src, see src/main/cpp/CMakeLists.txt
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    signingConfigs {
        releaseKeystore?.let { keystore ->
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("N3N_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("N3N_ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("N3N_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseKeystore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // reading QR codes, on the phone (Apache-2.0, pure Java, no network)
    implementation("com.google.zxing:core:3.5.4")
}
