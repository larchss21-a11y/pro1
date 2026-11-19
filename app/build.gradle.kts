import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.nexus.firewall"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.nexus.firewall"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    // Llave de firma fija: así cada APK nuevo se instala encima del anterior sin perder tus reglas.
    val ksFile = rootProject.file("keystore.properties")
    val ks = Properties()
    if (ksFile.exists()) ksFile.inputStream().use { ks.load(it) }
    signingConfigs {
        create("nexus") {
            storeFile = file(ks.getProperty("storeFile", "nexus-release.jks"))
            storePassword = ks.getProperty("storePassword", "")
            keyAlias = ks.getProperty("keyAlias", "nexus")
            keyPassword = ks.getProperty("keyPassword", "")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("nexus")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
}
