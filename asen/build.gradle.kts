@file:OptIn(ExperimentalWasmDsl::class, ExperimentalKotlinGradlePluginApi::class)

import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.kotlin.serialization)
}

group = "io.github.remmerw"
version = "0.4.5"

kotlin {

    androidTarget {
        instrumentedTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)
        publishLibraryVariants("release")
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    jvm()
    // iosX64()
    // iosArm64()
    // iosSimulatorArm64()
    // linuxArm64()
    // linuxX64()
    // linuxArm64()
    // wasmJs()
    // wasmWasi()
    // js()

    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                implementation(libs.kotlinx.serialization.protobuf)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.cryptography.core)
                implementation(libs.hmac.sha2)


                implementation(libs.frey)
                implementation(libs.borr)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        androidMain {
            dependencies {
                implementation(libs.cryptography.provider.jdk)
            }
        }

        jvmMain {
            dependencies {
                implementation(libs.cryptography.provider.jdk)
            }
        }

        androidInstrumentedTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.runner)
        }

        androidUnitTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}


android {
    namespace = "io.github.remmerw.asen"
    compileSdk = 36
    defaultConfig {
        minSdk = 27
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}


mavenPublishing {
    publishToMavenCentral()

    signAllPublications()

    coordinates(group.toString(), "asen", version.toString())

    pom {
        name = "asen"
        description = "Basic library for connecting to the libp2p network"
        inceptionYear = "2025"
        url = "https://github.com/remmerw/asen/"
        licenses {
            license {
                name = "The Apache License, Version 2.0"
                url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                distribution = "https://www.apache.org/licenses/LICENSE-2.0.txt"
            }
        }
        developers {
            developer {
                id = "remmerw"
                name = "Remmer Wilts"
                url = "https://github.com/remmerw/"
            }
        }
        scm {
            url = "https://github.com/remmerw/asen/"
            connection = "scm:git:git://github.com/remmerw/asen.git"
            developerConnection = "scm:git:ssh://git@github.com/remmerw/asen.git"
        }
    }
}
