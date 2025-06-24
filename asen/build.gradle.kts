@file:OptIn(ExperimentalWasmDsl::class)

import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.kotlin.serialization)
}

group = "io.github.remmerw"
version = "0.2.8"

kotlin {

    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    jvm()
    iosX64()
    iosArm64()
    iosSimulatorArm64()
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
                implementation(libs.hmac.sha2) // TODO replace in the future
                implementation(libs.ktor.network)
                implementation(libs.atomicfu)
                implementation(libs.cryptography.core)
                implementation(libs.indispensable) // TODO replace in the future
                implementation(libs.cryptography.bigint)
                implementation(libs.curve25519) // TODO replace in the future
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

        iosMain {
            dependencies {
                implementation(libs.cryptography.provider.apple)
                // or openssl3 provider with better algorithms coverage and other native targets support
                // implementation("dev.whyoleg.cryptography:cryptography-provider-openssl3-prebuilt:0.4.0")
            }
        }
    }
}


android {
    namespace = "io.github.remmerw.asen"
    compileSdk = 36
    defaultConfig {
        minSdk = 27
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}


mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)

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
