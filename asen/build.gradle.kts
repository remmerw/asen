
import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.kotlin.serialization)
}

group = "io.github.remmerw"
version = "0.2.5"

kotlin {

    jvm()
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    // todo iosX64()
    // todo iosArm64()
    // todo iosSimulatorArm64()
    // todo linuxX64()


    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.kotlin.stdlib)
                implementation(libs.kotlinx.datetime)
                implementation(libs.uri.kmp) // TODO FUTURE [medium] remove when part of stdlib
                implementation(libs.kotlinx.serialization.protobuf)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.io.core) // TODO FUTURE [medium] remove when part of stdlib
                implementation(libs.sha2)
                implementation(libs.hmac.sha2)
                implementation(libs.crypto.rand)
                implementation(libs.ktor.network)
                implementation(libs.atomicfu)
                implementation(libs.cryptography.core)
                implementation(libs.indispensable)
                implementation(libs.cryptography.bigint)
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
